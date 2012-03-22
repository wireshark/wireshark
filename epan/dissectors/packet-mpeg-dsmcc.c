/* packet-dsmcc.c
 *
 * Routines for ISO/IEC 13818-6 DSM-CC
 * Copyright 2012, Weston Schmidt <weston_schmidt@alumni.purdue.edu>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/crc32-tvb.h>
#include <epan/dissectors/packet-mpeg-sect.h>

/* NOTE: Please try to keep this status comment up to date until the spec is
 * completely implemented - there are a large number of tables in the spec.
 *
 * 13818-6 Table status:
 *
 * Missing tables:
 * 3-1 3-2 3-3 3-4 3-6 3-7 3-8 3-9
 * 4-1 4-6 4-7 4-8 4-9 4-10 4-11 4-12 4-13 4-14 4-15 4-16 4-17 4-*
 * 5-*
 * 6-4
 * 7-5 7-8 7-10 7-12
 * 8-2 8-3 8-4 8-6
 * 9-5 9-6
 * 10-*
 * 11-*
 * 12-*
 *
 * Dissected tables:
 * 2-1 2-4 2-6 2-7
 * 6-1
 * 7-6 7-7 
 * 9-2
 *
 * Validated (all parameters are checked) tables:
 */


static int proto_dsmcc = -1;
static dissector_handle_t data_handle;
static gboolean dsmcc_sect_check_crc = FALSE;

/* NOTE: Please add values numerically according to 13818-6 so it is easier to
 * keep track of what parameters/tables are associated with each other.
 */

/* table 2-1 dsmccMessageHeader - start */
static int hf_dsmcc_protocol_discriminator = -1;
static int hf_dsmcc_type = -1;
static int hf_dsmcc_message_id = -1;
static int hf_dsmcc_transaction_id = -1;
static int hf_dsmcc_header_reserved = -1;
static int hf_dsmcc_adaptation_length = -1;
static int hf_dsmcc_message_length = -1;
/* table 2-1 dsmccMessageHeader - end */

/* table 2-4 dsmccAdaptationHeader - start */
static int hf_dsmcc_adaptation_type = -1;
/* table 2-4 dsmccAdaptationHeader - end */

/* table 2-6 dsmccConditionalAccess - start */
static int hf_dsmcc_adaptation_ca_reserved = -1;
static int hf_dsmcc_adaptation_ca_system_id = -1;
static int hf_dsmcc_adaptation_ca_length = -1;
/* table 2-6 dsmccConditionalAccess - end */

/* table 2-7 dsmccUserId - start */
static int hf_dsmcc_adaptation_user_id_reserved = -1;
/* table 2-7 dsmccUserId - end */

/* table 6-1 compatabilityDescriptor - start */
static int hf_compat_desc_length = -1;
static int hf_compat_desc_count = -1;
static int hf_desc_type = -1;
static int hf_desc_length = -1;
static int hf_desc_spec_type = -1;
static int hf_desc_spec_data = -1;
static int hf_desc_model = -1;
static int hf_desc_version = -1;
static int hf_desc_sub_desc_count = -1;
static int hf_desc_sub_desc_type = -1;
static int hf_desc_sub_desc_len = -1;
/* table 6-1 compatabilityDescriptor - end */

/* table 7-3 dsmccDownloadDataHeader - start */
static int hf_dsmcc_dd_download_id = -1;
static int hf_dsmcc_dd_message_id = -1;
/* table 7-3 dsmccDownloadDataHeader - end */

/* table 7-6 dsmccDownloadInfoIndication/InfoResponse - start */
static int hf_dsmcc_dii_download_id = -1;
static int hf_dsmcc_dii_block_size = -1;
static int hf_dsmcc_dii_window_size = -1;
static int hf_dsmcc_dii_ack_period = -1;
static int hf_dsmcc_dii_t_c_download_window = -1;
static int hf_dsmcc_dii_t_c_download_scenario = -1;
static int hf_dsmcc_dii_number_of_modules = -1;
static int hf_dsmcc_dii_module_id = -1;
static int hf_dsmcc_dii_module_size = -1;
static int hf_dsmcc_dii_module_version = -1;
static int hf_dsmcc_dii_module_info_length = -1;
static int hf_dsmcc_dii_private_data_length = -1;
/* table 7-6 dsmccDownloadInfoIndication/InfoResponse - end */

/* table 7-7 dsmccDownloadDataBlock - start */
static int hf_dsmcc_ddb_module_id = -1;
static int hf_dsmcc_ddb_version = -1;
static int hf_dsmcc_ddb_reserved = -1;
static int hf_dsmcc_ddb_block_number = -1;
/* table 7-7 dsmccDownloadDataBlock - end */

/* table 9-2 dsmccSection - start */
static int hf_dsmcc_table_id = -1;
static int hf_dsmcc_section_syntax_indicator = -1;
static int hf_dsmcc_private_indicator = -1;
static int hf_dsmcc_reserved = -1;
static int hf_dsmcc_section_length = -1;
static int hf_dsmcc_table_id_extension = -1;
static int hf_dsmcc_reserved2 = -1;
static int hf_dsmcc_version_number = -1;
static int hf_dsmcc_current_next_indicator = -1;
static int hf_dsmcc_section_number = -1;
static int hf_dsmcc_last_section_number = -1;
static int hf_dsmcc_crc = -1;
static int hf_dsmcc_checksum = -1;
/* table 9-2 dsmccSection - end */

/* TODO: this should really live in the ETV dissector, but I'm not sure how
 * to make the functionality work exactly right yet.  Will work on a patch
 * for this next.
 */
static int hf_etv_module_abs_path = -1;
static int hf_etv_dii_authority = -1;

static gint ett_dsmcc = -1;
static gint ett_dsmcc_payload = -1;
static gint ett_dsmcc_header = -1;
static gint ett_dsmcc_adaptation_header = -1;
static gint ett_dsmcc_compat = -1;
static gint ett_dsmcc_compat_sub_desc = -1;
static gint ett_dsmcc_dii_module = -1;

#define DSMCC_TID_LLCSNAP	0x3a
#define DSMCC_TID_UN_MSG	0x3b
#define DSMCC_TID_DD_MSG	0x3c
#define DSMCC_TID_DESC_LIST	0x3d
#define DSMCC_TID_PRIVATE	0x3e

#define DSMCC_SSI_MASK		0x8000
#define DSMCC_PRIVATE_MASK	0x4000
#define DSMCC_RESERVED_MASK	0x3000
#define DSMCC_LENGTH_MASK  	0x0fff

#define DSMCC_RESERVED2_MASK			0xc0
#define DSMCC_VERSION_NUMBER_MASK		0x3e
#define DSMCC_CURRENT_NEXT_INDICATOR_MASK	0x01

static const range_string dsmcc_header_type_vals[] = {
	{    0,    0, "ISO/IEC 13818-6 Reserved" },
	{ 0x01, 0x01, "ISO/IEC 13818-6 User-to-Network Configuration Message" },
	{ 0x02, 0x02, "ISO/IEC 13818-6 User-to-Network Session Message" },
	{ 0x03, 0x03, "ISO/IEC 13818-6 Download Message" },
	{ 0x04, 0x04, "ISO/IEC 13818-6 SDB Channel Change Protocol Message" },
	{ 0x05, 0x05, "ISO/IEC 13818-6 User-to-Network Pass-Thru Message" },
	{ 0x06, 0x7f, "ISO/IEC 13818-6 Reserved" },
	{ 0x80, 0xff, "User Defined Message Type" },
	{    0,    0, NULL }
};

static const range_string dsmcc_adaptation_header_vals[] = {
	{    0,    0, "ISO/IEC 13818-6 Reserved" },
	{ 0x01, 0x01, "DSM-CC Conditional Access Adaptation Format" },
	{ 0x02, 0x02, "DSM-CC User ID Adaptation Format" },
	{ 0x03, 0x7f, "ISO/IEC 13818-6 Reserved" },
	{ 0x80, 0xff, "User Defeined Adaption Type" },
	{    0,    0, NULL }
};

static const value_string dsmcc_payload_name_vals[] = {
	{ DSMCC_TID_LLCSNAP,   "LLCSNAP" },
	{ DSMCC_TID_UN_MSG,    "User Network Message" },
	{ DSMCC_TID_DD_MSG,    "Download Data Message" },
	{ DSMCC_TID_DESC_LIST, "Descriptor List" },
	{ DSMCC_TID_PRIVATE,   "Private" },
	{                 0,   NULL }
};

static const value_string dsmcc_dd_message_id_vals[] = {
	{ 0x1001,   "Download Info Request" },
	{ 0x1002,   "Download Info Indication" },
	{ 0x1003,   "Download Data Block" },
	{ 0x1004,   "Download Data Request" },
	{ 0x1005,   "Download Data Cancel" },
	{ 0x1006,   "Download Server Initiate" },
	{      0,   NULL }
};

static void
dissect_dsmcc_adaptation_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *sub_tvb;
	guint offset = 0;
	proto_item *pi;
	proto_tree *sub_tree;
	guint8 type, tmp;
	guint16 ca_len;

	type = tvb_get_guint8(tvb, offset);

	if (1 == type) {
		pi = proto_tree_add_text(tree, tvb, offset, -1, "Adaptation Header");
		sub_tree = proto_item_add_subtree(pi, ett_dsmcc_adaptation_header);
		proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;
		tmp = tvb_get_guint8(tvb, offset);
		pi = proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_ca_reserved, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		if (0xff != tmp) {
			PROTO_ITEM_SET_GENERATED(pi);
			expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
						"Invalid value - should be 0xff");
		}
		offset++;
		proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_ca_system_id, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		ca_len = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_ca_length, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		sub_tvb = tvb_new_subset(tvb, offset, ca_len, ca_len);
		call_dissector(data_handle, sub_tvb, pinfo, tree);
	} else if (2 == type) {
		pi = proto_tree_add_text(tree, tvb, offset, -1, "Adaptation Header");
		sub_tree = proto_item_add_subtree(pi, ett_dsmcc_adaptation_header);
		proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;
		tmp = tvb_get_guint8(tvb, offset);
		pi = proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_user_id_reserved, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		if (0xff != tmp) {
			PROTO_ITEM_SET_GENERATED(pi);
			expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
						"Invalid value - should be 0xff");
		}
		offset++;
		/* TODO: handle the userId */
	} else {
		pi = proto_tree_add_text(tree, tvb, offset, -1, "Unknown Adaptation Header");
		sub_tree = proto_item_add_subtree(pi, ett_dsmcc_adaptation_header);
		proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	}
}

static guint
dissect_dsmcc_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
			gboolean download_header)
{
	tvbuff_t *sub_tvb;
	proto_item *pi;
	proto_tree *sub_tree;
	guint8 prot_disc;
	guint reserved;
	guint8 adaptation_len;
	guint len = 0;
	int msg_id, tx_id;

	prot_disc = tvb_get_guint8(tvb, offset);
	reserved = tvb_get_guint8(tvb, 8+offset);
	adaptation_len = tvb_get_guint8(tvb, 9+offset);

	pi = proto_tree_add_text(tree, tvb, offset, 12+adaptation_len, "DSM-CC Header");
	sub_tree = proto_item_add_subtree(pi, ett_dsmcc_header);
	pi = proto_tree_add_item(sub_tree, hf_dsmcc_protocol_discriminator, tvb,
				 offset, 1, ENC_BIG_ENDIAN);
	if (0x11 != prot_disc) {
		PROTO_ITEM_SET_GENERATED(pi);
		expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
					"Invalid value - should be 0x11");
	}
	offset++;
	proto_tree_add_item(sub_tree, hf_dsmcc_type, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	offset++;
	if (TRUE == download_header) {
		msg_id = hf_dsmcc_dd_message_id;
		tx_id = hf_dsmcc_dd_download_id;
	} else {
		msg_id = hf_dsmcc_message_id;
		tx_id = hf_dsmcc_transaction_id;
	}
	proto_tree_add_item(sub_tree, msg_id, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(sub_tree, tx_id, tvb,
		offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	pi = proto_tree_add_item(sub_tree, hf_dsmcc_header_reserved, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	if (0xff != reserved) {
		PROTO_ITEM_SET_GENERATED(pi);
		expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
					"Invalid value - should be 0xff");
	}
	offset++;

	proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_length, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(sub_tree, hf_dsmcc_message_length, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	len = 12;
	if (0 < adaptation_len) {
		sub_tvb = tvb_new_subset(tvb, offset, adaptation_len, adaptation_len);
		dissect_dsmcc_adaptation_header(sub_tvb, pinfo, sub_tree);
		offset += adaptation_len;
	}

	return len;
}


static guint
dissect_dsmcc_dii_compat_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				guint offset)
{
	gint i, j;
	guint8 sub_count, sub_len;
	guint16 len, count;
	proto_item *pi;
	proto_tree *compat_tree;
	proto_tree *desc_sub_tree;

	len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_compat_desc_length, tvb, offset,
				2, ENC_BIG_ENDIAN);
	offset += 2;

	if (0 < len) {
		count = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_compat_desc_count, tvb, offset,
					2, ENC_BIG_ENDIAN);
		offset += 2;

		for (i = 0; i < count; i++) {
			pi = proto_tree_add_text(tree, tvb, offset, len, "Compatibility Descriptor");
			compat_tree = proto_item_add_subtree(pi, ett_dsmcc_compat);
			proto_tree_add_item(compat_tree, hf_desc_type, tvb, offset,
						1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(compat_tree, hf_desc_length, tvb, offset,
						1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(compat_tree, hf_desc_spec_type, tvb, offset,
						1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(compat_tree, hf_desc_spec_data, tvb, offset,
						3, ENC_BIG_ENDIAN);
			offset += 3;
			proto_tree_add_item(compat_tree, hf_desc_model, tvb, offset,
						2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(compat_tree, hf_desc_version, tvb, offset,
						2, ENC_BIG_ENDIAN);
			offset += 2;

			sub_count = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(compat_tree, hf_desc_sub_desc_count, tvb, offset,
						1, ENC_BIG_ENDIAN);
			offset++;

			for (j = 0; j < sub_count; j++) {
				sub_len = tvb_get_guint8(tvb, offset+1);

				pi = proto_tree_add_text(compat_tree, tvb, offset, sub_len+2, "Sub Descriptor");
				desc_sub_tree = proto_item_add_subtree(pi, ett_dsmcc_compat_sub_desc);
				proto_tree_add_item(desc_sub_tree, hf_desc_sub_desc_type, tvb, offset,
							1, ENC_BIG_ENDIAN);
				offset++;
				proto_tree_add_item(desc_sub_tree, hf_desc_sub_desc_len, tvb, offset,
							1, ENC_BIG_ENDIAN);
				offset++;

				offset += sub_len;
			}
		}

		if( 1000 == offset ) {
			expert_add_info_format( pinfo, NULL, PI_MALFORMED,
						PI_ERROR, "Invalid CRC" );
		}
	}

	return 2 + len;
}

static void
dissect_dsmcc_dii(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		guint offset)
{
	guint8 module_info_len;
	guint16 modules, private_data_len;
	guint16 module_id;
	guint8 module_version;
	guint module_size;
	guint i;
	proto_item *pi;
	proto_tree *mod_tree;

	proto_tree_add_item(tree, hf_dsmcc_dii_download_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_dsmcc_dii_block_size, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_dsmcc_dii_window_size, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_dsmcc_dii_ack_period, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_dsmcc_dii_t_c_download_window, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_dsmcc_dii_t_c_download_scenario, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	offset += dissect_dsmcc_dii_compat_desc(tvb, pinfo, tree, offset);
	proto_tree_add_item(tree, hf_dsmcc_dii_number_of_modules, tvb, offset, 2, ENC_BIG_ENDIAN);
	modules = tvb_get_ntohs(tvb, offset);
	offset += 2;

	for (i = 0; i < modules; i++ ) {
		module_id = tvb_get_ntohs(tvb, offset);
		module_size = tvb_get_ntohl(tvb, 2+offset);
		module_version = tvb_get_guint8(tvb, 6+offset);

		pi = proto_tree_add_text(tree, tvb, offset, -1,
				"Module Id: 0x%x, Version: %u, Size: %u",
				module_id, module_version, module_size);
		mod_tree = proto_item_add_subtree(pi, ett_dsmcc_dii_module);
		proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_size, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		module_info_len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_info_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		if (0 < module_info_len) {
			proto_tree_add_item(mod_tree, hf_etv_module_abs_path, tvb, offset, 1,
				ENC_ASCII|ENC_BIG_ENDIAN);
			offset += module_info_len;
		}
	}

	private_data_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_dsmcc_dii_private_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	if (0 < private_data_len) {
		proto_tree_add_item(tree, hf_etv_dii_authority, tvb, offset, 1,
			ENC_ASCII|ENC_BIG_ENDIAN);
		offset += private_data_len;
	}
}


static void
dissect_dsmcc_ddb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			proto_tree *top_tree, guint offset)
{
	tvbuff_t *sub_tvb;
	proto_item *pi;
	guint8 reserved;

	proto_tree_add_item(tree, hf_dsmcc_ddb_module_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_dsmcc_ddb_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	reserved = tvb_get_guint8(tvb, offset);
	pi = proto_tree_add_item(tree, hf_dsmcc_ddb_reserved, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	if (0xff != reserved) {
		PROTO_ITEM_SET_GENERATED(pi);
		expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
					"Invalid value - should be 0xff");
	}
	offset++;
	proto_tree_add_item(tree, hf_dsmcc_ddb_block_number, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	sub_tvb = tvb_new_subset(tvb, offset, -1, -1);
	call_dissector(data_handle, sub_tvb, pinfo, top_tree);
}


static void
dissect_dsmcc_un_download(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				proto_tree *top_tree)
{
	proto_item *pi;
	proto_tree *sub_tree;
	guint16 msg_id;
	guint offset = 0;

	msg_id = tvb_get_ntohs(tvb, offset+2);

	pi = proto_tree_add_text(tree, tvb, 0, -1, "User Network Message - %s",
			val_to_str(msg_id, dsmcc_dd_message_id_vals, "%s"));
	sub_tree = proto_item_add_subtree(pi, ett_dsmcc_payload);

	switch (msg_id) {
		case 0x1001:
		case 0x1002:
			offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, FALSE);
			dissect_dsmcc_dii(tvb, pinfo, sub_tree, offset);
			break;
		case 0x1003:
			offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, TRUE);
			dissect_dsmcc_ddb(tvb, pinfo, sub_tree, top_tree, offset);
			break;
		case 0x1004:
			/* TODO: Add support */
			break;
		case 0x1005:
			/* TODO: Add support */
			break;
		case 0x1006:
			/* TODO: Add support */
			break;
		default:
			break;
	}
}

static void
dissect_dsmcc_un(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			proto_tree *top_tree)
{
	guint8 type;

	/* dsmccMessageHeader.dsmccType */
	type = tvb_get_guint8(tvb, 1);

	switch (type) {
		case 1: /* user-to-network configuration */
			/* TODO: Add support */
			break;
		case 2: /* user-to-network session */
			/* TODO: Add support */
			break;
		case 3: /* user-to-network download */
			dissect_dsmcc_un_download(tvb, pinfo, tree, top_tree);
			break;
		case 4: /* sdb channel change protocol */
			/* TODO: Add support */
			break;
		case 5: /* user-to-network pass-thru */
			/* TODO: Add support */
			break;
		default:
			break;
	}
}

static gboolean
dissect_dsmcc_ts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_in)
{
	proto_item *pi;
	proto_tree *tree;
	guint8 tid;
	guint16 sect_len;
	guint crc_start;
	guint32 crc, calculated_crc;
	const char *label;
	tvbuff_t *sub_tvb;
	guint16 ssi;
	guint offset = 0;

	pi = proto_tree_add_item(tree_in, proto_dsmcc, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(pi, ett_dsmcc);

	tid = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_dsmcc_table_id, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	offset++;
	ssi = tvb_get_ntohs(tvb, offset);
	ssi &= DSMCC_SSI_MASK;
	proto_tree_add_item(tree, hf_dsmcc_section_syntax_indicator, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsmcc_private_indicator, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsmcc_reserved, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsmcc_section_length, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	sect_len = tvb_get_ntohs(tvb, offset);
	sect_len &= DSMCC_LENGTH_MASK;
	offset += 2;
	crc_start = offset;

	proto_tree_add_item(tree, hf_dsmcc_table_id_extension, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_dsmcc_reserved2, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsmcc_version_number, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsmcc_current_next_indicator, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_dsmcc_section_number, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_dsmcc_last_section_number, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	offset++;

	sub_tvb = tvb_new_subset(tvb, offset, sect_len-9, sect_len-9);
	switch (tid) {
		case DSMCC_TID_LLCSNAP:
			/* TODO: Add support */
			break;
		case DSMCC_TID_UN_MSG:
		case DSMCC_TID_DD_MSG:
			dissect_dsmcc_un(sub_tvb, pinfo, tree, tree_in);
			break;
		case DSMCC_TID_DESC_LIST:
			/* TODO: Add support */
			break;
		case DSMCC_TID_PRIVATE:
			/* TODO: Add support */
			break;
		default:
			break;
	}

	if (ssi) {
		crc = tvb_get_ntohl(tvb, crc_start+sect_len-4);

		calculated_crc = crc;
		label = "Unverified";
		if (dsmcc_sect_check_crc) {
			label = "Verified";
			calculated_crc = crc32_mpeg2_tvb_offset(tvb, crc_start, sect_len-4);
		}

		if (calculated_crc == crc) {
			proto_tree_add_uint_format( tree, hf_dsmcc_crc, tvb,
				crc_start+sect_len-4, 4, crc, "CRC: 0x%08x [%s]", crc, label);
		} else {
			proto_item *msg_error = NULL;

			msg_error = proto_tree_add_uint_format( tree, hf_dsmcc_crc, tvb,
								crc_start+sect_len-4, 4, crc,
								"CRC: 0x%08x [Failed Verification (Calculated: 0x%08x)]",
								crc, calculated_crc );
			PROTO_ITEM_SET_GENERATED(msg_error);
			expert_add_info_format( pinfo, msg_error, PI_MALFORMED,
						PI_ERROR, "Invalid CRC" );
		}
	} else {
		/* TODO: actually check the checksum */
		proto_tree_add_item(tree, hf_dsmcc_checksum, tvb,
			crc_start+sect_len-4, 4, ENC_BIG_ENDIAN);
	}

	return TRUE;
}

static void
dissect_dsmcc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSM-CC");
	dissect_dsmcc_ts(tvb, pinfo, tree);
}

void
proto_register_dsmcc(void)
{
	/* NOTE: Please add tables numerically according to 13818-6 so it is
	 * easier to keep track of what parameters/tables are associated with
	 * each other.
	 */
	static hf_register_info hf[] = {
		/* table 2-1 dsmccMessageHeader - start */
		{ &hf_dsmcc_protocol_discriminator, {
			"Protocol Discriminator", "dsmcc.protocol",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_type, {
			"Type", "dsmcc.type",
			FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(dsmcc_header_type_vals), 0, NULL, HFILL
		} },

		{ &hf_dsmcc_message_id, {
			"Message ID", "dsmcc.message_id",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_transaction_id, {
			"Transaction ID", "dsmcc.transaction_id",
			FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_header_reserved, {
			"Reserved", "dsmcc.header_reserved",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_adaptation_length, {
			"Adaptation Length", "dsmcc.adaptation_length",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_message_length, {
			"Message Length", "dsmcc.message_length",
			FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
		} },
		/* table 2-1 dsmccMessageHeader - end */


		/* table 2-4 dsmccAdaptationHeader - start */
		{ &hf_dsmcc_adaptation_type, {
			"Adaptation Type", "dsmcc.adaptation_header.type",
			FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(dsmcc_adaptation_header_vals), 0, NULL, HFILL
		} },
		/* table 2-4 dsmccAdaptationHeader - end */


		/* table 2-6 dsmccConditionalAccess - start */
		{ &hf_dsmcc_adaptation_ca_reserved, {
			"Reserved", "dsmcc.adaptation_header.ca.reserved",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_adaptation_ca_system_id, {
			"System ID", "dsmcc.adaptation_header.ca.system_id",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_adaptation_ca_length, {
			"System ID", "dsmcc.adaptation_header.ca.length",
			FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
		} },
		/* table 2-6 dsmccConditionalAccess - end */


		/* table 2-7 dsmccUserId - start */
		{ &hf_dsmcc_adaptation_user_id_reserved, {
			"Reserved", "dsmcc.adaptation_header.uid.reserved",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },
		/* table 2-7 dsmccUserId - start */


		/* table 6-1 compatabilityDescriptor - start */
		{ &hf_compat_desc_length, {
			"Compatibility Descriptor Length", "dsmcc.dii.compat_desc_len",
			FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_compat_desc_count, {
			"Descriptor Length", "dsmcc.dii.compat_desc_count",
			FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_desc_type, {
			"Descriptor Type", "dsmcc.dii.compat.type",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_desc_length, {
			"Descriptor Length", "dsmcc.dii.compat.length",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_desc_spec_type, {
			"Specifier Type", "dsmcc.dii.compat.spec_type",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_desc_spec_data, {
			"Specifier Data", "dsmcc.dii.compat.spec_data",
			FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_desc_model, {
			"Model", "dsmcc.dii.compat.model",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_desc_version, {
			"Version", "dsmcc.dii.compat.version",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_desc_sub_desc_count, {
			"Version", "dsmcc.dii.compat.sub_count",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_desc_sub_desc_type, {
			"Type", "dsmcc.dii.compat.sub_type",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_desc_sub_desc_len, {
			"Length", "dsmcc.dii.compat.sub_len",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },
		/* table 6-1 compatabilityDescriptor - end */


		/* table 7-3 dsmccDownloadDataHeader - start */
		{ &hf_dsmcc_dd_download_id, {
			"Download ID", "dsmcc.download_id",
			FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dd_message_id, {
			"Message ID", "dsmcc.message_id",
			FT_UINT16, BASE_HEX, VALS(dsmcc_dd_message_id_vals), 0, NULL, HFILL
		} },
		/* table 7-3 dsmccDownloadDataHeader - end */


		/* table 7-6 downloadInfoIndication - start */
		{ &hf_dsmcc_dii_download_id, {
			"Download ID", "dsmcc.dii.download_id",
			FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_block_size, {
			"Block Size", "dsmcc.dii.block_size",
			FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_window_size, {
			"Window Size", "dsmcc.dii.window_size",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_ack_period, {
			"ACK Period", "dsmcc.dii.ack_period",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_t_c_download_window, {
			"Carousel Download Window", "dsmcc.dii.carousel_download_window",
			FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_t_c_download_scenario, {
			"Carousel Download Scenario", "dsmcc.dii.carousel_download_scenario",
			FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_number_of_modules, {
			"Number of Modules", "dsmcc.dii.module_count",
			FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_module_id, {
			"Module ID", "dsmcc.dii.module_id",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_module_size, {
			"Module Size", "dsmcc.dii.module_size",
			FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_module_version, {
			"Module Version", "dsmcc.dii.module_version",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_module_info_length, {
			"Module Info Length", "dsmcc.dii.module_info_length",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_dii_private_data_length, {
			"Private Data Length", "dsmcc.dii.private_data_length",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },
		/* table 7-6 downloadInfoIndication - end */


		/* table 7-7 dsmccDownloadDataBlock - start */
		{ &hf_dsmcc_ddb_module_id, {
			"Module ID", "dsmcc.ddb.module_id",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_ddb_version, {
			"Version", "dsmcc.ddb.version",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_ddb_reserved, {
			"Reserved", "dsmcc.ddb.reserved",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_ddb_block_number, {
			"Block Number", "dsmcc.ddb.block_num",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },
		/* table 7-7 dsmccDownloadDataBlock - end */


		/* table 9-2 - start */
		{ &hf_dsmcc_table_id, {
			"Table ID", "mpeg_sect.table_id",
			FT_UINT8, BASE_HEX, VALS(dsmcc_payload_name_vals), 0, NULL, HFILL
		} },

		{ &hf_dsmcc_section_syntax_indicator, {
			"Session Syntax Indicator", "mpeg_sect.ssi",
			FT_UINT16, BASE_DEC, NULL, DSMCC_SSI_MASK, NULL, HFILL
		} },

		{ &hf_dsmcc_private_indicator, {
			"Private Indicator", "dsmcc.private_indicator",
			FT_UINT16, BASE_DEC, NULL, DSMCC_PRIVATE_MASK, NULL, HFILL
		} },

		{ &hf_dsmcc_reserved, {
			"Reserved", "mpeg_sect.reserved",
			FT_UINT16, BASE_HEX, NULL, DSMCC_RESERVED_MASK, NULL, HFILL
		} },

		{ &hf_dsmcc_section_length, {
			"Length", "mpeg_sect.section_length",
			FT_UINT16, BASE_DEC, NULL, DSMCC_LENGTH_MASK, NULL, HFILL
		} },

		{ &hf_dsmcc_table_id_extension, {
			"Table ID Extension", "dsmcc.table_id_extension",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_reserved2, {
			"Reserved", "dsmcc.reserved2",
			FT_UINT8, BASE_HEX, NULL, DSMCC_RESERVED2_MASK, NULL, HFILL
		} },

		{ &hf_dsmcc_version_number, {
			"Version Number", "dsmcc.version_number",
			FT_UINT8, BASE_DEC, NULL, DSMCC_VERSION_NUMBER_MASK, NULL, HFILL
		} },

		{ &hf_dsmcc_current_next_indicator, {
			"Current Next Indicator", "dsmcc.current_next_indicator",
			FT_UINT8, BASE_DEC, NULL, DSMCC_CURRENT_NEXT_INDICATOR_MASK, NULL, HFILL
		} },

		{ &hf_dsmcc_section_number, {
			"Section Number", "dsmcc.section_number",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_last_section_number, {
			"Last Section Number", "dsmcc.last_section_number",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_crc, {
			"CRC 32", "mpeg_sect.crc",
			FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dsmcc_checksum, {
			"Checksum", "dsmcc.checksum",
			FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
		} },
		/* table 9-2 - end */


		{ &hf_etv_module_abs_path, {
			"Module Absolute Path", "etv.dsmcc.dii.module_abs_path",
			FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
		} },

		{ &hf_etv_dii_authority, {
			"Authority", "etv.dsmcc.dii.authority",
			FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
		} }
	};

	static gint *ett[] = {
		&ett_dsmcc,
		&ett_dsmcc_payload,
		&ett_dsmcc_adaptation_header,
		&ett_dsmcc_header,
		&ett_dsmcc_compat,
		&ett_dsmcc_compat_sub_desc,
		&ett_dsmcc_dii_module
	};
	module_t *dsmcc_module;

	proto_dsmcc = proto_register_protocol("MPEG DSM-CC", "MPEG DSM-CC", "mpeg-dsmcc");

	proto_register_field_array(proto_dsmcc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	new_register_dissector("mp2t-dsmcc", dissect_dsmcc_ts, proto_dsmcc);

	dsmcc_module = prefs_register_protocol(proto_dsmcc, NULL);

	prefs_register_bool_preference(dsmcc_module, "verify_crc",
		"Verify the section CRC or checksum",
		"Whether the section dissector should verify the CRC or checksum",
		&dsmcc_sect_check_crc);
}


void
proto_reg_handoff_dsmcc(void)
{
	dissector_handle_t dsmcc_handle;

	dsmcc_handle = create_dissector_handle(dissect_dsmcc, proto_dsmcc);
	dissector_add_uint("mpeg_sect.tid", DSMCC_TID_LLCSNAP, dsmcc_handle);
	dissector_add_uint("mpeg_sect.tid", DSMCC_TID_UN_MSG, dsmcc_handle);
	dissector_add_uint("mpeg_sect.tid", DSMCC_TID_DD_MSG, dsmcc_handle);
	dissector_add_uint("mpeg_sect.tid", DSMCC_TID_DESC_LIST, dsmcc_handle);
	dissector_add_uint("mpeg_sect.tid", DSMCC_TID_PRIVATE, dsmcc_handle);
	data_handle = find_dissector("data");
}


