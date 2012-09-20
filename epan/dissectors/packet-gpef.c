/* packet-gpef.c
 * Routines for dissection of Group Policy : Encrypted File System Extension
 * Described in Microsoft document MS-GPEF.pdf
 * Copyright 2008, Ronnie Sahlberg
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "packet-windows-common.h"
#include <epan/asn1.h>
#include "packet-x509af.h"
#include "packet-x509if.h"

static int proto_gpef = -1;
static int hf_gpef_keycount = -1;
static int hf_gpef_efskey = -1;
static int hf_gpef_efskey_length1 = -1;
static int hf_gpef_efskey_length2 = -1;
static int hf_gpef_efskey_sid_offset = -1;
static int hf_gpef_efskey_cert_offset = -1;
static int hf_gpef_efskey_cert_length = -1;
static int hf_gpef_efskey_certificate = -1;

static gint ett_gpef = -1;
static gint ett_gpef_efskey = -1;


/* MS-GPEF section 2.2.1.2.2 EfsKey*/
static int
dissect_gpef_efskey(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset = offset;
	guint32 length1, sid_offset;
	guint32 cert_length, cert_offset;
	tvbuff_t *next_tvb;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_gpef_efskey, tvb, -1, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_gpef_efskey);
	}

	/* length 1 */
	length1 = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_gpef_efskey_length1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* length 2 */
	proto_tree_add_item(tree, hf_gpef_efskey_length2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* sid offset */
	sid_offset = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_gpef_efskey_sid_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* reserved */
	offset += 4;

	/* cert length */
	cert_length = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_gpef_efskey_cert_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* cert offset */
	cert_offset = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_gpef_efskey_cert_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* reserved, must be 0x20 0x00 0x00 0x00 */
	offset += 4;

	/* sid */
	dissect_nt_sid(tvb, old_offset+4+sid_offset, tree, "sid", NULL, -1);

	/* certificate */
	next_tvb = tvb_new_subset(tvb, old_offset+4+cert_offset, cert_length, cert_length);
        (void)dissect_x509af_Certificate(FALSE, next_tvb, 0, &asn1_ctx, tree, hf_gpef_efskey_certificate);


	offset = old_offset + length1;
	proto_item_set_len(item, offset-old_offset);
	return offset;
}

/* MS-GPEF section 2.2.1.2.1 */
static int
dissect_gpef_efsblob(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void *data _U_)
{
	int offset = 0;
	proto_tree *tree = NULL;
	proto_item *item = NULL;
	guint32 count;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_gpef, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_gpef);
	}

	/* reserved, must be 0x01 0x00 0x01 0x00 */
	offset += 4;

	/* key count */
	count = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_gpef_keycount, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	while (count--) {
	      offset = dissect_gpef_efskey(tvb, offset, pinfo, tree);
	}

	return offset;
}

void
proto_register_gpef(void)
{
	static hf_register_info hf[] = {
	{ &hf_gpef_keycount,
	{ "Key Count",   "gpef.key_count", FT_UINT32, BASE_DEC, NULL,
		0x0, NULL, HFILL }},

	{ &hf_gpef_efskey_length1,
	{ "Length1",   "gpef.efskey.length1", FT_UINT32, BASE_DEC, NULL,
		0x0, NULL, HFILL }},

	{ &hf_gpef_efskey_length2,
	{ "Length2",   "gpef.efskey.length2", FT_UINT32, BASE_DEC, NULL,
		0x0, NULL, HFILL }},

	{ &hf_gpef_efskey_sid_offset,
	{ "SID Offset",   "gpef.efskey.sid_offset", FT_UINT32, BASE_DEC, NULL,
		0x0, NULL, HFILL }},

	{ &hf_gpef_efskey_cert_offset,
	{ "Cert Offset",   "gpef.efskey.cert_offset", FT_UINT32, BASE_DEC, NULL,
		0x0, NULL, HFILL }},

	{ &hf_gpef_efskey_cert_length,
	{ "Cert Length",   "gpef.efskey.cert_length", FT_UINT32, BASE_DEC, NULL,
		0x0, NULL, HFILL }},

	{ &hf_gpef_efskey,
	{ "EfsKey",   "gpef.efskey", FT_NONE, BASE_NONE, NULL,
		0x0, NULL, HFILL }},

	{ &hf_gpef_efskey_certificate,
	{ "Certificate", "gpef.efskey.certificate", FT_NONE, BASE_NONE, NULL,
		0x0, NULL, HFILL }},

	};

	static gint *ett[] = {
		&ett_gpef,
		&ett_gpef_efskey,
	};

	proto_gpef = proto_register_protocol("GPEF", "GPEF", "gpef");
	proto_register_field_array(proto_gpef, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	new_register_dissector("efsblob", dissect_gpef_efsblob, proto_gpef);
}

void
proto_reg_handoff_gpef(void)
{
}
