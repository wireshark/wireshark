/* packet-pppoe.c
 * Routines for PPP Over Ethernet (PPPoE) packet disassembly (RFC2516)
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/etypes.h>

static int proto_pppoed = -1;

static gint ett_pppoed = -1;
static gint ett_pppoed_tags = -1;

static int proto_pppoes = -1;

static dissector_handle_t ppp_handle;

/* For lack of a better source, I made up the following defines. -jsj */

#define PPPOE_CODE_SESSION 0x00
#define PPPOE_CODE_PADO 0x7
#define PPPOE_CODE_PADI 0x9
#define PPPOE_CODE_PADR 0x19
#define PPPOE_CODE_PADS 0x65
#define PPPOE_CODE_PADT 0xa7

#define PPPOE_TAG_EOL 0x0000
#define PPPOE_TAG_SVC_NAME 0x0101
#define PPPOE_TAG_AC_NAME 0x0102
#define PPPOE_TAG_HOST_UNIQ 0x0103
#define PPPOE_TAG_AC_COOKIE 0x0104
#define PPPOE_TAG_VENDOR 0x0105
#define PPPOE_TAG_RELAY_ID 0x0110
#define PPPOE_TAG_SVC_ERR 0x0201
#define PPPOE_TAG_AC_ERR 0x0202
#define PPPOE_TAG_GENERIC_ERR 0x0203

static const gchar *
pppoecode_to_str(guint8 codetype, const char *fmt) {
	static const value_string code_vals[] = {
		{PPPOE_CODE_SESSION, "Session Data"                             },
		{PPPOE_CODE_PADO, "Active Discovery Offer (PADO)"               },
		{PPPOE_CODE_PADI, "Active Discovery Initiation (PADI)"          },
		{PPPOE_CODE_PADR, "Active Discovery Request (PADR)"             },
		{PPPOE_CODE_PADS, "Active Discovery Session-confirmation (PADS)"},
		{PPPOE_CODE_PADT, "Active Discovery Terminate (PADT)"           },
		{0,	NULL                                                        } };

		return val_to_str(codetype, code_vals, fmt);
}

static const gchar *
pppoetag_to_str(guint16 tag_type, const char *fmt) {
	static const value_string code_vals[] = {
		{PPPOE_TAG_EOL,        "End-Of-List"       },
		{PPPOE_TAG_SVC_NAME,   "Service-Name"      },
		{PPPOE_TAG_AC_NAME,    "AC-Name"           },
		{PPPOE_TAG_HOST_UNIQ,  "Host-Uniq"         },
		{PPPOE_TAG_AC_COOKIE,  "AC-Cookie"         },
		{PPPOE_TAG_VENDOR,     "Vendor-Specific"   },
		{PPPOE_TAG_RELAY_ID,   "Relay-Session-Id"  },
		{PPPOE_TAG_SVC_ERR,    "Service-Name-Error"},
		{PPPOE_TAG_AC_ERR,     "AC-System-Error"   },
		{PPPOE_TAG_GENERIC_ERR,"Generic-Error"     },
		{0,                    NULL                } };

		return val_to_str(tag_type, code_vals, fmt);
}


static void
dissect_pppoe_tags(tvbuff_t *tvb, int offset, proto_tree *tree, int payload_length) {

	guint16 poe_tag;
	guint16 poe_tag_length;
	int tagstart;

	proto_tree  *pppoe_tree;
	proto_item  *ti;

	/* Start Decoding Here. */

	if (tree) {
		ti = proto_tree_add_text(tree, tvb,offset,payload_length,"PPPoE Tags");
		pppoe_tree = proto_item_add_subtree(ti, ett_pppoed_tags);

		tagstart = offset;
		while(tagstart <= payload_length-2 ) {

			poe_tag = tvb_get_ntohs(tvb, tagstart);
			poe_tag_length = tvb_get_ntohs(tvb, tagstart + 2);

			proto_tree_add_text(pppoe_tree, tvb,tagstart,4,
				"Tag: %s", pppoetag_to_str(poe_tag,"Unknown (0x%02x)"));

			switch(poe_tag) {
			case PPPOE_TAG_SVC_NAME:
			case PPPOE_TAG_AC_NAME:
			case PPPOE_TAG_SVC_ERR:
			case PPPOE_TAG_AC_ERR:
			case PPPOE_TAG_GENERIC_ERR:
				/* tag value should be interpreted as a utf-8 unterminated string.*/
				if(poe_tag_length > 0 ) {
					/* really should do some limit checking here.  :( */
					proto_tree_add_text(pppoe_tree, tvb,tagstart+4,poe_tag_length,
						"  String Data: %s",
						tvb_format_text(tvb, tagstart+4,poe_tag_length ));
				}
				break;
			default:
				if(poe_tag_length > 0 ) {
				 proto_tree_add_text(pppoe_tree, tvb,tagstart+4,poe_tag_length,
						"  Binary Data: (%d bytes)", poe_tag_length );
				}
			}

			if (poe_tag == PPPOE_TAG_EOL) break;

			tagstart += 4 + poe_tag_length;
		}
	}
}

static void
dissect_pppoed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	guint8 pppoe_ver_type;
	guint8 pppoe_ver;
	guint8 pppoe_type;
	guint8	pppoe_code;
	guint16	pppoe_session_id;
	guint16	pppoe_length;

	proto_tree  *pppoe_tree;
	proto_item  *ti;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo,COL_PROTOCOL, "PPPoED");
	}
	if (check_col(pinfo->cinfo,COL_INFO)) {
		col_clear(pinfo->cinfo,COL_INFO);
	}

	/* Start Decoding Here. */
	pppoe_ver_type = tvb_get_guint8(tvb, 0);
	pppoe_ver = (pppoe_ver_type >> 4) & 0x0f;
	pppoe_type = pppoe_ver_type & 0x0f;
	pppoe_code = tvb_get_guint8(tvb, 1);

	if (check_col(pinfo->cinfo,COL_INFO)) {
		col_add_fstr(pinfo->cinfo,COL_INFO,pppoecode_to_str(pppoe_code,"Unknown code (0x%02x)"));
	}

	pppoe_session_id = tvb_get_ntohs(tvb, 2);
	pppoe_length = tvb_get_ntohs(tvb, 4);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_pppoed, tvb,0,
			pppoe_length+6, FALSE);
		pppoe_tree = proto_item_add_subtree(ti, ett_pppoed);
		proto_tree_add_text(pppoe_tree, tvb,0,1,
			"Version: %u", pppoe_ver);
		proto_tree_add_text(pppoe_tree, tvb,0,1,
			"Type: %u", pppoe_type);
		proto_tree_add_text(pppoe_tree, tvb,1,1,
			"Code: %s", pppoecode_to_str(pppoe_code,"Unknown (0x%02x)"));
		proto_tree_add_text(pppoe_tree, tvb,2,2,
			"Session ID: %04x", pppoe_session_id);
		proto_tree_add_text(pppoe_tree, tvb,4,2,
			"Payload Length: %u", pppoe_length);
	}
	dissect_pppoe_tags(tvb,6,tree,6+pppoe_length);
}

void
proto_register_pppoed(void)
{
	static gint *ett[] = {
		&ett_pppoed,
		&ett_pppoed_tags,
	};

	proto_pppoed = proto_register_protocol("PPP-over-Ethernet Discovery",
	    "PPPoED", "pppoed");

	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pppoed(void)
{
	dissector_handle_t pppoed_handle;

	pppoed_handle = create_dissector_handle(dissect_pppoed, proto_pppoed);
	dissector_add("ethertype", ETHERTYPE_PPPOED, pppoed_handle);
}

static void
dissect_pppoes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	guint8 pppoe_ver_type;
	guint8 pppoe_ver;
	guint8 pppoe_type;
	guint8	pppoe_code;
	guint16	pppoe_session_id;
	guint16	pppoe_length;
	gint length, reported_length;

	proto_tree  *pppoe_tree;
	proto_item  *ti;
	tvbuff_t    *next_tvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo,COL_PROTOCOL, "PPPoES");
	}
	if (check_col(pinfo->cinfo,COL_INFO)) {
		col_clear(pinfo->cinfo,COL_INFO);
	}

	/* Start Decoding Here. */
	pppoe_ver_type = tvb_get_guint8(tvb, 0);
	pppoe_ver = (pppoe_ver_type >> 4) & 0x0f;
	pppoe_type = pppoe_ver_type & 0x0f;
	pppoe_code = tvb_get_guint8(tvb, 1);

	if (check_col(pinfo->cinfo,COL_INFO)) {
		col_add_fstr(pinfo->cinfo,COL_INFO,
		    pppoecode_to_str(pppoe_code,"Unknown code (0x%02x)"));
	}

	pppoe_session_id = tvb_get_ntohs(tvb, 2);
	pppoe_length = tvb_get_ntohs(tvb, 4);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_pppoes, tvb,0,
			6, FALSE);
		pppoe_tree = proto_item_add_subtree(ti, ett_pppoed);
		proto_tree_add_text(pppoe_tree, tvb,0,1,
			"Version: %u", pppoe_ver);
		proto_tree_add_text(pppoe_tree, tvb,0,1,
			"Type: %u", pppoe_type);
		proto_tree_add_text(pppoe_tree, tvb,1,1,
			"Code: %s", pppoecode_to_str(pppoe_code,"Unknown (0x%02x)"));
		proto_tree_add_text(pppoe_tree, tvb,2,2,
			"Session ID: %04x", pppoe_session_id);
		proto_tree_add_text(pppoe_tree, tvb,4,2,
			"Payload Length: %u", pppoe_length);
	}
	/* dissect_ppp is apparently done as a 'top level' dissector,
	 * so this doesn't work:
	 * dissect_ppp(pd,offset+6,pinfo->fd,tree);
	 * Im gonna try fudging it.
	 */
	length = tvb_length_remaining(tvb, 6);
	reported_length = tvb_reported_length_remaining(tvb, 6);
	DISSECTOR_ASSERT(length >= 0);
	DISSECTOR_ASSERT(reported_length >= 0);
	if (length > reported_length)
		length = reported_length;
	if ((guint)length > pppoe_length)
		length = pppoe_length;
	if ((guint)reported_length > pppoe_length)
		reported_length = pppoe_length;
	next_tvb = tvb_new_subset(tvb,6,length,reported_length);
	call_dissector(ppp_handle,next_tvb,pinfo,tree);
}
void
proto_register_pppoes(void)
{
	proto_pppoes = proto_register_protocol("PPP-over-Ethernet Session",
	    "PPPoES", "pppoes");
}

void
proto_reg_handoff_pppoes(void)
{
	dissector_handle_t pppoes_handle;

	pppoes_handle = create_dissector_handle(dissect_pppoes, proto_pppoes);
	dissector_add("ethertype", ETHERTYPE_PPPOES, pppoes_handle);

	/*
	 * Get a handle for the PPP dissector.
	 */
	ppp_handle = find_dissector("ppp");
}
