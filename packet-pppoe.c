/* packet-arp.c
 * Routines for ARP packet disassembly
 *
 * $Id: packet-pppoe.c,v 1.8 2000/05/11 08:15:35 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include "etypes.h"
#include "packet.h"
#include "packet-ppp.h"

static gint ett_pppoed = -1;
static gint ett_pppoed_tags = -1;

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

static gchar *
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

static gchar *
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
dissect_pppoe_tags(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int payload_length) {

	guint16 poe_tag;
	guint16 poe_tag_length;
	int tagstart;

	proto_tree  *pppoe_tree;
	proto_item  *ti;

	/* Start Decoding Here. */

	if (tree) {
		ti = proto_tree_add_text(tree, NullTVB,offset,payload_length,"PPPoE Tags");
		pppoe_tree = proto_item_add_subtree(ti, ett_pppoed_tags);

		tagstart = offset;
		while(tagstart <= payload_length-2 ) {

			poe_tag = pntohs(&pd[tagstart]);
			poe_tag_length = pntohs(&pd[tagstart + 2]);

			proto_tree_add_text(pppoe_tree, NullTVB,tagstart,4,
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
					proto_tree_add_text(pppoe_tree, NullTVB,tagstart+4,poe_tag_length,
						"  String Data: %s", format_text(&pd[tagstart+4],poe_tag_length ));
				}
				break;
			default:
				if(poe_tag_length > 0 ) {
				 proto_tree_add_text(pppoe_tree, NullTVB,tagstart+4,poe_tag_length,
						"  Binary Data: (%d bytes)", poe_tag_length );
				}
			}

			if (poe_tag == PPPOE_TAG_EOL) break;

			tagstart += 4 + poe_tag_length;
		}
	}
}

static void
dissect_pppoed(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
	guint8 pppoe_ver;
	guint8 pppoe_type;
	guint8	pppoe_code;
	guint16	pppoe_session_id;
	guint16	pppoe_length;

	proto_tree  *pppoe_tree;
	proto_item  *ti;

	/* Start Decoding Here. */
	pppoe_ver = (guint8) ((pd[offset] >> 4) & 0x0f);
	pppoe_type = (guint8) (pd[offset] & 0x0f);
	pppoe_code = (guint8) pd[offset + 1];
	pppoe_session_id = pntohs(&pd[offset + 2]);
	pppoe_length = pntohs(&pd[offset + 4]);

	if (check_col(fd, COL_PROTOCOL)) {
		col_add_str(fd,COL_PROTOCOL, "PPPoED");
	}

	if (check_col(fd,COL_INFO)) {
		col_add_fstr(fd,COL_INFO,pppoecode_to_str(pppoe_code,"Unknown code (0x%02x)"));
	}

	if (tree) {
		ti = proto_tree_add_text(tree, NullTVB,offset,pppoe_length+6,"PPPoE Discovery");
		pppoe_tree = proto_item_add_subtree(ti, ett_pppoed);
		proto_tree_add_text(pppoe_tree, NullTVB,offset,1,
			"Version: %d", pppoe_ver);
		proto_tree_add_text(pppoe_tree, NullTVB,offset,1,
			"Type: %d", pppoe_type);
		proto_tree_add_text(pppoe_tree, NullTVB,offset+1,1,
			"Code: %s", pppoecode_to_str(pppoe_code,"Unknown (0x%02x)"));
		proto_tree_add_text(pppoe_tree, NullTVB,offset+2,2,
			"Session ID: %04x", pppoe_session_id);
		proto_tree_add_text(pppoe_tree, NullTVB,offset+4,2,
			"Payload Length: %d", pppoe_length);
	}
	dissect_pppoe_tags(pd,offset+6,fd,tree,offset+6+pppoe_length);

}

static void
dissect_pppoes(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
	guint8 pppoe_ver;
	guint8 pppoe_type;
	guint8	pppoe_code;
	guint16	pppoe_session_id;
	guint16	pppoe_length;

	proto_tree  *pppoe_tree;
	proto_item  *ti;

	/* Start Decoding Here. */
	pppoe_ver = (guint8) ((pd[offset] >> 4) & 0x0f);
	pppoe_type = (guint8) (pd[offset] & 0x0f);
	pppoe_code = (guint8) pd[offset + 1];
	pppoe_session_id = pntohs(&pd[offset + 2]);
	pppoe_length = pntohs(&pd[offset + 4]);

	if (check_col(fd, COL_PROTOCOL)) {
		col_add_str(fd,COL_PROTOCOL, "PPPoES");
	}

	if (check_col(fd,COL_INFO)) {
		col_add_fstr(fd,COL_INFO,pppoecode_to_str(pppoe_code,"Unknown code (0x%02x)"));
	}

	if (tree) {
		ti = proto_tree_add_text(tree, NullTVB,offset,pppoe_length+6,"PPPoE Session");
		pppoe_tree = proto_item_add_subtree(ti, ett_pppoed);
		proto_tree_add_text(pppoe_tree, NullTVB,offset,1,
			"Version: %d", pppoe_ver);
		proto_tree_add_text(pppoe_tree, NullTVB,offset,1,
			"Type: %d", pppoe_type);
		proto_tree_add_text(pppoe_tree, NullTVB,offset+1,1,
			"Code: %s", pppoecode_to_str(pppoe_code,"Unknown (0x%02x)"));
		proto_tree_add_text(pppoe_tree, NullTVB,offset+2,2,
			"Session ID: %04x", pppoe_session_id);
		proto_tree_add_text(pppoe_tree, NullTVB,offset+4,2,
			"Payload Length: %d", pppoe_length);
	}
	/* dissect_ppp is apparently done as a 'top level' dissector,
		* so this doesn't work:  
		* dissect_ppp(pd,offset+6,fd,tree);
		* Im gonna try fudging it.
		*/

	dissect_payload_ppp(pd,offset+6,fd,tree);
}

void
proto_register_pppoed(void)
{
	static gint *ett[] = {
		&ett_pppoed,
		&ett_pppoed_tags,
	};

	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pppoe(void)
{
	dissector_add("ethertype", ETHERTYPE_PPPOED, dissect_pppoed);
	dissector_add("ethertype", ETHERTYPE_PPPOES, dissect_pppoes);
}
