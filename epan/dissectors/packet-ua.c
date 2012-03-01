/* packet-ua.c
 * Routines for UA/UDP (Universal Alcatel over UDP) packet dissection.
 * Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "epan/packet.h"
#include "epan/prefs.h"
#include "epan/tap.h"
#include "epan/value_string.h"
#include "epan/dissectors/packet-rtp.h"
#include "epan/dissectors/packet-rtcp.h"
#include <string.h>

#include "packet-uaudp.h"



/*-----------------------------------------------------------------------------
  GLOBALS
  ---------------------------------------------------------------------------*/
static int  proto_ua_msg		= -1;
static gint ett_ua_msg			= -1;

e_ua_direction message_direction; /* Uses to determine UA3G messages */

static gboolean setup_conversations_enabled = TRUE;

static dissector_handle_t rtp_handle = NULL;
static dissector_handle_t rtcp_handle = NULL;

extern gint find_terminal_port(guint port);


extern void dhs2ua(char *p, const char *ptr, int opcode, int length);
extern void ua2dhs(char *p, const char *ptr, int opcode, int length);


static void uadecode(e_ua_direction direction,
					 proto_tree *tree,
					 packet_info *pinfo,
					 tvbuff_t *tvb,
					 gint offset,
					 gint opcode,
					 gint length)
{
	message_direction = direction;

	switch(opcode & 0x7f) /* suppression of the CP bit */
	{
	case 0x15:
	case 0x16:
		{
			call_dissector(find_dissector("noe"),
				tvb_new_subset(tvb, offset, length, length),
				pinfo,
				tree);
			break;
		}
	case 0x00:
	case 0x01:
	case 0x02:
	case 0x03:
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:	/* Only UA NOE */
	case 0x08:	/* Only UA NOE */
	case 0x09:
	case 0x0A:
	case 0x0B:
	case 0x0C:
	case 0x0D:
	case 0x0E:
	case 0x0F:
	case 0x11:
	case 0x12:
	case 0x13:
	case 0x14:
	case 0x17:
	case 0x18:
	case 0x1F:	/* case 0x9F */
	case 0x20:
	case 0x21:
	case 0x22:
	case 0x23:
	case 0x24:	/* Only IP NOE */
	case 0x25:	/* Only IP NOE */
	case 0x26:
	case 0x27:
	case 0x28:
	case 0x29:
	case 0x2A:
	case 0x2B:	/* Only UA NOE */
	case 0x2C:
	case 0x2D:
	case 0x2E:
	case 0x30:
	case 0x31:
	case 0x32:	/* Only UA NOE */
	case 0x33:
	case 0x35:
	case 0x36:	/* IP Phone */
	case 0x38:
	case 0x39:
	case 0x3A:
	case 0x3B:
	case 0x3C:
	case 0x3D:
	case 0x3E:
	case 0x3F:
	case 0x40:
	case 0x41:
	case 0x42:
	case 0x43:
	case 0x44:
	case 0x45:
	case 0x46:
	case 0x47:
	case 0x48:
	case 0x49:
	case 0x4A:
	case 0x4B:
	case 0x4C:
	case 0x4D:
	case 0x4E:
	case 0x4F:
	case 0x50:	/* Only UA NOE */
		{
			call_dissector(find_dissector("ua3g"),
			tvb_new_subset(tvb, offset, length, length),
			pinfo,
			tree);
			break;
		}
	default:
		{
			/* add text to the frame "INFO" column */
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, " - UA3G Message ERR: Opcode Unknown");

			proto_tree_add_text(tree,
				tvb,
				offset,
				length,
				"Opcode Unknown 0x%02x",
				tvb_get_guint8(tvb, (offset + 2)));
			break;
		}
	}
}



/*-----------------------------------------------------------------------------
  UA DISSECTOR
  ---------------------------------------------------------------------------*/
static void _dissect_ua_msg(tvbuff_t *tvb,
						packet_info *pinfo,
						proto_tree *tree,
						e_ua_direction direction)
{
	proto_item *ua_msg_item = NULL;
	proto_tree *ua_msg_tree = NULL;
	gint offset = 0;
	gint length = 0;
	gint opcode = 0;
	gint suboffset  = 0;
	address remote_rtp_addr;
	guint32 remote_rtp_port = 0;

	if(tree)
	{
		ua_msg_item = proto_tree_add_protocol_format(tree, proto_ua_msg, tvb, 0, -1,
			"Universal Alcatel Protocol, %s",
			((direction == SYS_TO_TERM) ?
			"System -> Terminal" : "Terminal -> System"));

		ua_msg_tree = proto_item_add_subtree(ua_msg_item, ett_ua_msg);

		while (tvb_offset_exists(tvb, offset))
		{
			length = (tvb_get_guint8(tvb, offset+0) +
				tvb_get_guint8(tvb, offset+1) * 256) + 2;

			opcode = tvb_get_guint8(tvb, offset+2);

			/* RTP/RTCP conversation setup */
			if(setup_conversations_enabled && opcode==0x13 && tvb_get_guint8(tvb, offset+3)==0x01)
			{
				/* StartRTP */
				suboffset = offset+5;
				remote_rtp_addr.data = NULL;

				while(suboffset < offset+length)
				{
					switch(tvb_get_guint8(tvb, suboffset))
					{
					case 0x00: /* local port */
						{
						/*local_rtp_port = tvb_get_ntohs(tvb, suboffset+2);*/
						break;
						}
					case 0x01: /* remote IP */
						{
						remote_rtp_addr.type=AT_IPv4;
						remote_rtp_addr.len=4;
						remote_rtp_addr.data=tvb_get_ptr(tvb, suboffset+2, 4);
						break;
						}
					case 0x02: /* remote port */
						{
						remote_rtp_port = tvb_get_ntohs(tvb, suboffset+2);
						break;
						}
					}

				suboffset += tvb_get_guint8(tvb, suboffset+1) + 2;
				}

				if(remote_rtp_addr.data!=NULL && remote_rtp_port!=0)
				{
					if(rtp_handle)
					{
						rtp_add_address(pinfo, &remote_rtp_addr, remote_rtp_port, 0,
						"UA", pinfo->fd->num, 0, NULL);
					}
					if(rtcp_handle)
					{
						rtcp_add_address(pinfo, &remote_rtp_addr, remote_rtp_port+1, 0,
						"UA", pinfo->fd->num);
					}
				}
			}

			uadecode(direction, ua_msg_tree, pinfo, tvb, offset, opcode, length);

			offset += length;
		}
	}
}


static void dissect_ua_sys_to_term(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	_dissect_ua_msg(tvb, pinfo, tree, SYS_TO_TERM);
}

static void dissect_ua_term_to_sys(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	_dissect_ua_msg(tvb, pinfo, tree, TERM_TO_SYS);
}


/*-----------------------------------------------------------------------------
  DISSECTORS REGISTRATION FUNCTIONS
  ---------------------------------------------------------------------------*/

void proto_reg_handoff_ua_msg(void)
{
	static gboolean prefs_initialized = FALSE;
	dissector_handle_t handle_ua_msg;

	if(!prefs_initialized)
	{
		/* hooking of UA on UAUDP */
		register_dissector_table("uaudp.opcode",
			"UAUDP opcode",
			FT_UINT8,
			BASE_DEC);

		handle_ua_msg = find_dissector("ua_sys_to_term");
		dissector_add_uint("uaudp.opcode", UAUDP_DATA, handle_ua_msg);

		handle_ua_msg = find_dissector("ua_term_to_sys");
		dissector_add_uint("uaudp.opcode", UAUDP_DATA, handle_ua_msg);
		prefs_initialized = TRUE;
	}
}


void proto_register_ua_msg(void)
{
	module_t *ua_msg_module;

	static gint *ett[] =
	{
		&ett_ua_msg,
	};

	/* used for StartRTP conversation setup */
	rtp_handle = find_dissector("rtp");
	rtcp_handle = find_dissector("rtcp");

	/* UA dissector registration */
	proto_ua_msg = proto_register_protocol("Universal Alcatel Protocol", "UA", "ua");

	register_dissector("ua_sys_to_term", dissect_ua_sys_to_term, proto_ua_msg);
	register_dissector("ua_term_to_sys", dissect_ua_term_to_sys, proto_ua_msg);

	/* Common subtree array registration */
	proto_register_subtree_array(ett, array_length(ett));

	/* Register preferences */
	ua_msg_module = prefs_register_protocol(proto_ua_msg, proto_reg_handoff_ua_msg);

	prefs_register_bool_preference(ua_msg_module, "setup_conversations",
		"Setup RTP/RTCP conversations on Start RTP",
		"Setup RTP/RTCP conversations when parsing Start RTP messages",
		&setup_conversations_enabled);
}
