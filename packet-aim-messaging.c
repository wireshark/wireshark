/* packet-aim-messaging.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Messaging
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 * Copyright 2004, Devin Heitmueller <dheitmueller@netilla.com>
 *
 * $Id: packet-aim-messaging.c,v 1.3 2004/04/02 07:59:22 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

#define FAMILY_MESSAGING  0x0004

/* Family Messaging Service */
#define FAMILY_MESSAGING_ERROR          0x0001
#define FAMILY_MESSAGING_SETICBMPARAM   0x0002
#define FAMILY_MESSAGING_RESETICBMPARAM 0x0003
#define FAMILY_MESSAGING_REQPARAMINFO   0x0004
#define FAMILY_MESSAGING_PARAMINFO      0x0005
#define FAMILY_MESSAGING_OUTGOING       0x0006
#define FAMILY_MESSAGING_INCOMING       0x0007
#define FAMILY_MESSAGING_EVIL           0x0009
#define FAMILY_MESSAGING_MISSEDCALL     0x000a
#define FAMILY_MESSAGING_CLIENTAUTORESP 0x000b
#define FAMILY_MESSAGING_ACK            0x000c
#define FAMILY_MESSAGING_MINITYPING     0x0014
#define FAMILY_MESSAGING_DEFAULT        0xffff

static const value_string aim_fnac_family_messaging[] = {
  { FAMILY_MESSAGING_ERROR, "Error" },
  { FAMILY_MESSAGING_SETICBMPARAM, "Set ICBM Parameter" },
  { FAMILY_MESSAGING_RESETICBMPARAM, "Reset ICBM Parameter" },
  { FAMILY_MESSAGING_REQPARAMINFO, "Request Parameter Info" },
  { FAMILY_MESSAGING_PARAMINFO, "Parameter Info" },
  { FAMILY_MESSAGING_INCOMING, "Incoming" },
  { FAMILY_MESSAGING_OUTGOING, "Outgoing" },
  { FAMILY_MESSAGING_EVIL, "Evil" },
  { FAMILY_MESSAGING_MISSEDCALL, "Missed Call" },
  { FAMILY_MESSAGING_CLIENTAUTORESP, "Client Auto Response" },
  { FAMILY_MESSAGING_ACK, "Acknowledge" },
  { FAMILY_MESSAGING_MINITYPING, "Mini Typing Notifications (MTN)" },
  { FAMILY_MESSAGING_DEFAULT, "Messaging Default" },
  { 0, NULL }
};


#define INCOMING_CH1_MESSAGE_BLOCK     0x0002
#define INCOMING_CH1_SERVER_ACK_REQ    0x0003
#define INCOMING_CH1_MESSAGE_AUTH_RESP 0x0004
#define INCOMING_CH1_MESSAGE_OFFLINE   0x0006
#define INCOMING_CH1_ICON_PRESENT      0x0008
#define INCOMING_CH1_BUDDY_REQ         0x0009
#define INCOMING_CH1_TYPING            0x000b

static const aim_tlv messaging_incoming_ch1_tlvs[] = {
  { INCOMING_CH1_MESSAGE_BLOCK, "Message Block", FT_BYTES },
  { INCOMING_CH1_SERVER_ACK_REQ, "Server Ack Requested", FT_BYTES },
  { INCOMING_CH1_MESSAGE_AUTH_RESP, "Message is Auto Response", FT_BYTES },
  { INCOMING_CH1_MESSAGE_OFFLINE, "Message was received offline", FT_BYTES },
  { INCOMING_CH1_ICON_PRESENT, "Icon present", FT_BYTES },
  { INCOMING_CH1_BUDDY_REQ, "Buddy Req", FT_BYTES },
  { INCOMING_CH1_TYPING, "Non-direct connect typing notification", FT_BYTES },
  { 0, "Unknown", 0 }
};

/* Initialize the protocol and registered fields */
static int proto_aim_messaging = -1;
static int hf_aim_icbm_cookie = -1;
static int hf_aim_message_channel_id = -1;
static int hf_aim_userinfo_warninglevel = -1;
static int hf_aim_userinfo_tlvcount = -1;

/* Initialize the subtree pointers */
static gint ett_aim_messaging = -1;

static int dissect_aim_messaging(tvbuff_t *tvb, packet_info *pinfo, 
				       proto_tree *tree)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH + 1];
  guchar msg[1000];
  int offset = 0;
  struct aiminfo *aiminfo = pinfo->private_data;
  guint16 tlv_count = 0;

  switch(aiminfo->subtype)
    {    
	case FAMILY_MESSAGING_ERROR:
      return dissect_aim_snac_error(tvb, pinfo, offset, tree);
    case FAMILY_MESSAGING_OUTGOING:

      /* Unknown */
      offset += 10;

      buddyname_length = aim_get_buddyname( buddyname, tvb, offset, offset + 1 );

      /* Buddyname length */
      offset += 1;

      /* djh - My test suggest that this is broken.  Need to give this a
	 closer look @@@@@@@@@ */
      aim_get_message( msg, tvb, 36 + buddyname_length, tvb_length(tvb) - 36
		   - buddyname_length );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo, COL_INFO, "to: %s", buddyname);
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      
      if(tree) {
	proto_tree_add_text(tree, tvb, offset, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      
      return offset;
      
    case FAMILY_MESSAGING_INCOMING:

      /* ICBM Cookie */
      proto_tree_add_item(tree, hf_aim_icbm_cookie, tvb, offset, 8, FALSE);
      offset += 8;

      /* Message Channel ID */
      proto_tree_add_item(tree, hf_aim_message_channel_id, tvb, offset, 2,
			  FALSE);
      offset += 2;

      buddyname_length = aim_get_buddyname( buddyname, tvb, offset, offset + 1 );

      /* Buddyname length */
      offset += 1;

      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo, COL_INFO, " from: %s", buddyname);
	
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }

      if(tree) {
	proto_tree_add_text(tree, tvb, offset, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }

      offset += buddyname_length;

      /* Warning level */
      proto_tree_add_item(tree, hf_aim_userinfo_warninglevel, tvb, offset, 2, FALSE);
      offset += 2;
      
      /* TLV Count */
      tlv_count = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(tree, hf_aim_userinfo_tlvcount, tvb, offset, 2, FALSE);
      offset += 2;

      offset += 9;

      while(tvb_length_remaining(tvb, offset) > 0) {
	offset = dissect_aim_tlv_specific(tvb, pinfo, offset, tree, 
					  messaging_incoming_ch1_tlvs);
      }
      
      return offset;
	case FAMILY_MESSAGING_SETICBMPARAM:
	case FAMILY_MESSAGING_RESETICBMPARAM:
	case FAMILY_MESSAGING_REQPARAMINFO:
	case FAMILY_MESSAGING_PARAMINFO:
	case FAMILY_MESSAGING_EVIL:
	case FAMILY_MESSAGING_MISSEDCALL:
	case FAMILY_MESSAGING_CLIENTAUTORESP:
	case FAMILY_MESSAGING_ACK:
	case FAMILY_MESSAGING_MINITYPING:
	case FAMILY_MESSAGING_DEFAULT:
		/*FIXME*/

	default:
	  return 0;
    }
}

/* Register the protocol with Ethereal */
void
proto_register_aim_messaging(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_aim_icbm_cookie,
      { "ICBM Cookie", "aim.messaging.icbmcookie", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_message_channel_id,
      { "Message Channel ID", "aim.messaging.channelid", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_userinfo_warninglevel,
      { "Warning Level", "aim.userinfo.warninglevel", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_userinfo_tlvcount,
      { "TLV Count", "aim.userinfo.tlvcount", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
    },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_messaging,
  };

/* Register the protocol name and description */
  proto_aim_messaging = proto_register_protocol("AIM Messaging", "AIM Messaging", "aim_messaging");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim_messaging, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_messaging(void)
{
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim_messaging, proto_aim_messaging);
  dissector_add("aim.family", FAMILY_MESSAGING, aim_handle);
  aim_init_family(FAMILY_MESSAGING, "Messaging", aim_fnac_family_messaging);
}
