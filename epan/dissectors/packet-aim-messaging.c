/* packet-aim-messaging.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Messaging
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 * Copyright 2004, Devin Heitmueller <dheitmueller@netilla.com>
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
#define FAMILY_MESSAGING_EVILREQ		0x0008
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
  { FAMILY_MESSAGING_EVILREQ, "Evil Request" },
  { FAMILY_MESSAGING_EVIL, "Evil Response" },
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
  { INCOMING_CH1_MESSAGE_BLOCK, "Message Block", dissect_aim_tlv_value_messageblock },
  { INCOMING_CH1_SERVER_ACK_REQ, "Server Ack Requested", dissect_aim_tlv_value_bytes },
  { INCOMING_CH1_MESSAGE_AUTH_RESP, "Message is Auto Response", dissect_aim_tlv_value_bytes },
  { INCOMING_CH1_MESSAGE_OFFLINE, "Message was received offline", dissect_aim_tlv_value_bytes },
  { INCOMING_CH1_ICON_PRESENT, "Icon present", dissect_aim_tlv_value_bytes },
  { INCOMING_CH1_BUDDY_REQ, "Buddy Req", dissect_aim_tlv_value_bytes },
  { INCOMING_CH1_TYPING, "Non-direct connect typing notification", dissect_aim_tlv_value_bytes },
  { 0, "Unknown", NULL }
};

#define MINITYPING_FINISHED_SIGN			0x0000
#define MINITYPING_TEXT_TYPED_SIGN			0x0001
#define MINITYPING_BEGUN_SIGN				0x0002

static const value_string minityping_type[] = {
	{MINITYPING_FINISHED_SIGN, "Typing finished sign" },
	{MINITYPING_TEXT_TYPED_SIGN, "Text typed sign" },
	{MINITYPING_BEGUN_SIGN, "Typing begun sign" },
	{0, NULL }
};

#define EVIL_ORIGIN_ANONYMOUS		1
#define EVIL_ORIGIN_NONANONYMOUS 	2

static const value_string evil_origins[] = {
	{EVIL_ORIGIN_ANONYMOUS, "Anonymous"},
	{EVIL_ORIGIN_NONANONYMOUS, "Non-Anonymous"},
	{0, NULL },
};

/* Initialize the protocol and registered fields */
static int proto_aim_messaging = -1;
static int hf_aim_icbm_channel = -1;
static int hf_aim_icbm_cookie = -1;
static int hf_aim_icbm_msg_flags = -1;
static int hf_aim_icbm_max_sender_warnlevel = -1;
static int hf_aim_icbm_max_receiver_warnlevel = -1;
static int hf_aim_icbm_max_snac_size = -1;
static int hf_aim_icbm_min_msg_interval = -1;
static int hf_aim_icbm_unknown = -1;
static int hf_aim_icbm_notification_cookie = -1;
static int hf_aim_icbm_notification_channel = -1;
static int hf_aim_icbm_notification_type = -1;
static int hf_aim_message_channel_id = -1;
static int hf_aim_icbm_evil = -1;
static int hf_aim_evil_warn_level = -1;
static int hf_aim_evil_new_warn_level = -1;

/* Initialize the subtree pointers */
static gint ett_aim_messaging = -1;

static int dissect_aim_messaging(tvbuff_t *tvb, packet_info *pinfo, 
				       proto_tree *tree)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH + 1];
  int offset = 0;
  struct aiminfo *aiminfo = pinfo->private_data;
  proto_item *ti = NULL;
  proto_tree *msg_tree = NULL;
  
  if(tree) {
    ti = proto_tree_add_text(tree, tvb, 0, -1,"AIM Messaging Service");
    msg_tree = proto_item_add_subtree(ti, ett_aim_messaging);
  }

  switch(aiminfo->subtype)
    {    
    case FAMILY_MESSAGING_ERROR:
      return dissect_aim_snac_error(tvb, pinfo, offset, msg_tree);
    case FAMILY_MESSAGING_RESETICBMPARAM:
    case FAMILY_MESSAGING_REQPARAMINFO:
      /* No data */
      return 0;
    case FAMILY_MESSAGING_OUTGOING:

      /* ICBM Cookie */
      proto_tree_add_item(msg_tree, hf_aim_icbm_cookie, tvb, offset, 8, FALSE);
      offset += 8;

      /* Message Channel ID */
      proto_tree_add_item(msg_tree, hf_aim_message_channel_id, tvb, offset, 2,
			  FALSE);
      offset += 2;

      /* Add the outgoing username to the info column */
      if (check_col(pinfo->cinfo, COL_INFO)) {
	buddyname_length = aim_get_buddyname(buddyname, tvb, offset, 
					     offset + 1);
	col_append_fstr(pinfo->cinfo, COL_INFO, " to: %s",
	                format_text(buddyname, buddyname_length));
      }

      offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);

      while(tvb_reported_length_remaining(tvb, offset) > 0) {
	/* djh - Note that we reuse the "incoming ch1 tlv" set even though this
	   is outgoing.  We may need to split this to a separate TLV set, but
	   so far I haven't seen the need @@@@@@@@ */
	offset = dissect_aim_tlv(tvb, pinfo, offset, msg_tree, 
					  messaging_incoming_ch1_tlvs);
      }

      return offset;
      
    case FAMILY_MESSAGING_INCOMING:

      /* ICBM Cookie */
      proto_tree_add_item(msg_tree, hf_aim_icbm_cookie, tvb, offset, 8, FALSE);
      offset += 8;

      /* Message Channel ID */
      proto_tree_add_item(msg_tree, hf_aim_message_channel_id, tvb, offset, 2,
			  FALSE);
      offset += 2;

      offset = dissect_aim_userinfo(tvb, pinfo, offset, msg_tree);
	  
      while(tvb_reported_length_remaining(tvb, offset) > 0) {
	offset = dissect_aim_tlv(tvb, pinfo, offset, msg_tree, 
					  messaging_incoming_ch1_tlvs);
      }
      
      return offset;
    case FAMILY_MESSAGING_SETICBMPARAM:
    case FAMILY_MESSAGING_PARAMINFO:
      proto_tree_add_item(msg_tree, hf_aim_icbm_channel, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      proto_tree_add_item(msg_tree, hf_aim_icbm_msg_flags, tvb, offset, 4, tvb_get_ntoh24(tvb, offset)); offset+=4;
      proto_tree_add_item(msg_tree, hf_aim_icbm_max_snac_size, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      proto_tree_add_item(msg_tree, hf_aim_icbm_max_sender_warnlevel, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      proto_tree_add_item(msg_tree, hf_aim_icbm_max_receiver_warnlevel, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      proto_tree_add_item(msg_tree, hf_aim_icbm_min_msg_interval, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      proto_tree_add_item(msg_tree, hf_aim_icbm_unknown, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      return offset;
    case FAMILY_MESSAGING_EVILREQ:
      proto_tree_add_item(msg_tree, hf_aim_icbm_evil, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      return dissect_aim_buddyname(tvb, pinfo, offset, tree);
    case FAMILY_MESSAGING_EVIL:
      proto_tree_add_item(msg_tree, hf_aim_evil_warn_level, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      proto_tree_add_item(msg_tree, hf_aim_evil_new_warn_level, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      return offset;
    case FAMILY_MESSAGING_MINITYPING:
      proto_tree_add_item(msg_tree,hf_aim_icbm_notification_cookie, tvb, offset, 8, FALSE); offset+=8;
      proto_tree_add_item(msg_tree,hf_aim_icbm_notification_channel, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      offset = dissect_aim_buddyname(tvb, pinfo, offset, msg_tree);
      proto_tree_add_item(msg_tree,hf_aim_icbm_notification_type, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
      return offset;
    case FAMILY_MESSAGING_MISSEDCALL:
    case FAMILY_MESSAGING_CLIENTAUTORESP:
    case FAMILY_MESSAGING_ACK:
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
    { &hf_aim_icbm_channel,
      { "Channel to setup", "aim.icbm.channel", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_icbm_msg_flags, 
      { "Message Flags", "aim.icbm.flags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_icbm_max_snac_size,
      { "Max SNAC Size", "aim.icbm.max_snac", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_icbm_max_sender_warnlevel,
      { "Max sender warn level", "aim.icbm.max_sender_warn-level", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_icbm_max_receiver_warnlevel,
      { "max receiver warn level", "aim.icbm.max_receiver_warnlevel", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_icbm_min_msg_interval,
      { "Minimum message interval (seconds)", "aim.icbm.min_msg_interval", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_icbm_unknown,
      { "Unknown parameter", "aim.icbm.unknown", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_icbm_cookie,
      { "ICBM Cookie", "aim.messaging.icbmcookie", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_message_channel_id,
      { "Message Channel ID", "aim.messaging.channelid", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_icbm_evil,
      { "Send Evil Bit As", "aim.evilreq.origin", FT_UINT16, BASE_DEC, VALS(evil_origins), 0x0, "", HFILL },
    },
    { &hf_aim_evil_warn_level,
      { "Old warning level", "aim.evil.warn_level", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_evil_new_warn_level,
      { "New warning level", "aim.evil.new_warn_level", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_icbm_notification_cookie,
      { "Notification Cookie", "aim.notification.cookie", FT_BYTES, BASE_DEC, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_icbm_notification_channel,
      { "Notification Channel", "aim.notification.channel", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_icbm_notification_type,
      { "Notification Type", "aim.notification.type", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
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
