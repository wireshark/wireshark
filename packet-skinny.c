/* packet-skinny.c
 *
 * Dissector for the Skinny Client Control Protocol
 *   (The "D-Channel"-Protocol for Cisco Systems' IP-Phones)
 * Copyright 2001, Joerg Mayer (email: see AUTHORS file)
 *
 * This file is based on packet-aim.c, which is
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 *
 * $Id: packet-skinny.c,v 1.2 2001/10/11 16:01:53 guy Exp $
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

/* This implementation is based on a draft version of the 3.0
 * specification
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* REMOVE?
 * #include <stdio.h>
 * #include <stdlib.h>
 * #include <string.h>
 * #include <ctype.h>
 * 
 * #ifdef HAVE_SYS_TYPES_H
 * # include <sys/types.h>
 * #endif
 * 
 * #ifdef HAVE_NETINET_IN_H
 * # include <netinet/in.h>
 * #endif
 * 
 * #include <glib.h> // already in packet.h -> tvbuff.h
 *
 * #ifdef NEED_SNPRINTF_H
 * # include "snprintf.h"
 * #endif
 */

#include "packet.h"
/* REMOVE?
 * #include "strutil.h"
 */

#define TCP_PORT_SKINNY 2000

/* I will probably need this again when I change things
 * to function pointers, but let me use the existing
 * infrastructure for now
 *
 * typedef struct {
 *   guint32	id;
 *   char *	name;
 * } message_id_t;
 */

static const value_string  message_id[] = {

  /* Station -> Callmanager */
  {0x0000, "KeepAliveMessage"},
  {0x0001, "RegisterMessage"},
  {0x0002, "IpPortMessage"},
  {0x0003, "KeypadButtonMessage"},
  {0x0004, "EnblocCallMessage"},
  {0x0005, "StimulusMessage"},
  {0x0006, "OffHookMessage"},
  {0x0007, "OnHookMessage"},
  {0x0008, "HookFlashMessage"},
  {0x0009, "ForwardStatReqMessage"},
  {0x000A, "SpeedDialStatReqMessage"},
  {0x000B, "LineStatReqMessage"},
  {0x000C, "ConfigStatReqMessage"},
  {0x000D, "TimeDateReqMessage"},
  {0x000E, "ButtonTemplateReqMessage"},
  {0x000F, "VersionReqMessage"},
  {0x0010, "CapabilitiesResMessage"},
  {0x0011, "MediaPortListMessage"},
  {0x0012, "ServerReqMessage"},
  {0x0020, "AlarmMessage"},
  {0x0021, "MulticastMediaReceptionAck"},
  {0x0022, "OpenReceiveChannelAck"},
  {0x0023, "ConnectionStatisticsRes"},
  {0x0024, "OffHookWithCgpnMessage"},
  {0x0025, "SoftKeySetReqMessage"},
  {0x0026, "SoftKeyEventMessage"},
  {0x0027, "UnregisterMessage"},
  {0x0028, "SoftKeyEventMessage"},
  {0x0029, "RegisterTokenReq"},
  
  /* Callmanager -> Station */
  /* 0x0000, 0x0003? */
  {0x0081, "RegisterAckMessage"},
  {0x0082, "StartToneMessage"},
  {0x0083, "StopToneMessage"},
  {0x0085, "SetRingerMessage"},
  {0x0086, "SetLampMessage"},
  {0x0087, "SetHkFDetectMessage"},
  {0x0088, "SetSpeakerModeMessage"},
  {0x0089, "SetMicroModeMessage"},
  {0x008A, "StartMediaTransmission"},
  {0x008B, "StopMediaTransmission"},
  {0x008C, "StartMediaReception"},
  {0x008D, "StopMediaReception"},
  {0x008F, "CallInfoMessage"},
  {0x0090, "ForwardStatMessage"},
  {0x0091, "SpeedDialStatMessage"},
  {0x0092, "LineStatMessage"},
  {0x0093, "ConfigStatMessage"},
  {0x0094, "DefineTimeDate"},
  {0x0095, "StartSessionTransmission"},
  {0x0096, "StopSessionTransmission"},
  {0x0097, "ButtonTemplateMessage"},
  {0x0098, "VersionMessage"},
  {0x0099, "DisplayTextMessage"},
  {0x009A, "ClearDisplay"},
  {0x009B, "CapabilitiesReqMessage"},
  {0x009C, "EnunciatorCommandMessage"},
  {0x009D, "RegisterRejectMessage"},
  {0x009E, "ServerResMessage"},
  {0x009F, "Reset"},
  {0x0100, "KeepAliveAckMessage"},
  {0x0101, "StartMulticastMediaReception"},
  {0x0102, "StartMulticastMediaTransmission"},
  {0x0103, "StopMulticastMediaReception"},
  {0x0104, "StopMulticastMediaTransmission"},
  {0x0105, "OpenReceiveChannel"},
  {0x0106, "CloseReceiveChannel"},
  {0x0107, "ConnectionStatisticsReq"},
  {0x0108, "SoftKeyTemplateResMessage"},
  {0x0109, "SoftKeySetResMessage"},
  {0x0110, "SelectSoftKeysMessage"},
  {0x0111, "CallStateMessage"},
  {0x0112, "DisplayPromptStatusMessage"},
  {0x0113, "ClearPromptStatusMessage"},
  {0x0114, "DisplayNotifyMessage"},
  {0x0115, "ClearNotifyMessage"},
  {0x0116, "ActivateCallPlaneMessage"},
  {0x0117, "DeactivateCallPlaneMessage"},
  {0x0118, "UnregisterAckMessage"},
  {0x0119, "BackSpaceReqMessage"},
  {0x011A, "RegisterTokenAck"},
  {0x011B, "RegisterTokenReject"},

  {0     , NULL}	/* needed for value_string automagic */
};

static void dissect_skinny(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_skinny          = -1;
static int hf_skinny_data_length = -1;
static int hf_skinny_reserved    = -1;
static int hf_skinny_messageid   = -1;

/* Initialize the subtree pointers */
static gint ett_skinny          = -1;

/* Code to actually dissect the packets */
static void dissect_skinny(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* The general structure of a packet: {IP-Header|TCP-Header|n*SKINNY}
   * SKINNY-Packet: {Header(Size, Reserved)|Data(MessageID, Message-Data)}
   */

  /* Header fields */
  guint32 hdr_data_length;
  guint32 hdr_reserved;
  guint32 data_messageid;
  gchar   *messageid_str;
  guint32 data_size;

/* Set up structures we will need to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *skinny_tree = NULL;

/* check, if this is really an SKINNY packet, they start with a length + 0 */

/* get relevant header information */
  hdr_data_length = tvb_get_letohl(tvb, 0);
  hdr_reserved    = tvb_get_letohl(tvb, 4);
  data_messageid   = tvb_get_letohl(tvb, 8);
  data_size       = MIN(8+hdr_data_length, tvb_length(tvb)) - 0xC;

  /* hdr_data_length > 1024 is just a heuristic. Better values/checks welcome */
  if (hdr_data_length < 4 || hdr_data_length > 1024 || hdr_reserved != 0) {
    /* Not an SKINNY packet, just happened to use the same port */
    return;
  }
  
  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->fd, COL_PROTOCOL)) 
    col_set_str(pinfo->fd, COL_PROTOCOL, "SKINNY");
    
  if (check_col(pinfo->fd, COL_INFO)) 
    col_add_str(pinfo->fd, COL_INFO, "Skinny Client Control Protocol");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
   * necessary to generate protocol tree items. */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_skinny, tvb, 0,
		data_size + 0xC, FALSE); 
    skinny_tree = proto_item_add_subtree(ti, ett_skinny);
    proto_tree_add_uint(skinny_tree, hf_skinny_data_length, tvb,
		0, 4, hdr_data_length);  
    proto_tree_add_uint(skinny_tree, hf_skinny_reserved, tvb,
		4, 4, hdr_reserved);
  }
  messageid_str = val_to_str(data_messageid, message_id, "0x%08X (Unknown)");
  if (check_col(pinfo->fd, COL_INFO)) {
	col_add_str(pinfo->fd, COL_INFO, messageid_str);
  }
  if (tree) {
    proto_tree_add_uint(skinny_tree, hf_skinny_messageid, tvb,
		8, 4, data_messageid /* FIXME: add messageid_str */ );
    if (data_size > 0) {
	proto_tree_add_protocol_format(skinny_tree, proto_skinny, tvb,
		0xC,
		data_size, "Data (%d byte%s)", data_size,
		plurality(data_size, "", "s"));
    }
  }

  /*FIXME: call dissect_skinny recursively until all data is used up */
}

/* Register the protocol with Ethereal */
void 
proto_register_skinny(void)
{                 

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_skinny_data_length,
      { "Data Length", "skinny.data_length",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		"Number of bytes in the data portion.",
		HFILL }
    },
    { &hf_skinny_reserved,
      { "Reserved", "skinny.reserved",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		"Reserved for furture(?) use.",
		HFILL }
    },
    /* FIXME: Enable use of message name ???  */
    { &hf_skinny_messageid,
      { "Message ID", "skinny.messageid",
		/* FIXME: FT_UINT32, BASE_HEX, VALS(message_id), 0x0, */
		FT_UINT32, BASE_HEX, NULL, 0x0,
		"The function requested/done with this message.",
		HFILL }
    },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_skinny,
  };

/* Register the protocol name and description */
  proto_skinny = proto_register_protocol("Skinny Client Control Protocol",
		"SKINNY", "skinny");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_skinny, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_skinny(void)
{
  dissector_add("tcp.port", TCP_PORT_SKINNY, &dissect_skinny, proto_skinny);
}
