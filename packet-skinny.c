/* packet-skinny.c
 *
 * Dissector for the Skinny Client Control Protocol
 *   (The "D-Channel"-Protocol for Cisco Systems' IP-Phones)
 * Copyright 2001, Joerg Mayer (email: see AUTHORS file)
 *
 * Further decode work by pee@erkkila.org 
 *
 * This file is based on packet-aim.c, which is
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 *
 * $Id: packet-skinny.c,v 1.10 2002/03/18 00:45:10 guy Exp $
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

#include <string.h>

#include <epan/packet.h>

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
  {0x002B, "unknownClientMessage1"},
  {0x002D, "unknownClientMessage2"},
  
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
  {0x011D, "unknownForwardMessage1"},

  {0     , NULL}	/* needed for value_string automagic */
};

static void dissect_skinny(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_skinny          = -1;
static int hf_skinny_data_length = -1;
static int hf_skinny_reserved    = -1;
static int hf_skinny_messageid   = -1;
static int hf_skinny_callIdentifier = -1;
static int hf_skinny_packetsSent = -1;
static int hf_skinny_octetsSent  = -1;
static int hf_skinny_packetsRecv = -1;
static int hf_skinny_octetsRecv  = -1;
static int hf_skinny_packetsLost = -1;
static int hf_skinny_latency     = -1;
static int hf_skinny_jitter      = -1;
static int hf_skinny_extension   = -1;
static int hf_skinny_displayMessage = -1;
static int hf_skinny_timeStamp = -1;
static int hf_skinny_unknown = -1;
static int hf_skinny_ipDest = -1;
static int hf_skinny_ipSrc = -1;
static int hf_skinny_dateYear = -1;
static int hf_skinny_dateMonth = -1;
static int hf_skinny_dateDay = -1;
static int hf_skinny_dateHour = -1;
static int hf_skinny_dateMinute = -1;
static int hf_skinny_destPort = -1;
static int hf_skinny_srcPort = -1;
static int hf_skinny_softKeyNumber = -1;
static int hf_skinny_line = -1;
static int hf_skinny_dialedDigit = -1;

/* Initialize the subtree pointers */
static gint ett_skinny          = -1;

static dissector_handle_t data_handle;

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
  /*  guint32 data_size; */

  guint32 offset = 0;

  guint32 callIdentifier = 0;
  guint32 packetsSent = 0;
  guint32 octetsSent = 0;
  guint32 packetsRecv = 0;
  guint32 octetsRecv = 0;
  guint32 packetsLost = 0; 
  guint32 latency = 0;
  guint32 jitter = 0;
  guint32 timeStamp = 0;
  guint32 ipSrc = 0;
  guint32 ipDest = 0;
  guint32 year = 0;
  guint32 month = 0;
  guint32 day = 0;
  guint32 hour = 0;
  guint32 minute = 0;
  guint32 destPort = 0;
  guint32 srcPort = 0;
  guint32 softKeyNumber = 0;
  guint32 line = 0;
  guint32 dialedDigit = 0;

  guint32 unknown1 = 0;
  guint32 unknown2 = 0;
  guint32 unknown3 = 0;
  guint32 unknown4 = 0;
  guint32 unknown5 = 0;
  guint32 unknown6 = 0;
  guint32 unknown7 = 0;
  guint32 unknown8 = 0;
  guint32 unknown9 = 0;
  guint32 unknown10 = 0;
  guint32 unknown11 = 0;

  int extensionLength = 10;
  int displayLength   = 100;
  char extension[extensionLength];
  char displayMessage[displayLength];
  int softKeyLoop = 0;
  
  /* Set up structures we will need to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *skinny_tree = NULL;
  
  /* check, if this is really an SKINNY packet, they start with a length + 0 */
  
  /* get relevant header information */
  hdr_data_length = tvb_get_letohl(tvb, 0);
  hdr_reserved    = tvb_get_letohl(tvb, 4);
  data_messageid   = tvb_get_letohl(tvb, 8);


  /*  data_size       = MIN(8+hdr_data_length, tvb_length(tvb)) - 0xC; */
  
  /* hdr_data_length > 1024 is just a heuristic. Better values/checks welcome */
  if (hdr_data_length < 4 || hdr_data_length > 1024 || hdr_reserved != 0) {
    /* Not an SKINNY packet, just happened to use the same port */
    call_dissector(data_handle,tvb, pinfo, tree);
    return;
  }
  
  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SKINNY");
  }
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_set_str(pinfo->cinfo, COL_INFO, "Skinny Client Control Protocol");
  }
  
  while (tvb_reported_length_remaining(tvb, offset) != 0) {

    hdr_data_length = tvb_get_letohl(tvb, offset);
    hdr_reserved    = tvb_get_letohl(tvb, offset+4);
    data_messageid  = tvb_get_letohl(tvb, offset+8);

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items. */
    if (tree) {
      ti = proto_tree_add_item(tree, proto_skinny, tvb, offset, hdr_data_length+8, FALSE); 
      skinny_tree = proto_item_add_subtree(ti, ett_skinny);
      proto_tree_add_uint(skinny_tree, hf_skinny_data_length, tvb, offset, 4, hdr_data_length);  
      proto_tree_add_uint(skinny_tree, hf_skinny_reserved, tvb, offset+4, 4, hdr_reserved);
    }

    messageid_str = val_to_str(data_messageid, message_id, "0x%08X (Unknown)");

    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_add_str(pinfo->cinfo, COL_INFO, messageid_str);
    }

    if (tree) {
      proto_tree_add_uint(skinny_tree, hf_skinny_messageid, tvb,offset+8, 4, data_messageid );
    }

    if (tree) {
      switch(data_messageid) {

	/* cases that do not need to be decoded */
      case 0x0 :    /* keepAlive */
	break;

      case 0x6 :    /* offHook */
	break;

      case 0x7 :    /* onHook    */
	break;

      case 0xd :    /* timeDateReqMessage */
	break;

      case 0xe :    /* buttoneTemplateReqMessage */
	break;

      case 0x25 :   /* softKeySetReqMessage */
	break;

      case 0x27 :   /* unregisterMessage */
	break;

      case 0x28 :   /* softKeyEventMessage */
	break;

      case 0x83 :   /* stopTone */
	break;

      case 0x9b :   /* capabilitiesReqMessage */
	break;

      case 0x100 :    /* keepAliveAck */
	break;
	
	/*
	** cases that need decode
	**
	*/

      case 0x1 :   /* register message */
	memset(displayMessage, '\0', displayLength);
	tvb_memcpy(tvb, displayMessage, offset+12, 15); /* Note hack on field size ^_^ */
	unknown1 = tvb_get_letohl(tvb, offset+28);
	unknown2 = tvb_get_letohl(tvb, offset+32);
	tvb_memcpy(tvb, (guint8 *)&ipSrc, offset+36,4);
	unknown4 = tvb_get_letohl(tvb, offset+40);
	unknown5 = tvb_get_letohl(tvb, offset+44);
	unknown6 = tvb_get_letohl(tvb, offset+48);
	unknown7 = tvb_get_letohl(tvb, offset+52);

	proto_tree_add_string(skinny_tree, hf_skinny_displayMessage, tvb, offset+12, strlen(displayMessage), displayMessage);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+28, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+32, 4, unknown2);
	proto_tree_add_ipv4(skinny_tree, hf_skinny_ipSrc, tvb, offset+36, 4, ipSrc);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+40, 4, unknown4);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+44, 4, unknown5);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+48, 4, unknown6);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+52, 4, unknown7);
	break;

      case 0x2 :  /* ipPortMessage */
	srcPort = tvb_get_ntohs(tvb, offset+12);
	
	proto_tree_add_uint(skinny_tree, hf_skinny_srcPort, tvb, offset+12, 4, srcPort);
	break;

      case 0x3 :  /* keyPadButtonMessage */
	dialedDigit = tvb_get_letohl(tvb, offset+12);
	
	proto_tree_add_uint(skinny_tree, hf_skinny_dialedDigit, tvb, offset+12, 4, dialedDigit);
	break;

      case 0x5 :
	unknown1 = tvb_get_letohl(tvb, offset+12);
	unknown2 = tvb_get_letohl(tvb, offset+16);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
	break;

      case 0xa :  /* speedDialStatReqMessage */
	line = tvb_get_letohl(tvb, offset+12);

	proto_tree_add_uint(skinny_tree, hf_skinny_line, tvb, offset+12, 4, line);
	break;

      case 0xb :  /* LineStatReqMessage */
	line = tvb_get_letohl(tvb, offset+12);

	proto_tree_add_uint(skinny_tree, hf_skinny_line, tvb, offset+12, 4, line);
	break;

      case 0x10 :  /* capabilitiesResMessage ===== LOTS to decode here, check jtapi */
	break;

      case 0x20 :   /* alarmMessage */
	unknown1   = tvb_get_letohl(tvb,offset+12);
	memset(displayMessage, '\0', displayLength);
	tvb_memcpy(tvb, displayMessage, offset+16, 76); /* Note hack on field size ^_^ */
	unknown2 = tvb_get_letohl(tvb, offset+92);
	unknown3 = tvb_get_letohl(tvb, offset+96);
	unknown4 = tvb_get_letohl(tvb, offset+100);
	tvb_memcpy(tvb, (guint8 *)&ipSrc, offset+100,4);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_string(skinny_tree, hf_skinny_displayMessage, tvb, offset+16, strlen(displayMessage), displayMessage);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+92, 4, unknown2);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+96, 4, unknown3);
	proto_tree_add_ipv4(skinny_tree, hf_skinny_ipSrc,   tvb, offset+100, 4, ipSrc);
	break;

      case 0x22 :
	unknown1 = tvb_get_letohl(tvb, offset+12);
	tvb_memcpy(tvb, (guint8 *)&ipSrc, offset+16,4);
	srcPort  = tvb_get_letohl(tvb, offset+20);
	unknown3 = tvb_get_letohl(tvb, offset+24);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_ipv4(skinny_tree, hf_skinny_ipSrc,   tvb, offset+16, 4, ipSrc);
	proto_tree_add_uint(skinny_tree, hf_skinny_srcPort, tvb, offset+20, 4, srcPort);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+24, 4, unknown3);
	break;	

      case 0x26 :  /* softKeyEventMessage */
	unknown1 = tvb_get_letohl(tvb, offset+12);
	unknown2 = tvb_get_letohl(tvb, offset+16);
	callIdentifier = tvb_get_letohl(tvb, offset+20);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
	proto_tree_add_uint(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, callIdentifier);
	break;

      case 0x2b :  /* unknownClientMessage1 */
	unknown1 = tvb_get_letohl(tvb, offset+12);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	break;

      case 0x2d :  /* unknownClientMessage2 */
	unknown1 = tvb_get_letohl(tvb, offset+12);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	break;

      case 0x81 :  /* registerAck */
	unknown1 = tvb_get_letohl(tvb, offset+12);
	unknown2 = tvb_get_letohl(tvb, offset+16);
	unknown3 = tvb_get_letohl(tvb, offset+20);
	unknown4 = tvb_get_letohl(tvb, offset+24);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+20, 4, unknown3);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+24, 4, unknown4);
	break;

      case 0x82 :  /* startTone */
	unknown1 = tvb_get_letohl(tvb, offset+12);
	
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	break;

      case 0x85 :
	unknown1 = tvb_get_letohl(tvb, offset+12);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	break;
	
      case 0x86 :
	unknown1 = tvb_get_letohl(tvb, offset+12);
	unknown2 = tvb_get_letohl(tvb, offset+16);
	unknown3 = tvb_get_letohl(tvb, offset+20);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+20, 4, unknown3);
	break;

      case 0x88 :
	unknown1 = tvb_get_letohl(tvb, offset+12);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	break;
	
      case 0x8a :
	unknown1  = tvb_get_letohl(tvb, offset+12);
	unknown2  = tvb_get_letohl(tvb, offset+16);
	tvb_memcpy(tvb, (guint8 *)&ipDest, offset+20,4);
	destPort  = tvb_get_letohl(tvb, offset+24);
	unknown5  = tvb_get_letohl(tvb, offset+28);
	unknown6  = tvb_get_letohl(tvb, offset+32);
	unknown7  = tvb_get_letohl(tvb, offset+36);
	unknown8  = tvb_get_letohl(tvb, offset+40);
	unknown9  = tvb_get_letohl(tvb, offset+44);
	unknown10 = tvb_get_letohl(tvb, offset+48);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
	proto_tree_add_ipv4(skinny_tree, hf_skinny_ipDest,   tvb, offset+20, 4, ipDest);
	proto_tree_add_uint(skinny_tree, hf_skinny_destPort,tvb, offset+24, 4, destPort);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+28, 4, unknown5);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+32, 4, unknown6);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+36, 4, unknown7);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+40, 4, unknown8);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+44, 4, unknown9);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+48, 4, unknown10);
	break;

      case 0x8b :  /* stopMediaTransmission */
	unknown1 = tvb_get_letohl(tvb, offset+12);
	unknown2 = tvb_get_letohl(tvb, offset+16);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
	break;

      case 0x91 : /* speedDialStatMessage */
	line = tvb_get_letohl(tvb, offset+12);
	
	proto_tree_add_uint(skinny_tree, hf_skinny_line, tvb, offset+12, 4, line);
	break;

      case 0x92 : /* lineStatMessage */
	line = tvb_get_letohl(tvb, offset+12);

	proto_tree_add_uint(skinny_tree, hf_skinny_line, tvb, offset+12, 4, line);
	break;

      case 0x94 :
	year      = tvb_get_letohl(tvb, offset+12);
	month     = tvb_get_letohl(tvb, offset+16);
	unknown1  = tvb_get_letohl(tvb, offset+20);
	day       = tvb_get_letohl(tvb, offset+24);
	hour      = tvb_get_letohl(tvb, offset+28);
	minute    = tvb_get_letohl(tvb, offset+32);
	unknown2  = tvb_get_letohl(tvb, offset+36);
	unknown3  = tvb_get_letohl(tvb, offset+40);
	timeStamp = tvb_get_letohl(tvb, offset+44);

	proto_tree_add_uint(skinny_tree, hf_skinny_dateYear,  tvb, offset+12, 4, year);
	proto_tree_add_uint(skinny_tree, hf_skinny_dateMonth, tvb, offset+16, 4, month);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown,   tvb, offset+20, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_dateDay,   tvb, offset+24, 4, day);
	proto_tree_add_uint(skinny_tree, hf_skinny_dateHour,  tvb, offset+28, 4, hour);
	proto_tree_add_uint(skinny_tree, hf_skinny_dateMinute,tvb, offset+32, 4, minute);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown,   tvb, offset+36, 4, unknown2);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown,   tvb, offset+40, 4, unknown3);
	proto_tree_add_uint(skinny_tree, hf_skinny_timeStamp, tvb, offset+44, 4, timeStamp);
	break;
	
      case 0x97 :  /* buttonTemplateMessage === LOTS here check jtapi for hints */
	break;

      case 0x99 :  /* displayTextMessage */
	memset(displayMessage, '\0', displayLength);
	tvb_memcpy(tvb, displayMessage, offset+12, 32);
	unknown1  = tvb_get_letohl(tvb, offset+44);

	proto_tree_add_string(skinny_tree, hf_skinny_displayMessage, tvb, offset+12, strlen(displayMessage), displayMessage);	  
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+44, 4, unknown1);
	break;

      case 0x9f :   /* reset */
	unknown1  = tvb_get_letohl(tvb, offset+12);
	
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	break;

      case 0x106 :  /* closeReceiveChannel */
	unknown1 = tvb_get_letohl(tvb, offset+12);
	unknown2 = tvb_get_letohl(tvb, offset+16);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
	break;

      case 0x105 :
	unknown1 = tvb_get_letohl(tvb, offset+12);
	unknown2 = tvb_get_letohl(tvb, offset+16);
	unknown3 = tvb_get_letohl(tvb, offset+20);
	unknown4 = tvb_get_letohl(tvb, offset+24);
	unknown5 = tvb_get_letohl(tvb, offset+28);
	unknown6 = tvb_get_letohl(tvb, offset+32);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+20, 4, unknown3);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+24, 4, unknown4);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+28, 4, unknown5);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+32, 4, unknown6);
	break;

      case 0x107 :	
	memset(extension, '\0', extensionLength);
	tvb_get_nstringz0(tvb, offset+12, extensionLength, extension);
	callIdentifier = tvb_get_letohl(tvb, offset+36);

	proto_tree_add_string(skinny_tree, hf_skinny_extension, tvb, offset+12, strlen(extension), extension);
	proto_tree_add_uint(skinny_tree, hf_skinny_callIdentifier, tvb, offset+36, 4, callIdentifier);
	break;

      case 0x108 :   /* softkeyTemplateResMessage == Jtapi again :P, can decode some*/
	unknown1  = tvb_get_letohl(tvb, offset+12);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);

	unknown2  = tvb_get_letohl(tvb, offset+16);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);

	unknown3  = tvb_get_letohl(tvb, offset+20);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+20, 4, unknown3);

	softKeyNumber = 0;
	softKeyLoop = 0;
	/* NOTE ***** This loop *MIGHT* need to revolve around the unknow1/2 properties, not sure though */
	while (softKeyLoop < 18) {
	  int softOffset = offset+(softKeyLoop*20);
	  memset(displayMessage, '\0', displayLength);
	  tvb_memcpy(tvb, displayMessage, softOffset+24, 16);
	  proto_tree_add_string(skinny_tree, hf_skinny_displayMessage, tvb, softOffset+24, strlen(displayMessage), displayMessage);
	  softKeyNumber = tvb_get_letohl(tvb, softOffset+40);
	  proto_tree_add_uint(skinny_tree, hf_skinny_softKeyNumber, tvb, softOffset+40, 4, softKeyNumber);

	  softKeyLoop++;
	}

	break;

      case 0x110 :
	unknown1       = tvb_get_letohl(tvb, offset+12);
	callIdentifier = tvb_get_letohl(tvb, offset+16);
	unknown2       = tvb_get_letohl(tvb, offset+20);
        unknown3       = tvb_get_letohl(tvb, offset+24);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, callIdentifier);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+20, 4, unknown2);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+24, 4, unknown3);
	break;
	
      case 0x111 :
	unknown1 = tvb_get_letohl(tvb, offset+12);
	unknown2 = tvb_get_letohl(tvb, offset+16);
	callIdentifier = tvb_get_letohl(tvb, offset+20);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+16, 4, unknown2);
	proto_tree_add_uint(skinny_tree, hf_skinny_callIdentifier, tvb, offset+20, 4, callIdentifier);
	break;
	
      case 0x112 :
	memset(displayMessage,'\0',displayLength);
	unknown1 = tvb_get_letohl(tvb, offset+12);
	tvb_get_nstringz0(tvb,offset+16,displayLength, displayMessage);
	unknown2 = tvb_get_letohl(tvb, offset+48);
	callIdentifier = tvb_get_letohl(tvb, offset+52);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_string(skinny_tree, hf_skinny_displayMessage, tvb, offset+16, strlen(displayMessage), displayMessage);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+48, 4, unknown2);
	proto_tree_add_uint(skinny_tree, hf_skinny_callIdentifier, tvb, offset+52, 4, callIdentifier);
	break;
	
      case 0x113:
	callIdentifier = tvb_get_letohl(tvb, offset+16);
	proto_tree_add_uint(skinny_tree, hf_skinny_callIdentifier, tvb, offset+16, 4, callIdentifier);
	break;
	
      case 0x114 :
	
	unknown1 = tvb_get_letohl(tvb, offset+12);
	memset(displayMessage,'\0',displayLength);
	tvb_memcpy(tvb, displayMessage, offset+16, 16);
	unknown2 = tvb_get_letohl(tvb, offset+32);
	unknown3 = tvb_get_letohl(tvb, offset+36);
	unknown4 = tvb_get_letohl(tvb, offset+40);
	unknown5 = tvb_get_letohl(tvb, offset+44);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	proto_tree_add_string(skinny_tree, hf_skinny_displayMessage, tvb, offset+16, strlen(displayMessage), displayMessage);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+32, 4, unknown2);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+36, 4, unknown3);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+40, 4, unknown4);
	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+44, 4, unknown5);
	break;
	
      case 0x116 :
	unknown1 = tvb_get_letohl(tvb, offset+12);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	break;

      case 0x118 :    /* unregisterAckMessage */
	unknown1 = tvb_get_letohl(tvb, offset+12);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+12, 4, unknown1);
	break;

      case 0x0023    :
	
	memset(extension,'\0', extensionLength);
	tvb_get_nstringz0(tvb,offset+12,extensionLength,extension);
	callIdentifier = tvb_get_letohl(tvb,offset+36);
	packetsSent    = tvb_get_letohl(tvb,offset+44);
	octetsSent     = tvb_get_letohl(tvb,offset+48);
	packetsRecv    = tvb_get_letohl(tvb,offset+52);
	octetsRecv     = tvb_get_letohl(tvb,offset+56);
	packetsLost    = tvb_get_letohl(tvb,offset+60);
	jitter         = tvb_get_letohl(tvb,offset+64);
	latency        = tvb_get_letohl(tvb,offset+68);

	proto_tree_add_string(skinny_tree, hf_skinny_extension, tvb, offset+12, strlen(extension), extension);
	proto_tree_add_uint(skinny_tree, hf_skinny_callIdentifier, tvb, offset+36, 4, callIdentifier);
	proto_tree_add_uint(skinny_tree, hf_skinny_packetsSent, tvb, offset+44, 4, packetsSent);
	proto_tree_add_uint(skinny_tree, hf_skinny_octetsSent, tvb, offset+48, 4, octetsSent);
	proto_tree_add_uint(skinny_tree, hf_skinny_packetsRecv, tvb, offset+52, 4, packetsRecv);
	proto_tree_add_uint(skinny_tree, hf_skinny_octetsRecv, tvb, offset+56, 4, octetsRecv);
	proto_tree_add_uint(skinny_tree, hf_skinny_packetsLost, tvb, offset+60, 4, packetsLost);
	proto_tree_add_uint(skinny_tree, hf_skinny_latency, tvb, offset+64, 4, latency);
	proto_tree_add_uint(skinny_tree, hf_skinny_jitter, tvb, offset+68, 4, jitter);
	break;
	
      case 0x11D :
	unknown1       = tvb_get_letohl(tvb, offset+36);
	callIdentifier = tvb_get_letohl(tvb, offset+40);

	proto_tree_add_uint(skinny_tree, hf_skinny_unknown, tvb, offset+36, 4, unknown1);
	proto_tree_add_uint(skinny_tree, hf_skinny_callIdentifier, tvb, offset+40, 4, callIdentifier);
	break;

	
      default:
	break;
      }
      
    }
    offset = offset + hdr_data_length+8;
  }
}

/* Register the protocol with Ethereal */
void 
proto_register_skinny(void)
{                 
  
  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_skinny_data_length,
      { "Data Length", "skinny.data_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
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
	FT_UINT32, BASE_HEX, VALS(message_id), 0x0,
	"The function requested/done with this message.",
	HFILL }
    },

    { &hf_skinny_callIdentifier,
      { "Call Identifier", "skinny.callIdentifier",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Call identifier for this call.",
	HFILL }
    },

    { &hf_skinny_packetsSent,
      { "Packets Sent", "skinny.packetsSent",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Packets Sent during the call.",
	HFILL }
    },

    { &hf_skinny_octetsSent,
      { "Octets Sent", "skinny.octetsSent",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Octets sent during the call.",
	HFILL }
    },

    { &hf_skinny_packetsRecv,
      { "Packets Received", "skinny.packetsRecv",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Packets received during the call.",
	HFILL }
    },


    { &hf_skinny_octetsRecv,
      { "Octets Received", "skinny.octetsRecv",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Octets received during the call.",
	HFILL }
    },


    { &hf_skinny_packetsLost,
      { "Packets Lost", "skinny.packetsLost",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Packets lost during the call.",
	HFILL }
    },


    { &hf_skinny_latency,
      { "Latency(ms)", "skinny.latency",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Average packet latency during the call.",
	HFILL }
    },

    { &hf_skinny_jitter,
      { "Jitter", "skinny.jitter",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Average jitter during the call.",
	HFILL }
    },

    { &hf_skinny_extension,
      { "Extension", "skinny.extension",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The extension this packets is for.",
	HFILL }
    },

    { &hf_skinny_displayMessage,
      { "Text", "skinny.displayMessage",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"The message displayed on the phone.",
	HFILL }
    },

    { &hf_skinny_timeStamp,
      { "Timestamp", "skinny.timeStamp",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Time stamp for the call reference",
	HFILL }
    },

    { &hf_skinny_unknown,
      { "Unknown Long", "skinny.unknown",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"An as yet undecoded long value",
	HFILL }
    },
   
    { &hf_skinny_ipSrc,
      { "IP Source", "skinny.ipSrc",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Ip source address",
	HFILL }
    },

    { &hf_skinny_ipDest,
      { "IP Destination", "skinny.ipDest",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"IP destination address",
	HFILL }
    },

    { &hf_skinny_dateYear,
      { "Year", "skinny.year",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The current year",
	HFILL }
    },

    { &hf_skinny_dateMonth,
      { "Month", "skinny.month",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The current month",
	HFILL }
    },

    { &hf_skinny_dateDay,
      { "Day", "skinny.day",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"The day of the current month",
	HFILL }
    },

    { &hf_skinny_dateHour,
      { "Hour", "skinny.hour",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Hour of the day",
	HFILL }
    },

    { &hf_skinny_dateMinute,
      { "Minute", "skinny.minute",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Minute",
	HFILL }
    },

    { &hf_skinny_destPort,
      { "Destination Port", "skinny.destPort",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Destination Port",
	HFILL }
    },

    { &hf_skinny_srcPort,
      { "Source Port", "skinny.srcPort",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Source Port",
	HFILL }
    },

    { &hf_skinny_softKeyNumber,
      { "SoftKey", "skinny.softKeyNumber",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"SoftKey",
	HFILL }
    },

    { &hf_skinny_dialedDigit,
      { "Dialed Digit", "skinny.dialedDigit",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Dialed Digit",
	HFILL }
    },

    { &hf_skinny_line,
      { "Line", "skinny.line",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Line",
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
  dissector_handle_t skinny_handle;

  data_handle = find_dissector("data");
  skinny_handle = create_dissector_handle(dissect_skinny, proto_skinny);
  dissector_add("tcp.port", TCP_PORT_SKINNY, skinny_handle);
}
