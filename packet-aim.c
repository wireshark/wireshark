/* packet-aim.c
 * Routines for AIM Instant Messenger (OSCAR) dissection
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 *
 * $Id: packet-aim.c,v 1.19 2003/01/12 04:58:32 guy Exp $
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

#define TCP_PORT_AIM 5190
#define MAX_BUDDYNAME_LENGTH 30

#define STRIP_TAGS 1

/* channels */
#define CHANNEL_NEW_CONN    0x01
#define CHANNEL_SNAC_DATA   0x02
#define CHANNEL_FLAP_ERR    0x03
#define CHANNEL_CLOSE_CONN  0x04

/* SNAC families */
#define FAMILY_GENERIC    0x0001
#define FAMILY_LOCATION   0x0002
#define FAMILY_BUDDYLIST  0x0003
#define FAMILY_MESSAGING  0x0004
#define FAMILY_ADVERTS    0x0005
#define FAMILY_INVITATION 0x0006
#define FAMILY_ADMIN      0x0007
#define FAMILY_POPUP      0x0008
#define FAMILY_BOS        0x0009
#define FAMILY_USERLOOKUP 0x000A
#define FAMILY_STATS      0x000B
#define FAMILY_TRANSLATE  0x000C
#define FAMILY_CHAT_NAV   0x000D
#define FAMILY_CHAT       0x000E
#define FAMILY_SSI        0x0013
#define FAMILY_ICQ        0x0015
#define FAMILY_SIGNON     0x0017
#define FAMILY_OFT        0xfffe

/* Family Signon */
#define FAMILY_SIGNON_LOGON          0x0002
#define FAMILY_SIGNON_LOGON_REPLY    0x0003
#define FAMILY_SIGNON_SIGNON         0x0006
#define FAMILY_SIGNON_SIGNON_REPLY   0x0007

/* Family Signon */
#define FAMILY_GENERIC_ERROR          0x0001
#define FAMILY_GENERIC_CLIENTREADY    0x0002
#define FAMILY_GENERIC_SERVERREADY    0x0003
#define FAMILY_GENERIC_SERVICEREQ     0x0004
#define FAMILY_GENERIC_REDIRECT       0x0005
#define FAMILY_GENERIC_RATEINFOREQ    0x0006
#define FAMILY_GENERIC_RATEINFO       0x0007
#define FAMILY_GENERIC_RATEINFOACK    0x0008
#define FAMILY_GENERIC_UNKNOWNx09     0x0009
#define FAMILY_GENERIC_RATECHANGE     0x000a
#define FAMILY_GENERIC_SERVERPAUSE    0x000b
#define FAMILY_GENERIC_SERVERRESUME   0x000d
#define FAMILY_GENERIC_REQSELFINFO    0x000e
#define FAMILY_GENERIC_SELFINFO       0x000f
#define FAMILY_GENERIC_EVIL           0x0010
#define FAMILY_GENERIC_SETIDLE        0x0011
#define FAMILY_GENERIC_MIGRATIONREQ   0x0012
#define FAMILY_GENERIC_MOTD           0x0013
#define FAMILY_GENERIC_SETPRIVFLAGS   0x0014
#define FAMILY_GENERIC_WELLKNOWNURL   0x0015
#define FAMILY_GENERIC_NOP            0x0016
#define FAMILY_GENERIC_DEFAULT        0xffff

/* messaging */
#define MSG_TO_CLIENT     0x006
#define MSG_FROM_CLIENT   0x007

static const value_string aim_fnac_family_ids[] = {
  { FAMILY_GENERIC, "Generic" }, 
  { FAMILY_LOCATION, "Location" },
  { FAMILY_BUDDYLIST, "Buddy List" },
  { FAMILY_MESSAGING, "Messaging" },
  { FAMILY_ADVERTS, "Advertisement" },
  { FAMILY_INVITATION, "Invitation" },
  { FAMILY_ADMIN, "Admin" },
  { FAMILY_POPUP, "Popup" },
  { FAMILY_BOS, "Bos" },
  { FAMILY_USERLOOKUP, "User Lookup" },
  { FAMILY_STATS, "Stats" },
  { FAMILY_TRANSLATE, "Translate" },
  { FAMILY_CHAT_NAV, "Chat Nav" },
  { FAMILY_CHAT, "Chat" },
  { FAMILY_SSI, "Server Stored Info" },
  { FAMILY_ICQ, "ICQ" },
  { FAMILY_SIGNON, "Sign-on" },
  { FAMILY_OFT, "OFT/Rvous" },
  { 0, NULL }
};

static const value_string aim_fnac_family_signon[] = {
  { FAMILY_SIGNON_LOGON, "Logon" },
  { FAMILY_SIGNON_LOGON_REPLY, "Logon Reply" },
  { FAMILY_SIGNON_SIGNON, "Sign-on" },
  { FAMILY_SIGNON_SIGNON_REPLY, "Sign-on Reply" },
  { 0, NULL }
};

static const value_string aim_fnac_family_generic[] = {
  { FAMILY_GENERIC_ERROR, "Error" },
  { FAMILY_GENERIC_CLIENTREADY , "Client Ready" },
  { FAMILY_GENERIC_SERVERREADY, "Server Ready" },
  { FAMILY_GENERIC_SERVICEREQ, "Service Req" },
  { FAMILY_GENERIC_REDIRECT, "Redirect" },
  { FAMILY_GENERIC_RATEINFOREQ, "Rate Info Req" },
  { FAMILY_GENERIC_RATEINFO, "Rate Info" },
  { FAMILY_GENERIC_RATEINFOACK, "Rate Info Ack" },
  { FAMILY_GENERIC_UNKNOWNx09, "Unknown" },
  { FAMILY_GENERIC_RATECHANGE, "Rate Change" },
  { FAMILY_GENERIC_SERVERPAUSE, "Server Pause" },
  { FAMILY_GENERIC_SERVERRESUME, "Server Resume" },
  { FAMILY_GENERIC_REQSELFINFO, "Self Info Req" },
  { FAMILY_GENERIC_SELFINFO, "Self Info" },
  { FAMILY_GENERIC_EVIL, "Evil" },
  { FAMILY_GENERIC_SETIDLE, "Set Idle" },
  { FAMILY_GENERIC_MIGRATIONREQ, "Migration Req" },
  { FAMILY_GENERIC_MOTD, "MOTD" },
  { FAMILY_GENERIC_SETPRIVFLAGS, "Set Privilege Flags" },
  { FAMILY_GENERIC_WELLKNOWNURL, "Well Known URL" },
  { FAMILY_GENERIC_NOP, "noop" },
  { FAMILY_GENERIC_DEFAULT, "Generic Default" },
  { 0, NULL }
};

static void dissect_aim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void get_message( guchar *msg, tvbuff_t *tvb, int msg_offset, int msg_length);
static int get_buddyname( char *name, tvbuff_t *tvb, int len_offset, int name_offset);
static void dissect_aim_newconn(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac(tvbuff_t *tvb, packet_info *pinfo, 
			     int offset, proto_tree *tree);
static void dissect_aim_snac_fnac_subtype(tvbuff_t *tvb, int offset, 
					  proto_tree *tree, guint16 family);
static void dissect_aim_snac_signon(tvbuff_t *tvb, packet_info *pinfo, 
				    int offset, proto_tree *tree, 
				    guint16 subtype);
static void dissect_aim_snac_signon_logon(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac_signon_logon_reply(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac_signon_signon(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac_signon_signon_reply(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static void dissect_aim_snac_generic(tvbuff_t *tvb, packet_info *pinfo, 
				     int offset, proto_tree *tree, 
				     guint16 subtype);
static void dissect_aim_snac_buddylist(tvbuff_t *tvb, packet_info *pinfo, 
				       int offset, proto_tree *tree, 
				       guint16 subtype);
static void dissect_aim_snac_location(tvbuff_t *tvb, packet_info *pinfo, 
				      int offset, proto_tree *tree, 
				      guint16 subtype);
static void dissect_aim_snac_location_request_user_information(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_aim_snac_location_user_information(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_aim_snac_adverts(tvbuff_t *tvb, packet_info *pinfo, 
				     int offset, proto_tree *tree, 
				     guint16 subtype);
static void dissect_aim_snac_userlookup(tvbuff_t *tvb, packet_info *pinfo, 
					int offset, proto_tree *tree, 
					guint16 subtype);
static void dissect_aim_snac_chat(tvbuff_t *tvb, packet_info *pinfo, 
				  int offset, proto_tree *tree, 
				  guint16 subtype);
static void dissect_aim_snac_messaging(tvbuff_t *tvb, packet_info *pinfo, 
				       int offset, proto_tree *tree, 
				       guint16 subtype);
static void dissect_aim_flap_err(tvbuff_t *tvb, packet_info *pinfo, 
				 int offset, proto_tree *tree);
static void dissect_aim_close_conn(tvbuff_t *tvb, packet_info *pinfo, 
				   int offset, proto_tree *tree);
static void dissect_aim_unknown_channel(tvbuff_t *tvb, packet_info *pinfo, 
					int offset, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_aim = -1;
static int hf_aim_cmd_start = -1;
static int hf_aim_channel = -1;
static int hf_aim_seqno = -1;
static int hf_aim_data = -1;
static int hf_aim_data_len = -1;
static int hf_aim_signon_challenge_len = -1;
static int hf_aim_signon_challenge = -1;
static int hf_aim_fnac_family = -1;
static int hf_aim_fnac_subtype = -1;
static int hf_aim_fnac_subtype_signon = -1;
static int hf_aim_fnac_subtype_generic = -1;
static int hf_aim_fnac_flags = -1;
static int hf_aim_fnac_id = -1;
static int hf_aim_infotype = -1;
static int hf_aim_buddyname_len = -1;
static int hf_aim_buddyname = -1;
static int hf_aim_userinfo_warninglevel = -1;
static int hf_aim_userinfo_tlvcount = -1;

/* Initialize the subtree pointers */
static gint ett_aim          = -1;
static gint ett_aim_fnac     = -1;

/* Code to actually dissect the packets */
static void dissect_aim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* Header fields */
  unsigned char  hdr_channel;           /* channel ID */
  unsigned short hdr_sequence_no;       /* Internal frame sequence number, not needed */
  unsigned short hdr_data_field_length; /* length of data within frame */

  int offset=0;

/* Set up structures we will need to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *aim_tree = NULL;

/* check, if this is really an AIM packet, they start with 0x2a */

  if(!(tvb_get_guint8(tvb, offset) == 0x2a)) {
    /* Not an instant messenger packet, just happened to use the same port */
    return;
  }
  offset += 1;

/* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIM");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO, "AOL Instant Messenger");

  /* get relevant header information */
  hdr_channel           = tvb_get_guint8(tvb, offset);
  offset += 1;
  hdr_sequence_no       = tvb_get_ntohs(tvb, offset);
  offset += 2;
  hdr_data_field_length = tvb_get_ntohs(tvb, offset);
  offset += 2;

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
  if (tree) {

    ti = proto_tree_add_item(tree, proto_aim, tvb, 0, -1, FALSE);
    aim_tree = proto_item_add_subtree(ti, ett_aim);
    proto_tree_add_uint(aim_tree, hf_aim_cmd_start, tvb, 0, 1, '*');
    proto_tree_add_uint(aim_tree, hf_aim_channel, tvb, 1, 1, hdr_channel);
    proto_tree_add_uint(aim_tree, hf_aim_seqno, tvb, 2, 2, hdr_sequence_no);
    proto_tree_add_uint(aim_tree, hf_aim_data_len, tvb, 4, 2, hdr_data_field_length);

  }

  switch(hdr_channel)
  {
    /* New connection request */
    case CHANNEL_NEW_CONN:
      dissect_aim_newconn(tvb, pinfo, offset, aim_tree);
      break;
    case CHANNEL_SNAC_DATA:
      dissect_aim_snac(tvb, pinfo, offset, aim_tree);
      break;
    case CHANNEL_FLAP_ERR:
      dissect_aim_flap_err(tvb, pinfo, offset, aim_tree);
      break;
    case CHANNEL_CLOSE_CONN:
      dissect_aim_close_conn(tvb, pinfo, offset, aim_tree);
      break;
    default:
      dissect_aim_unknown_channel(tvb, pinfo, offset, aim_tree);
      break;
  }

}


static int get_buddyname( char *name, tvbuff_t *tvb, int len_offset, int name_offset)
{
  guint8 buddyname_length;

  buddyname_length = tvb_get_guint8(tvb, len_offset);

  if(buddyname_length > MAX_BUDDYNAME_LENGTH ) buddyname_length = MAX_BUDDYNAME_LENGTH;
  memset( name, '\0', sizeof(name));
  tvb_get_nstringz0(tvb, name_offset, buddyname_length, name);

  return buddyname_length;
}


static void get_message( guchar *msg, tvbuff_t *tvb, int msg_offset, int msg_length)
{
  int i,j,c;
  int bracket = FALSE;
  int max, tagchars = 0;
  int new_offset = msg_offset;
  int new_length = msg_length;



  /* make sure nothing bigger than 1000 bytes is printed */
  if( msg_length > 999 ) return;

  memset( msg, '\0', 1000);
  i = 0;
  c = 0;

  /* loop until HTML tag is reached - quick&dirty way to find start of message
   * (it is nearly impossible to find the correct start offset for all client versions) */
  while( (tagchars < 6) && (new_length > 5) )
  {
     j = tvb_get_guint8(tvb, new_offset);
     if( ( (j == '<') && (tagchars == 0) ) ||
         ( (j == 'h') && (tagchars == 1) ) ||
         ( (j == 'H') && (tagchars == 1) ) ||
         ( (j == 't') && (tagchars == 2) ) ||
         ( (j == 'T') && (tagchars == 2) ) ||
         ( (j == 'm') && (tagchars == 3) ) ||
         ( (j == 'M') && (tagchars == 3) ) ||
         ( (j == 'l') && (tagchars == 4) ) ||
         ( (j == 'L') && (tagchars == 4) ) ||
         ( (j == '>') && (tagchars == 5) ) ) tagchars++;
     new_offset++;
     new_length--;
  }

  /* set offset and length of message to after the first HTML tag */
  msg_offset = new_offset;
  msg_length = new_length;
  max = msg_length - 1;
  tagchars = 0;

  /* find the rest of the message until either a </html> is reached or the end of the frame.
   * All other HTML tags are stripped to display only the raw message (printable characters) */
  while( (c < max) && (tagchars < 7) )
  {
     j = tvb_get_guint8(tvb, msg_offset+c);


     /* make sure this is an HTML tag by checking the order of the chars */
     if( ( (j == '<') && (tagchars == 0) ) ||
         ( (j == '/') && (tagchars == 1) ) ||
         ( (j == 'h') && (tagchars == 2) ) ||
         ( (j == 'H') && (tagchars == 2) ) ||
         ( (j == 't') && (tagchars == 3) ) ||
         ( (j == 'T') && (tagchars == 3) ) ||
         ( (j == 'm') && (tagchars == 4) ) ||
         ( (j == 'M') && (tagchars == 4) ) ||
         ( (j == 'l') && (tagchars == 5) ) ||
         ( (j == 'L') && (tagchars == 5) ) ||
         ( (j == '>') && (tagchars == 6) ) ) tagchars++;

#ifdef STRIP_TAGS
     if( j == '<' ) bracket = TRUE;
     if( j == '>' ) bracket = FALSE;
     if( (isprint(j) ) && (bracket == FALSE) && (j != '>'))
#else
     if( isprint(j) )
#endif
     {
       msg[i] = j;
       i++;
     }
     c++;
  }
}

static void dissect_aim_newconn(tvbuff_t *tvb, packet_info *pinfo, 
				int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) 
    col_add_fstr(pinfo->cinfo, COL_INFO, "New Connection");
  proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
		      tvb_length_remaining (tvb, offset), FALSE);
}

static void dissect_aim_snac(tvbuff_t *tvb, packet_info *pinfo, 
			     int offset, proto_tree *aim_tree)
{
  guint16 family;
  guint16 subtype;
  guint16 flags;
  guint32 id;
  proto_item *ti1;
  proto_tree *aim_tree_fnac = NULL;
  int orig_offset;

  orig_offset = offset;
  family = tvb_get_ntohs(tvb, offset);
  offset += 2;
  subtype = tvb_get_ntohs(tvb, offset);
  offset += 2;
  flags = tvb_get_ntohs(tvb, offset);
  offset += 2;
  id = tvb_get_ntohl(tvb, offset);
  offset += 4;
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "SNAC data");
  }
  if( aim_tree )
    {
      offset = orig_offset;
      ti1 = proto_tree_add_text(aim_tree, tvb, 6, 10, "FNAC");
      aim_tree_fnac = proto_item_add_subtree(ti1, ett_aim_fnac);

      proto_tree_add_item (aim_tree_fnac, hf_aim_fnac_family,
			   tvb, offset, 2, FALSE);
      offset += 2;

      /* Dissect the subtype based on the family */
      dissect_aim_snac_fnac_subtype(tvb, offset, aim_tree_fnac, family);
      offset += 2;

      proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_flags, tvb, offset, 
			  2, flags);
      offset += 2;
      proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_id, tvb, offset,
			  4, id);
      offset += 4;
    }

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Family: %s",
		    val_to_str(family, aim_fnac_family_ids,
			       "Unknown Family ID"));
  
  switch(family)
    {
    case FAMILY_SIGNON:
      dissect_aim_snac_signon(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_GENERIC:
      dissect_aim_snac_generic(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_BUDDYLIST:
      dissect_aim_snac_buddylist(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_LOCATION:
      dissect_aim_snac_location(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_ADVERTS:
      dissect_aim_snac_adverts(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_USERLOOKUP:
      dissect_aim_snac_userlookup(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_CHAT:
      dissect_aim_snac_chat(tvb, pinfo, offset, aim_tree, subtype);
      break;
    case FAMILY_MESSAGING:
      dissect_aim_snac_messaging(tvb, pinfo, offset, aim_tree, subtype);
      break;
    }
}

static void dissect_aim_snac_signon(tvbuff_t *tvb, packet_info *pinfo, 
				    int offset, proto_tree *tree, 
				    guint16 subtype)
{
  switch(subtype)
    {
    case FAMILY_SIGNON_LOGON:
      dissect_aim_snac_signon_logon(tvb, pinfo, offset, tree);
      break;
    case FAMILY_SIGNON_LOGON_REPLY:
      dissect_aim_snac_signon_logon_reply(tvb, pinfo, offset, tree);
      break;
    case FAMILY_SIGNON_SIGNON:
      dissect_aim_snac_signon_signon(tvb, pinfo, offset, tree);
      break;
    case FAMILY_SIGNON_SIGNON_REPLY:
      dissect_aim_snac_signon_signon_reply(tvb, pinfo, offset, tree);
      break;
    }
}

static void dissect_aim_snac_signon_logon(tvbuff_t *tvb, packet_info *pinfo, 
					  int offset, proto_tree *tree)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH];

  /* Info Type */
  proto_tree_add_item(tree, hf_aim_infotype, tvb, offset, 2, FALSE);
  offset += 2;

  /* Unknown */
  offset += 1;

  /* Buddy Name */
  buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Logon, Username: %s", 
		    buddyname);
  }
  
  if(tree) {
    proto_tree_add_text(tree, tvb, offset + 1, buddyname_length, 
			"Screen Name: %s", buddyname);
  }
  offset += buddyname_length + 1;
}

static void dissect_aim_snac_signon_logon_reply(tvbuff_t *tvb, 
						packet_info *pinfo, 
						int offset, proto_tree *tree)
{
    if (check_col(pinfo->cinfo, COL_INFO)) 
      col_append_fstr(pinfo->cinfo, COL_INFO, ", Login information reply");

    /* Show the undissected payload */
    proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
			tvb_length_remaining (tvb, offset), FALSE);
}

static void dissect_aim_snac_signon_signon(tvbuff_t *tvb, packet_info *pinfo, 
					   int offset, proto_tree *tree)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH];

  /* Info Type */
  proto_tree_add_item(tree, hf_aim_infotype, tvb, offset, 2, FALSE);
  offset += 2;

  /* Unknown */
  offset += 1;

  /* Buddy Name */
  buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " Username: %s", buddyname);
  }
  
  if(tree) {
    proto_tree_add_text(tree, tvb, offset + 1, buddyname_length, 
			"Screen Name: %s", buddyname);
  }
  
  offset += buddyname_length + 1;
}

static void dissect_aim_snac_signon_signon_reply(tvbuff_t *tvb, 
						 packet_info *pinfo, 
						 int offset, proto_tree *tree)
{
  guint16 challenge_length = 0;

  if (check_col(pinfo->cinfo, COL_INFO)) 
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Sign-on reply");

  /* Logon Challenge Length */
  challenge_length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_aim_signon_challenge_len, tvb, offset, 2, FALSE);
  offset += 2;

  /* Challenge */
  proto_tree_add_item(tree, hf_aim_signon_challenge, tvb, offset, challenge_length, FALSE);
  offset += challenge_length;
}

static void dissect_aim_snac_generic(tvbuff_t *tvb, packet_info *pinfo, 
				    int offset, proto_tree *tree, 
				    guint16 subtype)
{
  switch(subtype)
    {
    case 0x0001:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Generic Error");
      break;
    case 0x0002:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, 
		     "Client is now online and ready for normal function");
      break;
    case 0x0003:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, 
		     "Server is now ready for normal functions");
      break;
    case 0x0004:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, 
		     "Request for new service (server will redirect client)");
      break;
    case 0x0005:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Redirect response");
      break;
    case 0x0006:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request Rate Information");
      break;
    case 0x0007:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Rate information response");
      break;
    case 0x0008:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Rate Information Response Ack");
      break;
    case 0x000a:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Rate Change");
      break;
    case 0x000b:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Server Pause");
      break;
    case 0x000d:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Server Resume");
      break;
    case 0x000e:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request Self Info");
      break;
    case 0x000f:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Self Info");
      break;
    case 0x0010:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Evil");
      break;
    case 0x0011:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Set Idle");
      break;
    case 0x0012:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request Migration");
      break;
    case 0x0013:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "MOTD");
      break;
    case 0x0014:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Set Privilege Flags");
      break;
    case 0x0015:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Well Known URL");
      break;
    case 0x0016:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "No-op");
      break;
    case 0xffff:
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "Generic Default");
      break;
    }
  
  /* Show the undissected payload */
  proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
		      tvb_length_remaining (tvb, offset), FALSE);
}

static void dissect_aim_snac_buddylist(tvbuff_t *tvb, packet_info *pinfo, 
				       int offset, proto_tree *tree, 
				       guint16 subtype)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH];

  switch(subtype)
    {
    case 0x0001:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Buddylist - Error");
      break;
       
   case 0x0002:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request Rights information");
      break;
      
    case 0x0003:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Rights information");
      break;
      
    case 0x0004:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Add to Buddylist");
      break;
      
    case 0x0005:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Remove from Buddylist");
      break;
      
    case 0x000b:
      buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Oncoming Buddy");
	col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", buddyname);
      }
      
      if (tree) {
	proto_tree_add_text(tree, tvb, offset + 1, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      offset += buddyname_length + 1;
      break;
      
    case 0x000c:
      buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Offgoing Buddy");
	col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", buddyname);
      }
      
      if (tree) {
	proto_tree_add_text(tree, tvb, offset + 1, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      offset += buddyname_length + 1;
      break;
    }

  /* Show the undissected payload */
  proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
		      tvb_length_remaining (tvb, offset), FALSE);
}

static void dissect_aim_snac_location(tvbuff_t *tvb, packet_info *pinfo, 
				      int offset, proto_tree *tree, 
				      guint16 subtype)
{
  switch(subtype)
    {
    case 0x0001:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Location - Error");
      break;
    case 0x0002:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request Rights Information");
      break;
    case 0x0003:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Rights Information");
      break;
    case 0x0004:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Set User Information");
      break;
    case 0x0005:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Request User Information");
      dissect_aim_snac_location_request_user_information(tvb, offset, tree);
      break;
    case 0x0006:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "User Information");
      dissect_aim_snac_location_user_information(tvb, offset, tree);
      break;
    case 0x0007:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Watcher Subrequest");
      break;
    case 0x0008:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Watcher Notification");
      break;
    }
}

static void dissect_aim_snac_location_request_user_information(tvbuff_t *tvb, 
							  int offset,
							  proto_tree *tree)
{
  guint8 buddyname_length = 0;

  /* Info Type */
  proto_tree_add_item(tree, hf_aim_infotype, tvb, offset, 2, FALSE);
  offset += 2;

  /* Buddy Name length */
  buddyname_length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_aim_buddyname_len, tvb, offset, 1, FALSE);
  offset += 1;
  
  /* Buddy name */
  proto_tree_add_item(tree, hf_aim_buddyname, tvb, offset, buddyname_length, FALSE);
  offset += buddyname_length;

  /* Show the undissected payload */
  proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
		      tvb_length_remaining (tvb, offset), FALSE);
}

static void dissect_aim_snac_location_user_information(tvbuff_t *tvb, 
						  int offset, proto_tree *tree)
{
  guint8 buddyname_length = 0;
  guint16 tlv_count = 0;

  /* Buddy Name length */
  buddyname_length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_aim_buddyname_len, tvb, offset, 1, FALSE);
  offset += 1;
  
  /* Buddy name */
  proto_tree_add_item(tree, hf_aim_buddyname, tvb, offset, buddyname_length, FALSE);
  offset += buddyname_length;

  /* Warning level */
  proto_tree_add_item(tree, hf_aim_userinfo_warninglevel, tvb, offset, 2, FALSE);
  offset += 2;

  /* TLV Count */
  tlv_count = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_aim_userinfo_tlvcount, tvb, offset, 2, FALSE);
  offset += 2;

  /* Show the undissected payload */
  proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
		      tvb_length_remaining (tvb, offset), FALSE);
}

static void dissect_aim_snac_adverts(tvbuff_t *tvb _U_, 
				     packet_info *pinfo _U_, 
				     int offset _U_, proto_tree *tree _U_, 
				     guint16 subtype)
{
  switch(subtype)
    {
    case 0x0001:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Advertisements - Error");
      break;
    case 0x0002:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Advertisement Request");
      break;
    case 0x0003:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Advertisement data (GIF)");
      break;
    }

  /* Show the undissected payload */
  proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
		      tvb_length_remaining (tvb, offset), FALSE);
}

static void dissect_aim_snac_userlookup(tvbuff_t *tvb _U_, packet_info *pinfo, 
					int offset _U_, proto_tree *tree _U_, 
					guint16 subtype)
{
  switch(subtype)
    {
    case 0x0001:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, 
		     "Search - Error (could be: not found)");
      break;
    case 0x0002:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, 
		     "Search for Screen Name by e-mail");
      break;
    case 0x0003:
      if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_fstr(pinfo->cinfo, COL_INFO, "Screen Name Search Result");
      break;
    }

  /* Show the undissected payload */
  proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
		      tvb_length_remaining (tvb, offset), FALSE);
}

static void dissect_aim_snac_chat(tvbuff_t *tvb, packet_info *pinfo, 
				  int offset _U_, proto_tree *tree, 
				  guint16 subtype)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH];
  guchar msg[1000];

  switch(subtype)
    {
    case 0x005:
      /* channel message from client */
      get_message( msg, tvb, 40 + buddyname_length, tvb_length(tvb) 
		   - 40 - buddyname_length );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Chat Message ");
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      break;
      
    case 0x006:
      /* channel message to client */
      buddyname_length = get_buddyname( buddyname, tvb, 30, 31 );
      get_message( msg, tvb, 36 + buddyname_length, tvb_length(tvb) 
		   - 36 - buddyname_length );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Chat Message ");
	col_append_fstr(pinfo->cinfo, COL_INFO, "from: %s", buddyname);
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      
      if(tree) {
	proto_tree_add_text(tree, tvb, 31, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      break;
    }
}

static void dissect_aim_snac_messaging(tvbuff_t *tvb, packet_info *pinfo, 
				       int offset, proto_tree *tree, 
				       guint16 subtype)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH];
  guchar msg[1000];

  switch(subtype)
    {    
    case MSG_TO_CLIENT:

      /* Unknown */
      offset += 10;

      buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );

      /* djh - My test suggest that this is broken.  Need to give this a
	 closer look @@@@@@@@@ */
      get_message( msg, tvb, 36 + buddyname_length, tvb_length(tvb) - 36
		   - buddyname_length );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Message ");
	col_append_fstr(pinfo->cinfo, COL_INFO, "to: %s", buddyname);
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      
      if(tree) {
	proto_tree_add_text(tree, tvb, 27, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      
      break;
      
    case MSG_FROM_CLIENT:

      /* Unknown */
      offset += 10;

      buddyname_length = get_buddyname( buddyname, tvb, offset, offset + 1 );

      /* djh - My test suggest that this is broken.  Need to give this a
	 closer look @@@@@@@@@ */      
      get_message( msg, tvb, 36 + buddyname_length,  tvb_length(tvb) - 36
		   - buddyname_length);
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Message");
	col_append_fstr(pinfo->cinfo, COL_INFO, " from: %s", buddyname);
	
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
      }
      
      if(tree) {
	proto_tree_add_text(tree, tvb, 27, buddyname_length, 
			    "Screen Name: %s", buddyname);
      }
      break;
    }
}

static void dissect_aim_snac_fnac_subtype(tvbuff_t *tvb, int offset, 
				     proto_tree *tree, guint16 family)
{
  /* Since the subtypes differ by family, we need to display the correct
     subtype based on the family.  If we don't know the family, or we do
     not have the subtypes enumerated for a known family, we just dump the
     subtype as-is */

  switch (family)
    {
    case FAMILY_GENERIC:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_generic,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_LOCATION:
    case FAMILY_BUDDYLIST:
    case FAMILY_MESSAGING:
    case FAMILY_ADVERTS:
    case FAMILY_INVITATION:
    case FAMILY_ADMIN:
    case FAMILY_POPUP:
    case FAMILY_BOS:
    case FAMILY_USERLOOKUP:
    case FAMILY_STATS:
    case FAMILY_TRANSLATE:
    case FAMILY_CHAT_NAV:
    case FAMILY_CHAT:
    case FAMILY_SSI:
    case FAMILY_ICQ:
      proto_tree_add_item(tree, hf_aim_fnac_subtype, tvb, offset, 2, FALSE);
      break;
    case FAMILY_SIGNON:
      proto_tree_add_item (tree, hf_aim_fnac_subtype_signon,
			   tvb, offset, 2, FALSE);
      break;
    case FAMILY_OFT:
    default:
      proto_tree_add_item(tree, hf_aim_fnac_subtype, tvb, offset, 2, FALSE);
      break;

    }
}

static void dissect_aim_flap_err(tvbuff_t *tvb, packet_info *pinfo, 
				 int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "FLAP error");
  }

  /* Show the undissected payload */
  proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
		      tvb_length_remaining (tvb, offset), FALSE);
}

static void dissect_aim_close_conn(tvbuff_t *tvb, packet_info *pinfo, 
				   int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "Close Connection");
  }

  /* Show the undissected payload */
  proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
		      tvb_length_remaining (tvb, offset), FALSE);
}

static void dissect_aim_unknown_channel(tvbuff_t *tvb, packet_info *pinfo, 
					int offset, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Channel");
  }

  /* Show the undissected payload */
  proto_tree_add_item(tree, hf_aim_data, tvb, offset, 
		      tvb_length_remaining (tvb, offset), FALSE);
}

/* Register the protocol with Ethereal */
void
proto_register_aim(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_aim_cmd_start,
      { "Command Start", "aim.cmd_start", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_channel,
      { "Channel ID", "aim.channel", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_seqno,
      { "Sequence Number", "aim.seqno", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_data_len,
      { "Data Field Length", "aim.datalen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_data,
      { "Data", "aim.data", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_signon_challenge_len,
      { "Signon challenge length", "aim.signon.challengelen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_signon_challenge,
      { "Signon challenge", "aim.signon.challenge", FT_STRING, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_family,
      { "FNAC Family ID", "aim.fnac.family", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_ids), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_signon,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_signon), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_generic,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_generic), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_flags,
      { "FNAC Flags", "aim.fnac.flags", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_id,
      { "FNAC ID", "aim.fnac.id", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_infotype,
      { "Infotype", "aim.infotype", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_buddyname_len,
      { "Buddyname len", "aim.buddynamelen", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_buddyname,
      { "Buddy Name", "aim.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
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
    &ett_aim,
    &ett_aim_fnac,
  };

/* Register the protocol name and description */
  proto_aim = proto_register_protocol("AOL Instant Messenger", "AIM", "aim");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_aim(void)
{
  dissector_handle_t aim_handle;

  aim_handle = create_dissector_handle(dissect_aim, proto_aim);
  dissector_add("tcp.port", TCP_PORT_AIM, aim_handle);
}
