/* packet-aim.c
 * Routines for AIM Instant Messenger (OSCAR) dissection
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 *
 * $Id: packet-aim.c,v 1.18 2003/01/11 07:17:37 guy Exp $
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
#define FAMILY_SIGNON     0x0017

/* messaging */
#define MSG_TO_CLIENT     0x006
#define MSG_FROM_CLIENT   0x007

static void dissect_aim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void get_message( guchar *msg, tvbuff_t *tvb, int msg_offset, int msg_length);
static int get_buddyname( char *name, tvbuff_t *tvb, int len_offset, int name_offset);
static void dissect_aim_signon_reply(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_aim_request_user_information(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_aim_user_information(tvbuff_t *tvb, int offset, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_aim = -1;
static int hf_aim_cmd_start = -1;
static int hf_aim_channel = -1;
static int hf_aim_seqno = -1;
static int hf_aim_data_len = -1;
static int hf_aim_signon_challenge_len = -1;
static int hf_aim_signon_challenge = -1;
static int hf_aim_fnac_family = -1;
static int hf_aim_fnac_subtype = -1;
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

  guint16 family;
  guint16 subtype;
  guint16 flags;
  guint32 id;
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH];
  guchar msg[1000];
  int offset;

/* Set up structures we will need to add the protocol subtree and manage it */
  proto_item *ti;
  proto_item *ti1;
  proto_tree *aim_tree = NULL;
  proto_tree *aim_tree_fnac = NULL;

/* check, if this is really an AIM packet, they start with 0x2a */

  if(!(tvb_get_guint8(tvb, 0) == 0x2a)) {
    /* Not an instant messenger packet, just happened to use the same port */
    return;
  }

/* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIM");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO, "AOL Instant Messenger");

/* get relevant header information */

  hdr_channel           = tvb_get_guint8(tvb, 1);
  hdr_sequence_no       = tvb_get_ntohs(tvb, 2);
  hdr_data_field_length = tvb_get_ntohs(tvb, 4);

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
      if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "New Connection");
      break;

    /* SNAC channel. Most packets are of this type, such as messages or buddy list
     * management.
     */
    case CHANNEL_SNAC_DATA:
      family = tvb_get_ntohs(tvb, 6);
      subtype = tvb_get_ntohs(tvb, 8);
      flags = tvb_get_ntohs(tvb, 10);
      id = tvb_get_ntohl(tvb, 12);

      if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "SNAC data");
      }
      if( tree )
      {
        ti1 = proto_tree_add_text(aim_tree, tvb, 6, 10, "FNAC");
        aim_tree_fnac = proto_item_add_subtree(ti1, ett_aim_fnac);
        proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_family, tvb, 6, 2, family);
        proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_subtype, tvb, 8, 2, subtype);
        proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_flags, tvb, 10, 2, flags);
        proto_tree_add_uint(aim_tree_fnac, hf_aim_fnac_id, tvb, 12, 4, id);
      }

      offset = 16;

      if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Family: 0x%04x - Subtype: 0x%04x (unknown)", family, subtype);

        switch(family)
        {
          case FAMILY_SIGNON:
            switch(subtype)
            {
              case 0x0002:
                buddyname_length = get_buddyname( buddyname, tvb, 19, 20 );

                if (check_col(pinfo->cinfo, COL_INFO)) {
                  col_add_fstr(pinfo->cinfo, COL_INFO, "Login");
                  col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", buddyname);
                }

                if( tree  )
                {
                  proto_tree_add_text(aim_tree_fnac, tvb, 20, buddyname_length, "Screen Name: %s", buddyname);
                }

                break;
              case 0x0003:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Login information reply");
                break;
              case 0x0006:
                buddyname_length = get_buddyname( buddyname, tvb, 19, 20 );

                if (check_col(pinfo->cinfo, COL_INFO)) {
                  col_add_fstr(pinfo->cinfo, COL_INFO, "Sign-on");
                  col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", buddyname);
                }

                if( tree )
                {
                  proto_tree_add_text(aim_tree_fnac, tvb, 20, buddyname_length, "Screen Name: %s", buddyname);
                }

                break;
              case 0x0007:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Sign-on reply");
		dissect_aim_signon_reply(tvb, offset, aim_tree);
                break;
            }
            break;

          case FAMILY_GENERIC:
            switch(subtype)
            {
              case 0x0002:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Client is now online and ready for normal function");
                break;
              case 0x0003:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Server is now ready for normal functions");
                break;
              case 0x0004:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Request for new service (server will redirect client)");
                break;
              case 0x0005:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Redirect response");
                break;
              case 0x0006:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Request Rate Information");
                break;
              case 0x0007:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Rate information response");
                break;
              case 0x0008:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Rate Information Response Ack");
                break;
              case 0x0016:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "No-op");
                break;
            }
            break;

          case FAMILY_BUDDYLIST:
            switch(subtype)
            {
              case 0x0001:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Buddylist - Error");
                break;

              case 0x0002:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Request Rights information");
                break;

              case 0x0003:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Rights information");
                break;

              case 0x0004:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Add to Buddylist");
                break;

              case 0x0005:
                if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Remove from Buddylist");
                break;

              case 0x000b:
                buddyname_length = get_buddyname( buddyname, tvb, 16, 17 );

                if (check_col(pinfo->cinfo, COL_INFO)) {
                  col_add_fstr(pinfo->cinfo, COL_INFO, "Oncoming Buddy");
                  col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", buddyname);
                }

                if( tree )
                {
                  proto_tree_add_text(aim_tree_fnac, tvb, 17, buddyname_length, "Screen Name: %s", buddyname);
                }

                break;

              case 0x000c:

                buddyname_length = get_buddyname( buddyname, tvb, 16, 17 );

                if (check_col(pinfo->cinfo, COL_INFO)) {
                  col_add_fstr(pinfo->cinfo, COL_INFO, "Offgoing Buddy");
                  col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", buddyname);
                }

                if( tree )
                {
                  proto_tree_add_text(aim_tree_fnac, tvb, 17, buddyname_length, "Screen Name: %s", buddyname);
                }


                break;
            }
          break;

        case FAMILY_LOCATION:
          switch(subtype)
          {
            case 0x0001:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Location - Error");
              break;
            case 0x0002:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Request Rights Information");
              break;
            case 0x0003:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Rights Information");
              break;
            case 0x0004:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Set User Information");
              break;
            case 0x0005:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Request User Information");
	      dissect_aim_request_user_information(tvb, offset, aim_tree);
              break;
            case 0x0006:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "User Information");
	      dissect_aim_user_information(tvb, offset, aim_tree);
              break;
            case 0x0007:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Watcher Subrequest");
              break;
            case 0x0008:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Watcher Notification");
              break;
          }
          break;

        case FAMILY_ADVERTS:
          switch(subtype)
          {
            case 0x0001:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Advertisements - Error");
              break;
            case 0x0002:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Advertisement Request");
              break;
            case 0x0003:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Advertisement data (GIF)");
              break;
          }
          break;

        case FAMILY_USERLOOKUP:
          switch(subtype)
          {
            case 0x0001:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Search - Error (could be: not found)");
              break;
            case 0x0002:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Search for Screen Name by e-mail");
              break;
            case 0x0003:
              if (check_col(pinfo->cinfo, COL_INFO)) col_add_fstr(pinfo->cinfo, COL_INFO, "Screen Name Search Result");
              break;
          }
          break;

        case FAMILY_CHAT:
          switch(subtype)
          {
            case 0x005:
              /* channel message from client */
              get_message( msg, tvb, 40 + buddyname_length, tvb_length(tvb) - 40 - buddyname_length );

              if (check_col(pinfo->cinfo, COL_INFO)) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "Chat Message ");
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
              }
              break;

            case 0x006:
              /* channel message to client */
              buddyname_length = get_buddyname( buddyname, tvb, 30, 31 );
              get_message( msg, tvb, 36 + buddyname_length, tvb_length(tvb) - 36 - buddyname_length );

              if (check_col(pinfo->cinfo, COL_INFO)) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "Chat Message ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "from: %s", buddyname);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
              }

              if( tree )
              {
                proto_tree_add_text(aim_tree_fnac, tvb, 31, buddyname_length, "Screen Name: %s", buddyname);
              }
              break;
          }
          break;


        case FAMILY_MESSAGING:
          switch(subtype)
          {
            case MSG_TO_CLIENT:
              buddyname_length = get_buddyname( buddyname, tvb, 26, 27 );

              get_message( msg, tvb, 36 + buddyname_length, tvb_length(tvb) - 36 - buddyname_length );

              if (check_col(pinfo->cinfo, COL_INFO)) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "Message ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "to: %s", buddyname);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
              }

              if( tree )
              {
                proto_tree_add_text(aim_tree_fnac, tvb, 27, buddyname_length, "Screen Name: %s", buddyname);
              }

              break;

            case MSG_FROM_CLIENT:
              buddyname_length = get_buddyname( buddyname, tvb, 26, 27 );

              get_message( msg, tvb, 36 + buddyname_length,  tvb_length(tvb) - 36 - buddyname_length);

              if (check_col(pinfo->cinfo, COL_INFO)) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "Message");
                col_append_fstr(pinfo->cinfo, COL_INFO, " from: %s", buddyname);

                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
              }

              if( tree )
              {
                proto_tree_add_text(aim_tree_fnac, tvb, 27, buddyname_length, "Screen Name: %s", buddyname);
              }
              break;
          }

          break;
      }



      break;

    case CHANNEL_FLAP_ERR:
      if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "FLAP error");
      }
      break;

    case CHANNEL_CLOSE_CONN:
      if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Close Connection");
      }
      break;

    default:
      if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Channel: %d", hdr_channel );
      }
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

static void dissect_aim_signon_reply(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  guint16 challenge_length = 0;

  /* Logon Challenge Length */
  challenge_length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_aim_signon_challenge_len, tvb, offset, 2, FALSE);
  offset += 2;

  /* Challenge */
  proto_tree_add_item(tree, hf_aim_signon_challenge, tvb, offset, challenge_length, FALSE);
  offset += challenge_length;
}

static void dissect_aim_request_user_information(tvbuff_t *tvb, int offset, proto_tree *tree)
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
}

static void dissect_aim_user_information(tvbuff_t *tvb, int offset, proto_tree *tree)
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
    { &hf_aim_signon_challenge_len,
      { "Signon challenge length", "aim.signon.challengelen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_signon_challenge,
      { "Signon challenge", "aim.signon.challenge", FT_STRING, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_family,
      { "FNAC Family ID", "aim.fnac.family", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype,
      { "FNAC Subtype ID", "aim.fnac.subtype", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
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
