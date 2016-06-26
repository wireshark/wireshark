/* packet-sametime.c
 * Routines for SAMETIME dissection
 * Copyright 2010, Toralf Foerster <toralf.foerster [AT] gmx.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/stats_tree.h>
#include "packet-tcp.h"

#define DEFAULT_SAMETIME_PORT 1533

void proto_register_sametime(void);
void proto_reg_handoff_sametime(void);

static int proto_sametime = -1;
static guint global_sametime_port = DEFAULT_SAMETIME_PORT;
static dissector_handle_t sametime_handle;

/*preferences*/
static gboolean global_sametime_show_length = FALSE;
static gboolean global_sametime_reassemble_packets = TRUE;

/*heart beat*/
static int hf_sametime_heartbeat = -1;

/*sametime message header*/
static int hf_sametime_message_length = -1;
static int hf_sametime_message_type = -1;
static int hf_sametime_message_options = -1;
static int hf_sametime_message_options_attribute = -1;
static int hf_sametime_message_options_encrypted = -1;
static int hf_sametime_message_channel = -1;

/*common types*/
static int hf_sametime_field_length = -1;
static int hf_sametime_field_text = -1;
static int hf_sametime_code = -1;
static int hf_sametime_login_type = -1;
static int hf_sametime_time = -1;

/*handshake*/
static int hf_sametime_handshake_major = -1;
static int hf_sametime_handshake_minor = -1;
static int hf_sametime_handshake_srvrcalc_addr = -1;
static int hf_sametime_handshake_loclcalc_addr = -1;

/*channel*/
static int hf_sametime_channel_service = -1;
static int hf_sametime_channel_id = -1;
static int hf_sametime_channel_send_type = -1;
static int hf_sametime_channel_awareness = -1;

/*user status*/
static int hf_sametime_user_status = -1;

/*location*/
static int hf_sametime_location_country = -1;
static int hf_sametime_location_postalcode = -1;
static int hf_sametime_location_province = -1;
static int hf_sametime_location_city = -1;
static int hf_sametime_location_phone = -1;
static int hf_sametime_location_name = -1;
static int hf_sametime_location_timezone = -1;

/*packet detail tree*/
static gint ett_sametime = -1;
static gint ett_sametime_options = -1;

/*statistics*/
static int sametime_tap = -1;
static const guint8* st_str_packet = "Sametime Message Count";
static const guint8* st_str_message_type = "Message Type";
static const guint8* st_str_send_type = "Send Type";
static const guint8* st_str_user_status = "User Status";
static int st_node_packet = -1;
static int st_node_message_type = -1;
static int st_node_send_type = -1;
static int st_node_user_status = -1;

typedef struct SametimeTap {
   gint message_type;
   gint send_type;
   gint user_status;
} SametimeTap;

#define SAMETIME_MESSAGETYPE_HEARTBEAT        0x80
#define SAMETIME_MESSAGETYPE_HANDSHAKE        0x0000

#define SAMETIME_MESSAGETYPE_HANDSHAKE_ACK    0x8000
#define SAMETIME_MESSAGETYPE_HANDSHAKE_SYN    0x0025
#define SAMETIME_MESSAGETYPE_LOGIN            0x0001
#define SAMETIME_MESSAGETYPE_LOGIN_ACK        0x8001
#define SAMETIME_MESSAGETYPE_LOGIN_REDIRECT   0x0018
#define SAMETIME_MESSAGETYPE_LOGIN_CONTINUE   0x0016

#define SAMETIME_MESSAGETYPE_CHANNEL_CREATE   0x0002
#define SAMETIME_MESSAGETYPE_CHANNEL_DESTROY  0x0003
#define SAMETIME_MESSAGETYPE_CHANNEL_SEND     0x0004
#define SAMETIME_MESSAGETYPE_CHANNEL_ACCEPT   0x0006

#define SAMETIME_MESSAGETYPE_SET_USER_STATUS  0x0009
#define SAMETIME_MESSAGETYPE_SET_PRIVACY_LIST 0x000b
#define SAMETIME_MESSAGETYPE_SENSE_SERVICE    0x0011
#define SAMETIME_MESSAGETYPE_ADMIN            0x0019
#define SAMETIME_MESSAGETYPE_ANNOUNCE         0x0022


static const value_string messagetypenames[] = {
   {  SAMETIME_MESSAGETYPE_HEARTBEAT,        "HEARTBEAT" },

   {  SAMETIME_MESSAGETYPE_HANDSHAKE,        "HANDSHAKE" },
   {  SAMETIME_MESSAGETYPE_HANDSHAKE_SYN,    "HANDSHAKE_SYN" },
   {  SAMETIME_MESSAGETYPE_HANDSHAKE_ACK,    "HANDSHAKE_ACK" },
   {  SAMETIME_MESSAGETYPE_LOGIN,            "LOGIN" },
   {  SAMETIME_MESSAGETYPE_LOGIN_ACK,        "LOGIN_ACK" },
   {  SAMETIME_MESSAGETYPE_LOGIN_REDIRECT,   "LOGIN_REDIRECT" },
   {  SAMETIME_MESSAGETYPE_LOGIN_CONTINUE,   "LOGIN_CONTINUE" },

   {  SAMETIME_MESSAGETYPE_CHANNEL_CREATE,   "CHANNEL_CREATE" },
   {  SAMETIME_MESSAGETYPE_CHANNEL_DESTROY,  "CHANNEL_DESTROY" },
   {  SAMETIME_MESSAGETYPE_CHANNEL_SEND,     "CHANNEL_SEND" },
   {  SAMETIME_MESSAGETYPE_CHANNEL_ACCEPT,   "CHANNEL_ACCEPT" },

   {  SAMETIME_MESSAGETYPE_SET_USER_STATUS,  "SET_USER_STATUS" },
   {  SAMETIME_MESSAGETYPE_SET_PRIVACY_LIST, "SET_PRIVACY_LIST" },
   {  SAMETIME_MESSAGETYPE_SENSE_SERVICE,    "SENSE_SERVICE" },
   {  SAMETIME_MESSAGETYPE_ADMIN,            "ADMIN" },
   {  SAMETIME_MESSAGETYPE_ANNOUNCE,         "ANNOUNCE" },

   { 0, NULL }
};

#define SAMETIME_MESSAGEOPTION_ENCRYPT     0x4000
#define SAMETIME_MESSAGEOPTION_HAS_ATTRIBS 0x8000

static const value_string optionnames[] = {
   {  0x0,                                "" },
   {  SAMETIME_MESSAGEOPTION_ENCRYPT,     "ENCRYPT" },
   {  SAMETIME_MESSAGEOPTION_HAS_ATTRIBS, "HAS_ATTRIBS" },

   { 0, NULL }
};

static const value_string userstatusnames[] = {
   { 0x0020, "ACTIVE" },  /* "I am available" */
   { 0x0040, "IDLE" },    /* never seen in the wild, maybe non-pc :-) ? */
   { 0x0060, "AWAY" },    /* "I am away from my computer now" */
   { 0x0080, "BUSY" },    /* "Please do not disturb me" */
   { 0x0008, "MEETING" }, /* "I am in a meeting" */

   { 0, NULL }
};

#define SAMETIME_SENDTYPE_AWARE_ADD      0x0068
#define SAMETIME_SENDTYPE_OPT_DO_SET     0x00c9
#define SAMETIME_SENDTYPE_AWARE_SNAPSHOT 0x01f4
#define SAMETIME_SENDTYPE_AWARE_UPDATE   0x01f5
#define SAMETIME_SENDTYPE_OPT_GOT_SET    0x0259

static const value_string sendtypenames[] = {
   { SAMETIME_SENDTYPE_AWARE_ADD,      "AWARE_ADD" },
   { 0x0069,                           "AWARE_REMOVE" },
   { SAMETIME_SENDTYPE_OPT_DO_SET,     "OPT_DO_SET" },
   { 0x00cb,                           "OPT_WATCH" },
   { SAMETIME_SENDTYPE_AWARE_SNAPSHOT, "AWARE_SNAPSHOT" },
   { SAMETIME_SENDTYPE_AWARE_UPDATE,   "AWARE_UPDATE" },
   { SAMETIME_SENDTYPE_OPT_GOT_SET,    "OPT_GOT_SET" },
   { 0x025a,                           "?" },
   { 0x025d,                           "OPT_DID_SET" },

   { 0, NULL }
};

static const value_string awarenessnames[] = {
   { 0x0002, "USER" },
   { 0x0003, "GROUP" },
   { 0x0008, "SERVER" },
   { 0, NULL }
};

static const value_string codenames[] = {
   { 0x00000011, "SERVICE_AWARE" },
   { 0x00000015, "SERVICE_RESOLVE" },
   { 0x00000018, "SERVICE_STORAGE" },
   { 0x0000001a, "SERVICE_DIRECTORY" },

   { 0x80000011, "ERR_USER_SKETCHY" },
   { 0x80000015, "ERR_TOKEN_INVALID" },
   { 0x80000018, "ERR_PORT_IN_USE" },
   { 0x80000022, "ERR_CHANNEL_DESTROYED" },

   { 0, NULL }
};


static int
add_text_item(tvbuff_t *tvb, proto_tree *tree, int offset, int hf)
{
   guint16 length;

   /* heuristic rule, string should start w/ valid character(s) */
   if (! tvb_get_guint8(tvb, offset + 2))
      return 0;

   length = tvb_get_ntohs(tvb, offset);
   if (length)        {
      /* the string length must not exceed the packet length */
      if (length > tvb_reported_length_remaining(tvb, offset + 2))
         return 0;

      /* add string length only if preferences is set */
      if (global_sametime_show_length)
         proto_tree_add_item(tree, hf_sametime_field_length, tvb, offset, 2, ENC_BIG_ENDIAN);

      /* add string */
      proto_tree_add_item(tree, hf, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
   }

   return 2 + length;
}


static guint16
dissect_set_user_status(tvbuff_t *tvb, proto_tree *tree, int offset)
{
   guint16 user_status;

   user_status = tvb_get_ntohs(tvb, offset);
   proto_item_append_text(tree, ", %s", val_to_str(user_status, userstatusnames, "0x%04x"));
   proto_tree_add_item(tree, hf_sametime_user_status, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;
   proto_tree_add_item(tree, hf_sametime_time, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;
   add_text_item(tvb, tree, offset, hf_sametime_field_text);

   return user_status;
}


static int
dissect_handshake(tvbuff_t *tvb, proto_tree *tree, int offset)
{
   proto_tree_add_item(tree, hf_sametime_handshake_major, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;
   proto_tree_add_item(tree, hf_sametime_handshake_minor, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;
   offset += 4;
   proto_tree_add_item(tree, hf_sametime_handshake_srvrcalc_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;
   proto_tree_add_item(tree, hf_sametime_login_type, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;
   proto_tree_add_item(tree, hf_sametime_handshake_loclcalc_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;
   offset += 6;
   offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
   offset += 8;
   offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);

   return offset;
}


static void
dissect_handshake_ack(tvbuff_t *tvb, proto_tree *tree, int offset)
{
   proto_tree_add_item(tree, hf_sametime_handshake_major, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;
   proto_tree_add_item(tree, hf_sametime_handshake_minor, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;
   proto_tree_add_item(tree, hf_sametime_handshake_loclcalc_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;
   offset += 4;
   offset += 4;
   add_text_item(tvb, tree, offset, hf_sametime_field_text);
}


static void
dissect_login(tvbuff_t *tvb, proto_tree *tree, int offset)
{
   offset += 2;
   add_text_item(tvb, tree, offset, hf_sametime_field_text);
}


static void
dissect_login_redirect(tvbuff_t *tvb, proto_tree *tree, int offset)
{
   offset += 2;
   add_text_item(tvb, tree, offset, hf_sametime_field_text);
}


static void
dissect_login_ack(tvbuff_t *tvb, proto_tree *tree, int offset)
{
   offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
   proto_tree_add_item(tree, hf_sametime_login_type, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;
   offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
   offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
   offset += 3;
   offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
   proto_tree_add_item(tree, hf_sametime_handshake_loclcalc_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;
   offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
   offset += 21;
   offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
   add_text_item(tvb, tree, offset, hf_sametime_field_text);
}


static void
dissect_channel_create(tvbuff_t *tvb, proto_tree *tree, int offset)
{
   offset += 4;
   proto_tree_add_item(tree, hf_sametime_channel_id, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;
   offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
   proto_tree_add_item(tree, hf_sametime_channel_service, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;
   offset += 8;
   add_text_item(tvb, tree, offset, hf_sametime_field_text);
}


static guint16
dissect_channel_send(tvbuff_t *tvb, proto_tree *tree, int offset)
{
   guint16 send_type, awareness;
   guint na;

   send_type = tvb_get_ntohs(tvb, offset);
   proto_item_append_text(tree, ", %s", val_to_str(send_type, sendtypenames, "0x%04x"));
   proto_tree_add_item(tree, hf_sametime_channel_send_type, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   switch (send_type)        {
      case SAMETIME_SENDTYPE_AWARE_ADD:
         offset += 8;
         awareness = tvb_get_ntohs(tvb, offset);
         proto_item_append_text(tree, ", %s", val_to_str(awareness, awarenessnames, "0x%04x"));
         proto_tree_add_item(tree, hf_sametime_channel_awareness, tvb, offset, 2, ENC_BIG_ENDIAN);
         offset += 2;
         add_text_item(tvb, tree, offset, hf_sametime_field_text);

         break;

      case SAMETIME_SENDTYPE_OPT_DO_SET:
         offset += 20;
         na = tvb_get_ntohl(tvb, offset);
         offset += 4;
         if (na == 0x33)        {
            offset += add_text_item(tvb, tree, offset, hf_sametime_location_country);
            offset += add_text_item(tvb, tree, offset, hf_sametime_location_postalcode);
            offset += add_text_item(tvb, tree, offset, hf_sametime_location_province);
            offset += add_text_item(tvb, tree, offset, hf_sametime_location_city);
            offset += add_text_item(tvb, tree, offset, hf_sametime_location_phone);
            offset += 1;
            offset += add_text_item(tvb, tree, offset, hf_sametime_location_name);
            add_text_item(tvb, tree, offset, hf_sametime_location_timezone);
         } else        {
            add_text_item(tvb, tree, offset, hf_sametime_field_text);
         }

         break;

      case SAMETIME_SENDTYPE_OPT_GOT_SET:
         offset += 8;
         awareness = tvb_get_ntohs(tvb, offset);
         proto_item_append_text(tree, ", %s", val_to_str(awareness, awarenessnames, "0x%04x"));
         proto_tree_add_item(tree, hf_sametime_channel_awareness, tvb, offset, 2, ENC_BIG_ENDIAN);
         offset += 2;
         while (tvb_reported_length_remaining(tvb, offset) > 2)        {
            int n = add_text_item(tvb, tree, offset, hf_sametime_field_text);
            offset += (n) ? n : 1;
         }

         break;

      case SAMETIME_SENDTYPE_AWARE_SNAPSHOT:
         offset += 12;
         awareness = tvb_get_ntohs(tvb, offset);
         proto_item_append_text(tree, ", %s", val_to_str(awareness, awarenessnames, "0x%04x"));
         proto_tree_add_item(tree, hf_sametime_channel_awareness, tvb, offset, 2, ENC_BIG_ENDIAN);
         offset += 2;
         add_text_item(tvb, tree, offset, hf_sametime_field_text);

         break;

      case SAMETIME_SENDTYPE_AWARE_UPDATE:
         offset += 4;
         offset += 4;
         awareness = tvb_get_ntohs(tvb, offset);
         proto_item_append_text(tree, ", %s", val_to_str(awareness, awarenessnames, "0x%04x"));
         proto_tree_add_item(tree, hf_sametime_channel_awareness, tvb, offset, 2, ENC_BIG_ENDIAN);
         offset += 2;
         offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
         offset += 4;
         if (tvb_get_guint8(tvb, offset))        {
            offset += 1;
            offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
            dissect_set_user_status(tvb, tree, offset);
         }

         break;

      case 0x0000:
         offset += 14;
         add_text_item(tvb, tree, offset, hf_sametime_field_text);

         break;

      case 0x0002:
         offset += 8;
         offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
         offset += 3;
         add_text_item(tvb, tree, offset, hf_sametime_field_text);

         break;

      case 0x0005:        /* XML */
         if (26 <= tvb_reported_length_remaining(tvb, offset + 2))        {
            offset += 26;
            add_text_item(tvb, tree, offset, hf_sametime_field_text);
         }

         break;

      case 0x0007:
         offset += 8;
         if (4 <= tvb_reported_length_remaining(tvb, offset + 2))        {
            offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
            offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
            offset += 3;
            offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
            add_text_item(tvb, tree, offset, hf_sametime_field_text);
         }

         break;

      case 0x025a:
         offset += 10;
         add_text_item(tvb, tree, offset, hf_sametime_field_text);

         break;

      default:
         break;
   }

   return send_type;
}


static void
dissect_channel_accept(tvbuff_t *tvb, proto_tree *tree, int offset)
{
   offset += 34;
   if (tvb_reported_length_remaining(tvb, offset + 2))        {
      offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
      if (tvb_get_guint8(tvb, offset))        {
         offset += 1;
         offset += add_text_item(tvb, tree, offset, hf_sametime_field_text);
         dissect_set_user_status(tvb, tree, offset);
      }
   }
}


static void
dissect_sense_service(tvbuff_t *tvb, proto_tree *tree, int offset)
{
   guint32 code;

   code = tvb_get_ntohl(tvb, offset);
   proto_item_append_text(tree, ", %s", val_to_str(code, codenames, "0x%04x"));
   proto_tree_add_item(tree, hf_sametime_code, tvb, offset, 4, ENC_BIG_ENDIAN);
}


/*
        here we really dissect the message(s)
*/
static int
dissect_sametime_content(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   proto_tree *sametime_tree;
   proto_item *ti;
   static SametimeTap *sinfo;
   gint message_type;
   int packet_length, offset = 0;

   /* we expect either 1 heartbeat byte (0x80) or a sametime message */
   packet_length = tvb_reported_length_remaining(tvb, offset);
   if (packet_length == 1)        {
      message_type = tvb_get_guint8(tvb, 0);

   } else if (packet_length < 12)        {
      message_type = -1;

   } else        {
      message_type = tvb_get_ntohs(tvb, 4);
   }

   /* add message type */
   col_append_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, messagetypenames, "0x%04x"));
   col_append_str(pinfo->cinfo, COL_INFO, " ");

   /* message type statistic */
   sinfo = wmem_new(wmem_packet_scope(), struct SametimeTap);
   sinfo->message_type = message_type;
   sinfo->send_type = -1;
   sinfo->user_status = -1;

   /* packet detail tree */
   ti = proto_tree_add_item(tree, proto_sametime, tvb, offset, -1, ENC_NA);
   sametime_tree = proto_item_add_subtree(ti, ett_sametime);
   proto_item_append_text(sametime_tree, ", %s", val_to_str(message_type, messagetypenames, "0x%04x"));

   /* dissect message */
   if (message_type == SAMETIME_MESSAGETYPE_HEARTBEAT)        {
      proto_tree_add_item(sametime_tree, hf_sametime_heartbeat, tvb, offset, 1, ENC_BIG_ENDIAN);

   } else if (message_type != -1) {
      proto_tree *options_tree;
      proto_item *op;

      /* first 4 bytes gives the length of the sametime message */
      if (global_sametime_show_length)        {
         proto_tree_add_item(sametime_tree, hf_sametime_message_length, tvb, offset, 4, ENC_BIG_ENDIAN);
      }
      offset += 4;

      /* next 2 bytes gives the message type */
      proto_tree_add_item(sametime_tree, hf_sametime_message_type, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      /* next 2 bytes are the message options */
      op = proto_tree_add_item(sametime_tree, hf_sametime_message_options, tvb, offset, 2, ENC_BIG_ENDIAN);
      options_tree = proto_item_add_subtree(op, ett_sametime_options);
      proto_tree_add_item(options_tree, hf_sametime_message_options_attribute, tvb, offset, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(options_tree, hf_sametime_message_options_encrypted, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      /* next 4 bytes contains the channel id */
      proto_tree_add_item(sametime_tree, hf_sametime_message_channel, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      switch (message_type)
      {
         case SAMETIME_MESSAGETYPE_HANDSHAKE:
            dissect_handshake(tvb, sametime_tree, offset);
            break;

         case SAMETIME_MESSAGETYPE_HANDSHAKE_ACK:
            dissect_handshake_ack(tvb, sametime_tree, offset);
            break;

         case SAMETIME_MESSAGETYPE_HANDSHAKE_SYN:
            break;

         case SAMETIME_MESSAGETYPE_LOGIN:
            dissect_login(tvb, sametime_tree, offset);
            break;

         case SAMETIME_MESSAGETYPE_LOGIN_REDIRECT:
            dissect_login_redirect(tvb, sametime_tree, offset);
            break;

         case SAMETIME_MESSAGETYPE_LOGIN_ACK:
            dissect_login_ack(tvb, sametime_tree, offset);
            break;

         case SAMETIME_MESSAGETYPE_CHANNEL_CREATE:
            dissect_channel_create(tvb, sametime_tree, offset);
            break;

         case SAMETIME_MESSAGETYPE_CHANNEL_SEND:
            sinfo->send_type = dissect_channel_send(tvb, sametime_tree, offset);
            break;

         case SAMETIME_MESSAGETYPE_CHANNEL_ACCEPT:
            dissect_channel_accept(tvb, sametime_tree, offset);
            break;

         case SAMETIME_MESSAGETYPE_SET_USER_STATUS:
            sinfo->user_status = dissect_set_user_status(tvb, sametime_tree, offset);
            break;

         case SAMETIME_MESSAGETYPE_SENSE_SERVICE:
            dissect_sense_service(tvb, sametime_tree, offset);
            break;

         default:
            /* do not fill the statistics with useless data from encrypted packages */
            sinfo->message_type = -1;
            break;
      }
   }

   tap_queue_packet(sametime_tap, pinfo, sinfo);
   return tvb_captured_length(tvb);
}


/*
        tick statistics
*/
static int
sametime_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p)
{
   const struct SametimeTap *pi = (const struct SametimeTap *)p;

   tick_stat_node(st, st_str_packet, 0, FALSE);
   if (pi->message_type != -1)
      stats_tree_tick_pivot(st, st_node_message_type, val_to_str(pi->message_type, messagetypenames, "Unknown (0x%04x)"));

   if (pi->send_type != -1)
      stats_tree_tick_pivot(st, st_node_send_type, val_to_str(pi->send_type, sendtypenames, "Unknown (0x%04x)"));

   if (pi->user_status != -1)
      stats_tree_tick_pivot(st, st_node_user_status, val_to_str(pi->user_status, userstatusnames, "Unknown (0x%04x)"));

   return 1;
}


/*
        init statistic
*/
static void
sametime_stats_tree_init(stats_tree* st)
{
   st_node_packet = stats_tree_create_node(st, st_str_packet, 0, TRUE);
   st_node_message_type = stats_tree_create_pivot(st, st_str_message_type, st_node_packet);
   st_node_send_type = stats_tree_create_pivot(st, st_str_send_type, st_node_packet);
   st_node_user_status = stats_tree_create_pivot(st, st_str_user_status, st_node_packet);
}


/*
        length of the sametime message
*/
static guint
get_sametime_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                         int offset, void *data _U_)
{
   /* XXX: Actually: the length of the tvb will always be 4 or greater at this point */
   /*      because tcp_dissect_pdus was called with 4 as a required "fixed length".  */
   /*        But newer variants of this protocol with a full encrypted network stream  */
   /*        may require a more sophisticated dissection logic here                    */
   guint32 N = tvb_captured_length_remaining(tvb, offset);

   return (N < 4) ? N : tvb_get_ntohl(tvb, offset) + 4;
}


/*
        the dissector itself
*/
static int
dissect_sametime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "SAMETIME");
   col_clear(pinfo->cinfo,COL_INFO);

   tcp_dissect_pdus(tvb, pinfo, tree, global_sametime_reassemble_packets, 4,
         get_sametime_message_len, dissect_sametime_content, data);
   return tvb_captured_length(tvb);
}


void
proto_register_sametime(void)
{
   static hf_register_info hf[] = {
      /*tcp payload is one byte : SAMETIME_MESSAGETYPE_HEARTBEAT*/
      { &hf_sametime_heartbeat,
         { "heartbeat", "sametime.heartbeat",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
      },

      /*sametime message header*/
      { &hf_sametime_message_length,
         { "msg length", "sametime.message_length",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
      },
      { &hf_sametime_message_type,
         { "msg type", "sametime.message_type",
            FT_UINT16, BASE_HEX,
            VALS(messagetypenames), 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_message_options,
         { "msg options", "sametime.message_options",
            FT_UINT16, BASE_HEX,
            VALS(optionnames), 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_message_options_encrypted,
         { "ENCRYPT", "sametime.message_options.encrypted",
            FT_BOOLEAN, 16,
            NULL, SAMETIME_MESSAGEOPTION_ENCRYPT,
            NULL, HFILL }
      },
      { &hf_sametime_message_options_attribute,
         { "HAS_ATTRIBS", "sametime.message_options.attribute",
            FT_BOOLEAN, 16,
            NULL, SAMETIME_MESSAGEOPTION_HAS_ATTRIBS,
            NULL, HFILL }
      },
      { &hf_sametime_message_channel,
         { "msg channel", "sametime.message_channel",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
      },

      /*common fields within various message types*/
      { &hf_sametime_field_length,
         { "length", "sametime.field_length",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
      },
      { &hf_sametime_field_text,
         { "text", "sametime.field_text",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_code,
         { "code", "sametime.code",
            FT_UINT32, BASE_HEX,
            VALS(codenames), 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_login_type,
         { "login type", "sametime.login_type",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_time,
         { "time", "sametime.time",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
      },

      /*type handshake*/
      { &hf_sametime_handshake_major,
         { "major", "sametime.handshake.major",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_handshake_minor,
         { "minor", "sametime.handshake.minor",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_handshake_srvrcalc_addr,
         { "srvr", "sametime.handshake.srvrcalc_addr",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_handshake_loclcalc_addr,
         { "locl", "sametime.handshake.loclcalc_addr",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
      },

      /*type channel*/
      { &hf_sametime_channel_service,
         { "service id", "sametime.channel.service",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
      },
      { &hf_sametime_channel_id,
         { "channel id", "sametime.channel.id",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
      },
      { &hf_sametime_channel_send_type,
         { "send type", "sametime.channel.send_type",
            FT_UINT16, BASE_HEX,
            VALS(sendtypenames), 0,
            NULL, HFILL }
      },
      { &hf_sametime_channel_awareness,
         { "awareness", "sametime.channel.awareness",
            FT_UINT16, BASE_HEX,
            VALS(awarenessnames), 0x0,
            NULL, HFILL }
      },

      /*type user status*/
      { &hf_sametime_user_status,
         { "user status", "sametime.user_status_type",
            FT_UINT16, BASE_HEX,
            VALS(userstatusnames), 0x0,
            NULL, HFILL }
      },

      /*type location*/
      { &hf_sametime_location_name,
         { "name", "sametime.location.name",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_location_city,
         { "city", "sametime.location.city",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_location_province,
         { "province", "sametime.location.province",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_location_postalcode,
         { "postal code", "sametime.location.postalcode",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_location_country,
         { "country", "sametime.location.country",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_location_phone,
         { "phone", "sametime.location.phone",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_sametime_location_timezone,
         { "time zone", "sametime.location.timezone",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
      },
   };

   static gint *ett[] = {
      &ett_sametime,
      &ett_sametime_options
   };

   module_t *sametime_module;

   proto_sametime = proto_register_protocol (
         "Sametime Protocol", /* name */
         "SAMETIME",          /* short name */
         "sametime"           /* abbrev */
         );
   proto_register_field_array(proto_sametime, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   sametime_tap = register_tap("sametime");

   /* Preference setting */
   sametime_module = prefs_register_protocol(proto_sametime, NULL);
   prefs_register_bool_preference(sametime_module, "show_length",
         "Show length",
         "Show length of text field",
         &global_sametime_show_length);
   prefs_register_bool_preference(sametime_module, "reassemble",
         "Reassemble","reassemble packets",
         &global_sametime_reassemble_packets);
   prefs_register_uint_preference(sametime_module, "tcp_port",
         "SAMETIME port number",
         "port number for sametime traffic",
         10, &global_sametime_port);
}


/*
        create / register
*/
void
proto_reg_handoff_sametime(void)
{
   static gboolean initialized = FALSE;
   static guint saved_sametime_tcp_port;

   if (!initialized) {
      sametime_handle = create_dissector_handle(dissect_sametime, proto_sametime);
      stats_tree_register("sametime", "sametime", "Sametime/Messages", 0,
            sametime_stats_tree_packet,
            sametime_stats_tree_init, NULL );
      initialized = TRUE;
   } else {
      dissector_delete_uint("tcp.port", saved_sametime_tcp_port, sametime_handle);
   }

   dissector_add_uint("tcp.port", global_sametime_port, sametime_handle);
   saved_sametime_tcp_port = global_sametime_port;
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
