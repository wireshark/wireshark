/* packet-unistim.c
  * Routines for unistim packet dissection
  * Copyright 2007 Don Newton <dnewton@cypresscom.net>
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
#include <epan/tap.h>
#include <epan/emem.h>
#include <epan/expert.h>
#include <epan/address.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/dissectors/packet-rtcp.h>
#include <string.h>
#include "packet-unistim.h"
#include "defines.h"
#include "audio.h"
#include "basic.h"
#include "display.h"
#include "network.h"
#include "key.h"
#include "broadcast.h"
#include "uftp.h"
#include "expansion.h"

/* Don't set this to 5000 until this dissector is made a heuristic one!
   It collides (at least) with tapa.
   static guint global_unistim_port = 5000; */
static guint global_unistim_port = 0;

static unistim_info_t *uinfo;
static int unistim_tap = -1;

void proto_reg_handoff_unistim(void);
static void dissect_payload(proto_tree *unistim_tree,tvbuff_t *tvb,gint offset, packet_info *pinfo);
static int dissect_unistim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint dissect_broadcast_switch(proto_tree *msg_tree,
                                     tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_audio_switch(proto_tree *msg_tree,packet_info *pinfo,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_expansion_switch(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_display_switch(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_key_indicator_switch(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_basic_switch(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_network_switch(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_broadcast_phone(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_audio_phone(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_expansion_phone(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_display_phone(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_key_indicator_phone(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_basic_phone(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_network_phone(proto_tree *msg_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static gint dissect_unistim_message(proto_tree *unistim_tree, packet_info *pinfo,
                                   tvbuff_t *tvb,gint offset);
static gint dissect_uftp_message(proto_tree *unistim_tree, packet_info *pinfo,
                                   tvbuff_t *tvb,gint offset);


static void set_ascii_item(proto_tree *unistim_tree, tvbuff_t *tvb,
                           gint offset,guint msg_len);


static int proto_unistim = -1;
static int hf_unistim_seq_nu = -1;
static int hf_unistim_packet_type = -1;
static int hf_unistim_payload = -1;
static int hf_unistim_cmd_add = -1;
static int hf_unistim_len =-1;
static int hf_terminal_id=-1;
static int hf_basic_bit_field=-1;
static const true_false_string basic_bit_yn={
   "For Following Byte",
   "For Following Byte"
};

static int hf_basic_switch_cmd=-1;
static int hf_basic_phone_cmd=-1;
static int hf_broadcast_switch_cmd=-1;
static int hf_broadcast_phone_cmd=-1;
static int hf_audio_switch_cmd=-1;
static int hf_audio_phone_cmd=-1;
static int hf_display_switch_cmd=-1;
static int hf_display_phone_cmd=-1;
static int hf_key_switch_cmd=-1;
static int hf_key_phone_cmd=-1;
static int hf_network_switch_cmd=-1;
static int hf_network_phone_cmd=-1;
static int hf_expansion_switch_cmd=-1;
static int hf_expansion_phone_cmd=-1;

static int hf_generic_data=-1;
static int hf_generic_string=-1;

static gint ett_unistim = -1;

static const value_string packet_names[]={
   {0,"NAK"},
   {1,"ACK"},
   {2,"Payload"},
   {0,NULL}
};

static const value_string payload_names[]={
   {0x00,"NULL Protocol"},
   {0x01,"Aggregate Unistim"},
   {0x02,"Aggregate Unistim with Terminal ID"},
   {0x03,"UFTP"},
   {0xff,"Free Form Protocol"},
   {0,NULL}
};

static const range_string sequence_numbers[]={
   {0x00,0xFFFFFFFE,"Normal Sequence Number"},
   {0xFFFFFFFF,0xFFFFFFFF, "RESET Sequence Number"},
   {0,0,NULL}
};

static const value_string command_address[]={
   {0x09,"Expansion Module-1 Manager Switch"},
   {0x0A,"Expansion Module-2 Manager Switch"},
   {0x0B,"Expansion Module-3 Manager Switch"},
   {0x0C,"Expansion Module-4 Manager Switch"},
   {0x0D,"Expansion Module-5 Manager Switch"},
   {0x0E,"Expansion Module-6 Manager Switch"},
   {0x10,"Expansion Module Manager Phone"},
   {0x11,"Broadcast Manager Switch"},
   {0x16,"Audio Manager Switch"},
   {0x17,"Display Manager Switch"},
   {0x19,"Key/Indicator Manager Switch"},
   {0x1a,"Basic Manager Switch"},
   {0x1e,"Network Manager Switch"},
   {0x89,"Expansion Module-1 Manager Phone"},
   {0x8A,"Expansion Module-2 Manager Phone"},
   {0x8B,"Expansion Module-3 Manager Phone"},
   {0x8C,"Expansion Module-4 Manager Phone"},
   {0x8D,"Expansion Module-5 Manager Phone"},
   {0x8E,"Expansion Module-6 Manager Phone"},
   {0x91,"Broadcast Manager Phone"},
   {0x96,"Audio Manager Phone"},
   {0x97,"Display Manager Phone"},
   {0x99,"Key/Indicator Manager Phone"},
   {0x9a,"Basic Manager Phone"},
   {0x9e,"Network Manager Phone"},
   {0,NULL}
};

static int
dissect_unistim(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree){
   gint offset=0;
   proto_item *ti= NULL;
   proto_item *ti1= NULL;
   proto_tree *overall_unistim_tree = NULL;
   proto_tree *rudpm_tree=NULL;
   gint size;

   /* heuristic*/
   switch(tvb_get_guint8(tvb,offset+4)) {/*rudp packet type 0,1,2 only */
      case 0x0:/*NAK*/
      case 0x1:/*ACK*/
         break;
      case 0x2:/*PAYLOAD*/
         switch(tvb_get_guint8(tvb,offset+5)){/*payload type 0,1,2,3,ff only */
            case 0x0: /*NULL*/
            case 0x1: /*UNISTIM*/
            case 0x2: /*UNISTIM WITH TERM ID*/
            case 0x3: /*UFTP*/
            case 0xff:/*UNKNOWN BUT VALID*/
               break;
            default:
               return 0;
         }
         break;
      default:
         return 0;
   }


   size=tvb_length_remaining(tvb, offset);
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNISTIM");
   /* Clear out stuff in the info column */
   col_clear(pinfo->cinfo, COL_INFO);
   ti = proto_tree_add_item(tree,proto_unistim,tvb,offset,-1,FALSE);
   overall_unistim_tree = proto_item_add_subtree(ti,ett_unistim);
   ti1=proto_tree_add_text(overall_unistim_tree,tvb,offset,5,"Reliable UDP");
   rudpm_tree=proto_item_add_subtree(ti1,ett_unistim);

   proto_tree_add_item(rudpm_tree,hf_unistim_seq_nu,tvb,offset,4,ENC_BIG_ENDIAN);

   /* Allocate new mem for queueing */
   uinfo = (unistim_info_t *)se_alloc(sizeof(unistim_info_t));

   /* Clear tap struct */
   uinfo->rudp_type = 0;
   uinfo->payload_type = 0;
   uinfo->sequence = tvb_get_ntohl(tvb,offset);
   uinfo->termid = 0;
   uinfo->key_val = -1;
   uinfo->key_state = -1;
   uinfo->hook_state = -1;
   uinfo->stream_connect = -1;
   uinfo->trans_connect = -1;
   uinfo->set_termid = -1;
   uinfo->string_data = NULL;
   uinfo->key_buffer = NULL;
   SET_ADDRESS(&uinfo->it_ip, AT_NONE, 0, NULL);
   SET_ADDRESS(&uinfo->ni_ip, AT_NONE, 0, NULL);
   uinfo->it_port = 0;

   offset+=4;
   proto_tree_add_item(rudpm_tree,hf_unistim_packet_type,tvb,offset,1,ENC_BIG_ENDIAN);
   uinfo->rudp_type = tvb_get_guint8(tvb,offset);

   switch(tvb_get_guint8(tvb,offset)) {
      case 0x00:
         /*NAK*/
         col_add_fstr(pinfo->cinfo, COL_INFO, "NAK for seq -   0x%X",
                      tvb_get_ntohl(tvb, offset-4));
         break;
      case 0x01:
         /*ACK*/
         col_add_fstr(pinfo->cinfo, COL_INFO, "ACK for seq -   0x%X",
                      tvb_get_ntohl(tvb, offset-4));
         break;
      case 0x02:
         col_add_fstr(pinfo->cinfo, COL_INFO, "Payload seq -   0x%X",
                      tvb_get_ntohl(tvb, offset-4));
         offset+=1;
         dissect_payload(overall_unistim_tree,tvb,offset,pinfo);
         break;
      default:
         return 0;
         break;
   }

   /* Queue packet for tap */
   tap_queue_packet(unistim_tap, pinfo, uinfo);
   return size;
}

static void
dissect_payload(proto_tree *overall_unistim_tree,tvbuff_t *tvb, gint offset, packet_info *pinfo){
   proto_item *ti;
   proto_tree *unistim_tree;
   guint payload_proto=tvb_get_guint8(tvb,offset);

   /* Payload type for tap */
   uinfo->payload_type = payload_proto;

   ti=proto_tree_add_item(overall_unistim_tree,hf_unistim_payload,
                          tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;
   unistim_tree=proto_item_add_subtree(ti,ett_unistim);

   switch(payload_proto){
      case 0x00:
   /*NULL PROTO - NOTHING LEFT TO DO*/
         return;
      case 0x01:
   /*UNISTIM only so no term id but further payload work*/
         /* Collect info for tap */
         /* If no term id then packet sourced from NI */
         COPY_ADDRESS(&(uinfo->ni_ip), &(pinfo->src));
         COPY_ADDRESS(&(uinfo->it_ip), &(pinfo->dst));
         uinfo->it_port = pinfo->destport;
         break;
      case 0x02:
   /*UNISTIM with term id*/
         /* Termid packs are always sourced from the it, so collect relevant infos */
         COPY_ADDRESS(&(uinfo->ni_ip),&(pinfo->dst));
         COPY_ADDRESS(&(uinfo->it_ip),&(pinfo->src));
         uinfo->it_port = pinfo->srcport;
         uinfo->termid = tvb_get_ntohl(tvb,offset);

         proto_tree_add_item(unistim_tree,hf_terminal_id,tvb,offset,4,ENC_BIG_ENDIAN);
         offset+=4;
         break;
      case 0x03:
   /* UFTP */
         offset = dissect_uftp_message(unistim_tree,pinfo,tvb,offset);
         break;
      case 0xff:
   /*TODO flesh this out probably only for init*/
         break;
   }

   /* Handle UFTP seperately because it is significantly different
      than standard UNISTIM */
   while (tvb_length_remaining(tvb, offset) > 0)
      offset = dissect_unistim_message(unistim_tree,pinfo,tvb,offset);

}

static gint
dissect_uftp_message(proto_tree *unistim_tree,packet_info *pinfo _U_,tvbuff_t *tvb,gint offset){

   guint command;
   guint str_len;
   guint dat_len;
   proto_item *ti;
   proto_tree *msg_tree;

   ti = proto_tree_add_text(unistim_tree,tvb,offset,-1,"UFTP CMD");

   msg_tree = proto_item_add_subtree(ti,ett_unistim);

   command=tvb_get_guint8(tvb,offset);

   proto_tree_add_item(msg_tree,hf_uftp_command,tvb,offset,1,ENC_BIG_ENDIAN);

   offset += 1;

   switch(command)
   {
      case 0x80:
         /* Connection request */
         /* Nothing to do */
         break;

      case 0x81:
         /* Connection Details */
         /* Get datablock size */
         proto_tree_add_item(msg_tree,hf_uftp_datablock_size,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;
         /* Get datablock limit b4 flow control */
         proto_tree_add_item(msg_tree,hf_uftp_datablock_limit,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         /* Get filename */
         str_len = tvb_length_remaining(tvb, offset);
         proto_tree_add_item(msg_tree,hf_uftp_filename,tvb,offset,str_len,ENC_ASCII|ENC_NA);
         offset += str_len;
         break;

      case 0x82:
         /* Flow Control off */
         /* Nothing to do */
         break;

      case 0x00:
         /* Connection Granted */
         /* Nothing to do */
         break;

      case 0x01:
         /* Connection Denied */
         /* Nothing to do */
         break;

      case 0x02:
         /* File Data Block */
         /* Raw Data.. */
         dat_len = tvb_length_remaining(tvb, offset);
         proto_tree_add_item(msg_tree,hf_uftp_datablock,tvb,offset,dat_len,ENC_NA);
         offset += dat_len;
         break;
   }

   return offset;

}


static gint
dissect_unistim_message(proto_tree *unistim_tree,packet_info *pinfo,tvbuff_t *tvb,gint offset){
   guint addr;
   guint msg_len;
   proto_item *ti;
   proto_tree *msg_tree;

   ti = proto_tree_add_text(unistim_tree,tvb,offset,-1,"Unistim CMD");

   msg_tree = proto_item_add_subtree(ti,ett_unistim);

   addr=tvb_get_guint8(tvb,offset);

   proto_tree_add_item(msg_tree,hf_unistim_cmd_add,tvb,offset,1,ENC_BIG_ENDIAN);

   offset+=1;
   msg_len=tvb_get_guint8(tvb,offset);

   if (msg_len<=2)
   {
      ti=proto_tree_add_item(msg_tree,hf_unistim_len,tvb,offset,1,ENC_BIG_ENDIAN);
      expert_add_info_format(pinfo,ti,PI_MALFORMED,PI_ERROR,"Length too short");
      return tvb_length(tvb);
   } else {
      proto_item_set_len(ti,msg_len);
      proto_tree_add_item(msg_tree,hf_unistim_len,tvb,offset,1,ENC_BIG_ENDIAN);
   }

   offset+=1;
   /*from switch*/
   switch(addr){
      case 0x00:
   /*Nothing*/
         break;
   /*Expansion Manager Switch*/
      case 0x09:
      case 0x0A:
      case 0x0B:
      case 0x0C:
      case 0x0D:
      case 0x0E:
         offset = dissect_expansion_switch(msg_tree,tvb,offset,msg_len-2);
         break;

      case 0x11:
   /*Broadcast Manager Switch*/
         offset = dissect_broadcast_switch(msg_tree,tvb,offset,msg_len-2);
         break;
      case 0x16:
   /*Audio Manager Switch*/
         offset = dissect_audio_switch(msg_tree,pinfo,tvb,offset,msg_len-2);
         break;
      case 0x17:
   /*Display Manager Switch*/
         offset = dissect_display_switch(msg_tree,tvb,offset,msg_len-2);
         break;
      case 0x19:
   /*Key Indicator Manager Switch*/
         offset = dissect_key_indicator_switch(msg_tree,tvb,offset,msg_len-2);
         break;
      case 0x1a:
   /*Basic Manager Switch*/
         offset = dissect_basic_switch(msg_tree,tvb,offset,msg_len-2);
         break;
      case 0x1e:
   /*Network Manager Switch*/
         offset = dissect_network_switch(msg_tree,tvb,offset,msg_len-2);
         break;
      case 0x89:
      case 0x8A:
      case 0x8B:
      case 0x8C:
      case 0x8D:
      case 0x8E:
   /*Expansion Manager Phone*/
         offset = dissect_expansion_phone(msg_tree,tvb,offset,msg_len-2);
         break;

      case 0x91:
   /*Broadcast Manager phone*/
         offset = dissect_broadcast_phone(msg_tree,tvb,offset,msg_len-2);
         break;
      case 0x96:
   /*Audio Manager phone*/
         offset = dissect_audio_phone(msg_tree,tvb,offset,msg_len-2);
         break;
      case 0x97:
   /*Display Manager phone*/
         offset = dissect_display_phone(msg_tree,tvb,offset,msg_len-2);
         break;
      case 0x99:
   /*Key/Indicator Manager phone*/
         offset = dissect_key_indicator_phone(msg_tree,tvb,offset,msg_len-2);
         break;
      case 0x9a:
   /*Basic Manager phone*/
         offset = dissect_basic_phone(msg_tree,tvb,offset,msg_len-2);
         break;
      case 0x9e:
   /*Network Manager Switch*/
         offset = dissect_network_phone(msg_tree,tvb,offset,msg_len-2);
         break;
      default:
   /*See some undocumented messages.  Don't want to miss the ones we understand*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len-2,ENC_NA);

         offset+=(msg_len-2);
   }

   return offset;
}


   /*DONE*/
static gint
dissect_basic_phone(proto_tree *msg_tree,
                    tvbuff_t *tvb,gint offset, guint msg_len){
   guint basic_cmd;

   basic_cmd=tvb_get_guint8(tvb,offset);

   proto_tree_add_item(msg_tree,hf_basic_phone_cmd,tvb,offset,1,ENC_BIG_ENDIAN);

   offset+=1;msg_len-=1;
   switch(basic_cmd){

      case 0x00:
   /*Basic Manager Attributes Info*/
         proto_tree_add_item(msg_tree,hf_basic_phone_eeprom_stat_cksum,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_basic_phone_eeprom_dynam,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_basic_phone_eeprom_net_config_cksum,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x01:
   /*Basic Manager Options Report*/
         proto_tree_add_item(msg_tree,hf_basic_switch_options_secure,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x02:
   /*Firmware Version*/
         proto_tree_add_item(msg_tree,hf_basic_phone_fw_ver,
                             tvb,offset,msg_len,ENC_ASCII|ENC_NA);
         offset+=msg_len;
         break;
      case 0x03:
   /*IT Type*/
         proto_tree_add_item(msg_tree,hf_basic_it_type,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x07:
   /*Hardware ID*/
         proto_tree_add_item(msg_tree,hf_basic_phone_hw_id,
                             tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x08:
   /*Product Engineering Code*/
         proto_tree_add_item(msg_tree,hf_basic_prod_eng_code,
                             tvb,offset,msg_len,ENC_ASCII|ENC_NA);
         offset+=msg_len;
         break;
      case 0x09:
   /*Grey Market Info*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x0a:
   /*Encapsulate Command*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x11:
   /*Phone Ethernet address*/
         proto_tree_add_item(msg_tree,hf_basic_ether_address,
                             tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x0b:
   /*not in pdf but get them*/
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
   }

   return offset;
}
   /*DONE*/
static gint
dissect_basic_switch(proto_tree *msg_tree,
                     tvbuff_t *tvb,gint offset,guint msg_len){
   guint basic_cmd;
   basic_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_basic_switch_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;msg_len-=1;
   switch(basic_cmd){
      case 0x01:
   /*Query Basic Manager*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_attr,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_opts,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_fw,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_hw_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_it_type,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_prod_eng_code,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_gray_mkt_info,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x02:
   /*Basic Manager Options*/
         proto_tree_add_item(msg_tree,hf_basic_switch_options_secure,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x06:
   /*EEprom Write*/
         proto_tree_add_item(msg_tree,hf_basic_switch_element_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_basic_switch_eeprom_data,
                             tvb,offset,msg_len,ENC_NA);
         offset+=1;
         break;
      case 0x07:
   /*Assign Terminal ID*/
         /* Set tap info */
         uinfo->set_termid = 1;

         proto_tree_add_item(msg_tree,hf_basic_switch_terminal_id,
                             tvb,offset,msg_len,ENC_BIG_ENDIAN);
         offset+=msg_len;
         break;
      case 0x08:
   /*Encapsulate Command*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x0f:
   /*showing up in captures but not in pdf*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;

   }

   return offset;
}


   /*DONE*/
static gint
dissect_broadcast_switch(proto_tree *msg_tree,
                         tvbuff_t *tvb,gint offset, guint msg_len){
   guint bcast_cmd;
   guint year,month,day,hour,minute,second;
   proto_item *date_label;
   proto_item *time_label;
   proto_tree *date_tree;
   proto_tree *time_tree;
   bcast_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_broadcast_switch_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;msg_len-=1;
   switch(bcast_cmd){
      case 0x00:
   /*Accessory Sync Update   -   len=3 */
         break;
      case 0x01:
   /*Logical Icon Update*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_state,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_cadence,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x02:
   /*Time and Date Download*/
         year=tvb_get_guint8(tvb,offset);
         month=tvb_get_guint8(tvb,offset+1);
         day=tvb_get_guint8(tvb,offset+2);
         hour=tvb_get_guint8(tvb,offset+3);
         minute=tvb_get_guint8(tvb,offset+4);
         second=tvb_get_guint8(tvb,offset+5);
         date_label=proto_tree_add_text(msg_tree,tvb,offset,3,
                                        "Date %i/%i/%i",month,day,year%100);
         date_tree=proto_item_add_subtree(date_label,ett_unistim);
         proto_tree_add_item(date_tree,hf_broadcast_year,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(date_tree,hf_broadcast_month,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(date_tree,hf_broadcast_day,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;

         time_label=proto_tree_add_text(msg_tree,tvb,offset,3,
                                        "Time %i:%i:%i",hour,minute,second);
         time_tree=proto_item_add_subtree(time_label,ett_unistim);
         proto_tree_add_item(time_tree,hf_broadcast_hour,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(time_tree,hf_broadcast_minute,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(time_tree,hf_broadcast_second,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x03:
   /*Set Default Character Table Config */
         /* UGLY may work may not*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
   }

   return offset;
}
   /*DONE Haven't seen any phone broadcasts, wouldn't expect to*/
static gint
dissect_broadcast_phone(proto_tree *msg_tree,
                        tvbuff_t *tvb, gint offset,guint msg_len){

   proto_tree_add_item(msg_tree,hf_generic_data, tvb,offset,msg_len,ENC_NA);
   offset+=msg_len;

   return offset;
}

   /*DONE*/
static gint
dissect_display_switch(proto_tree *msg_tree,
                       tvbuff_t *tvb, gint offset,guint msg_len){
   guint clear_mask;
   guint highlight_cmd;
   guint time_date_mask;
   guint display_cmd;
   guint address_byte;
   guint movement_byte;
   proto_tree *address_tree;
   proto_item *tmp_ti;
   display_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_display_switch_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;msg_len-=1;

   switch(display_cmd){
      case 0x01:
   /*Restore Default Character Table Configuration length = 3*/
         break;
      case 0x04:
   /*Arrow*/
         proto_tree_add_item(msg_tree,hf_display_arrow,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x05:
   /*Query Status Bar Icon*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x06:
   /*Highlight Off length = 3*/
         break;
      case 0x07:
   /*Highlight On length = 3*/
         break;
      case 0x09:
   /*Restore Time and Date length  = 3*/
         break;
      case 0x0a:
   /*Clear Time and Date length  = 3*/
         break;
      case 0x0b:
   /*Call Duration Timer*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_call_timer_mode,tvb,offset,
                             1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_call_timer_reset,tvb,offset,
                             1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_call_timer_display,tvb,offset,
                             1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_call_timer_delay,tvb,offset,
                             1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_call_timer_id,tvb,offset,
                             1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0c:
   /*Query Display Manager*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x0d:
   /*Download Call Duration Timer Delay*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x0e:
   /*Disable Display Field*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x0f:
   /*Clear Field*/
         clear_mask=tvb_get_guint8(tvb,offset);
   /*need to know which paths to take*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_clear_numeric,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_clear_context,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_clear_date,
                             tvb,offset,1,ENC_BIG_ENDIAN);

         proto_tree_add_item(msg_tree,hf_display_clear_time,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_clear_line,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_clear_softkey,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_clear_softkey_label,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         if((clear_mask&DISPLAY_CLEAR_LINE)==DISPLAY_CLEAR_LINE){
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_line_1,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_line_2,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_line_3,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_line_4,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_line_5,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_line_6,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_line_7,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_line_8,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         if((clear_mask&DISPLAY_CLEAR_STATUS_BAR_ICON)==
                        DISPLAY_CLEAR_STATUS_BAR_ICON){
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_1,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_2,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_3,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_4,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_5,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_6,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_7,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_8,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         if((clear_mask&DISPLAY_CLEAR_SOFTKEY)==DISPLAY_CLEAR_SOFTKEY){
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_1,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_2,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_3,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_4,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_5,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_6,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_7,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_8,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         if((clear_mask&DISPLAY_CLEAR_SOFTKEY_LABEL)==DISPLAY_CLEAR_SOFTKEY_LABEL){
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_sk_label_key_id,tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_clear_all_slks,tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x10:
   /*Cursor Control*/
         movement_byte=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_move_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_blink,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         if(msg_len==0){
   /*turn cursor off*/
            break;
         }
         if((movement_byte&0x01)==0x01){
            address_byte=tvb_get_guint8(tvb,offset);
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_write_address_numeric,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_write_address_context,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_write_address_line,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_write_address_soft_key,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)==
                             DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)
               proto_tree_add_item(msg_tree,
                                   hf_display_write_address_softkey_id,
                                   tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
            if(msg_len==0){
   /*turn cursor off*/
               break;
            }
         }
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_address_char_pos,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_address_line_number,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x12:
   /*Display Scroll with Data (before)*/
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x13:
   /*Display Scroll with Data (after)*/
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x14:
   /*Status Bar Icon Update*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field, tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_icon_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_basic_bit_field, tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_state,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_cadence,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x15:
   /*Month Labels Download*/
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x16:
   /*Call Duration Timer Label Download*/
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=1;msg_len-=1;
         break;
      case 0x17:
   /*Time and Date Format*/
         time_date_mask=tvb_get_guint8(tvb,offset);
         if((time_date_mask&DISPLAY_USE_TIME_FORMAT)==DISPLAY_USE_TIME_FORMAT){
            proto_tree_add_item(msg_tree,hf_display_time_format,tvb,offset,1,ENC_BIG_ENDIAN);
         }
         if((time_date_mask&DISPLAY_USE_DATE_FORMAT)==DISPLAY_USE_DATE_FORMAT){
            proto_tree_add_item(msg_tree,hf_display_date_format,tvb,offset,1,ENC_BIG_ENDIAN);
         }
         proto_tree_add_item(msg_tree,hf_display_use_time_format,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_use_date_format,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x18:
   /*address|no control|no tag|no*/
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x19:
   /*address|yes control|no tag|no*/
         tmp_ti=proto_tree_add_text(msg_tree,tvb,offset,0,"Address");

         address_tree=proto_item_add_subtree(tmp_ti,ett_unistim);
         address_byte=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(address_tree,hf_basic_bit_field,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_numeric,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_context,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_line,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_key,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_label,
                             tvb,offset,1,ENC_BIG_ENDIAN);

         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)==
                          DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_softkey_id,
                                tvb,offset,1,ENC_BIG_ENDIAN);
         }
         offset+=1;msg_len-=1;
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)==
             DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG){
            proto_tree_add_item(address_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(address_tree,
                                hf_display_write_address_char_pos,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)!=
                             DISPLAY_WRITE_ADDRESS_LINE_FLAG){
               offset+=1;msg_len-=1;
            }
         }
         if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)==
             DISPLAY_WRITE_ADDRESS_LINE_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_line_number,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         if(msg_len>0){
            /* I'm guessing this will work flakily at best */
            uinfo->string_data = tvb_get_string(tvb,offset,msg_len);
            set_ascii_item(msg_tree,tvb,offset,msg_len);
         }

         offset+=msg_len;
         break;
      case 0x1a:
   /*address|no control|yes tag|no*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_cursor_move,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_clear_left,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_clear_right,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_shift_left,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_shift_right,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_highlight,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         proto_tree_add_item(msg_tree,hf_generic_string,
                             tvb,offset,msg_len,ENC_ASCII|ENC_NA);
         offset+=msg_len;
         break;
      case 0x1b:
   /*address|yes control|yes tag|no*/
         tmp_ti=proto_tree_add_text(msg_tree,tvb,offset,0,"Address Data");
         address_tree=proto_item_add_subtree(tmp_ti,ett_unistim);
         address_byte=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(address_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,
                             hf_display_write_address_numeric,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,
                             hf_display_write_address_context,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,
                             hf_display_write_address_line,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,
                             hf_display_write_address_soft_key,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,
                             hf_display_write_address_soft_label,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)==
                          DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG){
            proto_tree_add_item(address_tree,hf_display_write_address_softkey_id,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1; msg_len-=1;
         }
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)==
                          DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_char_pos,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)!=
                             DISPLAY_WRITE_ADDRESS_LINE_FLAG)
               offset+=1;msg_len-=1;
         }
         if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)==
                          DISPLAY_WRITE_ADDRESS_LINE_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_line_number,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_cursor_move,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_clear_left,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_clear_right,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_shift_left,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_shift_right,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_highlight,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x1c:
   /*address|no control|no tag|yes*/
         proto_tree_add_item(msg_tree,hf_display_write_tag,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x1d:
   /*address|yes control|no tag|yes*/
         tmp_ti=proto_tree_add_text(msg_tree,tvb,offset,0,"Address Data");
         address_tree=proto_item_add_subtree(tmp_ti,ett_unistim);
         address_byte=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(address_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_numeric,tvb,
                             offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_context,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_line,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_key,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_label,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)==
             DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)
            proto_tree_add_item(address_tree,
                                hf_display_write_address_softkey_id,
                                tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1; msg_len-=1;
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)==
             DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_char_pos,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)!=
                DISPLAY_WRITE_ADDRESS_LINE_FLAG)
               offset+=1;msg_len-=1;
         }
         if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)==
             DISPLAY_WRITE_ADDRESS_LINE_FLAG){
            proto_tree_add_item(address_tree,hf_display_write_address_line_number,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x1e:
   /*address|no control|yes tag|yes*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_cursor_move,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_clear_left,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_clear_right,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_shift_left,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_shift_right,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_highlight,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;

         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         proto_tree_add_item(msg_tree,hf_display_write_tag,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x1f:
   /*address|yes control|yes tag|yes*/
         tmp_ti=proto_tree_add_text(msg_tree,tvb,offset,0,"Address");
         address_tree=proto_item_add_subtree(tmp_ti,ett_unistim);
         address_byte=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(address_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_numeric,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_context,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_line,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_key,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_label,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)==
                          DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)
            proto_tree_add_item(address_tree,hf_display_write_address_softkey_id,
                                tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1; msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_string,
                             tvb,offset,msg_len,ENC_ASCII|ENC_NA);
         offset+=msg_len;
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)==
                          DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG){
            proto_tree_add_item(address_tree,hf_display_write_address_char_pos,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)!=
                             DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)
               offset+=1;msg_len-=1;
         }
         if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)==
                          DISPLAY_WRITE_ADDRESS_LINE_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_line_number,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_cursor_move,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_clear_left,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_clear_right,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_shift_left,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_shift_right,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_write_highlight,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_write_tag,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x20:
   /*Context Info Bar Format*/
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_display_context_format,tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_display_context_field,tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x21:
   /*Set Default Character Table Configuration VERY UGLY*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x22:
   /*Special Character Download*/
         proto_tree_add_item(msg_tree,hf_display_char_address,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x23:
   /*Highlighted Field Definition*/
         highlight_cmd=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(msg_tree,hf_display_cursor_numeric,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_context ,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_line,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;proto_tree_add_item(msg_tree,hf_display_hlight_start,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_hlight_end,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         if(msg_len==0)
             break;
         if((highlight_cmd&DISPLAY_CURSOR_LINE)==DISPLAY_CURSOR_LINE){
           proto_tree_add_item(msg_tree,hf_display_cursor_char_pos,tvb,offset,1,ENC_BIG_ENDIAN);
           proto_tree_add_item(msg_tree,hf_display_cursor_line_number,tvb,offset,1,ENC_BIG_ENDIAN);
           offset+=1;msg_len-=1;
         }
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x24:
   /*Contrast*/
         proto_tree_add_item(msg_tree,hf_display_contrast,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x25:
   /*Caller Log Download*/
         proto_tree_add_item(msg_tree,hf_broadcast_hour,tvb,offset,msg_len,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_broadcast_minute,tvb,offset,msg_len,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x30:
   /*Layered Softkey Text Download*/
         proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_layer_number,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x31:
   /*Layered Softkey Clear*/
         proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_layer_all_skeys,tvb,offset,msg_len,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_layer_number,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x32:
   /*Set Visible Softkey Layer*/
         proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_layer_all_skeys,tvb,offset,msg_len,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_layer_number,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x33:
   /*Layered Softkey Cadence Download*/
         proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_once_or_cyclic,tvb,offset,msg_len,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_display_layer_number,tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
            proto_tree_add_item(msg_tree,hf_display_layer_duration,tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x34:
   /*Layered Softkey Cadencing On*/
        proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,ENC_BIG_ENDIAN);
        offset+=1;msg_len-=1;
        break;
      case 0x35:
   /*Layered Softkey Cadencing Off*/
         proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,
                             tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
   }

   return offset;
}
   /*DONE*/
static gint
dissect_display_phone(proto_tree *msg_tree,
                      tvbuff_t *tvb,gint offset,guint msg_len){
   guint display_cmd;
   guint highlight_cmd;
   display_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_display_phone_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;msg_len-=1;
   switch(display_cmd){
      case 0x00:
   /*Display Manager Attributes Info*/
         proto_tree_add_item(msg_tree,hf_display_line_width,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_lines,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_softkey_width,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_softkeys,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_icon,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_softlabel_key_width,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_context_width,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_numeric_width,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_time_width,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_date_width,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_char_dload,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_freeform_icon_dload,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_icon_type,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_charsets,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;

         break;
      case 0x01:
   /*Contrast Level Report*/
         proto_tree_add_item(msg_tree,hf_display_contrast,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x02:
   /*Cursor Location Report*/
         proto_tree_add_item(msg_tree,hf_display_cursor_numeric,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_context ,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_line,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_cursor_char_pos,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_line_number,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x03:
   /*Highlight Status On*/
         highlight_cmd=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(msg_tree,hf_display_cursor_numeric,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_context ,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_line,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;proto_tree_add_item(msg_tree,hf_display_hlight_start,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_hlight_end,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         if((highlight_cmd&DISPLAY_CURSOR_LINE)==DISPLAY_CURSOR_LINE){
           proto_tree_add_item(msg_tree,hf_display_cursor_char_pos,tvb,offset,1,ENC_BIG_ENDIAN);
           proto_tree_add_item(msg_tree,hf_display_cursor_line_number,tvb,offset,1,ENC_BIG_ENDIAN);
           offset+=1;msg_len-=1;
         }
         break;
      case 0x04:
   /*Current Character Table Configuration Status   VERY UGLY*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x05:
   /*Default Character Table Configuration Status   VERY UGLY*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x06:
   /*Timer And Date Format Report*/
         proto_tree_add_item(msg_tree,hf_display_time_format,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_display_date_format,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x07:
   /*Status Bar Icon State Report*/
         proto_tree_add_item(msg_tree,hf_icon_id,tvb,offset,msg_len,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_broadcast_icon_state,tvb,offset,msg_len,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_cadence,tvb,offset,msg_len,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0a:
   /*Highlight Status Off length = 3*/
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
   }

   return offset;
}


static gint
dissect_key_indicator_switch(proto_tree *msg_tree,
                             tvbuff_t *tvb, gint offset,guint msg_len){
   guint key_cmd;
   key_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_key_switch_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;msg_len-=1;
   switch(key_cmd){
      case 0x00:
   /*LED Update*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_key_led_cadence,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_key_led_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x01:
   /*Query Hookswitch length = 3 */
         break;
      case 0x02:
   /*User Activity Timer Stop length = 3*/
         break;
      case 0x03:
   /*User Activity Timer Start length = 3*/
         break;
      case 0x04:
   /*Downloadable Free Form Icon Access (Hardcoded) length of 3*/
         break;
      case 0x05:
   /*Downloadable Free Form Icon Access (Downloadable) length of 3*/
         break;
      case 0x06:
   /*Query Key/Indicator Manager*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x07:
   /*Key/Indicator Manager Options*/
         proto_tree_add_item(msg_tree,hf_keys_send_key_rel,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_enable_vol,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_conspic_prog_key,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_acd_super_control,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_local_dial_feedback,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x08:
   /*Logical Icon Mapping*/
         proto_tree_add_item(msg_tree,hf_key_icon_id,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_admin_command,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_keys_logical_icon_id,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         break;
      case 0x09:
   /*Key Repeat Timer Download*/
         proto_tree_add_item(msg_tree,hf_keys_repeat_timer_one,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_keys_repeat_timer_two,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0a:
   /*Query LED State*/
         proto_tree_add_item(msg_tree,hf_keys_led_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0b:
   /*Query Phone Icon State*/
         proto_tree_add_item(msg_tree,hf_keys_phone_icon_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0c:
   /*Indicator Cadence Download*/
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_keys_cadence_on_time,tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
            proto_tree_add_item(msg_tree,hf_keys_cadence_off_time,tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x0d:
   /*User Activity Timer Download*/
         proto_tree_add_item(msg_tree,hf_keys_user_activity_timeout,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0e:
   /*Free Form Icon Download*/
         proto_tree_add_item(msg_tree,hf_key_icon_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x0f:
   /*Phone Icon Update*/
         proto_tree_add_item(msg_tree,hf_key_icon_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_state,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_cadence,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0xff:
   /*Reserved*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
   }

   return offset;
}

/*DONE*/
static gint
dissect_key_indicator_phone(proto_tree *msg_tree,
                            tvbuff_t *tvb,gint offset, guint msg_len){
   guint key_cmd;
   key_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_key_phone_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;msg_len-=1;
   switch(key_cmd){
      case 0x00:
   /*Key Event*/
         /* Set the tap info */
         uinfo->key_state = tvb_get_guint8(tvb,offset);
         uinfo->key_state >>= 6;
         /* Extract the key code */
         uinfo->key_val = (tvb_get_guint8(tvb,offset) & 0x3F);

         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_key_code,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_key_command,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x01:
   /*LED Status Report*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x03:
   /*On Hook length = 3*/
         /* Set tap info.. */
         uinfo->hook_state = 0;

         break;
      case 0x04:
   /*Off Hook length = 3*/
         /* Set tap info.. */
         uinfo->hook_state = 1;

         break;
      case 0x05:
   /*User Activity Timer Expired length = 3*/
         break;
      case 0x06:
   /*Hookswitch State (on hook) length = 3*/
         break;
      case 0x07:
   /*Hookswitch State (off hook) length = 3*/
         break;
      case 0x08:
   /*Key/Indicator Manager Attributes Info*/
         proto_tree_add_item(msg_tree,hf_key_programmable_keys,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_soft_keys,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_keys_hd_key,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_mute_key,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_quit_key,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_copy_key,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_mwi_key,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_keys_num_nav_keys,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_num_conspic_keys,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;

         break;
      case 0x09:
   /*Key/Indicator Manager Options Report*/
         proto_tree_add_item(msg_tree,hf_keys_send_key_rel,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_enable_vol,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_conspic_prog_key,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_acd_super_control,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_keys_local_dial_feedback,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0a:
   /*Phone Icon Status Report*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
   }

   return offset;
}


/*Done*/
static gint
dissect_network_switch(proto_tree *msg_tree,
                       tvbuff_t *tvb,gint offset, guint msg_len){
   guint network_cmd;
   guint string_len;

   network_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_network_switch_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;msg_len-=1;
   switch(network_cmd){
      case 0x02:
   /*Soft Reset done*/
         break;
      case 0x03:
   /*Hard Reset done*/
         break;
      case 0x04:
   /*Query Network Manager*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_diag_flag,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_managers_flag,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_attributes_flag,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_serv_info_flag,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_options_flag,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_sanity_flag,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x05:
   /*Network Manager Options*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_enable_diag,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_enable_rudp,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x06:
   /*QoS Configuration*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x09:
   /*Set RTCP Source Description Item*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x0b:
   /*Download Server Information*/
         proto_tree_add_item(msg_tree,hf_net_server_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_net_server_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;
         proto_tree_add_item(msg_tree,hf_net_server_action,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_net_server_retry_count,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_net_server_failover_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_net_server_ip_address,tvb,offset,4,ENC_BIG_ENDIAN);
         offset+=4;
         break;
      case 0x0c:
   /*Server Switch*/
         proto_tree_add_item(msg_tree,hf_net_server_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x0d:
   /*Query Network Configuration Element*/
         proto_tree_add_item(msg_tree,hf_net_server_config_element,
                             tvb,offset-1,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x0e:
   /*Download Software Upgrade*/
         proto_tree_add_item(msg_tree,hf_net_file_xfer_mode,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_force_download,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_use_file_server_port,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_use_local_port,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,1,ENC_NA);
         offset+=1;msg_len-=1;
         string_len=tvb_strsize(tvb,offset);
         proto_tree_add_item(msg_tree,hf_net_full_pathname,tvb,offset,string_len,ENC_ASCII|ENC_NA);
         offset+=string_len;msg_len-=string_len;
         string_len=tvb_strsize(tvb,offset);
         proto_tree_add_item(msg_tree,hf_net_file_identifier,tvb,offset,string_len,ENC_ASCII|ENC_NA);
         offset+=string_len;msg_len-=string_len;
         proto_tree_add_item(msg_tree,hf_net_file_server_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_net_local_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_net_file_server_address,tvb,offset,4,ENC_BIG_ENDIAN);
         offset+=4;msg_len-=4;
         break;
      case 0x0f:
   /*Set RTCP Report Interval*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x10:
   /*Set Primary Server*/
         proto_tree_add_item(msg_tree,hf_net_server_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x12:
   /*Reset Watchdog*/
         proto_tree_add_item(msg_tree,hf_net_server_time_out,
                             tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;
         break;
      case 0x13:
   /*Set Recovery Procedure Time Interval*/
         proto_tree_add_item(msg_tree,hf_net_server_recovery_time_low,
                             tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;
         proto_tree_add_item(msg_tree,hf_net_server_recovery_time_high,
                             tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;
         break;
      case 0x14:
   /*Transport Reliability Layer Parameters Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,
                             tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0xff:
   /*Reserved*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;

   }

   return offset;
}

/*DONE*/
static gint
dissect_expansion_switch(proto_tree *msg_tree,
                      tvbuff_t *tvb,gint offset, guint msg_len){
   guint expansion_cmd;


   expansion_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_expansion_switch_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1; msg_len-=1;
   switch(expansion_cmd){
      case 0x17:
         break;
      case 0x57:
        /*skip a byte for now, not sure what it means*/
        offset+=1;
        msg_len-=1;


         proto_tree_add_item(msg_tree,hf_expansion_softlabel_number,tvb,
                          offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         msg_len-=1;

         set_ascii_item(msg_tree,tvb,offset,msg_len);
         break;
      case 0x59:
         /*skip a byte for now, not sure what it means*/
         offset+=1;
         msg_len-=1;
         proto_tree_add_item(msg_tree,hf_expansion_softlabel_number,tvb,
                          offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         msg_len-=1;
         proto_tree_add_item(msg_tree,hf_basic_bit_field,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_state,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_cadence,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         msg_len-=1;
         break;
   }
   offset+=msg_len;
   return offset;
}

static gint
dissect_expansion_phone(proto_tree *msg_tree,
                      tvbuff_t *tvb,gint offset, guint msg_len){
   guint expansion_cmd;
   guint key_number;

   expansion_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_expansion_phone_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1; msg_len-=1;
   key_number=(tvb_get_guint8(tvb,offset))-64;

   switch(expansion_cmd){
      case 0x59:
         proto_tree_add_text(msg_tree,tvb,offset,msg_len,"Module Key Number: %i",key_number);
         offset+=1;
         msg_len-=1;
         break;
   }
   offset+=msg_len;
   return offset;
}

static gint
dissect_network_phone(proto_tree *msg_tree,
                      tvbuff_t *tvb,gint offset, guint msg_len){
   guint network_cmd;
   proto_tree *server_tree;
   proto_item *server;
   guint i;
   network_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_network_phone_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;msg_len-=1;
   switch(network_cmd){
      case 0x00:
   /*Soft Reset Ack done length = 3*/
         break;
      case 0x01:
   /*Sanity OK done length = 3*/
         break;
      case 0x02:
   /*Network Manager Attributes Info*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x03:
   /*Network Manager Diagnostic Info*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_phone_rx_ovr_flag,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_phone_tx_ovr_flag,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_phone_rx_empty_flag,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_phone_invalid_msg_flag,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_phone_eeprom_insane_flag,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_net_phone_eeprom_unsafe_flag,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x04:
   /*Manager IDs*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x05:
   /*Network Manager Options Report*/
         proto_tree_add_boolean(msg_tree,hf_net_phone_diag,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_phone_rudp,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x08:
   /*Resume Connection with Server done*/
         break;
      case 0x09:
   /*Suspend Connection with Server done*/
         break;
      case 0x0b:
   /*Network Configuration Element Report*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x0c:
   /*Server Information Report*/
         proto_tree_add_item(msg_tree,hf_net_phone_primary_server_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         for (i=1; msg_len>8; i++){
   /*if less than 9 not full report so punt*/
/*          guint16 port_num;
            port_num=tvb_get_ntohs(tvb,offset);
            if(port_num<1064)
               break;
*/
            server=proto_tree_add_text(msg_tree,tvb,offset,9,
                                       "Server (S%d) Server ID: %X",i,i-1);
            server_tree=proto_item_add_subtree(server,ett_unistim);
            proto_tree_add_item(server_tree,
                                hf_net_phone_server_port,
                                tvb,offset,2,ENC_BIG_ENDIAN);
            offset+=2;msg_len-=2;
            proto_tree_add_item(server_tree,
                                hf_net_phone_server_action,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
            proto_tree_add_item(server_tree,
                                hf_net_phone_server_retry_count,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
            proto_tree_add_item(server_tree,
                                hf_net_phone_server_failover_id,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
            proto_tree_add_item(server_tree,hf_net_phone_server_ip,
                                tvb,offset,4,ENC_BIG_ENDIAN);
            offset+=4;msg_len-=4;
         }
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
   }

   return offset;
}
/*DONE*/
static gint
dissect_audio_switch(proto_tree *msg_tree,packet_info *pinfo,
                                    tvbuff_t *tvb,gint offset,guint msg_len){
   proto_tree *param_tree;
   proto_item *param;
   guint audio_cmd;
   guint apb_op_code;
   guint apb_data_len;
   guint vocoder_param;
   audio_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_audio_switch_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;msg_len-=1;
   switch(audio_cmd){
   case 0x00:
   /*Query Audio Manager*/
      proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_attr,tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opts,tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_alert,tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_adj_rx_vol,tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_def_rx_vol,tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_handset,tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_headset,tvb,offset,1,ENC_BIG_ENDIAN);
      offset+=1;
      proto_tree_add_item(msg_tree,hf_audio_default_rx_vol_id,
                          tvb,offset,1,ENC_BIG_ENDIAN);
      offset+=1;
      break;
   case 0x01:
   /*Query Supervisor Headset Status*/
      /*done*/
      break;
   case 0x02:
   /*Audio Manager Options*/
      proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_max_vol,
                          tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_adj_vol,
                          tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_aa_rx_vol_rpt,
                          tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_hs_on_air,
                          tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_hd_on_air,
                          tvb,offset,1,ENC_BIG_ENDIAN);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_noise_squelch,
                          tvb,offset,1,ENC_BIG_ENDIAN);
      offset+=1;
         break;
      case 0x04:
   /*Mute/Unmute*/
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_audio_mgr_mute,tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(msg_tree,hf_audio_mgr_tx_rx,tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
            proto_tree_add_item(msg_tree,hf_audio_mgr_stream_id,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x10:
   /*Transducer Based Tone On*/
         proto_tree_add_item(msg_tree,
                             hf_audio_mgr_transducer_based_tone_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_mgr_attenuated,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x11:
   /*Transducer Based Tone Off*/
         proto_tree_add_item(msg_tree,hf_audio_mgr_transducer_based_tone_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x12:
   /*Alerting Tone Configuration*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_mgr_warbler_select,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_mgr_transducer_routing,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_mgr_tone_vol_range,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_mgr_cadence_select,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x13:
   /*Special Tone Configuration*/
         proto_tree_add_item(msg_tree,hf_audio_mgr_transducer_routing,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_mgr_tone_vol_range,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_special_tone,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x14:
   /*Paging Tone Configuration*/
         proto_tree_add_item(msg_tree,hf_audio_mgr_transducer_routing,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_mgr_tone_vol_range,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_mgr_cadence_select,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x15:
   /*Alerting Tone Cadence Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
   /*TODO UGLY*/
      case 0x17:
   /*Paging Tone Cadence Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
   /*TODO UGLY*/
      case 0x18:
   /*Transducer Based Tone Volume Level*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,
                             hf_audio_mgr_transducer_based_tone_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_tone_level,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x1a:
   /*Visual Transducer Based Tone Enable*/
         proto_tree_add_item(msg_tree,hf_audio_visual_tones,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x1b:
   /*Stream Based Tone On*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_stream_based_tone_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_stream_based_tone_rx_tx,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_stream_based_tone_mute,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_stream_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_stream_based_volume,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x1c:
   /*Stream Based Tone Off*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_stream_based_tone_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_stream_based_tone_rx_tx,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_stream_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;
         break;
      case 0x1d:
   /*Stream Based Tone Frequency Component List Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x1e:
   /*Stream Based Tone Cadence Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x20:
   /*Select Adjustable Rx Volume*/
         proto_tree_add_item(msg_tree,hf_audio_default_rx_vol_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         break;
      case 0x21:
   /*Set APB's Rx Volume Level*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x22:
   /*Change Adjustable Rx Volume (quieter) DONE*/
         proto_tree_add_item(msg_tree,hf_generic_data,
                             tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x23:
   /*Change Adjustable Rx Volume (louder) DONE*/
         proto_tree_add_item(msg_tree,hf_generic_data,
                             tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x24:
   /*Adjust Default Rx Volume(quieter)*/
         proto_tree_add_item(msg_tree,hf_audio_default_rx_vol_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         break;
      case 0x25:
   /*Adjust Default Rx Volume(louder)*/
         proto_tree_add_item(msg_tree,hf_audio_default_rx_vol_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         break;
      case 0x28:
   /*APB Download*/
         proto_tree_add_item(msg_tree,hf_audio_apb_number,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         while(msg_len>0){
            apb_op_code=tvb_get_guint8(tvb,offset);
            proto_tree_add_item(msg_tree,hf_audio_apb_op_code,tvb,
                                offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
            if(apb_op_code>0x39){
   /*should have a len + data*/
               apb_data_len=tvb_get_guint8(tvb,offset);
               proto_tree_add_item(msg_tree,hf_audio_apb_param_len,tvb,
                                   offset,1,ENC_BIG_ENDIAN);
               offset+=1;msg_len-=1;
               proto_tree_add_item(msg_tree,hf_audio_apb_data,tvb,
                                   offset,apb_data_len,ENC_NA);
               offset+=apb_data_len;msg_len-=apb_data_len;
            }
         }
         break;
      case 0x30:
   /*Open Audio Stream*/
         /* Set the tap info */
         uinfo->stream_connect = 1;

         proto_tree_add_item(msg_tree,hf_audio_rx_stream_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_tx_stream_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_rx_vocoder_type,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_tx_vocoder_type,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_frames_per_packet,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_tos,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_precedence,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_frf_11,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_rtcp_bucket_id,
                             tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_data,
                             tvb,offset,4,ENC_NA);
         offset+=4;msg_len-=4;
         proto_tree_add_item(msg_tree,hf_audio_lcl_rtp_port,
                             tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_lcl_rtcp_port,
                             tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;

         proto_tree_add_item(msg_tree,hf_audio_far_rtp_port,
                             tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_rtcp_port,
                             tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;

         /* Sometimes the open stream does not specify an endpoint */
         /* In this circumstance the packet is truncated at the far end */
         /* rtp port */
         if(msg_len > 0){
            proto_tree_add_item(msg_tree,hf_audio_far_ip_add,tvb,offset,4,ENC_BIG_ENDIAN);
            offset+=4;msg_len-=4;
            {
               guint32 far_ip_addr;
               address far_addr;
               guint16 far_port;

               far_ip_addr = tvb_get_ipv4(tvb, offset-4);
               SET_ADDRESS(&far_addr, AT_IPv4, 4, &far_ip_addr);

               far_port = tvb_get_ntohs(tvb, offset-8);
               rtp_add_address(pinfo, &far_addr, far_port, 0, "UNISTIM", pinfo->fd->num, FALSE, NULL);

               far_port = tvb_get_ntohs(tvb, offset-6);
               rtcp_add_address(pinfo, &far_addr, far_port, 0, "UNISTIM", pinfo->fd->num);
            }
         }
         break;
      case 0x31:
   /*Close Audio Stream*/
         /* Set the tap info */
         uinfo->stream_connect = 0;

         proto_tree_add_item(msg_tree,hf_audio_rx_stream_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_tx_stream_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x32:
   /*Connect Transducer*/
         /* Tap info again */
         uinfo->trans_connect = 1;

         proto_tree_add_item(msg_tree,hf_basic_bit_field, tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_transducer_pair,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_enable,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_tx_enable,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_basic_bit_field, tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_apb_number,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_sidetone_disable,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_destruct_additive,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_dont_force_active,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_audio_mgr_stream_id,tvb,offset,1,ENC_LITTLE_ENDIAN);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x34:
   /*Filter Block Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x37:
   /*Query RTCP Statistics*/
         proto_tree_add_item(msg_tree,hf_audio_rtcp_bucket_id,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_clear_bucket,tvb,offset,1,ENC_BIG_ENDIAN);

         offset+=1;msg_len-=1;
         break;
      case 0x38:
   /*Configure Vocoder Parameters*/
         proto_tree_add_item(msg_tree,hf_audio_mgr_stream_id,tvb,offset,1,ENC_LITTLE_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_vocoder_id,tvb,offset,1,FALSE),
         offset+=1;msg_len-=1;
         while(msg_len>0){
            param=proto_tree_add_text(msg_tree,tvb,offset,0,"Param");
            param_tree=proto_item_add_subtree(param,ett_unistim);
            vocoder_param=tvb_get_guint8(tvb,offset);
            proto_tree_add_item(param_tree,hf_basic_bit_field,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(param_tree,hf_audio_vocoder_param,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(param_tree,hf_audio_vocoder_entity,
                                tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
            if((vocoder_param&0x0a)==0x0a){
               proto_tree_add_item(param_tree,hf_audio_vocoder_annexa,
                                   tvb,offset,1,ENC_BIG_ENDIAN);
               proto_tree_add_item(param_tree,hf_audio_vocoder_annexb,
                                   tvb,offset,1,ENC_BIG_ENDIAN);
               offset+=1;msg_len-=1;
            }
            else if((vocoder_param&0x0b)==0x0b){
               proto_tree_add_item(param_tree,hf_audio_sample_rate,
                                   tvb,offset,1,ENC_BIG_ENDIAN);
               offset+=1;msg_len-=1;
            }
            else if((vocoder_param&0x0c)==0x0c){
               proto_tree_add_item(param_tree,hf_audio_rtp_type,
                                   tvb,offset,1,ENC_BIG_ENDIAN);
               offset+=1;msg_len-=1;
            }
            else if((vocoder_param&0x20)==0x20){
               proto_tree_add_item(param_tree,hf_audio_bytes_per_frame,
                                   tvb,offset,2,ENC_BIG_ENDIAN);
               offset+=2;msg_len-=2;
            }
         }
         break;
      case 0x39:
   /*Query RTCP Bucket's SDES Information*/
         proto_tree_add_item(msg_tree,hf_audio_source_descr,tvb,offset,msg_len,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_sdes_rtcp_bucket,tvb,offset,msg_len,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x3a:
   /*Jitter Buffer Parameters Configuration*/
         proto_tree_add_item(msg_tree,hf_audio_rx_stream_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_desired_jitter,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_high_water_mark,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_early_packet_resync_thresh,tvb,
                             offset,4,ENC_BIG_ENDIAN);
         offset+=4;msg_len-=4;
         proto_tree_add_item(msg_tree,hf_audio_late_packet_resync_thresh,tvb,
                             offset,4,ENC_BIG_ENDIAN);
         offset+=4;msg_len-=4;
         break;
      case 0x3b:
   /*Resolve Port Mapping*/
         proto_tree_add_item(msg_tree,hf_audio_resolve_phone_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_end_echo_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_end_ip_address,tvb,offset,4,ENC_BIG_ENDIAN);
         offset+=4;msg_len-=4;
         break;
      case 0x3c:
   /*Port Mapping Discovery Ack*/
         proto_tree_add_item(msg_tree,hf_audio_nat_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_nat_ip_address,tvb,offset,4,ENC_BIG_ENDIAN);
         offset+=4;msg_len-=4;
         break;
      case 0x3d:
   /*Query Audio Stream Status*/
         proto_tree_add_item(msg_tree,hf_audio_direction_code,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_mgr_stream_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0xff:
   /*Reserved*/
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
   }

   return offset;
}

/*DONE*/
static gint
dissect_audio_phone(proto_tree *msg_tree,
                                 tvbuff_t *tvb,gint offset,guint msg_len){
   guint audio_cmd;
   guint apb_op_code;
   guint apb_data_len;
   guint stream_dir;
   guint stream_state;
   audio_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_audio_phone_cmd,tvb,offset,1,ENC_BIG_ENDIAN);
   offset+=1;msg_len-=1;
   switch(audio_cmd){
      case 0x00:
   /*Handset Connected length =3*/
         /* Set the tap info */
         uinfo->hook_state = 1;
         break;
      case 0x01:
   /*Handset Disconnected length =3*/
         /* Set the tap info */
         uinfo->hook_state = 0;
         break;
      case 0x02:
   /*Headset Connected length =3*/
         /* Set the tap info */
         uinfo->hook_state = 1;
         break;
      case 0x03:
   /*Headset Disconnected length =3*/
         /* Set the tap info */
         uinfo->hook_state = 0;
         break;
      case 0x04:
   /*Supervisor Headset Connected length =3*/
         /* Set the tap info */
         uinfo->hook_state = 1;
         break;
      case 0x05:
   /*Supervisor Headset Disconnected length =3*/
         /* Set the tap info */
         uinfo->hook_state = 0;
         break;
      case 0x07:
   /*Audio Manager Attributes Info*/
         proto_tree_add_item(msg_tree,hf_audio_hf_support,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         while(msg_len>0){
          proto_tree_add_item(msg_tree,hf_rx_vocoder_type,tvb,offset,1,ENC_BIG_ENDIAN);
          offset+=1;msg_len-=1;
         }
         break;
      case 0x08:
   /*Audio Manager Options Report*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_max,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_adj_vol,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_auto_adj_vol,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_hs_on_air,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_hd_on_air,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_noise_squelch,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x09:
   /*Adjustable Rx Volume Report*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_apb_rpt,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_up,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_floor,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_ceiling,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0a:
   /*Adjustable Rx Volume Information*/
         proto_tree_add_item(msg_tree,hf_audio_current_adj_vol_id,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_apb_rpt,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_up,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_floor,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_ceiling,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_current_rx_level,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_current_rx_range,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0b:
   /*APB's Default Rx Volume Value*/
         proto_tree_add_item(msg_tree,hf_audio_current_adj_vol_id,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_apb_rpt,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_up,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_floor,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_ceiling,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_current_rx_level,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_current_rx_range,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0c:
   /*Alerting Tone Select*/
         proto_tree_add_item(msg_tree,hf_audio_cadence_select,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_warbler_select,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x0e:
   /*RTCP Statistics Report UGLY*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
         break;
      case 0x0f:
   /*Open Audio Stream Report*/
         proto_tree_add_item(msg_tree,hf_audio_open_stream_rpt,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x10:
   /*RTCP Bucket SDES Information Report*/
         proto_tree_add_item(msg_tree,hf_audio_sdes_rpt_source_desc,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_sdes_rpt_buk_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x11:
   /*Port Mapping Discovery*/
         proto_tree_add_item(msg_tree,hf_audio_phone_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_phone_ip,tvb,offset,4,ENC_BIG_ENDIAN);
         offset+=4;msg_len-=4;
         break;
      case 0x12:
   /*Resolve Port Mapping*/
         proto_tree_add_item(msg_tree,hf_audio_nat_listen_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_nat_ip,tvb,offset,4,ENC_BIG_ENDIAN);
         offset+=4;msg_len-=4;
         proto_tree_add_item(msg_tree,hf_audio_nat_add_len,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_phone_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_phone_ip,tvb,offset,4,ENC_BIG_ENDIAN);
         offset+=4;msg_len-=4;
         proto_tree_add_item(msg_tree,hf_audio_phone_add_len,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         break;
      case 0x13:
   /*Audio Stream Status Report*/
         stream_dir=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(msg_tree,hf_audio_stream_direction_code,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_mgr_stream_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         stream_state=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(msg_tree,hf_audio_stream_state,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         if((AUDIO_STREAM_STATE&stream_state)!=AUDIO_STREAM_STATE)
           break;
         if((AUDIO_STREAM_DIRECTION_RX&stream_dir)==AUDIO_STREAM_DIRECTION_RX)
            proto_tree_add_item(msg_tree,hf_rx_vocoder_type,tvb,offset,1,ENC_BIG_ENDIAN);
         else if((AUDIO_STREAM_DIRECTION_TX&stream_dir)==AUDIO_STREAM_DIRECTION_TX)
            proto_tree_add_item(msg_tree,hf_tx_vocoder_type,tvb,offset,1,ENC_BIG_ENDIAN);
         else
            proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,1,ENC_NA);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_frames_per_packet,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_tos,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_precedence,tvb,offset,1,ENC_BIG_ENDIAN);
         proto_tree_add_item(msg_tree,hf_audio_frf_11,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_rtcp_bucket_id,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_lcl_rtp_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_lcl_rtcp_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_rtp_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_rtcp_port,tvb,offset,2,ENC_BIG_ENDIAN);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_ip_add,tvb,offset,4,ENC_BIG_ENDIAN);
         offset+=4;msg_len-=4;
         proto_tree_add_item(msg_tree,hf_audio_transducer_list_length,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_audio_transducer_pair,tvb,offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
         }
      case 0x14:
   /*Query APB Response*/
         proto_tree_add_item(msg_tree,hf_audio_apb_number,tvb,offset,1,ENC_BIG_ENDIAN);
         offset+=1;msg_len-=1;
         while(msg_len>0){
            apb_op_code=tvb_get_guint8(tvb,offset);
            proto_tree_add_item(msg_tree,hf_audio_apb_op_code,tvb,
                                offset,1,ENC_BIG_ENDIAN);
            offset+=1;msg_len-=1;
            if(apb_op_code>0x39){
               /*should have a len + data*/
               apb_data_len=tvb_get_guint8(tvb,offset);
               proto_tree_add_item(msg_tree,hf_audio_apb_param_len,tvb,
                                   offset,1,ENC_BIG_ENDIAN);
               offset+=1;msg_len-=1;
               proto_tree_add_item(msg_tree,hf_audio_apb_data,tvb,
                                   offset,apb_data_len,ENC_NA);
               offset+=apb_data_len;msg_len-=apb_data_len;
            }
         }
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,ENC_NA);
         offset+=msg_len;
   }

   return offset;
}

static void
set_ascii_item(proto_tree *msg_tree,tvbuff_t *tvb, gint offset,guint msg_len){
   proto_tree_add_text(msg_tree,tvb,offset,msg_len,"DATA: %s",
                       tvb_format_text(tvb,offset,msg_len));
}

void
proto_register_unistim(void){

   module_t* unistim_module;

   static hf_register_info hf[] = {
         { &hf_unistim_seq_nu,
            { "RUDP Seq Num","unistim.num",FT_UINT32,
               BASE_HEX|BASE_RANGE_STRING, RVALS(sequence_numbers), 0x0, NULL, HFILL}
         },
         { &hf_unistim_cmd_add,
            { "UNISTIM CMD Address","unistim.add",FT_UINT8,
               BASE_HEX,VALS(command_address),0x0,NULL,HFILL}
         },
         { &hf_uftp_command,
            { "UFTP CMD","uftp.cmd",FT_UINT8,
               BASE_HEX,VALS(uftp_commands),0x0,NULL,HFILL}
         },
         { &hf_uftp_datablock_size,
            { "UFTP Datablock Size","uftp.blocksize",FT_UINT32,
               BASE_DEC,NULL,0x0,NULL,HFILL}
         },
         { &hf_uftp_datablock_limit,
            { "UFTP Datablock Limit","uftp.limit",FT_UINT8,
               BASE_DEC,NULL,0x0,NULL,HFILL}
         },
         { &hf_uftp_filename,
            { "UFTP Filename","uftp.filename",FT_STRINGZ,
               BASE_NONE,NULL,0x0,NULL,HFILL}
         },
         { &hf_uftp_datablock,
            { "UFTP Data Block","uftp.datablock",FT_BYTES,
               BASE_NONE,NULL,0x0,NULL,HFILL}
         },
         { &hf_unistim_packet_type,
            { "RUDP Pkt type","unistim.type",FT_UINT8,
               BASE_DEC, VALS(packet_names),0x0,NULL,HFILL}
         },
         { &hf_unistim_payload,
            { "UNISTIM Payload","unistim.pay",FT_UINT8,
               BASE_HEX, VALS(payload_names),0x0,NULL,HFILL}
         },
         { &hf_unistim_len ,
            { "UNISTIM CMD Length","unistim.len",FT_UINT8,
               BASE_DEC,NULL,0x0,NULL,HFILL}
         },
         { &hf_basic_bit_field,
            {"FLAGS","unistim.bit.fields",FT_BOOLEAN,
               8,TFS(&basic_bit_yn),0xff,NULL,HFILL}
         },
         { &hf_basic_switch_cmd ,
            {"Basic Cmd (switch)","unistim.basic.switch",FT_UINT8,
               BASE_HEX,VALS(basic_switch_msgs),0x0,NULL,HFILL}
         },
         { &hf_basic_phone_cmd ,
            {"Basic Cmd (phone)","unistim.basic.phone",FT_UINT8,
               BASE_HEX,VALS(basic_phone_msgs),0x0,NULL,HFILL}
         },
         { &hf_broadcast_switch_cmd ,
            {"Broadcast Cmd (switch)","unistim.broadcast.switch",FT_UINT8,
               BASE_HEX,VALS(broadcast_switch_msgs),0x0,NULL,HFILL}
         },
         { &hf_broadcast_phone_cmd ,
            {"Broadcast Cmd (phone)","unistim.broadcast.phone",FT_UINT8,
               BASE_HEX,VALS(broadcast_phone_msgs),0x0,NULL,HFILL}
         },
         { &hf_audio_switch_cmd ,
            {"Audio Cmd (switch)","unistim.audio.switch",FT_UINT8,
               BASE_HEX,VALS(audio_switch_msgs),0x0,NULL,HFILL}
         },
         { &hf_audio_phone_cmd ,
            {"Audio Cmd (phone)","unistim.audio.phone",FT_UINT8,
               BASE_HEX,VALS(audio_phone_msgs),0x0,NULL,HFILL}
         },
         { &hf_display_switch_cmd ,
            {"Display Cmd (switch)","unistim.display.switch",FT_UINT8,
               BASE_HEX,VALS(display_switch_msgs),0x0,NULL,HFILL}
         },
         { &hf_display_phone_cmd ,
            {"Display Cmd (phone)","unistim.display.phone",FT_UINT8,
               BASE_HEX,VALS(display_phone_msgs),0x0,NULL,HFILL}
         },
         { &hf_key_switch_cmd ,
            {"Key Cmd (switch)","unistim.key.switch",FT_UINT8,
               BASE_HEX,VALS(key_switch_msgs),0x0,NULL,HFILL}
         },
         { &hf_key_phone_cmd ,
            {"Key Cmd (phone)","unistim.key.phone",FT_UINT8,
               BASE_HEX,VALS(key_phone_msgs),0x0,NULL,HFILL}
         },
         { &hf_network_switch_cmd ,
            {"Network Cmd (switch)","unistim.network.switch",FT_UINT8,
               BASE_HEX,VALS(network_switch_msgs),0x0,NULL,HFILL}
         },
         { &hf_network_phone_cmd ,
            {"Network Cmd (phone)","unistim.network.phone",FT_UINT8,
               BASE_HEX,VALS(network_phone_msgs),0x0,NULL,HFILL}
         },
         { &hf_terminal_id,
            {"Terminal ID","unistim.terminal.id",FT_IPv4,
               BASE_NONE,NULL,0x0,NULL,HFILL}
         },
         { &hf_broadcast_year,
            {"Year","unistim.broadcast.year",FT_UINT8,
               BASE_DEC,NULL,0x7f,NULL,HFILL}
         },
         { &hf_broadcast_month,
            {"Month","unistim.broadcast.month",FT_UINT8,
               BASE_DEC,NULL,0x0,NULL,HFILL}
         },
         { &hf_broadcast_day,
            {"Day","unistim.broadcast.day",FT_UINT8,
               BASE_DEC,NULL,0x0,NULL,HFILL}
         },
         { &hf_broadcast_hour,
            {"Hour","unistim.broadcast.hour",FT_UINT8,
               BASE_DEC,NULL,0x0,NULL,HFILL}
         },
         { &hf_broadcast_minute,
            {"Minute","unistim.broadcast.minute",FT_UINT8,
               BASE_DEC,NULL,0x0,NULL,HFILL}
         },
         { &hf_broadcast_second,
            {"Second","unistim.broadcast.second",FT_UINT8,
               BASE_DEC,NULL,0x0,NULL,HFILL}
         },
         { &hf_net_diag_flag,
            {"Query Network Manager Diagnostic","unistim.query.diagnostic",
               FT_BOOLEAN,8, NULL,
               QUERY_NETWORK_MANAGER_DIAGNOSTIC, NULL,HFILL}
         },
         { &hf_net_managers_flag,
            {"Query Network Manager Managers","unistim.query.managers",
               FT_BOOLEAN,8, NULL,
               QUERY_NETWORK_MANAGER_MANAGERS, NULL,HFILL}
         },
         { &hf_net_attributes_flag,
            {"Query Network Manager Attributes","unistim.query.attributes",
               FT_BOOLEAN, 8,NULL,
               QUERY_NETWORK_MANAGER_ATTRIBUTES,NULL,HFILL}
         },
         { &hf_net_serv_info_flag,
            {"Query Network Manager Server Info","unistim.query.serverInfo",
               FT_BOOLEAN, 8,NULL,
               QUERY_NETWORK_MANAGER_SERVER_INFO,NULL,HFILL}
         },
         { &hf_net_options_flag,
            {"Query Network Manager Options","unistim.query.options",
               FT_BOOLEAN, 8,NULL,
               QUERY_NETWORK_MANAGER_OPTIONS,NULL,HFILL}
         },
         { &hf_net_sanity_flag,
            {"Query Network Manager Sanity","unistim.query.sanity",
               FT_BOOLEAN, 8,NULL,
               QUERY_NETWORK_MANAGER_SANITY,NULL,HFILL}
         },
         { &hf_net_enable_diag,
            {"Network Manager Enable DIAG","unistim.enable.diag",
               FT_BOOLEAN, 8,NULL,
               NETWORK_MANAGER_ENABLE_DIAG,NULL,HFILL}
         },
         { &hf_net_enable_rudp,
            {"Network Manager Enable RUDP","unistim.enable.network.rel.udp",
               FT_BOOLEAN, 8,NULL,
               NETWORK_MANAGER_ENABLE_RUDP,NULL,HFILL}
         },
         { &hf_net_server_id,
            {"Download Server ID","unistim.download.id",FT_UINT8,
               BASE_HEX, VALS(network_server_id),0x00,NULL,HFILL}
         },
         { &hf_net_server_port,
            {"Download Server Port","unistim.download.port",FT_UINT16,
               BASE_DEC, NULL,0x00,NULL,HFILL}
         },
         { &hf_net_server_action,
            {"Download Server Action","unistim.download.action",FT_UINT8,
               BASE_HEX, VALS(server_action),0x00,NULL,HFILL}
         },
         { &hf_net_server_retry_count,
            {"Download Retry Count","unistim.download.retry",FT_UINT8,
               BASE_DEC, NULL,0x00,NULL,HFILL}
         },
         { &hf_net_server_failover_id,
            {"Download Failover Server ID","unistim.download.failover",FT_UINT8,
               BASE_HEX, VALS(network_server_id),0x00,NULL,HFILL}
         },
         { &hf_net_server_ip_address,
            {"Download Server Address","unistim.download.address",FT_UINT32,
               BASE_HEX, NULL,0x00,NULL,HFILL}
         },
         { &hf_net_server_time_out,
            {"Watchdog Timeout","unistim.watchdog.timeout",FT_UINT16,
               BASE_DEC, NULL,0x00,NULL,HFILL}
         },
         { &hf_net_server_config_element,
            {"Configure Network Element","unistim.config.element",FT_UINT8,
               BASE_HEX, VALS(network_elements),0x00,NULL,HFILL}
         },
         { &hf_net_server_recovery_time_low,
            {"Recovery Procedure Idle Low Boundary","unistim.recovery.low",FT_UINT16,
               BASE_DEC, NULL,0x00,NULL,HFILL}
         },
         { &hf_net_server_recovery_time_high,
            {"Recovery Procedure Idle High Boundary","unistim.recovery.high",FT_UINT16,
               BASE_DEC, NULL,0x00,NULL,HFILL}
         },
         { &hf_net_phone_rx_ovr_flag,
            {"Receive Buffer Overflow","unistim.receive.overflow",
               FT_BOOLEAN, 8,NULL,
               RX_BUFFER_OVERFLOW,NULL,HFILL}
         },
         { &hf_net_phone_tx_ovr_flag,
            {"Transmit Buffer Overflow","unistim.trans.overflow",
               FT_BOOLEAN, 8,NULL,
               TX_BUFFER_OVERFLOW,NULL,HFILL}
         },
         { &hf_net_phone_rx_empty_flag,
            {"Receive Buffer Unexpectedly Empty","unistim.receive.empty",
               FT_BOOLEAN, 8,NULL,
               RX_UNEXPECT_EMPTY,NULL,HFILL}
         },
         { &hf_net_phone_invalid_msg_flag,
            {"Received Invalid MSG","unistim.invalid.msg",
               FT_BOOLEAN, 8,NULL,
               INVALID_MSG,NULL,HFILL}
         },
         { &hf_net_phone_eeprom_insane_flag,
            {"EEProm Insane","unistim.eeprom.insane",
               FT_BOOLEAN, 8,NULL,
               EEPROM_INSANE,NULL,HFILL}
         },
         { &hf_net_phone_eeprom_unsafe_flag,
            {"EEProm Unsafe","unistim.eeprom.unsafe",
               FT_BOOLEAN, 8,NULL,
               EEPROM_UNSAFE,NULL,HFILL}
         },
         { &hf_net_phone_diag,
            {"Diagnostic Command Enabled","unistim.diag.enabled",FT_BOOLEAN,
              8,NULL,NETWORK_MGR_REPORT_DIAG,NULL,HFILL}
         },
         { &hf_net_phone_rudp,
            {"Reliable UDP Active","unistim.rudp.active",FT_BOOLEAN,
              8,NULL,NETWORK_MGR_REPORT_RUDP,NULL,HFILL}
         },
         { &hf_basic_switch_query_flags,
            {"Query Basic Manager","unistim.basic.query",FT_UINT8,
               BASE_HEX, NULL,0x00,"INITIAL PHONE QUERY",HFILL}
         },
         { &hf_basic_switch_query_attr,
            {"Query Basic Manager Attributes","unistim.basic.attrs",FT_BOOLEAN,
              8,NULL,BASIC_QUERY_ATTRIBUTES,"Basic Query Attributes",HFILL}
         },
         { &hf_basic_switch_query_opts,
            {"Query Basic Manager Options","unistim.basic.opts",FT_BOOLEAN,
              8,NULL,BASIC_QUERY_OPTIONS,"Basic Query Options",HFILL}
         },
         { &hf_basic_switch_query_fw,
            {"Query Basic Switch Firmware","unistim.basic.fw",FT_BOOLEAN,
               8,NULL,BASIC_QUERY_FW,"Basic Query Firmware",HFILL}
         },
         { &hf_basic_switch_query_hw_id,
            {"Query Basic Manager Hardware ID","unistim.basic.hwid",FT_BOOLEAN,
              8,NULL,BASIC_QUERY_HW_ID,"Basic Query Hardware ID",HFILL}
         },
         { &hf_basic_switch_query_it_type,
            {"Query Basic Manager Phone Type","unistim.basic.type",FT_BOOLEAN,
              8,NULL,BASIC_QUERY_IT_TYPE,"Basic Query Phone Type",HFILL}
         },
         { &hf_basic_switch_query_prod_eng_code,
            {"Query Basic Manager Prod Eng Code","unistim.basic.code",FT_BOOLEAN,
              8,NULL,BASIC_QUERY_PROD_ENG_CODE,"Basic Query Production Engineering Code",HFILL}
         },
         { &hf_basic_switch_query_gray_mkt_info,
            {"Query Basic Manager Gray Mkt Info","unistim.basic.gray",FT_BOOLEAN,
              8,NULL,BASIC_QUERY_GRAY_MKT_INFO,"Basic Query Gray Market Info",HFILL}
         },
         { &hf_basic_switch_options_secure,
            {"Basic Switch Options Secure Code","unistim.basic.secure",FT_BOOLEAN,
              8,NULL,BASIC_OPTION_SECURE,NULL,HFILL}
         },
         { &hf_basic_switch_element_id,
            {"Basic Element ID","unistim.basic.element.id",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_basic_switch_eeprom_data,
            {"EEProm Data","unistim.basic.eeprom.data",FT_BYTES,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_basic_phone_eeprom_stat_cksum,
            {"Basic Phone EEProm Static Checksum","unistim.static.cksum",FT_UINT8,
               BASE_HEX,NULL,0x0,NULL,HFILL}
         },
         { &hf_basic_phone_eeprom_dynam,
            {"Basic Phone EEProm Dynamic Checksum","unistim.dynam.cksum",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_basic_phone_eeprom_net_config_cksum,
            {"Basic Phone EEProm Net Config Checksum","unistim.netconfig.cksum",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_basic_phone_hw_id,
            {"Basic Phone Hardware ID","unistim.basic.hw.id",FT_BYTES,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_basic_phone_fw_ver,
            {"Basic Phone Firmware Version","unistim.basic.fw.ver",FT_STRING,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_key_code,
            {"Key Name","unistim.key.name",FT_UINT8,
               BASE_HEX,VALS(key_names),0x3f,NULL,HFILL}
         },
         { &hf_key_command,
            {"Key Action","unistim.key.action",FT_UINT8,
               BASE_HEX,VALS(key_cmds),0xc0,NULL,HFILL}
         },
         { &hf_icon_id,
            {"Icon ID","unistim.icon.id",FT_UINT8,
               BASE_HEX,NULL, DISPLAY_ICON_ID,NULL,HFILL}
         },
         { &hf_broadcast_icon_state,
            {"Icon State","unistim.icon.state",FT_UINT8,
               BASE_HEX,VALS(bcast_icon_states),0x1f,NULL,HFILL}
         },
         { &hf_broadcast_icon_cadence,
            {"Icon Cadence","unistim.icon.cadence",FT_UINT8,
               BASE_HEX,VALS(bcast_icon_cadence),0xe0,NULL,HFILL}
         },
         { &hf_audio_mgr_attr,
            {"Query Audio Manager Attributes","unistim.audio.attr",FT_BOOLEAN,
               8,NULL,QUERY_AUDIO_MGR_ATTRIBUTES,NULL,HFILL}
         },
         { &hf_audio_mgr_opts,
            {"Query Audio Manager Options","unistim.audio.options",FT_BOOLEAN,
               8,NULL,QUERY_AUDIO_MGR_OPTIONS,NULL,HFILL}
         },
         { &hf_audio_mgr_alert,
            {"Query Audio Manager Alerting","unistim.audio.alerting",FT_BOOLEAN,
               8,NULL,QUERY_AUDIO_MGR_ALERTING ,NULL,HFILL}
         },
         { &hf_audio_mgr_adj_rx_vol,
            {"Query Audio Manager Adjustable Receive Volume","unistim.audio.adj.volume",FT_BOOLEAN,
               8,NULL,QUERY_AUDIO_MGR_ADJ_RX_VOL,NULL,HFILL}
         },
         { &hf_audio_mgr_def_rx_vol,
            {"Query Audio Manager Default Receive Volume","unistim.audio.def.volume",FT_BOOLEAN,
               8,NULL,QUERY_AUDIO_MGR_DEF_RX_VOL,NULL,HFILL}
         },
         { &hf_audio_mgr_handset,
            {"Query Audio Manager Handset","unistim.audio.handset",FT_BOOLEAN,
               8,NULL,QUERY_AUDIO_MGR_HANDSET,NULL,HFILL}
         },
         { &hf_audio_mgr_headset,
            {"Query Audio Manager Headset","unistim.audio.headset",FT_BOOLEAN,
               8,NULL,QUERY_AUDIO_MGR_HEADSET,NULL,HFILL}
         },
         { &hf_audio_default_rx_vol_id,
            {"Audio Manager Default Receive Volume ID","unistim.audio.volume.id",FT_UINT8,
               BASE_HEX,VALS(default_rx_vol_id),0x00,NULL,HFILL}
         },
         { &hf_audio_mgr_opt_max_vol,
            {"Audio Manager Enable Max Tone Volume","unistim.audio.max.tone",FT_BOOLEAN,
               8,TFS(&audio_opts_enable_max_tone_vol),AUDIO_MGR_OPTS_MAX_VOL,NULL,HFILL}
         },
         { &hf_audio_mgr_opt_adj_vol,
            {"Audio Manager Adjust Volume","unistim.audio.opts.adj.vol",FT_BOOLEAN,
               8,TFS(&audio_opts_adjust_volume),AUDIO_MGR_ADJ_VOL,NULL,HFILL}
         },
         { &hf_audio_mgr_opt_aa_rx_vol_rpt,
            {"Audio Manager Auto Adjust Volume RPT","unistim.audio.aa.vol.rpt",FT_BOOLEAN,
               8,TFS(&audio_opts_automatic_adjustable),AUDIO_MGR_AUTO_RX_VOL_RPT,NULL,HFILL}
         },
         { &hf_audio_mgr_opt_hs_on_air,
            {"Audio Manager Handset","unistim.audio.handset",FT_BOOLEAN,
               8,TFS(&audio_opts_hs_on_air_feature),AUDIO_MGR_HS_ON_AIR,NULL,HFILL}
         },
         { &hf_audio_mgr_opt_hd_on_air,
            {"Audio Manager Headset","unistim.audio.headset",FT_BOOLEAN,
               8,TFS(&audio_opts_hd_on_air_feature),AUDIO_MGR_HD_ON_AIR,NULL,HFILL}
         },
         { &hf_audio_mgr_opt_noise_squelch,
            {"Audio Manager Noise Squelch","unistim.audio.squelch",FT_BOOLEAN,
               8,TFS(&noise_sqlch_disable), AUDIO_MGR_NOISE_SQUELCH,NULL,HFILL}
         },
         { &hf_audio_mgr_mute,
            {"Audio Manager Mute","unistim.audio.mute",FT_BOOLEAN,
               8,TFS(&audio_mgr_mute_val),AUDIO_MGR_MUTE,NULL,HFILL}
         },
         { &hf_audio_mgr_tx_rx,
            {"Audio Manager RX or TX","unistim.audio.rx.tx",FT_BOOLEAN,
               8,TFS(&audio_mgr_tx_rx_val),AUDIO_MGR_TX_RX,NULL,HFILL}
         },
         { &hf_audio_mgr_stream_id,
            {"Audio Manager Stream ID","unistim.audio.stream.id",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_mgr_transducer_based_tone_id,
            {"Audio Manager Transducer Based Tone On","unistim.audio.transducer.on",FT_UINT8,
               BASE_HEX,VALS(trans_base_tone_ids),0x07,NULL,HFILL}
         },
         { &hf_audio_mgr_attenuated,
            {"Audio Manager Transducer Tone Attenuated","unistim.audio.attenuated.on",FT_BOOLEAN,
               8,NULL,AUDIO_MGR_ATTENUATED,NULL,HFILL}
         },
         { &hf_audio_mgr_warbler_select,
            {"Warbler Select","unistim.warbler.select",FT_UINT8,
               BASE_HEX,NULL,0x07,NULL,HFILL}
         },
         { &hf_audio_mgr_transducer_routing,
            {"Transducer Routing","unistim.transducer.routing",FT_UINT8,
               BASE_HEX,VALS(transducer_routing_vals),0xf8,NULL,HFILL}
         },
         { &hf_audio_mgr_tone_vol_range,
            {"Tone Volume Range in Steps","unistim.tone.volume.range",FT_UINT8,
               BASE_HEX,NULL,0x0f,NULL,HFILL}
         },
         { &hf_audio_mgr_cadence_select,
            {"Cadence Select","unistim.cadence.select",FT_UINT8,
               BASE_HEX,VALS(cadence_select_vals),0xf0,NULL,HFILL}
         },
         { &hf_audio_special_tone,
            {"Special Tone Select","unistim.special.tone.select",FT_UINT8,
               BASE_HEX,VALS(special_tones_vals),0x00,NULL,HFILL}
         },
         { &hf_audio_tone_level,
            {"Tone Level","unistim.audio.tone.level",FT_UINT8,
               BASE_DEC,NULL,0xf0,NULL,HFILL}
         },
         { &hf_audio_visual_tones,
            {"Enable Visual Tones","unistim.visual.tones",FT_BOOLEAN,
               8,NULL,AUDIO_MGR_VISUAL_TONE,NULL,HFILL}
         },
         { &hf_audio_stream_based_tone_id,
            {"Stream Based Tone ID","unistim.stream.tone.id",FT_UINT8,
               BASE_HEX,VALS(stream_based_tone_vals),0x1f,NULL,HFILL}
         },
         { &hf_audio_stream_based_tone_rx_tx,
            {"Stream Based Tone RX or TX","unistim.stream.based.tone.rx.tx",FT_BOOLEAN,
               8,TFS(&stream_based_tone_rx_tx_yn),AUDIO_STREAM_BASED_TONE_RX_TX,NULL,HFILL}
         },
         { &hf_audio_stream_based_tone_mute,
            {"Stream Based Tone Mute","unistim.stream.tone.mute",FT_BOOLEAN,
               8,TFS(&stream_based_tone_mute_yn),AUDIO_STREAM_BASED_TONE_MUTE,NULL,HFILL}
         },
         { &hf_audio_stream_id,
            {"Stream ID","unistim.audio.stream.id",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_stream_based_volume,
            {"Stream Based Volume ID","unistim.stream.volume.id",FT_UINT8,
               BASE_HEX,VALS(stream_base_vol_level),0x00,NULL,HFILL}
         },
         { &hf_basic_switch_terminal_id,
            {"Terminal ID assigned by Switch","unistim.switch.terminal.id",FT_IPv4,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_basic_it_type,
            {"IT (Phone) Type","unistim.it.type",FT_UINT8,
               BASE_HEX,VALS(it_types),0x00,NULL,HFILL}
         },
         { &hf_basic_prod_eng_code,
            {"Product Engineering Code for phone","unistim.basic.eng.code",FT_STRING,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_net_phone_primary_server_id,
            {"Phone Primary Server ID","unistim.net.phone.primary.id",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_net_phone_server_port,
            {"Port Number","unistim.server.port",FT_UINT16,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_net_phone_server_action,
            {"Action","unistim.server.action.byte",FT_UINT8,
               BASE_HEX,VALS(action_bytes),0x00,NULL,HFILL}
         },
         { &hf_net_phone_server_retry_count,
            {"Number of times to Retry","unistim.server.retry.count",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_net_phone_server_failover_id,
            {"Failover Server ID","unistim.server.failover.id",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_net_phone_server_ip,
            {"IP address","unistim.server.ip.address",FT_IPv4,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_apb_number,
            {"APB Number","unistim.audio.apb.number",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { & hf_audio_apb_op_code,
            {"APB Operation Code","unistim.audio.apb.op.code",FT_UINT8,
               BASE_HEX,VALS(apb_op_codes),0x00,NULL,HFILL}
         },
         { &hf_audio_apb_param_len,
            {"APB Operation Parameter Length","unistim.apb.param.len",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_apb_data,
            {"APB Operation Data","unistim.apb.operation.data",FT_BYTES,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_display_write_address_numeric,
            {"Is Address Numeric","unistim.write.address.numeric",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_ADDRESS_NUMERIC_FLAG,NULL,HFILL}
         },
         { &hf_display_write_address_context,
            {"Context Field in the Info Bar","unistim.write.address.context",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_ADDRESS_CONTEXT_FLAG,NULL,HFILL}
         },
         { &hf_display_write_address_line,
            {"Write A Line","unistim.write.address.line",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_ADDRESS_LINE_FLAG ,NULL,HFILL}
         },
         { &hf_display_write_address_soft_key,
            {"Write a SoftKey","unistim.write.address.softkey",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG,NULL,HFILL}
         },
         { &hf_display_write_address_soft_label,
            {"Write A Softkey Label","unistim.write.address.softkey.label",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG,NULL,HFILL}
         },
         { &hf_display_write_address_softkey_id,
            {"Soft Key ID","unistim.write.addres.softkey.id",FT_UINT8,
               BASE_HEX,NULL,DISPLAY_WRITE_ADDRESS_SOFT_KEY_ID,NULL,HFILL}
         },
         { &hf_display_write_address_char_pos,
            {"Character Position or Soft-Label Key ID","unistim.display.write.address.char.pos",FT_UINT8,
               BASE_HEX,NULL,DISPLAY_WRITE_ADDRESS_CHAR_POS,NULL,HFILL}
         },
         { &hf_display_write_address_line_number,
            {"Line Number","unistim.write.address.line.number",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_WRITE_ADDRESS_LINE_NUM,NULL,HFILL}
         },
         { &hf_display_write_cursor_move,
            {"Cursor Move","unistim.display.cursor.move",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_CURSOR_MOVE,NULL,HFILL}
         },
         { &hf_display_write_clear_left,
            {"Clear Left","unistim.display.clear.left",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_CLEAR_LEFT,NULL,HFILL}
         },
         { &hf_display_write_clear_right,
            {"Clear Right","unistim.display.clear.right",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_CLEAR_RIGHT,NULL,HFILL}
         },
         { &hf_display_write_shift_left,
            {"Shift Left","unistim.display.shift.left",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_SHIFT_LEFT,NULL,HFILL}
         },
         { &hf_display_write_shift_right,
            {"Shift Right","unistim.display.shift.right",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_SHIFT_RIGHT,NULL,HFILL}
         },
         { &hf_display_write_highlight,
            {"Highlight","unistim.display.highlight",FT_BOOLEAN,
               8,NULL,DISPLAY_WRITE_HIGHLIGHT,NULL,HFILL}
         },
         { &hf_display_write_tag,
            {"Tag for text","unistim.display.text.tag",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_display_cursor_move_cmd,
            {"Cursor Movement Command","unistim.cursor.move.cmd",FT_UINT8,
               BASE_HEX,VALS(cursor_move_cmds),DISPLAY_CURSOR_MOVE_CMD,NULL,HFILL}
         },
         { &hf_display_cursor_blink,
            {"Should Cursor Blink","unistim.cursor.blink",FT_BOOLEAN,
               8,NULL,DISPLAY_CURSOR_BLINK,NULL,HFILL}
         },
         { &hf_audio_vocoder_id,
            {"Vocoder Protocol","unistim.vocoder.id",FT_UINT8,
               BASE_HEX,VALS(vocoder_ids),0x00,NULL,HFILL}
         },
         { &hf_audio_vocoder_param,
            {"Vocoder Config Param","unistim.vocoder.config.param",FT_UINT8,
               BASE_HEX,VALS(vocoder_config_params),AUDIO_VOCODER_CONFIG_PARAM,NULL,HFILL}
         },
         { &hf_audio_vocoder_entity,
            {"Vocoder Entity","unistim.vocoder.entity",FT_UINT8,
               BASE_HEX,VALS(config_param_entities),AUDIO_VOCODER_CONFIG_ENTITY,NULL,HFILL}
         },
         { &hf_audio_vocoder_annexa,
            {"Enable Annex A","unistim.enable.annexa",FT_BOOLEAN,
               8,NULL,AUDIO_VOCODER_ANNEXA,NULL,HFILL}
         },
         { &hf_audio_vocoder_annexb,
            {"Enable Annex B","unistim.enable.annexb",FT_BOOLEAN,
               8,NULL,AUDIO_VOCODER_ANNEXB,NULL,HFILL}
         },
         { &hf_audio_sample_rate,
            {"Sample Rate","unistim.audio.sample.rate",FT_UINT8,
               BASE_HEX,VALS(sample_rates),0x00,NULL,HFILL}
         },
         { &hf_audio_rtp_type,
            {"RTP Type","unistim.audio.rtp.type",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_bytes_per_frame,
            {"Bytes Per Frame","unistim.audio.bytes.per.frame",FT_UINT16,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_rx_stream_id,
            {"Receive Stream Id","unistim.rx.stream.id",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_tx_stream_id,
            {"Transmit Stream Id","unistim.rx.stream.id",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_rx_vocoder_type,
            {"Receive Vocoder Protocol","unistim.vocoder.id",FT_UINT8,
               BASE_HEX,VALS(vocoder_ids),0x00,NULL,HFILL}
         },
         { &hf_tx_vocoder_type,
            {"Transmit Vocoder Protocol","unistim.vocoder.id",FT_UINT8,
               BASE_HEX,VALS(vocoder_ids),0x00,NULL,HFILL}
         },
         { &hf_frames_per_packet,
            {"Frames Per Packet","unistim.vocoder.frames.per.packet",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_tos,
            {"Type of Service","unistim.audio.type.service",FT_UINT8,
               BASE_HEX,VALS(types_of_service),AUDIO_TYPE_OF_SERVICE,NULL,HFILL}
         },
         { &hf_audio_precedence,
            {"Precedence","unistim.audio.precedence",FT_UINT8,
               BASE_HEX,VALS(precedences),AUDIO_PRECENDENCE,NULL,HFILL}
         },
         { &hf_audio_frf_11,
            {"FRF.11 Enable","unistim.audio.frf.11",FT_BOOLEAN,
               8,NULL,AUDIO_FRF_11,NULL,HFILL}
         },
         { &hf_audio_lcl_rtp_port,
            {"Phone RTP Port","unistim.local.rtp.port",FT_UINT16,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_lcl_rtcp_port,
            {"Phone RTCP Port","unistim.local.rtcp.port",FT_UINT16,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_far_rtp_port,
            {"Distant RTP Port","unistim.far.rtp.port",FT_UINT16,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_far_rtcp_port,
            {"Distant RTCP Port","unistim.far.rtcp.port",FT_UINT16,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_far_ip_add,
            {"Distant IP Address for RT[C]P","unistim.far.ip.address",FT_IPv4,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_rtcp_bucket_id,
            {"RTCP Bucket ID","unistim.rtcp.bucket.id",FT_UINT16,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_key_icon_id,
            {"Icon ID","unistim.key.icon.id",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_display_clear_numeric,
            {"Numeric Index Field in InfoBar","unistim.display.clear.numeric",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_NUMERIC,NULL,HFILL}
         },
         { &hf_display_clear_context ,
            {"Context Field in InfoBar","unistim.display.clear.context",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_CONTEXT,NULL,HFILL}
         },
         { &hf_display_clear_date ,
            {"Date Field","unistim.display.clear.date",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_DATE,NULL,HFILL}
         },
         { &hf_display_clear_time,
            {"Time Field","unistim.display.clear.time",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_TIME,NULL,HFILL}
         },
         { &hf_display_clear_line,
            {"Line Data","unistim.display.clear.line",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_LINE,NULL,HFILL}
         },
         { &hf_display_clear_status_bar_icon,
            {"Status Bar Icon","unistim.display.statusbar.icon",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_STATUS_BAR_ICON,NULL,HFILL}
         },
         { &hf_display_clear_softkey,
            {"Soft Key","unistim.display.clear.softkey",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_SOFTKEY,NULL,HFILL}
         },
         { &hf_display_clear_softkey_label ,
            {"Soft Key Label","unistim.display.clear.softkey.label",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_SOFTKEY_LABEL,NULL,HFILL}
         },
         { &hf_display_clear_line_1 ,
            {"Line 1","unistim.display.clear.line1",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_LINE_1,NULL,HFILL}
         },
         { &hf_display_clear_line_2 ,
            {"Line 2","unistim.display.clear.line2",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_LINE_2,NULL,HFILL}
         },
         { &hf_display_clear_line_3 ,
            {"Line 3","unistim.display.clear.line3",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_LINE_3,NULL,HFILL}
         },
         { &hf_display_clear_line_4 ,
            {"Line 4","unistim.display.clear.line4",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_LINE_4,NULL,HFILL}
         },
         { &hf_display_clear_line_5 ,
            {"Line 5","unistim.display.clear.line5",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_LINE_5,NULL,HFILL}
         },
         { &hf_display_clear_line_6 ,
            {"Line 6","unistim.display.clear.line6",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_LINE_6,NULL,HFILL}
         },
         { &hf_display_clear_line_7 ,
            {"Line 7","unistim.display.clear.line7",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_LINE_7,NULL,HFILL}
         },
         { &hf_display_clear_line_8 ,
            {"Line 8","unistim.display.clear.line8",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_LINE_8,NULL,HFILL}
         },
         { &hf_display_clear_status_bar_icon_1 ,
            {"Status Bar Icon 1","unistim.display.clear.sbar.icon1",FT_BOOLEAN,
               8,NULL,DISPLAY_STATUS_BAR_ICON_1,NULL,HFILL}
         },
         { &hf_display_clear_status_bar_icon_2 ,
            {"Status Bar Icon 2","unistim.display.clear.sbar.icon2",FT_BOOLEAN,
               8,NULL,DISPLAY_STATUS_BAR_ICON_2,NULL,HFILL}
         },
         { &hf_display_clear_status_bar_icon_3 ,
            {"Status Bar Icon 3","unistim.display.clear.sbar.icon3",FT_BOOLEAN,
               8,NULL,DISPLAY_STATUS_BAR_ICON_3,NULL,HFILL}
         },
         { &hf_display_clear_status_bar_icon_4 ,
            {"Status Bar Icon 4","unistim.display.clear.sbar.icon4",FT_BOOLEAN,
               8,NULL,DISPLAY_STATUS_BAR_ICON_4,NULL,HFILL}
         },
         { &hf_display_clear_status_bar_icon_5 ,
            {"Status Bar Icon 5","unistim.display.clear.sbar.icon5",FT_BOOLEAN,
               8,NULL,DISPLAY_STATUS_BAR_ICON_5,NULL,HFILL}
         },
         { &hf_display_clear_status_bar_icon_6 ,
            {"Status Bar Icon 6","unistim.display.clear.sbar.icon6",FT_BOOLEAN,
               8,NULL,DISPLAY_STATUS_BAR_ICON_6,NULL,HFILL}
         },
         { &hf_display_clear_status_bar_icon_7 ,
            {"Status Bar Icon 7","unistim.display.clear.sbar.icon7",FT_BOOLEAN,
               8,NULL,DISPLAY_STATUS_BAR_ICON_7,NULL,HFILL}
         },
         { &hf_display_clear_status_bar_icon_8 ,
            {"Status Bar Icon 8","unistim.display.clear.sbar.icon8",FT_BOOLEAN,
               8,NULL,DISPLAY_STATUS_BAR_ICON_8,NULL,HFILL}
         },
         { &hf_display_clear_soft_key_1 ,
            {"Soft Key 1","unistim.display.clear.soft.key1",FT_BOOLEAN,
               8,NULL,DISPLAY_SOFT_KEY_1,NULL,HFILL}
         },
         { &hf_display_clear_soft_key_2 ,
            {"Soft Key 2","unistim.display.clear.soft.key2",FT_BOOLEAN,
               8,NULL,DISPLAY_SOFT_KEY_2,NULL,HFILL}
         },
         { &hf_display_clear_soft_key_3 ,
            {"Soft Key 3","unistim.display.clear.soft.key3",FT_BOOLEAN,
               8,NULL,DISPLAY_SOFT_KEY_3,NULL,HFILL}
         },
         { &hf_display_clear_soft_key_4 ,
            {"Soft Key 4","unistim.display.clear.soft.key4",FT_BOOLEAN,
               8,NULL,DISPLAY_SOFT_KEY_4,NULL,HFILL}
         },
         { &hf_display_clear_soft_key_5 ,
            {"Soft Key 5","unistim.display.clear.soft.key5",FT_BOOLEAN,
               8,NULL,DISPLAY_SOFT_KEY_5,NULL,HFILL}
         },
         { &hf_display_clear_soft_key_6 ,
            {"Soft Key 6","unistim.display.clear.soft.key6",FT_BOOLEAN,
               8,NULL,DISPLAY_SOFT_KEY_6,NULL,HFILL}
         },
         { &hf_display_clear_soft_key_7 ,
            {"Soft Key 7","unistim.display.clear.soft.key7",FT_BOOLEAN,
               8,NULL,DISPLAY_SOFT_KEY_7,NULL,HFILL}
         },
         { &hf_display_clear_soft_key_8 ,
            {"Soft Key 8","unistim.display.clear.soft.key8",FT_BOOLEAN,
               8,NULL,DISPLAY_SOFT_KEY_8,NULL,HFILL}
         },
         { &hf_display_clear_sk_label_key_id,
            {"Soft Key Label ID","unistim.display.clear.sk.label.id",FT_UINT8,
               BASE_HEX,NULL, DISPLAY_CLEAR_SK_LABEL_KEY_ID,NULL,HFILL}
         },
         { &hf_display_clear_all_slks,
            {"Clear All Soft Key Labels","unistim.display.clear.all.sks",FT_BOOLEAN,
               8,NULL,DISPLAY_CLEAR_ALL_SLKS,NULL,HFILL}
         },
         { &hf_key_led_cadence,
            {"LED Cadence","unistim.key.led.cadence",FT_UINT8,
               BASE_HEX,VALS(led_cadences),KEY_LED_CADENCE,NULL,HFILL}
         },
         { &hf_key_led_id,
            {"LED ID","unistim.key.led.id",FT_UINT8,
               BASE_HEX,VALS(led_ids),KEY_LED_ID,NULL,HFILL}
         },
         { &hf_basic_ether_address,
            {"Phone Ethernet Address","unistim.phone.ether",FT_ETHER,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_rtcp_bucket_id,
            {"RTCP Bucket ID","unistim.audio.rtcp.bucket.id",FT_UINT8,
               BASE_HEX,NULL,AUDIO_RTCP_BUCKET_ID,NULL,HFILL}
         },
         { &hf_audio_clear_bucket,
            {"Clear Bucket Counter","unistim.clear.bucket",FT_BOOLEAN,
               8,NULL,AUDIO_CLEAR_BUCKET,NULL,HFILL}
         },
         { &hf_display_arrow,
            {"Arrow Display Direction","unistim.arrow.direction",FT_UINT8,
               BASE_HEX,VALS(arrow_dirs),0x00,NULL,HFILL}
         },
         { &hf_audio_transducer_pair,
            {"Audio Transducer Pair","unistim.transducer.pairs",FT_UINT8,
               BASE_HEX,VALS(transducer_pairs),AUDIO_TRANSDUCER_PAIR_ID,NULL,HFILL}
         },
         { &hf_audio_rx_enable,
            {"RX Enable","unistim.receive.enable",FT_BOOLEAN,
               8,NULL,AUDIO_RX_ENABLE,NULL,HFILL}
         },
         { &hf_audio_tx_enable,
            {"TX Enable","unistim.transmit.enable",FT_BOOLEAN,
               8,NULL,AUDIO_TX_ENABLE,NULL,HFILL}
         },
         { &hf_audio_sidetone_disable,
            {"Disable Sidetone","unistim.audio.sidetone.disable",FT_BOOLEAN,
               8,NULL,AUDIO_SIDETONE_DISABLE,NULL,HFILL}
         },
         { &hf_audio_destruct_additive,
            {"Destructive/Additive","unistim.destructive.active",FT_BOOLEAN,
               8,TFS(&destruct_additive),AUDIO_DESTRUCT_ADD,NULL,HFILL}
         },
         { &hf_audio_dont_force_active,
            {"Don't Force Active","unistim.dont.force.active",FT_BOOLEAN,
               8,TFS(&dont_force_active),AUDIO_DONT_FORCE_ACTIVE,NULL,HFILL}
         },
         { &hf_display_line_width,
            {"Phone Line Width","unistim.line.width",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_LINE_WIDTH,NULL,HFILL}
         },
         { &hf_display_lines,
            {"Number Of Lines","unistim.number.lines",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_LINES,NULL,HFILL}
         },
         { &hf_display_softkey_width,
            {"Phone Softkey Width","unistim.softkey.width",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_SKEY_WIDTH,NULL,HFILL}
         },
         { &hf_display_softkeys,
            {"Phone Softkeys","unistim.phone.softkeys",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_SKEYS,NULL,HFILL}
         },
         { &hf_display_icon,
            {"Phone Icon Type","unistim.phone.icon.type",FT_UINT8,
               BASE_HEX,VALS(icon_types),DISPLAY_ICON,NULL,HFILL}
         },
         { &hf_display_softlabel_key_width,
            {"Soft-Label Key width","unistim.softlabel.key.width",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_SOFTLABEL_WIDTH,NULL,HFILL}
         },
         { &hf_display_context_width,
            {"Phone Context Width","unistim.context.width",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_CONTEXT_WIDTH,NULL,HFILL}
         },
         { &hf_display_numeric_width,
            {"Phone Numeric Width","unistim.numeric.width",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_NUMERIC_WIDTH,NULL,HFILL}
         },
         { &hf_display_time_width,
            {"Phone Time Width","unistim.time.width",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_TIME_WIDTH,NULL,HFILL}
         },
         { &hf_display_date_width,
            {"Phone Date Width","unistim.date.width",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_DATE_WIDTH,NULL,HFILL}
         },
         { &hf_display_char_dload,
            {"Number of Downloadable Chars","unistim.number.dload.chars",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_CHAR_DLOAD,NULL,HFILL}
         },
         { &hf_display_freeform_icon_dload,
            {"Number of Freeform Icon Downloads","unistim.number.dload.icons",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_FFORM_ICON_DLOAD,NULL,HFILL}
         },
         { &hf_display_icon_type,
            {"Icon Types","unistim.icon.types",FT_UINT8,
               BASE_HEX,NULL,DISPLAY_ICON_TYPE,NULL,HFILL}
         },
         { &hf_display_charsets,
            {"Character Sets","unistim.phone.charsets",FT_UINT8,
               BASE_HEX,NULL,DISPLAY_CHARSET,NULL,HFILL}
         },
         { &hf_display_contrast,
            {"Phone Contrast Level","unistim.phone.contrast.level",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_display_cursor_numeric,
            {"Numeric Index Field","unistim.field.numeric",FT_BOOLEAN,
               8,NULL,DISPLAY_CURSOR_NUMERIC,NULL,HFILL}
         },
         { &hf_display_cursor_context,
            {"Context Field","unistim.field.context",FT_BOOLEAN,
               8,NULL,DISPLAY_CURSOR_CONTEXT,NULL,HFILL}
         },
         { &hf_display_cursor_line,
            {"Text Line","unistim.field.text.line",FT_BOOLEAN,
               8,NULL,DISPLAY_CURSOR_LINE,NULL,HFILL}
         },
         { &hf_display_cursor_softkey,
            {"Softkey Position","unistim.position.skey",FT_BOOLEAN,
               8,NULL,DISPLAY_CURSOR_SKEY,NULL,HFILL}
         },
         { &hf_display_cursor_softkey_id,
            {"Soft Key Id","unistim.cursor.skey.id",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_CURSOR_SKEY_ID,NULL,HFILL}
         },
         { &hf_display_cursor_char_pos,
            {"Character Position","unistim.phone.char.pos",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_CURSOR_CHAR_POS,NULL,HFILL}
         },
         { &hf_display_cursor_line_number,
            {"Display Line Number","unistim.display.line.number",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_CURSOR_LINE_NUM,NULL,HFILL}
         },
         { &hf_display_hlight_start,
            {"Display Highlight Start Position","unistim.hilite.start.pos",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_display_hlight_end,
            {"Display Highlight End Position","unistim.hilite.end.pos",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_display_date_format,
            {"Date Format","unistim.display.date.format",FT_UINT8,
               BASE_HEX,VALS(date_formats),DISPLAY_DATE_FORMAT,NULL,HFILL}
         },
         { &hf_display_time_format,
            {"Time Format","unistim.display.time.format",FT_UINT8,
               BASE_HEX,VALS(time_formats),DISPLAY_TIME_FORMAT,NULL,HFILL}
         },
         { &hf_display_use_time_format,
            {"Use Time Format","unistim.display.use.time.format",FT_BOOLEAN,
               8,NULL,DISPLAY_USE_TIME_FORMAT,NULL,HFILL}
         },
         { &hf_display_use_date_format,
            {"Use Date Format","unistim.display.use.date.format",FT_BOOLEAN,
               8,NULL,DISPLAY_USE_DATE_FORMAT,NULL,HFILL}
         },
         { &hf_display_context_format,
            {"Context Info Bar Format","unistim.display.context.format",FT_UINT8,
               BASE_HEX,VALS(display_formats),DISPLAY_CTX_FORMAT,NULL,HFILL}
         },
         { &hf_display_context_field,
            {"Context Info Bar Field","unistim.display.context.field",FT_UINT8,
               BASE_HEX,VALS(display_format_fields),DISPLAY_CTX_FIELD,NULL,HFILL}
         },
         { &hf_display_char_address,
            {"Display Character Address","unistim.display.char.address",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_display_layer_number,
            {"Softkey Layer Number","unistim.softkey.layer.num",FT_UINT8,
               BASE_HEX,NULL,0x00,NULL,HFILL}
         },
         { &hf_display_layer_skey_id,
            {"Softkey ID","unistim.layer.softkey.id",FT_UINT8,
               BASE_DEC,NULL,DISPLAY_LAYER_SKEY_ID,NULL,HFILL}
         },
         { &hf_display_layer_all_skeys,
            {"All Softkeys","unistim.layer.all.skeys",FT_BOOLEAN,
               8,NULL,DISPLAY_LAYER_ALL_SKEYS,NULL,HFILL}
         },
         { &hf_display_once_or_cyclic,
            {"Layer Softkey Once/Cyclic","unistim.layer.once.cyclic",FT_BOOLEAN,
               8,TFS(&once_or_cyclic),DISPLAY_ONE_OR_CYCLIC,NULL,HFILL}
         },
         { &hf_display_layer_duration,
            {"Display Duration (20ms steps)","unistim.layer.display.duration",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_key_programmable_keys,
            {"Number of Programmable Keys","unistim.num.prog.keys",FT_UINT8,
               BASE_DEC,NULL,KEY_NUM_PROG_KEYS,NULL,HFILL}
         },
         { &hf_keys_soft_keys,
            {"Number of Soft Keys","unistim.num.soft.keys",FT_UINT8,
               BASE_DEC,NULL,KEY_NUM_SOFT_KEYS,NULL,HFILL}
         },
         { &hf_keys_hd_key,
            {"Headset Key Exists","unistim.exist.hd.key",FT_BOOLEAN,
               8,NULL,KEY_HD_KEY_EXISTS,NULL,HFILL}
         },
         { &hf_keys_mute_key,
            {"Mute Key Exists","unistim.exist.mute.key",FT_BOOLEAN,
               8,NULL,KEY_MUTE_KEY_EXISTS,NULL,HFILL}
         },
         { &hf_keys_quit_key,
            {"Quit Key Exists","unistim.exist.quit.key",FT_BOOLEAN,
               8,NULL,KEY_QUIT_KEY_EXISTS,NULL,HFILL}
         },
         { &hf_keys_copy_key,
            {"Copy Key Exists","unistim.exist.copy.key",FT_BOOLEAN,
               8,NULL,KEY_COPY_KEY_EXISTS,NULL,HFILL}
         },
         { &hf_keys_mwi_key,
            {"Message Waiting Indicator Exists","unistim.exist.mwi.key",FT_BOOLEAN,
               8,NULL,KEY_MWI_EXISTS,NULL,HFILL}
         },
         { &hf_keys_num_nav_keys,
            {"Number of Navigation Keys","unistim.num.nav.keys",FT_UINT8,
               BASE_DEC,VALS(number_nav_keys),KEY_NUM_NAV_KEYS,NULL,HFILL}
         },
         { &hf_keys_num_conspic_keys,
            {"Number Of Conspicuous Keys","unistim.num.conspic.keys",FT_UINT8,
               BASE_DEC,NULL,KEY_NUM_CONSPIC_KEYS,NULL,HFILL}
         },
         { &hf_keys_send_key_rel,
            {"Send Key Release","unistim.key.send.release",FT_BOOLEAN,
               8,TFS(&key_release),KEY_SEND_KEY_RELEASE,NULL,HFILL}
         },
         { &hf_keys_enable_vol,
            {"Enable Volume Control","unistim.key.enable.vol",FT_BOOLEAN,
               8,TFS(&enable_vol),KEY_ENABLE_VOL_KEY,NULL,HFILL}
         },
         { &hf_keys_conspic_prog_key,
            {"Conspicuous and Programmable Keys Same","unistim.conspic.prog.keys",FT_BOOLEAN,
               8,TFS(&conspic_prog),KEY_CONSPIC_PROG_KEY0,NULL,HFILL}
         },
         { &hf_keys_acd_super_control,
            {"ACD Supervisor Control","unistim.acd.super.control",FT_BOOLEAN,
               8,TFS(&acd_supervisor),KEY_ACD_SUP_CONTROL,NULL,HFILL}
         },
         { &hf_keys_local_dial_feedback,
            {"Local Keypad Feedback","unistim.key.feedback",FT_UINT8,
               BASE_HEX,VALS(local_dialpad_feedback),KEY_LOCAL_DIAL_PAD_FEED,NULL,HFILL}
         },
         { &hf_audio_source_descr,
            {"Source Description Item","unistim.source.desc.item",FT_UINT8,
               BASE_HEX,VALS(source_descriptions),AUDIO_SOURCE_DESCRIPTION,NULL,HFILL}
         },
         { &hf_audio_sdes_rtcp_bucket,
            {"RTCP Bucket Id","unistim.sdes.rtcp.bucket",FT_UINT8,
               BASE_HEX,NULL,AUDIO_SDES_RTCP_BUCKET,NULL,HFILL}
         },
         { &hf_audio_desired_jitter,
            {"Desired Jitter","unistim.audio.desired.jitter",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_high_water_mark,
            {"Threshold of audio frames where jitter buffer removes frames","unistim.high.water.mark",FT_UINT8,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         {  &hf_audio_early_packet_resync_thresh,
            {"Threshold in x/8000 sec where packets are too early","unistim.early.packet.thresh",FT_UINT32,
              BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_late_packet_resync_thresh,
            {"Threshold in x/8000 sec where packets are too late","unistim.late.packet.thresh",FT_UINT32,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_resolve_phone_port,
            {"Resolve Phone Port","unistim.resolve.phone.port",FT_UINT16,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_far_end_echo_port,
            {"Resolve Far End Port","unistim.resolve.far.port",FT_UINT16,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_far_end_ip_address,
            {"Resolve Far End IP","unistim.resolve.far.ip",FT_IPv4,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_nat_port,
            {"NAT Port","unistim.audio.nat.port",FT_UINT16,
               BASE_DEC,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_nat_ip_address,
            {"NAT IP Address","unistim.audio.nat.ip",FT_IPv4,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_audio_direction_code,
            {"Stream Direction Code","unistim.audio.direction.codes",FT_UINT8,
               BASE_HEX,VALS(direction_codes),AUDIO_DIRECTION_CODE,NULL,HFILL}
         },
         { &hf_audio_hf_support,
            {"Handsfree supported","unistim.handsfree.support",FT_BOOLEAN,
               8,NULL,AUDIO_HF_SUPPORT,NULL,HFILL}
         },
         { &hf_audio_opt_rpt_max,
            {"Max Volume","unistim.max.vol",FT_BOOLEAN,
               8,TFS(&opt_rpt_enable_max_tone_vol),AUDIO_ENABLED_MAX_TONE,NULL,HFILL}
         },
         { &hf_audio_opt_rpt_adj_vol,
            {"Volume Adjustments","unistim.audio.volume.adj",FT_BOOLEAN,
               8,TFS(&opt_rpt_adjust_volume),AUDIO_ENABLED_ADJ_VOL,NULL,HFILL}
         },
         { &hf_audio_opt_rpt_auto_adj_vol,
            {"Auto Adjust RX Volume","unistim.auto.adj.rx.vol",FT_BOOLEAN,
               8,TFS(&opt_rpt_automatic_adjustable_rx_volume_report),
               AUDIO_AUTO_ADJ_RX_REP,NULL,HFILL}
         },
         { &hf_audio_opt_rpt_hs_on_air,
            {"HS On Air","unistim.audio.hs.on.air",FT_BOOLEAN,
               8,TFS(&opt_rpths_on_air_feature),AUDIO_HS_ON_AIR_FEATURE,NULL,HFILL}
         },
         { &hf_audio_opt_rpt_hd_on_air,
            {"HD On Air","unistim.audio.hd.on.air",FT_BOOLEAN,
               8,TFS(&opt_rpt_hd_on_air_feature),AUDIO_HD_ON_AIR_FEATURE,NULL,HFILL}
         },
         { &hf_audio_opt_rpt_noise_squelch,
            {"Automatic Squelch","unistim.auto.noise.squelch",FT_BOOLEAN,
               8,TFS(&opt_rpt_noise_sqlch_disable),AUDIO_NOISE_SQUELCH_DIS,NULL,HFILL}
         },
         { &hf_audio_rx_vol_apb_rpt,
            {"APB Volume Report","unistim.apb.volume.rpt",FT_UINT8,
               BASE_HEX,VALS(volume_rpt_apbs),AUDIO_APB_VOL_RPT,NULL,HFILL}
         },
         { &hf_audio_rx_vol_vol_up,
            {"Volume Up","unistim.audio.volume.up",FT_BOOLEAN,
               8,NULL,AUDIO_VOL_UP_RPT,NULL,HFILL}
         },
         { &hf_audio_rx_vol_vol_floor,
            {"RX Volume at Floor","unistim.audio.rx.vol.floor",FT_BOOLEAN,
               8,NULL,AUDIO_VOL_FLR_RPT,NULL,HFILL}
         },
         { &hf_audio_rx_vol_vol_ceiling,
            {"RX Volume at Ceiling","unistim.audio.rx.vol.ceiling",FT_BOOLEAN,
               8,NULL,AUDIO_VOL_CEIL_RPT,NULL,HFILL}
         },
         { &hf_audio_current_adj_vol_id,
            {"Current APB Volume Report","unistim.current.volume.rpt",FT_UINT8,
               BASE_HEX,VALS(volume_rpt_apbs),AUDIO_APB_VOL_RPT,NULL,HFILL}
          },
          { &hf_audio_current_rx_level,
             {"Current RX Volume Level","unistim.current.rx.vol.level",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_audio_current_rx_range,
             {"Current RX Volume Range","unistim.current.rx.vol.range",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_audio_cadence_select,
             {"Alerting Cadence Select","unistim.alert.cad.sel",FT_UINT8,
                BASE_HEX,NULL,AUDIO_ALERT_CADENCE_SEL,NULL,HFILL}
          },
          { &hf_audio_warbler_select,
             {"Alerting Warbler Select","unistim.alert.warb.select",FT_UINT8,
                BASE_HEX,NULL,AUDIO_ALERT_WARBLER_SEL,NULL,HFILL}
          },
          { &hf_audio_open_stream_rpt,
             {"Open Stream Report","unistim.open.audio.stream.rpt",FT_UINT8,
                BASE_HEX,VALS(stream_result),0x00,NULL,HFILL}
          },
          { &hf_audio_sdes_rpt_source_desc,
             {"Report Source Description","unistim.rpt.src.desc",FT_UINT8,
                BASE_HEX,VALS(source_descipts),AUDIO_SDES_INFO_RPT_DESC,NULL,HFILL}
          },
          { &hf_audio_sdes_rpt_buk_id,
             {"Report RTCP Bucket ID","unistim.rpt.rtcp.buk.id",FT_UINT8,
                BASE_HEX,NULL,AUDIO_SDES_INFO_RPT_BUK,NULL,HFILL}
          },
          { &hf_audio_phone_port,
             {"Phone Listen Port","unistim.phone.listen.port",FT_UINT16,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_audio_phone_ip,
             {"Phone Listen Address","unistim.phone.listen.address",FT_IPv4,
                BASE_NONE,NULL,0x00,NULL,HFILL}
          },
          { &hf_audio_phone_add_len,
             {"Phone Address Length","unistim.phone.address.len",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_audio_nat_listen_port,
             {"NAT Listen Port","unistim.nat.listen.port",FT_UINT16,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_audio_nat_ip,
             {"NAT Listen Address","unistim.nat.listen.address",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_audio_nat_add_len,
             {"NAT Address Length","unistim.nat.address.len",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_audio_stream_direction_code,
             {"Audio Stream Direction","unistim.audio.stream.direction",FT_UINT8,
                BASE_HEX,VALS(stream_direction_codes),AUDIO_STREAM_DIRECTION,NULL,HFILL}
          },
          { &hf_audio_stream_state,
             {"Audio Stream State","unistim.audio.stream.state",FT_BOOLEAN,
                8,TFS(&stream_states),AUDIO_STREAM_STATE,NULL,HFILL}
          },
          { &hf_audio_transducer_list_length,
             {"Transducer List Length","unistim.trans.list.len",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_net_file_xfer_mode,
             {"File Transfer Mode","unistim.net.file.xfer.mode",FT_UINT8,
                BASE_HEX,VALS(file_xfer_modes),NETWORK_FILE_XFER_MODE,NULL,HFILL}
          },
          { &hf_net_force_download ,
             {"Force Download","unistim.net.force.download",FT_BOOLEAN,
                8,NULL,NETWORK_FORCE_DLOAD,NULL,HFILL}
          },
          { &hf_net_use_file_server_port,
             {"Use Custom Server Port","unistim.net.use.server.port",FT_BOOLEAN,
                8,NULL,NETWORK_USE_FSERV_PORT,NULL,HFILL}
          },
          { &hf_net_use_local_port,
             {"Use Custom Local Port","unistim.net.use.local.port",FT_BOOLEAN,
                8,NULL,NETWORK_USE_LOCAL_PORT,NULL,HFILL}
          },
          { &hf_net_file_server_port,
             {"File Server Port","unistim.net.file.server.port",FT_UINT16,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_net_full_pathname,
             {"Full Pathname","unistim.net.full_pathname",FT_STRINGZ,
                BASE_NONE,NULL,0x00,NULL,HFILL}
          },
          { &hf_net_file_identifier,
             {"File Identifier","unistim.net.file_identifier",FT_STRINGZ,
                BASE_NONE,NULL,0x00,NULL,HFILL}
          },
          { &hf_net_local_port,
             {"Local XFer Port","unistim.net.local.xfer.port",FT_UINT16,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_net_file_server_address,
             {"File Server IP Address","unistim.net.file.server.address",FT_IPv4,
                BASE_NONE,NULL,0x00,NULL,HFILL}
          },
          { &hf_keys_admin_command,
             {"Admin Command","unistim.key.icon.admin.cmd",FT_UINT8,
                BASE_HEX,VALS(admin_commands),KEY_ADMIN_CMD,NULL,HFILL}
          },
          { &hf_keys_logical_icon_id,
             {"Logical Icon ID","unistim.keys.logical.icon.id",FT_UINT16,
                BASE_HEX,NULL,0x00,NULL,HFILL}
          },
          { &hf_keys_repeat_timer_one,
             {"Key Repeat Timer 1 Value","unistim.keys.repeat.time.one",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_keys_repeat_timer_two,
             {"Key Repeat Timer 2 Value","unistim.keys.repeat.time.two",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_keys_led_id,
             {"Led ID","unistim.keys.led.id",FT_UINT8,
                BASE_HEX,VALS(keys_led_ids),0x00,NULL,HFILL}
          },
          { &hf_keys_phone_icon_id,
             {"Phone Icon ID","unistim.keys.phone.icon.id",FT_UINT8,
                BASE_HEX,NULL,0x00,NULL,HFILL}
          },
          { &hf_keys_cadence_on_time,
             {"Indicator Cadence On Time","unistim.keys.cadence.on.time",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_keys_cadence_off_time,
             {"Indicator Cadence Off Time","unistim.keys.cadence.off.time",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_keys_user_activity_timeout,
             {"User Activity Timeout Value","unistim.keys.user.timeout.value",FT_UINT8,
                BASE_DEC,NULL,0x00,NULL,HFILL}
          },
          { &hf_display_call_timer_mode,
            {"Call Timer Mode","unistim.display.call.timer.mode",FT_BOOLEAN,
              8,TFS(&call_duration_timer_mode),DISPLAY_CALL_TIMER_MODE,NULL,HFILL}
          },
          { &hf_display_call_timer_reset,
            {"Call Timer Reset","unistim.display.call.timer.reset",FT_BOOLEAN,
              8,TFS(&call_duration_timer_reset),DISPLAY_CALL_TIMER_RESET,NULL,HFILL}
          },
          { &hf_display_call_timer_display,
            {"Call Timer Display","unistim.display.call.timer.display",FT_BOOLEAN,
              8,TFS(&call_duration_display_timer),DISPLAY_CALL_TIMER_DISPLAY,NULL,HFILL}
          },
          { &hf_display_call_timer_delay,
            {"Call Timer Delay","unistim.display.call.timer.delay",FT_BOOLEAN,
              8,TFS(&call_duration_timer_delay),DISPLAY_CALL_TIMER_DELAY,NULL,HFILL}
          },
          { &hf_display_call_timer_id,
            {"Call Timer ID","unistim.display.call.timer.id",FT_UINT8,
              BASE_DEC,NULL,DISPLAY_CALL_TIMER_ID,NULL,HFILL}
          },
          { &hf_expansion_switch_cmd,
            {"Expansion CMD (switch)","unistim.expansion.switch",FT_UINT8,
              BASE_HEX,VALS(expansion_switch_msgs),0x0,NULL,HFILL}
          },
          { &hf_expansion_phone_cmd,
             {"Expansion CMD (phone)","unistim.expansion.phone",FT_UINT8,
              BASE_HEX,VALS(expansion_phone_msgs),0x0,NULL,HFILL}
          },
          { &hf_expansion_softlabel_number,
            {"Module Soft Label Number","unistim.expansion.label.number",FT_UINT8,
              BASE_DEC,NULL,0x00,NULL,HFILL}
          },


         /****LAST****/
         { &hf_generic_string,
            {"DATA","unistim.generic.data",FT_STRING,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         },
         { &hf_generic_data,
            {"DATA","unistim.generic.data",FT_BYTES,
               BASE_NONE,NULL,0x00,NULL,HFILL}
         }
   };

/* Setup protocol subtree array */

   static gint *ett[] = {
         &ett_unistim
   };

   proto_unistim=proto_register_protocol("UNISTIM Protocol", "UNISTIM", "unistim");

   proto_register_subtree_array(ett,array_length(ett));
   proto_register_field_array(proto_unistim,hf,array_length(hf));

   unistim_tap = register_tap("unistim");

   unistim_module = prefs_register_protocol(proto_unistim, proto_reg_handoff_unistim);

   prefs_register_uint_preference(unistim_module, "udp.port", "UNISTIM UDP port",
                                  "UNISTIM port (default 5000)", 10, &global_unistim_port);
}

void
proto_reg_handoff_unistim(void) {
   static gboolean initialized = FALSE;
   static dissector_handle_t unistim_handle;
   static guint unistim_port;

   if (!initialized) {
      unistim_handle=new_create_dissector_handle(dissect_unistim,proto_unistim);
      dissector_add_handle("udp.port", unistim_handle);  /* for "decode as" */
      initialized=TRUE;
   } else {
      if (unistim_port != 0) {
         dissector_delete_uint("udp.port",unistim_port,unistim_handle);
      }
   }

   if (global_unistim_port != 0) {
      dissector_add_uint("udp.port",global_unistim_port,unistim_handle);
   }
   unistim_port = global_unistim_port;
}

