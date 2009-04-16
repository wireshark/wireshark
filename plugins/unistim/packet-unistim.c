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
static void set_ascii_null_term_item(proto_tree *msg_tree,tvbuff_t *tvb, 
                                     gint offset,guint msg_len, char *label);


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
	{0x11,"Broadcast Manager Switch"},
	{0x16,"Audio Manager Switch"},
	{0x17,"Display Manager Switch"},
	{0x19,"Key/Indicator Manager Switch"},
	{0x1a,"Basic Manager Switch"},
	{0x1e,"Network Manager Switch"},
	{0x91,"Broadcast Manager Phone"},
	{0x96,"Audio Manager Phone"},
	{0x97,"Display Manager Phone"},
	{0x99,"Key/Indicator Manager Phone"},
	{0x9a,"Basic Manager Phone"},
	{0x9e,"Network Manager Phone"},
	{0,NULL}
};

#include "header_field.h"

void
proto_register_unistim(void){

   module_t* unistim_module;

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
         dissector_delete("udp.port",unistim_port,unistim_handle);
      }
   }

   if (global_unistim_port != 0) {
      dissector_add("udp.port",global_unistim_port,unistim_handle);
   }
   unistim_port = global_unistim_port;
}


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
            case 0x0:/*NULL*/
            case 0x1:/*UNISTIM*/
            case 0x2:/*UNISTIM WITH TERM ID*/
            case 0x3:/*UFTP*/
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
   if(check_col(pinfo->cinfo,COL_PROTOCOL))
         col_set_str(pinfo->cinfo,COL_PROTOCOL,"UNISTIM");
      /* Clear out stuff in the info column */
   if (check_col(pinfo->cinfo,COL_INFO)) {
         col_clear(pinfo->cinfo,COL_INFO);
    }
    ti = proto_tree_add_item(tree,proto_unistim,tvb,offset,-1,FALSE);
    overall_unistim_tree = proto_item_add_subtree(ti,ett_unistim);
    ti1=proto_tree_add_text(overall_unistim_tree,tvb,offset,5,"Reliable UDP");
    rudpm_tree=proto_item_add_subtree(ti1,ett_unistim);

    proto_tree_add_item(rudpm_tree,hf_unistim_seq_nu,tvb,offset,4,FALSE);

    /* Allocate new mem for queueing */
    uinfo = se_alloc(sizeof(unistim_info_t));

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
    proto_tree_add_item(rudpm_tree,hf_unistim_packet_type,tvb,offset,1,FALSE);
    uinfo->rudp_type = tvb_get_guint8(tvb,offset);

    switch(tvb_get_guint8(tvb,offset)) {
          case 0x00:
              /*NAK*/
              if (check_col(pinfo->cinfo, COL_INFO))
                     col_add_fstr(pinfo->cinfo, COL_INFO, "NAK for seq -   0x%X",
                                   tvb_get_ntohl(tvb, offset-4));
              break;
          case 0x01:
              /*ACK*/
              if (check_col(pinfo->cinfo, COL_INFO))
                     col_add_fstr(pinfo->cinfo, COL_INFO, "ACK for seq -   0x%X",
                                   tvb_get_ntohl(tvb, offset-4));
              break;
          case 0x02:
              if (check_col(pinfo->cinfo, COL_INFO))
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
                             tvb,offset,1,FALSE);
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

            proto_tree_add_item(unistim_tree,hf_terminal_id,tvb,offset,4,FALSE);
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

	proto_tree_add_item(msg_tree,hf_uftp_command,tvb,offset,1,FALSE);

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
			proto_tree_add_item(msg_tree,hf_uftp_datablock_size,tvb,offset,2,FALSE);
			offset+=2;
			/* Get datablock limit b4 flow control */
			proto_tree_add_item(msg_tree,hf_uftp_datablock_limit,tvb,offset,1,FALSE);
			offset+=1;
			/* Get filename */
			str_len = tvb_length_remaining(tvb, offset);
			proto_tree_add_item(msg_tree,hf_uftp_filename,tvb,offset,str_len,FALSE);
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
			proto_tree_add_item(msg_tree,hf_uftp_datablock,tvb,offset,dat_len,FALSE);
			offset += dat_len;
			break;
	}

	return offset;
	
}


static gint
dissect_unistim_message(proto_tree *unistim_tree,packet_info *pinfo,tvbuff_t *tvb,gint offset){
   guint address;
   guint msg_len;
   proto_item *ti;
   proto_tree *msg_tree;

   ti = proto_tree_add_text(unistim_tree,tvb,offset,-1,"Unistim CMD");

   msg_tree = proto_item_add_subtree(ti,ett_unistim);

   address=tvb_get_guint8(tvb,offset);

   proto_tree_add_item(msg_tree,hf_unistim_cmd_add,tvb,offset,1,FALSE);

   offset+=1;
   msg_len=tvb_get_guint8(tvb,offset);

   if (msg_len<=2)
   {
     ti=proto_tree_add_item(msg_tree,hf_unistim_len,tvb,offset,1,FALSE);
     expert_add_info_format(pinfo,ti,PI_MALFORMED,PI_ERROR,"Length too short");
     return tvb_length(tvb);
   } else {
     proto_item_set_len(ti,msg_len);
     proto_tree_add_item(msg_tree,hf_unistim_len,tvb,offset,1,FALSE);
   }

   offset+=1;
   /*from switch*/
   switch(address){
      case 0x00:
   /*Nothing*/
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
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len-2,FALSE);

         offset+=(msg_len-2);
   }

   return offset;
}


   /*DONE*/
static gint
dissect_basic_phone(proto_tree *msg_tree,
                    tvbuff_t *tvb,gint offset, guint msg_len){
   guint basic_cmd;
   proto_item *ti;

   basic_cmd=tvb_get_guint8(tvb,offset);

   ti=proto_tree_add_item(msg_tree,hf_basic_phone_cmd,tvb,offset,1,FALSE);

   offset+=1;msg_len-=1;
   switch(basic_cmd){

      case 0x00:
   /*Basic Manager Attributes Info*/
         proto_tree_add_item(msg_tree,hf_basic_phone_eeprom_stat_cksum,
                             tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_basic_phone_eeprom_dynam,
                             tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_basic_phone_eeprom_net_config_cksum,
                             tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x01:
   /*Basic Manager Options Report*/
         proto_tree_add_item(msg_tree,hf_basic_switch_options_secure,
                             tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x02:
   /*Firmware Version*/
         proto_tree_add_item(msg_tree,hf_basic_phone_fw_ver,
                             tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x03:
   /*IT Type*/
         proto_tree_add_item(msg_tree,hf_basic_it_type,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x07:
   /*Hardware ID*/
         proto_tree_add_item(msg_tree,hf_basic_phone_hw_id,
                             tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x08:
   /*Product Engineering Code*/
         proto_tree_add_item(msg_tree,hf_basic_prod_eng_code,
                             tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x09:
   /*Grey Market Info*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x0a:
   /*Encapsulate Command*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x11:
   /*Phone Ethernet address*/
         proto_tree_add_item(msg_tree,hf_basic_ether_address,
                             tvb,offset,msg_len,FALSE);
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
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
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
   proto_tree_add_item(msg_tree,hf_basic_switch_cmd,tvb,offset,1,FALSE);
   offset+=1;msg_len-=1;
   switch(basic_cmd){
      case 0x01:
   /*Query Basic Manager*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_attr,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_opts,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_fw,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_hw_id,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_it_type,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_prod_eng_code,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_basic_switch_query_gray_mkt_info,
                             tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x02:
   /*Basic Manager Options*/
         proto_tree_add_item(msg_tree,hf_basic_switch_options_secure,
                             tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x06:
   /*EEprom Write*/
         proto_tree_add_item(msg_tree,hf_basic_switch_element_id,
                             tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_basic_switch_eeprom_data,
                             tvb,offset,msg_len,FALSE);
         offset+=1;
         break;
      case 0x07:
   /*Assign Terminal ID*/
         /* Set tap info */
         uinfo->set_termid = 1;

         proto_tree_add_item(msg_tree,hf_basic_switch_terminal_id,
                             tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x08:
   /*Encapsulate Command*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x0f:
   /*showing up in captures but not in pdf*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
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
   proto_tree_add_item(msg_tree,hf_broadcast_switch_cmd,tvb,offset,1,FALSE);
   offset+=1;
   switch(bcast_cmd){
      case 0x00:
   /*Accessory Sync Update   -   len=3 */
         break;
      case 0x01:
   /*Logical Icon Update*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_state,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_cadence,
                             tvb,offset,1,FALSE);
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
         proto_tree_add_item(date_tree,hf_broadcast_year,tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(date_tree,hf_broadcast_month,tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(date_tree,hf_broadcast_day,tvb,offset,1,FALSE);
         offset+=1;

         time_label=proto_tree_add_text(msg_tree,tvb,offset,3,
                                        "Time %i:%i:%i",hour,minute,second);
         time_tree=proto_item_add_subtree(time_label,ett_unistim);
         proto_tree_add_item(time_tree,hf_broadcast_hour,tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(time_tree,hf_broadcast_minute,tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(time_tree,hf_broadcast_second,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x03:
   /*Set Default Character Table Config */
         /* UGLY may work may not*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
   }

   return offset;
}
   /*DONE Haven't seen any phone broadcasts, wouldn't expect to*/
static gint
dissect_broadcast_phone(proto_tree *msg_tree,
                        tvbuff_t *tvb, gint offset,guint msg_len){

   proto_tree_add_item(msg_tree,hf_generic_data, tvb,offset,msg_len,FALSE);
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
   proto_tree_add_item(msg_tree,hf_display_switch_cmd,tvb,offset,1,FALSE);
   offset+=1;msg_len-=1;

   switch(display_cmd){
      case 0x01:
   /*Restore Default Character Table Configuration length = 3*/
         break;
      case 0x04:
   /*Arrow*/
         proto_tree_add_item(msg_tree,hf_display_arrow,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x05:
   /*Query Status Bar Icon*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
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
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_call_timer_mode,tvb,offset,
                             1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_call_timer_reset,tvb,offset,
                             1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_call_timer_display,tvb,offset,
                             1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_call_timer_delay,tvb,offset,
                             1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_call_timer_id,tvb,offset,
                             1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0c:
   /*Query Display Manager*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x0d:
   /*Download Call Duration Timer Delay*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x0e:
   /*Disable Display Field*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x0f:
   /*Clear Field*/
         clear_mask=tvb_get_guint8(tvb,offset);
   /*need to know which paths to take*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_clear_numeric,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_clear_context,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_clear_date,
                             tvb,offset,1,FALSE);

         proto_tree_add_item(msg_tree,hf_display_clear_time,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_clear_line,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_clear_softkey,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_clear_softkey_label,
                             tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         if((clear_mask&DISPLAY_CLEAR_LINE)==DISPLAY_CLEAR_LINE){
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_line_1,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_line_2,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_line_3,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_line_4,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_line_5,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_line_6,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_line_7,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_line_8,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
         if((clear_mask&DISPLAY_CLEAR_STATUS_BAR_ICON)==
                        DISPLAY_CLEAR_STATUS_BAR_ICON){
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_1,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_2,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_3,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_4,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_5,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_6,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_7,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_status_bar_icon_8,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
         if((clear_mask&DISPLAY_CLEAR_SOFTKEY)==DISPLAY_CLEAR_SOFTKEY){
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_1,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_2,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_3,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_4,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_5,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_6,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_7,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_soft_key_8,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
         if((clear_mask&DISPLAY_CLEAR_SOFTKEY_LABEL)==DISPLAY_CLEAR_SOFTKEY_LABEL){
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_sk_label_key_id,tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_clear_all_slks,tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x10:
   /*Cursor Control*/
         movement_byte=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_move_cmd,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_blink,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         if(msg_len==0){
   /*turn cursor off*/
            break;
         }
         if((movement_byte&0x01)==0x01){
            address_byte=tvb_get_guint8(tvb,offset);
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_write_address_numeric,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_write_address_context,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_write_address_line,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_write_address_soft_key,
                                tvb,offset,1,FALSE);
            if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)==
                             DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)
               proto_tree_add_item(msg_tree,
                                   hf_display_write_address_softkey_id,
                                   tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
            if(msg_len==0){
   /*turn cursor off*/
               break;
            }
         }
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_address_char_pos,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_address_line_number,
                             tvb,offset,1,FALSE);
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
         proto_tree_add_item(msg_tree,hf_basic_bit_field, tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_icon_id,tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_basic_bit_field, tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_state,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_cadence,
                             tvb,offset,1,FALSE);
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
            proto_tree_add_item(msg_tree,hf_display_time_format,tvb,offset,1,FALSE);
         }
         if((time_date_mask&DISPLAY_USE_DATE_FORMAT)==DISPLAY_USE_DATE_FORMAT){
            proto_tree_add_item(msg_tree,hf_display_date_format,tvb,offset,1,FALSE);
         }
         proto_tree_add_item(msg_tree,hf_display_use_time_format,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_use_date_format,tvb,offset,1,FALSE);
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
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_numeric,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_context,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_line,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_key,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_label,
                             tvb,offset,1,FALSE);

         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)==
                          DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_softkey_id,
                                tvb,offset,1,FALSE);
         }
         offset+=1;msg_len-=1;
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)==
             DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG){
            proto_tree_add_item(address_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
            proto_tree_add_item(address_tree,
                                hf_display_write_address_char_pos,
                                tvb,offset,1,FALSE);
            if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)!=
                             DISPLAY_WRITE_ADDRESS_LINE_FLAG){
               offset+=1;msg_len-=1;
            }
         }
         if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)==
             DISPLAY_WRITE_ADDRESS_LINE_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_line_number,
                                tvb,offset,1,FALSE);
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
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_cursor_move,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_clear_left,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_clear_right,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_shift_left,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_shift_right,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_highlight,
                             tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         proto_tree_add_item(msg_tree,hf_generic_string,
                             tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x1b:
   /*address|yes control|yes tag|no*/
         tmp_ti=proto_tree_add_text(msg_tree,tvb,offset,0,"Address Data");
         address_tree=proto_item_add_subtree(tmp_ti,ett_unistim);
         address_byte=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(address_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,
                             hf_display_write_address_numeric,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,
                             hf_display_write_address_context,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,
                             hf_display_write_address_line,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,
                             hf_display_write_address_soft_key,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,
                             hf_display_write_address_soft_label,
                             tvb,offset,1,FALSE);
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)==
                          DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG){
            proto_tree_add_item(address_tree,hf_display_write_address_softkey_id,
                                tvb,offset,1,FALSE);
            offset+=1; msg_len-=1;
         }
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)==
                          DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_char_pos,
                                tvb,offset,1,FALSE);
            if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)!=
                             DISPLAY_WRITE_ADDRESS_LINE_FLAG)
               offset+=1;msg_len-=1;
         }
         if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)==
                          DISPLAY_WRITE_ADDRESS_LINE_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_line_number,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_cursor_move,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_clear_left,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_clear_right,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_shift_left,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_shift_right,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_highlight,
                             tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x1c:
   /*address|no control|no tag|yes*/
         proto_tree_add_item(msg_tree,hf_display_write_tag,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x1d:
   /*address|yes control|no tag|yes*/
         tmp_ti=proto_tree_add_text(msg_tree,tvb,offset,0,"Address Data");
         address_tree=proto_item_add_subtree(tmp_ti,ett_unistim);
         address_byte=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(address_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_numeric,tvb,
                             offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_context,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_line,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_key,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_label,
                             tvb,offset,1,FALSE);
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)==
             DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)
            proto_tree_add_item(address_tree,
                                hf_display_write_address_softkey_id,
                                tvb,offset,1,FALSE);
         offset+=1; msg_len-=1;
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)==
             DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_char_pos,
                                tvb,offset,1,FALSE);
            if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)!=
                DISPLAY_WRITE_ADDRESS_LINE_FLAG)
               offset+=1;msg_len-=1;
         }
         if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)==
             DISPLAY_WRITE_ADDRESS_LINE_FLAG){
            proto_tree_add_item(address_tree,hf_display_write_address_line_number,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x1e:
   /*address|no control|yes tag|yes*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_cursor_move,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_clear_left,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_clear_right,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_shift_left,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_shift_right,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_highlight,
                             tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;

         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         proto_tree_add_item(msg_tree,hf_display_write_tag,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x1f:
   /*address|yes control|yes tag|yes*/
         tmp_ti=proto_tree_add_text(msg_tree,tvb,offset,0,"Address");
         address_tree=proto_item_add_subtree(tmp_ti,ett_unistim);
         address_byte=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(address_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_numeric,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_context,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_line,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_key,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(address_tree,hf_display_write_address_soft_label,
                             tvb,offset,1,FALSE);
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)==
                          DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG)
            proto_tree_add_item(address_tree,hf_display_write_address_softkey_id,
                                tvb,offset,1,FALSE);
         offset+=1; msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_string,
                             tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)==
                          DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG){
            proto_tree_add_item(address_tree,hf_display_write_address_char_pos,
                                tvb,offset,1,FALSE);
            if((address_byte&DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)!=
                             DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG)
               offset+=1;msg_len-=1;
         }
         if((address_byte&DISPLAY_WRITE_ADDRESS_LINE_FLAG)==
                          DISPLAY_WRITE_ADDRESS_LINE_FLAG){
            proto_tree_add_item(address_tree,
                                hf_display_write_address_line_number,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         } 
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_cursor_move,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_clear_left,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_clear_right,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_shift_left,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_shift_right,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_write_highlight,
                             tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_write_tag,
                             tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x20:
   /*Context Info Bar Format*/
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_display_context_format,tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_display_context_field,tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x21:
   /*Set Default Character Table Configuration VERY UGLY*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x22:
   /*Special Character Download*/
         proto_tree_add_item(msg_tree,hf_display_char_address,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x23:
   /*Highlighted Field Definition*/
         highlight_cmd=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(msg_tree,hf_display_cursor_numeric,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_context ,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_line,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;proto_tree_add_item(msg_tree,hf_display_hlight_start,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_hlight_end,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         if(msg_len==0)
             break;
         if((highlight_cmd&DISPLAY_CURSOR_LINE)==DISPLAY_CURSOR_LINE){
           proto_tree_add_item(msg_tree,hf_display_cursor_char_pos,tvb,offset,1,FALSE);
           proto_tree_add_item(msg_tree,hf_display_cursor_line_number,tvb,offset,1,FALSE);
           offset+=1;msg_len-=1;
         }
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x24:
   /*Contrast*/
         proto_tree_add_item(msg_tree,hf_display_contrast,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x25:
   /*Caller Log Download*/
         proto_tree_add_item(msg_tree,hf_broadcast_hour,tvb,offset,msg_len,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_broadcast_minute,tvb,offset,msg_len,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x30:
   /*Layered Softkey Text Download*/
         proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_layer_number,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x31:
   /*Layered Softkey Clear*/
         proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_layer_all_skeys,tvb,offset,msg_len,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_layer_number,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x32:
   /*Set Visible Softkey Layer*/
         proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_layer_all_skeys,tvb,offset,msg_len,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_layer_number,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x33:
   /*Layered Softkey Cadence Download*/
         proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_once_or_cyclic,tvb,offset,msg_len,FALSE);
         offset+=1;msg_len-=1;
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_display_layer_number,tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
            proto_tree_add_item(msg_tree,hf_display_layer_duration,tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x34:
   /*Layered Softkey Cadencing On*/
        proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,FALSE);
        offset+=1;msg_len-=1;
        break;
      case 0x35:
   /*Layered Softkey Cadencing Off*/
         proto_tree_add_item(msg_tree,hf_display_layer_skey_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,
                             tvb,offset,msg_len,FALSE);
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
   proto_tree_add_item(msg_tree,hf_display_phone_cmd,tvb,offset,1,FALSE);
   offset+=1;
   switch(display_cmd){
      case 0x00:
   /*Display Manager Attributes Info*/
         proto_tree_add_item(msg_tree,hf_display_line_width,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_lines,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_softkey_width,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_softkeys,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_icon,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_softlabel_key_width,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_context_width,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_numeric_width,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_time_width,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_date_width,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_char_dload,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_freeform_icon_dload,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_icon_type,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_charsets,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;

         break;
      case 0x01:
   /*Contrast Level Report*/
	 proto_tree_add_item(msg_tree,hf_display_contrast,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x02:
   /*Cursor Location Report*/
	 proto_tree_add_item(msg_tree,hf_display_cursor_numeric,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_context ,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_line,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey_id,tvb,offset,1,FALSE);
	 offset+=1;msg_len-=1;
	 proto_tree_add_item(msg_tree,hf_display_cursor_char_pos,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_line_number,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
	 break;
      case 0x03:
   /*Highlight Status On*/
         highlight_cmd=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(msg_tree,hf_display_cursor_numeric,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_context ,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_line,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_cursor_softkey_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;proto_tree_add_item(msg_tree,hf_display_hlight_start,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_display_hlight_end,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         if((highlight_cmd&DISPLAY_CURSOR_LINE)==DISPLAY_CURSOR_LINE){
           proto_tree_add_item(msg_tree,hf_display_cursor_char_pos,tvb,offset,1,FALSE);
           proto_tree_add_item(msg_tree,hf_display_cursor_line_number,tvb,offset,1,FALSE);
           offset+=1;msg_len-=1;
         }
         break;
      case 0x04:
   /*Current Character Table Configuration Status   VERY UGLY*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x05:
   /*Default Character Table Configuration Status   VERY UGLY*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x06:
   /*Timer And Date Format Report*/
         proto_tree_add_item(msg_tree,hf_display_time_format,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_display_date_format,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x07:
   /*Status Bar Icon State Report*/
         proto_tree_add_item(msg_tree,hf_icon_id,tvb,offset,msg_len,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_broadcast_icon_state,tvb,offset,msg_len,FALSE);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_cadence,tvb,offset,msg_len,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0a:
   /*Highlight Status Off length = 3*/
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
   }

   return offset;
}


static gint
dissect_key_indicator_switch(proto_tree *msg_tree, 
                             tvbuff_t *tvb, gint offset,guint msg_len){
   guint key_cmd;
   key_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_key_switch_cmd,tvb,offset,1,FALSE);
   offset+=1;msg_len-=1;
   switch(key_cmd){
      case 0x00:
   /*LED Update*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_key_led_cadence,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_key_led_id,tvb,offset,1,FALSE);
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
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x07:
   /*Key/Indicator Manager Options*/
         proto_tree_add_item(msg_tree,hf_keys_send_key_rel,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_enable_vol,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_conspic_prog_key,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_acd_super_control,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_local_dial_feedback,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x08:
   /*Logical Icon Mapping*/
         proto_tree_add_item(msg_tree,hf_key_icon_id,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_admin_command,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_keys_logical_icon_id,tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         break;
      case 0x09:
   /*Key Repeat Timer Download*/
         proto_tree_add_item(msg_tree,hf_keys_repeat_timer_one,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_keys_repeat_timer_two,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0a:
   /*Query LED State*/
         proto_tree_add_item(msg_tree,hf_keys_led_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0b:
   /*Query Phone Icon State*/
         proto_tree_add_item(msg_tree,hf_keys_phone_icon_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0c:
   /*Indicator Cadence Download*/
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_keys_cadence_on_time,tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
            proto_tree_add_item(msg_tree,hf_keys_cadence_off_time,tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x0d:
   /*User Activity Timer Download*/
         proto_tree_add_item(msg_tree,hf_keys_user_activity_timeout,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0e:
   /*Free Form Icon Download*/
         proto_tree_add_item(msg_tree,hf_key_icon_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x0f:
   /*Phone Icon Update*/
         proto_tree_add_item(msg_tree,hf_key_icon_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_state,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_broadcast_icon_cadence,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0xff:
   /*Reserved*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
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
   proto_tree_add_item(msg_tree,hf_key_phone_cmd,tvb,offset,1,FALSE);
   offset+=1;msg_len-=1;
   switch(key_cmd){
      case 0x00:
   /*Key Event*/
         /* Set the tap info */
         uinfo->key_state = tvb_get_guint8(tvb,offset);
         uinfo->key_state >>= 6;
         /* Extract the key code */
         uinfo->key_val = (tvb_get_guint8(tvb,offset) & 0x3F);

         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_key_code,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_key_command,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x01:
   /*LED Status Report*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
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
         proto_tree_add_item(msg_tree,hf_key_programmable_keys,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_soft_keys,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_keys_hd_key,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_mute_key,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_quit_key,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_copy_key,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_mwi_key,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_keys_num_nav_keys,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_num_conspic_keys,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;

         break;
      case 0x09:
   /*Key/Indicator Manager Options Report*/
         proto_tree_add_item(msg_tree,hf_keys_send_key_rel,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_enable_vol,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_conspic_prog_key,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_acd_super_control,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_keys_local_dial_feedback,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0a:
   /*Phone Icon Status Report*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
   }

   return offset;
}


/*Done*/
static gint
dissect_network_switch(proto_tree *msg_tree,
                       tvbuff_t *tvb,gint offset, guint msg_len){
   guint network_cmd; 
   network_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_network_switch_cmd,tvb,offset,1,FALSE);
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
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_diag_flag,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_managers_flag,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_attributes_flag,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_serv_info_flag,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_options_flag,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_sanity_flag,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x05:
   /*Network Manager Options*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_enable_diag,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_enable_rudp,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x06:
   /*QoS Configuration*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x09:
   /*Set RTCP Source Description Item*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x0b:
   /*Download Server Information*/
         proto_tree_add_item(msg_tree,hf_net_server_id,tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_net_server_port,tvb,offset,2,FALSE);
         offset+=2;
         proto_tree_add_item(msg_tree,hf_net_server_action,tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_net_server_retry_count,tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_net_server_failover_id,tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_net_server_ip_address,tvb,offset,4,FALSE);
         offset+=4;
         break;
      case 0x0c:
   /*Server Switch*/
         proto_tree_add_item(msg_tree,hf_net_server_id,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x0d:
   /*Query Network Configuration Element*/
         proto_tree_add_item(msg_tree,hf_net_server_config_element,
                             tvb,offset-1,1,FALSE);
         offset+=1;
         break;
      case 0x0e:
   /*Download Software Upgrade*/
         proto_tree_add_item(msg_tree,hf_net_file_xfer_mode,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_force_download,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_use_file_server_port,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_use_local_port,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         set_ascii_null_term_item(msg_tree,tvb,offset,msg_len,"Full Pathname :");
         set_ascii_null_term_item(msg_tree,tvb,offset,msg_len,"File Identifier :");
         proto_tree_add_item(msg_tree,hf_net_file_server_port,tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_net_local_port,tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_net_file_server_address,tvb,offset,4,FALSE);
         offset+=4;msg_len-=4;
         break;
      case 0x0f:
   /*Set RTCP Report Interval*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x10:
   /*Set Primary Server*/
         proto_tree_add_item(msg_tree,hf_net_server_id,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x12:
   /*Reset Watchdog*/
      proto_tree_add_item(msg_tree,hf_net_server_time_out,
                          tvb,offset,2,FALSE);
         offset+=2;
         break;
      case 0x13:
   /*Set Recovery Procedure Time Interval*/
         proto_tree_add_item(msg_tree,hf_net_server_recovery_time_low,
                             tvb,offset,2,FALSE);
         offset+=2;
         proto_tree_add_item(msg_tree,hf_net_server_recovery_time_high,
                             tvb,offset,2,FALSE);
         offset+=2;
         break;
      case 0x14:
   /*Transport Reliability Layer Parameters Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,
                             tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0xff:
   /*Reserved*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;

   }

   return offset;
}

/*DONE*/
static gint
dissect_network_phone(proto_tree *msg_tree, 
                      tvbuff_t *tvb,gint offset, guint msg_len){
   guint network_cmd;
   proto_tree *server_tree;
   proto_item *server;
   guint i;
   network_cmd=tvb_get_guint8(tvb,offset);
   proto_tree_add_item(msg_tree,hf_network_phone_cmd,tvb,offset,1,FALSE);
   offset+=1;
   switch(network_cmd){
      case 0x00:
   /*Soft Reset Ack done length = 3*/
         break;
      case 0x01:
   /*Sanity OK done length = 3*/
         break;
      case 0x02:
   /*Network Manager Attributes Info*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x03:
   /*Network Manager Diagnostic Info*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_phone_rx_ovr_flag,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_phone_tx_ovr_flag,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_phone_rx_empty_flag,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_phone_invalid_msg_flag,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_phone_eeprom_insane_flag,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_phone_eeprom_unsafe_flag,
                             tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x04:
   /*Manager IDs*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x05:
   /*Network Manager Options Report*/
         proto_tree_add_boolean(msg_tree,hf_net_phone_diag,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_net_phone_rudp,tvb,offset,1,FALSE);
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
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x0c:
   /*Server Information Report*/
         proto_tree_add_item(msg_tree,hf_net_phone_primary_server_id,
                             tvb,offset,1,FALSE);
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
                                tvb,offset,2,FALSE);
            offset+=2;msg_len-=2;
            proto_tree_add_item(server_tree,
                                hf_net_phone_server_action,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
            proto_tree_add_item(server_tree,
                                hf_net_phone_server_retry_count,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
            proto_tree_add_item(server_tree,
                                hf_net_phone_server_failover_id,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
            proto_tree_add_item(server_tree,hf_net_phone_server_ip,
                                tvb,offset,4,FALSE);
            offset+=4;msg_len-=4;
         }
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
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
   proto_tree_add_item(msg_tree,hf_audio_switch_cmd,tvb,offset,1,FALSE);
   offset+=1;msg_len-=1;
   switch(audio_cmd){
   case 0x00:
   /*Query Audio Manager*/
      proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_attr,tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opts,tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_alert,tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_adj_rx_vol,tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_def_rx_vol,tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_handset,tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_headset,tvb,offset,1,FALSE);
      offset+=1;
      proto_tree_add_item(msg_tree,hf_audio_default_rx_vol_id,
                          tvb,offset,1,FALSE);
      offset+=1;
      break;
   case 0x01:
   /*Query Supervisor Headset Status*/
      /*done*/
      break;
   case 0x02:
   /*Audio Manager Options*/
      proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_max_vol,
                          tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_adj_vol,
                          tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_aa_rx_vol_rpt,
                          tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_hs_on_air,
                          tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_hd_on_air,
                          tvb,offset,1,FALSE);
      proto_tree_add_item(msg_tree,hf_audio_mgr_opt_noise_squelch,
                          tvb,offset,1,FALSE);
      offset+=1;
         break;
      case 0x04:
   /*Mute/Unmute*/
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_audio_mgr_mute,tvb,offset,1,FALSE);
            proto_tree_add_item(msg_tree,hf_audio_mgr_tx_rx,tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
            proto_tree_add_item(msg_tree,hf_audio_mgr_stream_id,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x10:
   /*Transducer Based Tone On*/
         proto_tree_add_item(msg_tree,
                             hf_audio_mgr_transducer_based_tone_id,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_mgr_attenuated,
                             tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x11:
   /*Transducer Based Tone Off*/
         proto_tree_add_item(msg_tree,hf_audio_mgr_transducer_based_tone_id,
                             tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x12:
   /*Alerting Tone Configuration*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_mgr_warbler_select,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_mgr_transducer_routing,
                             tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_mgr_tone_vol_range,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_mgr_cadence_select,
                             tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x13:
   /*Special Tone Configuration*/
         proto_tree_add_item(msg_tree,hf_audio_mgr_transducer_routing,
                             tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_mgr_tone_vol_range,
                             tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_special_tone,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x14:
   /*Paging Tone Configuration*/
         proto_tree_add_item(msg_tree,hf_audio_mgr_transducer_routing,
                             tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_mgr_tone_vol_range,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_mgr_cadence_select,
                             tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x15:
   /*Alerting Tone Cadence Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
   /*TODO UGLY*/
      case 0x17:
   /*Paging Tone Cadence Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
   /*TODO UGLY*/
      case 0x18:
   /*Transducer Based Tone Volume Level*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,
                             hf_audio_mgr_transducer_based_tone_id,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_tone_level,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x1a:
   /*Visual Transducer Based Tone Enable*/
         proto_tree_add_item(msg_tree,hf_audio_visual_tones,
                             tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x1b:
   /*Stream Based Tone On*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_stream_based_tone_id,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_stream_based_tone_rx_tx,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_stream_based_tone_mute,
                             tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_stream_id,tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_stream_based_volume,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x1c:
   /*Stream Based Tone Off*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_stream_based_tone_id,
                             tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_stream_based_tone_rx_tx,
                             tvb,offset,1,FALSE);
         offset+=1;
         proto_tree_add_item(msg_tree,hf_audio_stream_id,tvb,offset,1,FALSE);
         offset+=1;
         break;
      case 0x1d:
   /*Stream Based Tone Frequency Component List Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x1e:
   /*Stream Based Tone Cadence Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x20:
   /*Select Adjustable Rx Volume*/
         proto_tree_add_item(msg_tree,hf_audio_default_rx_vol_id,
                             tvb,offset,1,FALSE);
         break;
      case 0x21:
   /*Set APB's Rx Volume Level*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x22:
   /*Change Adjustable Rx Volume (quieter) DONE*/
         proto_tree_add_item(msg_tree,hf_generic_data,
                             tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x23:
   /*Change Adjustable Rx Volume (louder) DONE*/
         proto_tree_add_item(msg_tree,hf_generic_data,
                             tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x24:
   /*Adjust Default Rx Volume(quieter)*/
         proto_tree_add_item(msg_tree,hf_audio_default_rx_vol_id,
                             tvb,offset,1,FALSE);
         break;
      case 0x25:
   /*Adjust Default Rx Volume(louder)*/
         proto_tree_add_item(msg_tree,hf_audio_default_rx_vol_id,
                             tvb,offset,1,FALSE);
         break;
      case 0x28:
   /*APB Download*/
         proto_tree_add_item(msg_tree,hf_audio_apb_number,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         while(msg_len>0){
            apb_op_code=tvb_get_guint8(tvb,offset);
            proto_tree_add_item(msg_tree,hf_audio_apb_op_code,tvb,
                                offset,1,FALSE);
            offset+=1;msg_len-=1;
            if(apb_op_code>0x39){
   /*should have a len + data*/
               apb_data_len=tvb_get_guint8(tvb,offset);
               proto_tree_add_item(msg_tree,hf_audio_apb_param_len,tvb,
                                   offset,1,FALSE);
               offset+=1;msg_len-=1;
               proto_tree_add_item(msg_tree,hf_audio_apb_data,tvb,
                                   offset,apb_data_len,FALSE);
               offset+=apb_data_len;msg_len-=apb_data_len;
            }
         }
         break;
      case 0x30:
   /*Open Audio Stream*/
         /* Set the tap info */
         uinfo->stream_connect = 1;

         proto_tree_add_item(msg_tree,hf_audio_rx_stream_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_tx_stream_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_rx_vocoder_type,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_tx_vocoder_type,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_frames_per_packet,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_tos,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_precedence,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_frf_11,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_rtcp_bucket_id,
                             tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_generic_data,
                             tvb,offset,4,FALSE);
         offset+=4;msg_len-=4;
         proto_tree_add_item(msg_tree,hf_audio_lcl_rtp_port,
                             tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_lcl_rtcp_port,
                             tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;

         proto_tree_add_item(msg_tree,hf_audio_far_rtp_port,
                             tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_rtcp_port,
                             tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;

         /* Sometimes the open stream does not specify an endpoint */
         /* In this circumstance the packet is truncated at the far end */
         /* rtp port */
         if(msg_len > 0){
            proto_tree_add_item(msg_tree,hf_audio_far_ip_add,tvb,offset,4,FALSE);
            offset+=4;msg_len-=4;
            {
               guint32 far_ip_addr;
               address far_addr;
               guint16 far_port;

               far_ip_addr = tvb_get_ipv4(tvb, offset-4);
               SET_ADDRESS(&far_addr, AT_IPv4, 4, &far_ip_addr);

               far_port = tvb_get_ntohs(tvb, offset-8);
               rtp_add_address(pinfo, &far_addr, far_port, 0, "UNISTIM", pinfo->fd->num, NULL);

               far_port = tvb_get_ntohs(tvb, offset-6);
               rtcp_add_address(pinfo, &far_addr, far_port, 0, "UNISTIM", pinfo->fd->num);
            }
         }
         break;
      case 0x31:
   /*Close Audio Stream*/
         /* Set the tap info */
         uinfo->stream_connect = 0;

         proto_tree_add_item(msg_tree,hf_audio_rx_stream_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_tx_stream_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x32:
   /*Connect Transducer*/
         /* Tap info again */
         uinfo->trans_connect = 1;

         proto_tree_add_item(msg_tree,hf_basic_bit_field, tvb,offset,1,FALSE); 
         proto_tree_add_item(msg_tree,hf_audio_transducer_pair,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_enable,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_tx_enable,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_basic_bit_field, tvb,offset,1,FALSE); 
         proto_tree_add_item(msg_tree,hf_audio_apb_number,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_sidetone_disable,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_destruct_additive,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_dont_force_active,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         while(msg_len>0){ 
            proto_tree_add_item(msg_tree,hf_audio_mgr_stream_id,tvb,offset,1,TRUE);
            offset+=1;msg_len-=1;
         }
         break;
      case 0x34:
   /*Filter Block Download*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x37:
   /*Query RTCP Statistics*/
         proto_tree_add_item(msg_tree,hf_audio_rtcp_bucket_id,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_clear_bucket,tvb,offset,1,FALSE);

         offset+=1;msg_len-=1;
         break;
      case 0x38:
   /*Configure Vocoder Parameters*/
         proto_tree_add_item(msg_tree,hf_audio_mgr_stream_id,tvb,offset,1,TRUE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_vocoder_id,tvb,offset,1,FALSE),
         offset+=1;msg_len-=1;
         while(msg_len>0){
            param=proto_tree_add_text(msg_tree,tvb,offset,0,"Param");
            param_tree=proto_item_add_subtree(param,ett_unistim);
            vocoder_param=tvb_get_guint8(tvb,offset);
            proto_tree_add_item(param_tree,hf_basic_bit_field,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(param_tree,hf_audio_vocoder_param,
                                tvb,offset,1,FALSE);
            proto_tree_add_item(param_tree,hf_audio_vocoder_entity,
                                tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
            if((vocoder_param&0x0a)==0x0a){
               proto_tree_add_item(param_tree,hf_audio_vocoder_annexa,
                                   tvb,offset,1,FALSE);
               proto_tree_add_item(param_tree,hf_audio_vocoder_annexb,
                                   tvb,offset,1,FALSE);
               offset+=1;msg_len-=1;
            }
            else if((vocoder_param&0x0b)==0x0b){
               proto_tree_add_item(param_tree,hf_audio_sample_rate,
                                   tvb,offset,1,FALSE);
               offset+=1;msg_len-=1;
            }
            else if((vocoder_param&0x0c)==0x0c){
               proto_tree_add_item(param_tree,hf_audio_rtp_type,
                                   tvb,offset,1,FALSE);
               offset+=1;msg_len-=1;
            }
            else if((vocoder_param&0x20)==0x20){
               proto_tree_add_item(param_tree,hf_audio_bytes_per_frame,
                                   tvb,offset,2,FALSE);
               offset+=2;msg_len-=2;
            }
         }
         break;
      case 0x39:
   /*Query RTCP Bucket's SDES Information*/
         proto_tree_add_item(msg_tree,hf_audio_source_descr,tvb,offset,msg_len,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_sdes_rtcp_bucket,tvb,offset,msg_len,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x3a:
   /*Jitter Buffer Parameters Configuration*/
         proto_tree_add_item(msg_tree,hf_audio_rx_stream_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_desired_jitter,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_high_water_mark,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_early_packet_resync_thresh,tvb,
                             offset,4,FALSE);
         offset+=4;msg_len-=4;
         proto_tree_add_item(msg_tree,hf_audio_late_packet_resync_thresh,tvb,
                             offset,4,FALSE);
         offset+=4;msg_len-=4;
         break;
      case 0x3b:
   /*Resolve Port Mapping*/
         proto_tree_add_item(msg_tree,hf_audio_resolve_phone_port,tvb,offset,1,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_end_echo_port,tvb,offset,1,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_end_ip_address,tvb,offset,1,FALSE);
         offset+=4;msg_len-=4;
         break;
      case 0x3c:
   /*Port Mpping Discovery Ack*/
         proto_tree_add_item(msg_tree,hf_audio_nat_port,tvb,offset,1,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_nat_ip_address,tvb,offset,1,FALSE);
         offset+=4;msg_len-=4;
         break;
      case 0x3d:
   /*Query Audio Stream Status*/
         proto_tree_add_item(msg_tree,hf_audio_direction_code,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_mgr_stream_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0xff:
   /*Reserved*/
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
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
   proto_tree_add_item(msg_tree,hf_audio_phone_cmd,tvb,offset,1,FALSE);
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
       proto_tree_add_item(msg_tree,hf_audio_hf_support,tvb,1,msg_len,FALSE);
         offset+=1;msg_len-=1;
         while(msg_len>0){
          proto_tree_add_item(msg_tree,hf_rx_vocoder_type,tvb,offset,1,FALSE);
          offset+=1;msg_len-=1;
         }
         break;
      case 0x08:
   /*Audio Manager Options Report*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_max,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_adj_vol,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_auto_adj_vol,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_hs_on_air,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_hd_on_air,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_opt_rpt_noise_squelch,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x09:
   /*Adjustable Rx Volume Report*/
         proto_tree_add_item(msg_tree,hf_basic_bit_field,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_apb_rpt,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_up,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_floor,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_ceiling,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0a:
   /*Adjustable Rx Volume Information*/
         proto_tree_add_item(msg_tree,hf_audio_current_adj_vol_id,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_apb_rpt,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_up,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_floor,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_ceiling,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_current_rx_level,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_current_rx_range,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0b:
   /*APB's Default Rx Volume Value*/
         proto_tree_add_item(msg_tree,hf_audio_current_adj_vol_id,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_apb_rpt,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_up,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_floor,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_rx_vol_vol_ceiling,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_current_rx_level,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_current_rx_range,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0c:
   /*Alerting Tone Select*/
         proto_tree_add_item(msg_tree,hf_audio_cadence_select,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_warbler_select,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x0e:
   /*RTCP Statistics Report UGLY*/
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
         break;
      case 0x0f:
   /*Open Audio Stream Report*/
         proto_tree_add_item(msg_tree,hf_audio_open_stream_rpt,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x10:
   /*RTCP Bucket SDES Information Report*/
         proto_tree_add_item(msg_tree,hf_audio_sdes_rpt_source_desc,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_sdes_rpt_buk_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         set_ascii_item(msg_tree,tvb,offset,msg_len);
         offset+=msg_len;
         break;
      case 0x11:
   /*Port Mapping Discovery*/
         proto_tree_add_item(msg_tree,hf_audio_phone_port,tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_phone_ip,tvb,offset,4,FALSE);
         offset+=4;msg_len-=4;
         break;
      case 0x12:
   /*Resolve Port Mapping*/
         proto_tree_add_item(msg_tree,hf_audio_nat_listen_port,tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_nat_ip,tvb,offset,4,FALSE);
         offset+=4;msg_len-=4;
         proto_tree_add_item(msg_tree,hf_audio_nat_add_len,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_phone_port,tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_phone_ip,tvb,offset,4,FALSE);
         offset+=4;msg_len-=4;
         proto_tree_add_item(msg_tree,hf_audio_phone_add_len,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         break;
      case 0x13:
   /*Audio Stream Status Report*/
         stream_dir=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(msg_tree,hf_audio_stream_direction_code,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_mgr_stream_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         stream_state=tvb_get_guint8(tvb,offset);
         proto_tree_add_item(msg_tree,hf_audio_stream_state,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         if((AUDIO_STREAM_STATE&stream_state)!=AUDIO_STREAM_STATE)
           break;
         if((AUDIO_STREAM_DIRECTION_RX&stream_dir)==AUDIO_STREAM_DIRECTION_RX)
            proto_tree_add_item(msg_tree,hf_rx_vocoder_type,tvb,offset,1,FALSE);
         else if((AUDIO_STREAM_DIRECTION_TX&stream_dir)==AUDIO_STREAM_DIRECTION_TX)
            proto_tree_add_item(msg_tree,hf_tx_vocoder_type,tvb,offset,1,FALSE);
         else
            proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_frames_per_packet,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_tos,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_precedence,tvb,offset,1,FALSE);
         proto_tree_add_item(msg_tree,hf_audio_frf_11,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_rtcp_bucket_id,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         proto_tree_add_item(msg_tree,hf_audio_lcl_rtp_port,tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_lcl_rtcp_port,tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_rtp_port,tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_rtcp_port,tvb,offset,2,FALSE);
         offset+=2;msg_len-=2;
         proto_tree_add_item(msg_tree,hf_audio_far_ip_add,tvb,offset,4,FALSE);
         offset+=4;msg_len-=4;
         proto_tree_add_item(msg_tree,hf_audio_transducer_list_length,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         while(msg_len>0){
            proto_tree_add_item(msg_tree,hf_audio_transducer_pair,tvb,offset,1,FALSE);
            offset+=1;msg_len-=1;
         }
      case 0x14:
   /*Query APB Response*/
         proto_tree_add_item(msg_tree,hf_audio_apb_number,tvb,offset,1,FALSE);
         offset+=1;msg_len-=1;
         while(msg_len>0){
           apb_op_code=tvb_get_guint8(tvb,offset);
           proto_tree_add_item(msg_tree,hf_audio_apb_op_code,tvb,
                            offset,1,FALSE);
           offset+=1;msg_len-=1;
           if(apb_op_code>0x39){
              /*should have a len + data*/
              apb_data_len=tvb_get_guint8(tvb,offset);
              proto_tree_add_item(msg_tree,hf_audio_apb_param_len,tvb,
                             offset,1,FALSE);
              offset+=1;msg_len-=1;
              proto_tree_add_item(msg_tree,hf_audio_apb_data,tvb,
                             offset,apb_data_len,FALSE);
              offset+=apb_data_len;msg_len-=apb_data_len;
           }
         }
         break;
      case 0xff:
   /*Reserved*/
         break;
      default:
         proto_tree_add_item(msg_tree,hf_generic_data,tvb,offset,msg_len,FALSE);
         offset+=msg_len;
   }

   return offset;
}

static void
set_ascii_item(proto_tree *msg_tree,tvbuff_t *tvb, gint offset,guint msg_len){
   char *buffer=NULL;
   gsize buffer_index=0;
   guint16 msg_index=0;
   guint8 character;
   char *label="DATA: ";
   #define MAX_BUFFER 1024
   buffer=ep_alloc(MAX_BUFFER);

   buffer_index=g_strlcpy(buffer,label,MAX_BUFFER);
   while((buffer_index<MAX_BUFFER-2)&&(msg_index<msg_len)){
      character=tvb_get_guint8(tvb,offset+msg_index);
      msg_index++;
      if((character>0x1f)&&(character<0x7f)){
         /*g_vsnprintf called in proto_tree_add_text blows up if you end up with %s as text so escape %*/
         if(character=='%'){
            buffer[buffer_index]='%';
            buffer_index++;
         }
         buffer[buffer_index]=character;
         buffer_index++;
      }
      else{
         buffer[buffer_index]='.';
         buffer_index++;
      }
   }
   buffer[buffer_index]='\0';

   proto_tree_add_text(msg_tree,tvb,offset,msg_len,"%s",buffer);
}

static void
set_ascii_null_term_item(proto_tree *msg_tree,tvbuff_t *tvb, gint offset,guint msg_len,char *label){
   char *buffer=NULL;
   gsize buffer_index=0;
   guint16 msg_index=0;
   guint8 character;
   #define MAX_BUFFER 1024
   buffer=ep_alloc(MAX_BUFFER);

   buffer_index=g_strlcpy(buffer,label,MAX_BUFFER);
   while((buffer_index<MAX_BUFFER-2)&&(msg_index<msg_len)){
      character=tvb_get_guint8(tvb,offset+msg_index);
      msg_index++;
      if((character>0x1f)&&(character<0x7f)){
         /*g_vsnprintf called in proto_tree_add_text blows up if you end up with %s as text so escape %*/
         if(character=='%'){
            buffer[buffer_index]='%';
            buffer_index++;
         }
         buffer[buffer_index]=character;
         buffer_index++;
      }
      else if(character==0x00)
         break;
      else{
         buffer[buffer_index]='.';
         buffer_index++;
      }
   }
   buffer[buffer_index]='\0';

   proto_tree_add_text(msg_tree,tvb,offset,msg_len,"%s",buffer);
}

