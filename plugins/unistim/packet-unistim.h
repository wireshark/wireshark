/* packet-unistim.h
  * header field declarations, value_string definitions, true_false_string 
  * definitions and function prototypes for main dissectors
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

#ifndef PACKET_UNISTIM_H
#define PACKET_UNISTIM_H

#include "defines.h"
#include "audio.h"
#include "basic.h"
#include "display.h"
#include "network.h"
#include "key.h"
#include "broadcast.h"


static void dissect_payload(proto_tree *unistim_tree,tvbuff_t *tvb,gint offset);
static void dissect_unistim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static dissector_handle_t unistim_handle;

static void dissect_broadcast_switch(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                     tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_audio_switch(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_display_switch(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_key_indicator_switch(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_basic_switch(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_network_switch(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_broadcast_phone(proto_tree *msg_tree,proto_tree *unistim_tree,
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_audio_phone(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_display_phone(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_key_indicator_phone(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_basic_phone(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_network_phone(proto_tree *msg_tree,proto_tree *unistim_tree, 
                                   tvbuff_t *tvb,gint offset,guint msg_len);
static void dissect_message(proto_tree *unistim_tree, tvbuff_t *tvb,gint offset);
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

#endif

