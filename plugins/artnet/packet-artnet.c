/* packet-artnet.c
 * Routines for ArtNET packet disassembly
 *
 * $Id: packet-artnet.c,v 1.1 2003/04/21 21:28:39 guy Exp $
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@muffin.org>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugins/plugin_api.h"

#include "moduleinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/resolv.h>
#include "prefs.h"
#include <epan/strutil.h>

#include "plugins/plugin_api_defs.h"

/* Define version if we are not building ethereal statically */

#ifndef __ETHEREAL_STATIC__
G_MODULE_EXPORT const gchar version[] = VERSION;
#endif

/*
 * See
 *
 *	http://www.artisticlicence.com/art-net.pdf
 */

/* Define udp_port for ArtNET */

#define UDP_PORT_ARTNET 0x1936

#define ARTNET_HEADER_LENGTH                 10
#define ARTNET_POLL_LENGTH                   4
#define ARTNET_POLL_REPLY_LENGTH             197
#define ARTNET_POLL_REPLY_PORT_INFO_LENGTH   22
#define ARTNET_POLL_REPLY_PORT_TYPES_LENGTH  4
#define ARTNET_POLL_REPLY_GOOD_INPUT_LENGTH  4
#define ARTNET_POLL_REPLY_GOOD_OUTPUT_LENGTH 4
#define ARTNET_POLL_REPLY_SWIN_LENGTH        4
#define ARTNET_POLL_REPLY_SWOUT_LENGTH       4
#define ARTNET_ADDRESS_LENGTH                97
#define ARTNET_ADDRESS_SWIN_LENGTH           4
#define ARTNET_ADDRESS_SWOUT_LENGTH          4
#define ARTNET_OUTPUT_LENGTH                 1
#define ARTNET_INPUT_LENGTH                  10
#define ARTNET_INPUT_INPUT_LENGTH            4
#define ARTNET_FIRMWARE_MASTER_LENGTH        1035
#define ARTNET_FIRMWARE_REPLY_LENGTH         26
#define ARTNET_VIDEO_SETUP_LENGTH            74
#define ARTNET_VIDEO_PALETTE_LENGTH          55
#define ARTNET_VIDEO_DATA_LENGTH             8


#define ARTNET_OP_POLL            0x2000
#define ARTNET_OP_POLL_REPLY      0x2100
#define ARTNET_OP_OUTPUT          0x5000
#define ARTNET_OP_ADDRESS         0x6000
#define ARTNET_OP_INPUT           0x7000
#define ARTNET_OP_VIDEO_SETUP     0xa010
#define ARTNET_OP_VIDEO_PALETTE   0xa020
#define ARTNET_OP_VIDEO_DATA      0xa040

#define ARTNET_OP_UNKNOWN_0x8000  0x8000
#define ARTNET_OP_UNKNOWN_0x8100  0x8100
#define ARTNET_OP_UNKNOWN_0x8200  0x8200
#define ARTNET_OP_UNKNOWN_0x8300  0x8300

#define ARTNET_OP_MAC_MASTER      0xf000
#define ARTNET_OP_MAC_SLAVE       0xf100
#define ARTNET_OP_FIRMWARE_MASTER 0xf200
#define ARTNET_OP_FIRMWARE_REPLY  0xf300

static const value_string artnet_opcode_vals[] = {
  { ARTNET_OP_POLL,            "ArtPoll packet" },
  { ARTNET_OP_POLL_REPLY,      "ArtPollReply packet" },
  { ARTNET_OP_OUTPUT,          "ArtDMX data packet" },
  { ARTNET_OP_ADDRESS,         "ArtAddress packet" },
  { ARTNET_OP_INPUT,           "ArtInput packet" },
  { ARTNET_OP_VIDEO_SETUP,     "ArtVideoSetup packet" },
  { ARTNET_OP_VIDEO_PALETTE,   "ArtVideoPalette packet" },
  { ARTNET_OP_VIDEO_DATA,      "ArtVideoData packet" },

  { ARTNET_OP_UNKNOWN_0x8000,  "Undocument opcode 0x8000" },
  { ARTNET_OP_UNKNOWN_0x8100,  "Undocument opcode 0x8100" },
  { ARTNET_OP_UNKNOWN_0x8200,  "Undocument opcode 0x8200" },
  { ARTNET_OP_UNKNOWN_0x8300,  "Undocument opcode 0x8300" },
  
  { ARTNET_OP_MAC_MASTER,      "ArtMacMaster packet" },
  { ARTNET_OP_MAC_SLAVE,       "ArtMacSlave packet" },
  { ARTNET_OP_FIRMWARE_MASTER, "ArtFirmwareMaster packet" },
  { ARTNET_OP_FIRMWARE_REPLY,  "ArtFirmwareReply packet" },
  { 0,                       NULL }
};

#define ARTNET_AC_NONE           0x00
#define ARTNET_AC_CANCEL_MERGE   0x01
#define ARTNET_AC_LED_NORMAL     0x02
#define ARTNET_AC_LED_MUTE       0x03
#define ARTNET_AC_LED_LOCATE     0x04
#define ARTNET_AC_RESET_RX_FLAGS 0x05
#define ARTNET_AC_MERGE_LTP0     0x10
#define ARTNET_AC_MERGE_LTP1     0x11
#define ARTNET_AC_MERGE_LTP2     0x12
#define ARTNET_AC_MERGE_LTP3     0x13
#define ARTNET_AC_MERGE_HTP0     0x50
#define ARTNET_AC_MERGE_HTP1     0x51
#define ARTNET_AC_MERGE_HTP2     0x52
#define ARTNET_AC_MERGE_HTP3     0x53
#define ARTNET_AC_CLEAR_OP0      0x90
#define ARTNET_AC_CLEAR_OP1      0x91
#define ARTNET_AC_CLEAR_OP2      0x92
#define ARTNET_AC_CLEAR_OP3      0x93

static const value_string artnet_address_command_vals[] = {
  { ARTNET_AC_NONE,            "No Action" },
  { ARTNET_AC_CANCEL_MERGE,    "Cancel merge" },
  { ARTNET_AC_LED_NORMAL,      "LED Normal" },
  { ARTNET_AC_LED_MUTE,        "LED Mute" },
  { ARTNET_AC_LED_LOCATE,      "LED Locate" },
  { ARTNET_AC_RESET_RX_FLAGS,  "Reset SIP text" },
  { ARTNET_AC_MERGE_LTP0,      "DMX port 1 LTP" },
  { ARTNET_AC_MERGE_LTP1,      "DMX port 2 LTP" },
  { ARTNET_AC_MERGE_LTP2,      "DXM port 3 LTP" },
  { ARTNET_AC_MERGE_LTP3,      "DMX port 4 LTP" },
  { ARTNET_AC_MERGE_HTP0,      "DMX port 1 HTP" },
  { ARTNET_AC_MERGE_HTP1,      "DMX port 2 HTP" },
  { ARTNET_AC_MERGE_HTP2,      "DXM port 3 HTP" },
  { ARTNET_AC_MERGE_HTP3,      "DMX port 4 HTP" },
  { ARTNET_AC_CLEAR_OP0,       "Clear DMX port 1" },
  { ARTNET_AC_CLEAR_OP1,       "Clear DMX port 2" },
  { ARTNET_AC_CLEAR_OP2,       "Clear DXM port 3" },
  { ARTNET_AC_CLEAR_OP3,       "Clear DMX port 4" },
  { 0,                         NULL }
};

#define ARTNET_FT_FIRM_FIRST 0x00
#define ARTNET_FT_FIRM_CONT  0x01
#define ARTNET_FT_FIRM_LAST  0x02
#define ARTNET_FT_UBEA_FIRST 0x03
#define ARTNET_FT_UBEA_CONT  0x04
#define ARTNET_FT_UBEA_LAST  0x05

static const value_string artnet_firmware_master_type_vals[] = {
  { ARTNET_FT_FIRM_FIRST, "FirmFirst" },
  { ARTNET_FT_FIRM_CONT,  "FirmCont" },
  { ARTNET_FT_FIRM_LAST,  "FirmLast" },
  { ARTNET_FT_UBEA_FIRST, "UbeaFirst" },
  { ARTNET_FT_UBEA_CONT,  "UbeaCont" },
  { ARTNET_FT_UBEA_LAST,  "UbeaLast" },
  { 0,                    NULL }
};

#define ARTNET_FRT_FIRM_BLOCK_GOOD 0x00
#define ARTNET_FRT_FIRM_ALL_GOOD   0x01
#define ARTNET_FRT_FIRM_FAIL       0xff

static const value_string artnet_firmware_reply_type_vals[] = {
  { ARTNET_FRT_FIRM_BLOCK_GOOD, "FirmBlockGood" },
  { ARTNET_FRT_FIRM_ALL_GOOD,   "FirmAllGood" },
  { ARTNET_FRT_FIRM_FAIL,       "FirmFail" },
  { 0,                          NULL }
};

void proto_reg_handoff_artnet(void);

/* Define the artnet proto */
static int proto_artnet = -1;

/* Header */
static int hf_artnet_header = -1;
static int hf_artnet_header_id = -1;
static int hf_artnet_header_opcode = -1;

/* ArtPoll */
static int hf_artnet_poll = -1;
static int hf_artnet_poll_protver = -1;
static int hf_artnet_poll_talktome = -1;
static int hf_artnet_poll_pad = -1;

/* ArtPollReply */
static int hf_artnet_poll_reply = -1;
static int hf_artnet_poll_reply_ip_address = -1;
static int hf_artnet_poll_reply_port_nr = -1;
static int hf_artnet_poll_reply_versinfo = -1;
static int hf_artnet_poll_reply_subswitch = -1;
static int hf_artnet_poll_reply_oem = -1;
static int hf_artnet_poll_reply_ubea_version = -1;
static int hf_artnet_poll_reply_status = -1;
static int hf_artnet_poll_reply_esta_man = -1;
static int hf_artnet_poll_reply_short_name = -1;
static int hf_artnet_poll_reply_long_name = -1;
static int hf_artnet_poll_reply_node_report = -1;
static int hf_artnet_poll_reply_port_info = -1;
static int hf_artnet_poll_reply_num_ports = -1;
static int hf_artnet_poll_reply_port_types = -1;
static int hf_artnet_poll_reply_port_types_1 = -1;
static int hf_artnet_poll_reply_port_types_2 = -1;
static int hf_artnet_poll_reply_port_types_3 = -1;
static int hf_artnet_poll_reply_port_types_4 = -1;
static int hf_artnet_poll_reply_good_input = -1;
static int hf_artnet_poll_reply_good_input_1 = -1;
static int hf_artnet_poll_reply_good_input_2 = -1;
static int hf_artnet_poll_reply_good_input_3 = -1;
static int hf_artnet_poll_reply_good_input_4 = -1;
static int hf_artnet_poll_reply_good_output = -1;
static int hf_artnet_poll_reply_good_output_1 = -1;
static int hf_artnet_poll_reply_good_output_2 = -1;
static int hf_artnet_poll_reply_good_output_3 = -1;
static int hf_artnet_poll_reply_good_output_4 = -1;
static int hf_artnet_poll_reply_swin = -1;
static int hf_artnet_poll_reply_swin_1 = -1;
static int hf_artnet_poll_reply_swin_2 = -1;
static int hf_artnet_poll_reply_swin_3 = -1;
static int hf_artnet_poll_reply_swin_4 = -1;
static int hf_artnet_poll_reply_swout = -1;
static int hf_artnet_poll_reply_swout_1 = -1;
static int hf_artnet_poll_reply_swout_2 = -1;
static int hf_artnet_poll_reply_swout_3 = -1;
static int hf_artnet_poll_reply_swout_4 = -1;
static int hf_artnet_poll_reply_swvideo = -1;
static int hf_artnet_poll_reply_swmacro = -1;
static int hf_artnet_poll_reply_swremote = -1;
static int hf_artnet_poll_reply_spare = -1;
static int hf_artnet_poll_reply_mac = -1;

/* ArtOutput */
static int hf_artnet_output = -1;
static int hf_artnet_output_protver = -1;
static int hf_artnet_output_sequence = -1;
static int hf_artnet_output_physical = -1;
static int hf_artnet_output_universe = -1;
static int hf_artnet_output_length = -1;
static int hf_artnet_output_data = -1;

/* ArtAddress */
static int hf_artnet_address = -1;
static int hf_artnet_address_protver = -1;
static int hf_artnet_address_filler = -1;
static int hf_artnet_address_short_name = -1;
static int hf_artnet_address_long_name = -1;
static int hf_artnet_address_swin = -1;
static int hf_artnet_address_swin_1 = -1;
static int hf_artnet_address_swin_2 = -1;
static int hf_artnet_address_swin_3 = -1;
static int hf_artnet_address_swin_4 = -1;
static int hf_artnet_address_swout = -1;
static int hf_artnet_address_swout_1 = -1;
static int hf_artnet_address_swout_2 = -1;
static int hf_artnet_address_swout_3 = -1;
static int hf_artnet_address_swout_4 = -1;
static int hf_artnet_address_subswitch = -1;
static int hf_artnet_address_swvideo = -1;
static int hf_artnet_address_command = -1;

/* ArtInput */
static int hf_artnet_input = -1;
static int hf_artnet_input_protver = -1;
static int hf_artnet_input_filler = -1;
static int hf_artnet_input_num_ports = -1;
static int hf_artnet_input_input = -1;
static int hf_artnet_input_input_1 = -1;
static int hf_artnet_input_input_2 = -1;
static int hf_artnet_input_input_3 = -1;
static int hf_artnet_input_input_4 = -1;

/* ArtFirmwareMaster */
static int hf_artnet_firmware_master = -1;
static int hf_artnet_firmware_master_protver = -1;
static int hf_artnet_firmware_master_filler = -1;
static int hf_artnet_firmware_master_type = -1;
static int hf_artnet_firmware_master_block_id = -1;
static int hf_artnet_firmware_master_length = -1;
static int hf_artnet_firmware_master_spare = -1;
static int hf_artnet_firmware_master_data = -1;

/* ArtFirmwareReply */
static int hf_artnet_firmware_reply = -1;
static int hf_artnet_firmware_reply_protver = -1;
static int hf_artnet_firmware_reply_filler = -1;
static int hf_artnet_firmware_reply_type = -1;
static int hf_artnet_firmware_reply_spare = -1;

/* ArtVideoSetup */
static int hf_artnet_video_setup = -1;
static int hf_artnet_video_setup_protver = -1;
static int hf_artnet_video_setup_filler = -1;
static int hf_artnet_video_setup_control = -1;
static int hf_artnet_video_setup_font_height = -1;
static int hf_artnet_video_setup_first_font = -1;
static int hf_artnet_video_setup_last_font = -1;
static int hf_artnet_video_setup_win_font_name = -1;
static int hf_artnet_video_setup_font_data = -1;

/* ArtVideoPalette */
static int hf_artnet_video_palette = -1;
static int hf_artnet_video_palette_protver = -1;
static int hf_artnet_video_palette_filler = -1;
static int hf_artnet_video_palette_colour_red = -1;
static int hf_artnet_video_palette_colour_green = -1;
static int hf_artnet_video_palette_colour_blue = -1;

/* ArtVideoData */
static int hf_artnet_video_data = -1;
static int hf_artnet_video_data_protver = -1;
static int hf_artnet_video_data_filler = -1;
static int hf_artnet_video_data_pos_x = -1;
static int hf_artnet_video_data_pos_y = -1;
static int hf_artnet_video_data_len_x = -1;
static int hf_artnet_video_data_len_y = -1;
static int hf_artnet_video_data_data = -1;



/* Define the tree for artnet */
static int ett_artnet = -1;

/* 
 * Here are the global variables associated with the preferences
 * for artnet
 */

static guint global_udp_port_artnet = UDP_PORT_ARTNET;
static guint udp_port_artnet = UDP_PORT_ARTNET;

/* A static handle for the ip dissector */
static dissector_handle_t ip_handle;

static guint
dissect_artnet_poll(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  guint8 talktome;
  guint16 protver;

  protver = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_protver, tvb,
                      offset, 2, protver);
  offset += 2;

  talktome = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_talktome, tvb,
                      offset, 1, talktome);
  offset += 1;
        
  proto_tree_add_item(tree, hf_artnet_poll_pad, tvb,
                      offset, 1, FALSE);
  offset += 1;
  
  return offset;
}

static guint 
dissect_artnet_poll_reply(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  proto_tree *hi,*si,*ti;
  guint32 ip_address;
  guint16 port_nr, versinfo,subswitch,oem;
  guint8 ubea_version,swin,swout,swvideo,swmacro,swremote;
  guint8 status,port_types,good_input,good_output;
  guint16 esta_man;
  guint16 num_ports;
        
  ip_address = tvb_get_letohl(tvb, offset);
  proto_tree_add_ipv4(tree, hf_artnet_poll_reply_ip_address, tvb,
                      offset, 4, ip_address);
  offset += 4;
      
  port_nr = tvb_get_letohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_reply_port_nr, tvb,
                      offset, 2, port_nr);
  offset += 2;

  versinfo = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_reply_versinfo, tvb,
                      offset, 2, versinfo);
  offset += 2;
      
  subswitch = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_reply_subswitch, tvb,
                      offset, 2, subswitch);
  offset += 2;
        
  oem = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_reply_oem, tvb,
                      offset, 2, oem);
  offset += 2;

  ubea_version = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_reply_ubea_version, tvb,
                      offset, 1, ubea_version);
  offset += 1;
   
  status = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_reply_status, tvb,
                      offset, 1, status);
  offset += 1;

  esta_man = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_reply_esta_man, tvb,
                      offset, 2, esta_man);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_short_name,
                      tvb, offset, 18, FALSE);
  offset += 18;
        
  proto_tree_add_item(tree, hf_artnet_poll_reply_long_name,
                      tvb, offset, 64, FALSE);
  offset += 64;

  proto_tree_add_item(tree, hf_artnet_poll_reply_node_report,
                      tvb, offset, 64, FALSE);
  offset += 64;

  
  hi = proto_tree_add_item(tree,
                           hf_artnet_poll_reply_port_info,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_PORT_INFO_LENGTH,
                           FALSE);

  si = proto_item_add_subtree(hi, ett_artnet);

  num_ports = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(si, hf_artnet_poll_reply_num_ports, tvb,
                      offset, 2, num_ports);
  offset += 2;

  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_port_types,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_PORT_TYPES_LENGTH,
                           FALSE);

  ti = proto_item_add_subtree(hi, ett_artnet);

  port_types = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_port_types_1, tvb,
                      offset, 1, port_types);
  offset += 1;

  port_types = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_port_types_2, tvb,
                      offset, 1, port_types);
  offset += 1;

  port_types = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_port_types_3, tvb,
                      offset, 1, port_types);
  offset += 1;

  port_types = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_port_types_4, tvb,
                      offset, 1, port_types);
  offset += 1;
  
  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_good_input,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_GOOD_INPUT_LENGTH,
                           FALSE);

  ti = proto_item_add_subtree(hi, ett_artnet);

  good_input = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_good_input_1, tvb,
                      offset, 1, good_input);
  offset += 1;

  good_input = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_good_input_2, tvb,
                      offset, 1, good_input);
  offset += 1;

  good_input = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_good_input_3, tvb,
                      offset, 1, good_input);
  offset += 1;

  good_input = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_good_input_4, tvb,
                      offset, 1, good_input);
  offset += 1;

  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_good_output,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_GOOD_OUTPUT_LENGTH,
                           FALSE);

  ti = proto_item_add_subtree(hi, ett_artnet);

  good_output = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_good_output_1, tvb,
                      offset, 1, good_output);
  offset += 1;

  good_output = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_good_output_2, tvb,
                      offset, 1, good_output);
  offset += 1;

  good_output = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_good_output_3, tvb,
                      offset, 1, good_output);
  offset += 1;

  good_output = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_good_output_4, tvb,
                      offset, 1, good_output);
  offset += 1;

  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_swin,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_SWIN_LENGTH,
                           FALSE);

  ti = proto_item_add_subtree(hi, ett_artnet);

  swin = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_swin_1, tvb,
                      offset, 1, swin);
  offset += 1;

  swin = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_swin_2, tvb,
                      offset, 1, swin);
  offset += 1;

  swin = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_swin_3, tvb,
                      offset, 1, swin);
  offset += 1;

  swin = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_swin_4, tvb,
                      offset, 1, swin);
  offset += 1;

  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_swout,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_SWOUT_LENGTH,
                           FALSE);

  ti = proto_item_add_subtree(hi, ett_artnet);

  swout = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_swout_1, tvb,
                      offset, 1, swout);
  offset += 1;

  swout = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_swout_2, tvb,
                      offset, 1, swout);
  offset += 1;

  swout = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_swout_3, tvb,
                      offset, 1, swout);
  offset += 1;

  swout = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_poll_reply_swout_4, tvb,
                      offset, 1, swout);
  offset += 1;

  swvideo = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_reply_swvideo, tvb,
                      offset, 1, swvideo);
  offset += 1;

  swmacro = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_reply_swmacro, tvb,
                      offset, 1, swmacro);
  offset += 1;

  swremote = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_poll_reply_swremote, tvb,
                      offset, 1, swremote);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_spare, tvb,
                      offset, 4, FALSE);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_poll_reply_mac,
                        tvb, offset, 6, FALSE);

  offset += 6;
  
  return offset;
}

static guint 
dissect_artnet_output(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  guint16 protver,universe,length;
  guint8 sequence,physical;
        
  protver = tvb_get_letohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_output_protver, tvb,
                      offset, 2, protver);
  offset += 2;

  sequence = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_output_sequence, tvb,
                      offset, 1, sequence);
  offset += 1;
  
  physical = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_output_physical, tvb,
                      offset, 1, physical);
  offset += 1;
  
  universe = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_output_universe, tvb,
                      offset, 2, universe);
  offset += 2;
  
  length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_output_length, tvb,
                      offset, 2, length);
  offset += 2;
  
  proto_tree_add_item(tree, hf_artnet_output_data, tvb,
                      offset, length, FALSE );
  offset += length;

  return offset;   
}

static guint
dissect_artnet_address(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  proto_tree *hi,*si,*ti;
  guint16 protver;
  guint8 swin,swout,swvideo,command;
        
  protver = tvb_get_letohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_address_protver, tvb,
                      offset, 2, protver);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_address_filler, tvb,
                      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_address_short_name,
                      tvb, offset, 18, FALSE);
  offset += 18;
        
  proto_tree_add_item(tree, hf_artnet_address_long_name,
                      tvb, offset, 64, FALSE);
  offset += 64;

  hi = proto_tree_add_item(tree,
                           hf_artnet_address_swin,
                           tvb,
                           offset,
                           ARTNET_ADDRESS_SWIN_LENGTH,
                           FALSE);

  ti = proto_item_add_subtree(hi, ett_artnet);

  swin = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_address_swin_1, tvb,
                      offset, 1, swin);
  offset += 1;

  swin = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_address_swin_2, tvb,
                      offset, 1, swin);
  offset += 1;

  swin = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_address_swin_3, tvb,
                      offset, 1, swin);
  offset += 1;

  swin = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(ti, hf_artnet_address_swin_4, tvb,
                      offset, 1, swin);
  offset += 1;

  hi = proto_tree_add_item(tree,
                           hf_artnet_address_swout,
                           tvb,
                           offset,
                           ARTNET_ADDRESS_SWOUT_LENGTH,
                           FALSE);

  si = proto_item_add_subtree(hi, ett_artnet);

  swout = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(si, hf_artnet_address_swout_1, tvb,
                      offset, 1, swout);
  offset += 1;

  swout = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(si, hf_artnet_address_swout_2, tvb,
                      offset, 1, swout);
  offset += 1;

  swout = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(si, hf_artnet_address_swout_3, tvb,
                      offset, 1, swout);
  offset += 1;

  swout = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(si, hf_artnet_address_swout_4, tvb,
                      offset, 1, swout);
  offset += 1;

  swvideo = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_address_swvideo, tvb,
                      offset, 1, swvideo);
  offset += 1;

  command = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_address_command, tvb,
                      offset, 1, command);

  offset += 1;
  
  return offset;
}

static guint 
dissect_artnet_input(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  proto_tree *hi,*si;
  guint16 protver, num_ports;
  guint8 input;
        
  protver = tvb_get_letohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_input_protver, tvb,
                      offset, 2, protver);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_input_filler, tvb,
                      offset, 2, FALSE);
  offset += 2;

  num_ports = tvb_get_letohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_input_num_ports, tvb,
                      offset, 2, num_ports);
  offset += 2;

  hi = proto_tree_add_item(tree,
                           hf_artnet_input_input,
                           tvb,
                           offset,
                           ARTNET_INPUT_INPUT_LENGTH,
                           FALSE);

  si = proto_item_add_subtree(hi, ett_artnet);

  input = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(si, hf_artnet_input_input_1, tvb,
                      offset, 1, input);
  offset += 1;

  input = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(si, hf_artnet_input_input_2, tvb,
                      offset, 1, input);
  offset += 1;

  input = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(si, hf_artnet_input_input_3, tvb,
                      offset, 1, input);
  offset += 1;

  input = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(si, hf_artnet_input_input_4, tvb,
                      offset, 1, input);
  offset += 1;
  
  return offset;
}

static guint
dissect_artnet_video_setup(tvbuff_t *tvb, guint offset, proto_tree *tree ) {
  guint16 protver;
  guint32 size;
  guint8 control,font_height, last_font,first_font;
        
  protver = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_setup_protver, tvb,
                      offset, 2, protver);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_video_setup_filler, tvb,
                      offset, 4, FALSE);
  offset += 4;

  control = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_setup_control, tvb,
                      offset, 1, control);
  offset += 1;

  font_height = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_setup_font_height, tvb,
                      offset, 1, font_height);
  offset += 1;

  first_font = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_setup_first_font, tvb,
                      offset, 1, first_font);
  offset += 1;

  last_font = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_setup_last_font, tvb,
                      offset, 1, last_font);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_video_setup_win_font_name,
                      tvb, offset, 64, FALSE);
  offset += 64;

  size = last_font * font_height;

  proto_tree_add_item(tree, hf_artnet_video_setup_font_data, tvb,
                      offset, size, FALSE );
  
  offset += size;

  return offset;
}

static guint 
dissect_artnet_video_palette(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  guint16 protver;
        
  protver = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_palette_protver, tvb,
                      offset, 2, protver);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_video_palette_filler, tvb,
                      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_video_palette_colour_red, tvb,
                      offset, 17, FALSE );
  
  offset += 17;

  proto_tree_add_item(tree, hf_artnet_video_palette_colour_green, tvb,
                      offset, 17, FALSE );
  
  offset += 17;
  proto_tree_add_item(tree, hf_artnet_video_palette_colour_blue, tvb,
                      offset, 17, FALSE );
  
  offset += 17;

  return offset;
}

static guint
dissect_artnet_video_data(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  guint16 protver;
  guint8 pos_x, pos_y, len_x, len_y;
  guint32 size;
        
  protver = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_data_protver, tvb,
                      offset, 2, protver);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_video_data_filler, tvb,
                      offset, 2, FALSE);
  offset += 2;

  pos_x = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_data_pos_x, tvb,
                      offset, 1, pos_x);
  offset += 1;

  pos_y = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_data_pos_y, tvb,
                      offset, 1, pos_y);
  offset += 1;

  len_x = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_data_len_x, tvb,
                      offset, 1, len_x);
  offset += 1;

  len_y = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_data_len_y, tvb,
                      offset, 1, len_y);
  offset += 1;

  size = len_x * len_y * 2;

  proto_tree_add_item(tree, hf_artnet_video_data_data, tvb,
                      offset, size, FALSE );
  
  offset += size;

  return offset;
}

static guint 
dissect_artnet_firmware_master(tvbuff_t *tvb, guint offset, proto_tree *tree ) {
  guint16 protver;
  guint8 type,block_id;
  guint32 length;
        
  protver = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_firmware_master_protver, tvb,
                      offset, 2, protver);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_firmware_master_filler, tvb,
                      offset, 2, FALSE);
  offset += 2;
  
  type = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_firmware_master_type, tvb,
                      offset, 1, type);
  offset += 1;
  
  block_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_firmware_master_block_id, tvb,
                      offset, 1, block_id);
  offset += 1;
  
  length = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_firmware_master_length, tvb,
                      offset, 4, length);
  offset += 4;
  
  proto_tree_add_item(tree, hf_artnet_firmware_master_spare, tvb,
                      offset, 20, FALSE );
  
  offset += 20;
  
  proto_tree_add_item(tree, hf_artnet_firmware_master_data, tvb,
                      offset, 1024, FALSE );
  
  offset += 1024;
  
  return offset;  
}

static guint 
dissect_artnet_firmware_reply(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  guint16 protver;
  guint8 type;
        
  protver = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_firmware_reply_protver, tvb,
                      offset, 2, protver);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_firmware_reply_filler, tvb,
                      offset, 2, FALSE);
  offset += 2;
  
  type = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_firmware_reply_type, tvb,
                      offset, 1, type);
  offset += 1;
  
  proto_tree_add_item(tree, hf_artnet_firmware_reply_spare, tvb,
                      offset, 21, FALSE );
  
  offset += 21;

  return offset;
}

static void 
dissect_artnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset = 0;
  guint size;
  guint16 opcode;
  proto_tree *ti,*hi,*si,*artnet_tree=NULL,*artnet_header_tree=NULL;

  /* Set the protocol column */
  if(check_col(pinfo->cinfo,COL_PROTOCOL)){
    col_set_str(pinfo->cinfo,COL_PROTOCOL,"ARTNET");
  }

  /* Clear out stuff in the info column */
  if(check_col(pinfo->cinfo,COL_INFO)){
    col_clear(pinfo->cinfo,COL_INFO);
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_artnet, tvb, offset, -1, FALSE); 
    artnet_tree = proto_item_add_subtree(ti, ett_artnet);

    hi = proto_tree_add_item(artnet_tree,
                             hf_artnet_header,
                             tvb,
                             offset,
                             ARTNET_HEADER_LENGTH ,
                             FALSE);

    artnet_header_tree = proto_item_add_subtree(hi, ett_artnet);
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
                    tvb_get_ptr(tvb, offset, 8));
  }
  if( tree ){
    proto_tree_add_item(artnet_header_tree, hf_artnet_header_id,
                        tvb, offset, 8, FALSE);
  }
  offset += 8;

  opcode = tvb_get_letohs(tvb, offset);
  /* set the info column */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
      val_to_str(opcode, artnet_opcode_vals, "Unknown (0x%04x)"));
  }
  
  if( tree ){
    proto_tree_add_uint(artnet_header_tree, hf_artnet_header_opcode, tvb,
                        offset, 2, opcode);
  }
  offset += 2;

  switch( opcode ) {
    case ARTNET_OP_POLL:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_poll,
                                 tvb,
                                 offset,
                                 ARTNET_POLL_LENGTH,
                                 FALSE);

        si = proto_item_add_subtree(hi, ett_artnet);
        
        size = dissect_artnet_poll( tvb, offset, si );
        size -= offset;
        
        proto_item_set_len(si, size); 
      }	
      break;

    case ARTNET_OP_POLL_REPLY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_poll_reply,
                                 tvb,
                                 offset,
                                 ARTNET_POLL_REPLY_LENGTH,
                                 FALSE);

        si = proto_item_add_subtree(hi, ett_artnet);
        
        size = dissect_artnet_poll_reply( tvb, offset, si);
        size -= offset;

        proto_item_set_len(si, size); 
      }	
      break;

    case ARTNET_OP_OUTPUT:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_output,
                                 tvb,
                                 offset,
                                 ARTNET_OUTPUT_LENGTH,
                                 FALSE);

        si = proto_item_add_subtree(hi, ett_artnet);
        
        size = dissect_artnet_output( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size); 
      }
      break;

    case ARTNET_OP_ADDRESS:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_address,
                                 tvb,
                                 offset,
                                 ARTNET_POLL_REPLY_LENGTH,
                                 FALSE);

        si = proto_item_add_subtree(hi, ett_artnet);
        
        size = dissect_artnet_address( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size); 
      }	
      break;

    case ARTNET_OP_INPUT:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_input,
                                 tvb,
                                 offset,
                                 ARTNET_INPUT_LENGTH,
                                 FALSE);

        si = proto_item_add_subtree(hi, ett_artnet);
        
        size = dissect_artnet_input( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size); 
      }      
      break;

    case ARTNET_OP_VIDEO_SETUP:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_input,
                                 tvb,
                                 offset,
                                 ARTNET_VIDEO_SETUP_LENGTH,
                                 FALSE);

        si = proto_item_add_subtree(hi, ett_artnet);
        
        size = dissect_artnet_video_setup( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size); 
      }      
      break;

    case ARTNET_OP_VIDEO_PALETTE:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_input,
                                 tvb,
                                 offset,
                                 ARTNET_VIDEO_PALETTE_LENGTH,
                                 FALSE);

        si = proto_item_add_subtree(hi, ett_artnet);
        
        size = dissect_artnet_video_palette( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size); 
      }      
      break;
    
    case ARTNET_OP_VIDEO_DATA:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_input,
                                 tvb,
                                 offset,
                                 ARTNET_VIDEO_DATA_LENGTH,
                                 FALSE);

        si = proto_item_add_subtree(hi, ett_artnet);
        
        size = dissect_artnet_video_data( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size); 
      }      
      break;

    case ARTNET_OP_FIRMWARE_MASTER:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_firmware_master,
                                 tvb,
                                 offset,
                                 ARTNET_FIRMWARE_MASTER_LENGTH,
                                 FALSE);

        si = proto_item_add_subtree(hi, ett_artnet);
        
        size = dissect_artnet_firmware_master( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size); 
      }      
      break;

    case ARTNET_OP_FIRMWARE_REPLY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_firmware_master,
                                 tvb,
                                 offset,
                                 ARTNET_FIRMWARE_REPLY_LENGTH,
                                 FALSE);

        si = proto_item_add_subtree(hi, ett_artnet);
        
        size = dissect_artnet_firmware_reply( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size); 
      }      
      break;
      
    default:
      if (tree) {
        proto_tree_add_text(artnet_tree, tvb, offset, -1,
          "Data (%d bytes)", tvb_reported_length_remaining(tvb, offset));
      }
      break;
  }
}

void 
proto_register_artnet(void) {
  static hf_register_info hf[] = {

    /* header */
    
    { &hf_artnet_header,
      { "Descriptor Header", 
        "artnet.header",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET Descriptor Header", HFILL }},

    { &hf_artnet_header_id,
      { "ID",             
        "artnet.header.id",
        FT_STRING, BASE_DEC, NULL, 0x0,
        "ArtNET ID", HFILL }},

    { &hf_artnet_header_opcode,
      { "Opcode",             
        "artnet.header.opcode",
        FT_UINT16, BASE_HEX, VALS(artnet_opcode_vals), 0x0,
        "ArtNET message type", HFILL }},
   
    /* ArtPoll */

    { &hf_artnet_poll,
      { "ArtPoll packet", 
        "artnet.poll",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtPoll packet", HFILL }},

    { &hf_artnet_poll_protver,
      { "ProVer",             
        "artnet.poll.protver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Protcol revision number", HFILL }},

    { &hf_artnet_poll_talktome,
      { "TalkToMe",             
        "artnet.poll.talktome",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "TalkToMe", HFILL }},

    { &hf_artnet_poll_pad,
      { "Pad",             
        "artnet.poll.pad",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "Filler byte", HFILL }},

    /* ArtPollReply */

    { &hf_artnet_poll_reply,
      { "ArtPollReply packet", 
        "artnet.poll_reply",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtPollReply packet", HFILL }},

    { &hf_artnet_poll_reply_ip_address,
      { "IP Address",             
        "artnet.poll_reply.ip_address",
        FT_IPv4, BASE_DEC, NULL, 0x0,
        "IP Address", HFILL }},

    { &hf_artnet_poll_reply_port_nr,
      { "Port number",             
        "artnet.poll_reply.port_nr",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Port Number", HFILL }},

    { &hf_artnet_poll_reply_versinfo,
      { "Version Info",             
        "artnet.poll_reply.versinfo",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Version info", HFILL }},

    { &hf_artnet_poll_reply_subswitch,
      { "SubSwitch",             
        "artnet.poll_reply.subswitch",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Subswitch version", HFILL }},

    { &hf_artnet_poll_reply_oem,
      { "Oem",             
        "artnet.poll_reply.oem",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "OEM", HFILL }},

    { &hf_artnet_poll_reply_ubea_version,
      { "UBEA Version",             
        "artnet.poll_reply.ubea_version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "UBEA version number", HFILL }},
        
    { &hf_artnet_poll_reply_status,
      { "Status",             
        "artnet.poll_reply.status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Status", HFILL }},

    { &hf_artnet_poll_reply_esta_man,
      { "ESTA Code",             
        "artnet.poll_reply.esta_man",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "ESTA Code", HFILL }},

    { &hf_artnet_poll_reply_short_name,
      { "Short Name",             
        "artnet.poll_reply.short_name",
        FT_STRING, BASE_DEC, NULL, 0x0,
        "Short Name", HFILL }},

    { &hf_artnet_poll_reply_long_name,
      { "Long Name",             
        "artnet.poll_reply.long_name",
        FT_STRING, BASE_DEC, NULL, 0x0,
        "Long Name", HFILL }},

    { &hf_artnet_poll_reply_node_report,
      { "Node Report",             
        "artnet.poll_reply.node_report",
        FT_STRING, BASE_DEC, NULL, 0x0,
        "Node Report", HFILL }},

    { &hf_artnet_poll_reply_port_info,
      { "Port Info", 
        "artnet.poll_reply.port_info",
        FT_NONE, BASE_NONE, NULL, 0,
        "Port Info", HFILL }},

    { &hf_artnet_poll_reply_num_ports,
      { "Number of Ports",             
        "artnet.poll_reply.num_ports",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of Ports", HFILL }},

    { &hf_artnet_poll_reply_port_types,
      { "Port Types", 
        "artnet.poll_reply.port_types",
        FT_NONE, BASE_NONE, NULL, 0,
        "Port Types", HFILL }},

    { &hf_artnet_poll_reply_port_types_1,
      { "Type of Port 1",             
        "artnet.poll_reply.port_types_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Type of Port 1", HFILL }},

    { &hf_artnet_poll_reply_port_types_2,
      { "Type of Port 2",             
        "artnet.poll_reply.port_types_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Type of Port 2", HFILL }},

    { &hf_artnet_poll_reply_port_types_3,
      { "Type of Port 3",             
        "artnet.poll_reply.port_types_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Type of Port 3", HFILL }},

    { &hf_artnet_poll_reply_port_types_4,
      { "Type of Port 4",             
        "artnet.poll_reply.port_types_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Type of Port 4", HFILL }},

    { &hf_artnet_poll_reply_good_input,
      { "Input Status", 
        "artnet.poll_reply.good_input",
        FT_NONE, BASE_NONE, NULL, 0,
        "Input Status", HFILL }},

    { &hf_artnet_poll_reply_good_input_1,
      { "Input status of Port 1",             
        "artnet.poll_reply.good_input_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input status of Port 1", HFILL }},

    { &hf_artnet_poll_reply_good_input_2,
      { "Input status of Port 2",             
        "artnet.poll_reply.good_input_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input status of Port 2", HFILL }},

    { &hf_artnet_poll_reply_good_input_3,
      { "Input status of Port 3",             
        "artnet.poll_reply.good_input_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input status of Port 3", HFILL }},

    { &hf_artnet_poll_reply_good_input_4,
      { "Input status of Port 4",             
        "artnet.poll_reply.good_input_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input status of Port 4", HFILL }},

    { &hf_artnet_poll_reply_good_output,
      { "Output Status", 
        "artnet.poll_reply.good_output",
        FT_NONE, BASE_NONE, NULL, 0,
        "Port output status", HFILL }},

    { &hf_artnet_poll_reply_good_output_1,
      { "Output status of Port 1",             
        "artnet.poll_reply.good_output_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Output status of Port 1", HFILL }},

    { &hf_artnet_poll_reply_good_output_2,
      { "Output status of Port 2",             
        "artnet.poll_reply.good_output_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Output status of Port 2", HFILL }},

    { &hf_artnet_poll_reply_good_output_3,
      { "Output status of Port 3",             
        "artnet.poll_reply.good_output_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Output status of Port 3", HFILL }},

    { &hf_artnet_poll_reply_good_output_4,
      { "Output status of Port 4",             
        "artnet.poll_reply.good_output_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Outpus status of Port 4", HFILL }},

    { &hf_artnet_poll_reply_swin,
      { "Input Subswitch", 
        "artnet.poll_reply.swin",
        FT_NONE, BASE_NONE, NULL, 0,
        "Input Subswitch", HFILL }},

    { &hf_artnet_poll_reply_swin_1,
      { "Input Subswitch of Port 1",             
        "artnet.poll_reply.swin_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input Subswitch of Port 1", HFILL }},

    { &hf_artnet_poll_reply_swin_2,
      { "Input Subswitch of Port 2",             
        "artnet.poll_reply.swin_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input Subswitch of Port 2", HFILL }},

    { &hf_artnet_poll_reply_swin_3,
      { "Input Subswitch of Port 3",             
        "artnet.poll_reply.swin_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input Subswitch of Port 3", HFILL }},

    { &hf_artnet_poll_reply_swin_4,
      { "Input Subswitch of Port 4",             
        "artnet.poll_reply.swin_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input Subswitch of Port 4", HFILL }},

    { &hf_artnet_poll_reply_swout,
      { "Output Subswitch", 
        "artnet.poll_reply.swout",
        FT_NONE, BASE_NONE, NULL, 0,
        "Output Subswitch", HFILL }},

    { &hf_artnet_poll_reply_swout_1,
      { "Output Subswitch of Port 1",             
        "artnet.poll_reply.swout_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Output Subswitch of Port 1", HFILL }},

    { &hf_artnet_poll_reply_swout_2,
      { "Output Subswitch of Port 2",             
        "artnet.poll_reply.swout_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Output Subswitch of Port 2", HFILL }},

    { &hf_artnet_poll_reply_swout_3,
      { "Output Subswitch of Port 3",             
        "artnet.poll_reply.swout_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Output Subswitch of Port 3", HFILL }},

    { &hf_artnet_poll_reply_swout_4,
      { "Output Subswitch of Port 4",             
        "artnet.poll_reply.swout_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Ouput Subswitch of Port 4", HFILL }},

    { &hf_artnet_poll_reply_swvideo,
      { "SwVideo",             
        "artnet.poll_reply.swvideo",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "SwVideo", HFILL }},

    { &hf_artnet_poll_reply_swmacro,
      { "SwMacro",             
        "artnet.poll_reply.swmacro",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "SwMacro", HFILL }},

    { &hf_artnet_poll_reply_swremote,
      { "SwRemote",             
        "artnet.poll_reply.swremote",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "SwRemote", HFILL }},

    { &hf_artnet_poll_reply_spare,
      { "spare",             
        "artnet.poll_reply.spare",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "spare", HFILL }},
        
    { &hf_artnet_poll_reply_mac,
      { "MAC",             
        "artnet.poll_reply.mac",
        FT_ETHER, BASE_HEX, NULL, 0x0,
        "MAC", HFILL }},
        
    /* ArtOutput */

    { &hf_artnet_output,
      { "ArtDMX packet", 
        "artnet.output",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtDMX packet", HFILL }},

    { &hf_artnet_output_protver,
      { "ProVers",             
        "artnet.output.protver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ProtVers", HFILL }},
        
    { &hf_artnet_output_sequence,
      { "Sequence",             
        "artnet.output.sequence",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Sequence", HFILL }},
        
    { &hf_artnet_output_physical,
      { "Physical",             
        "artnet.output.physical",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Physical", HFILL }},
        
    { &hf_artnet_output_universe,
      { "Universe",             
        "artnet.output.universe",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Universe", HFILL }},
        
    { &hf_artnet_output_length,
      { "Length",             
        "artnet.output.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length", HFILL }},
        
    { &hf_artnet_output_data,
      { "DMX data",             
        "artnet.output.data",
        FT_BYTES, BASE_DEC, NULL, 0x0,
        "DMX Data", HFILL }},
                
    /* ArtAddress */

    { &hf_artnet_address,
      { "ArtAddress packet", 
        "artnet.address",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtAddress packet", HFILL }},

    { &hf_artnet_address_protver,
      { "ProVers",             
        "artnet.address.protver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ProtVers", HFILL }},

    { &hf_artnet_address_filler,
      { "filler",             
        "artnet.address.filler",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "filler", HFILL }},

    { &hf_artnet_address_short_name,
      { "Short Name",             
        "artnet.address.short_name",
        FT_STRING, BASE_DEC, NULL, 0x0,
        "Short Name", HFILL }},

    { &hf_artnet_address_long_name,
      { "Long Name",             
        "artnet.address.long_name",
        FT_STRING, BASE_DEC, NULL, 0x0,
        "Long Name", HFILL }},
        
    { &hf_artnet_address_swin,
      { "Input Subswitch", 
        "artnet.address.swin",
        FT_NONE, BASE_NONE, NULL, 0,
        "Input Subswitch", HFILL }},

    { &hf_artnet_address_swin_1,
      { "Input Subswitch of Port 1", 
        "artnet.address.swin_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input Subswitch of Port 1", HFILL }},

    { &hf_artnet_address_swin_2,
      { "Input Subswitch of Port 2", 
        "artnet.address.swin_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input Subswitch of Port 2", HFILL }},

    { &hf_artnet_address_swin_3,
      { "Input Subswitch of Port 3",             
        "artnet.address.swin_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input Subswitch of Port 3", HFILL }},

    { &hf_artnet_address_swin_4,
      { "Input Subswitch of Port 4",             
        "artnet.address.swin_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Input Subswitch of Port 4", HFILL }},

    { &hf_artnet_address_swout,
      { "Output Subswitch", 
        "artnet.address.swout",
        FT_NONE, BASE_NONE, NULL, 0,
        "Output Subswitch", HFILL }},

    { &hf_artnet_address_swout_1,
      { "Output Subswitch of Port 1", 
        "artnet.address.swout_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Output Subswitch of Port 1", HFILL }},

    { &hf_artnet_address_swout_2,
      { "Output Subswitch of Port 2",             
        "artnet.address.swout_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Output Subswitch of Port 2", HFILL }},

    { &hf_artnet_address_swout_3,
      { "Output Subswitch of Port 3",             
        "artnet.address.swout_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Output Subswitch of Port 3", HFILL }},

    { &hf_artnet_address_swout_4,
      { "Output Subswitch of Port 4",             
        "artnet.address.swout_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Ouput Subswitch of Port 4", HFILL }},

    { &hf_artnet_address_subswitch,
      { "Subswitch",             
        "artnet.address.subswitch",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Subswitch", HFILL }},

    { &hf_artnet_address_swvideo,
      { "SwVideo",             
        "artnet.address.swvideo",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "SwVideo", HFILL }},

    { &hf_artnet_address_command,
      { "Command",             
        "artnet.address.command",
        FT_UINT8, BASE_HEX, VALS(artnet_address_command_vals), 0x0,
        "Command", HFILL }},

    /* ArtInput */

    { &hf_artnet_input,
      { "ArtInput packet", 
        "artnet.input",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtInput packet", HFILL }},

    { &hf_artnet_input_protver,
      { "ProVers",             
        "artnet.input.protver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ProtVers", HFILL }},

    { &hf_artnet_input_filler,
      { "filler",             
        "artnet.input.filler",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "filler", HFILL }},
        
    { &hf_artnet_input_num_ports,
      { "Number of Ports",             
        "artnet.input.num_ports",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of Ports", HFILL }},

    { &hf_artnet_input_input,
      { "Port Status", 
        "artnet.input.input",
        FT_NONE, BASE_NONE, NULL, 0,
        "Port Status", HFILL }},

    { &hf_artnet_input_input_1,
      { "Status of Port 1",
        "artnet.input.input_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Status of Port 1", HFILL }},

    { &hf_artnet_input_input_2,
      { "Status of Port 2",
        "artnet.input.input_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Status of Port 2", HFILL }},

    { &hf_artnet_input_input_3,
      { "Status of Port 3",
        "artnet.input.input_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Status of Port 3", HFILL }},

    { &hf_artnet_input_input_4,
      { "Status of Port 4",
        "artnet.input.input_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Status of Port 4", HFILL }},
        
    /* ArtFirmwareMaster */

    { &hf_artnet_firmware_master,
      { "ArtFirmwareMaster packet", 
        "artnet.firmware_master",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtFirmwareMaster packet", HFILL }},

    { &hf_artnet_firmware_master_protver,
      { "ProVers",             
        "artnet.firmware_master.protver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ProtVers", HFILL }},

    { &hf_artnet_firmware_master_filler,
      { "filler",             
        "artnet.firmware_master.filler",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "filler", HFILL }},
        
    { &hf_artnet_firmware_master_type,
      { "Type",             
        "artnet.firmware_master.type",
        FT_UINT8, BASE_HEX, VALS(artnet_firmware_master_type_vals), 0x0,
        "Number of Ports", HFILL }},
        
    { &hf_artnet_firmware_master_block_id,
      { "Block ID",             
        "artnet.firmware_master.block_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Block ID", HFILL }},
        
    { &hf_artnet_firmware_master_length,
      { "Lentgh",             
        "artnet.firmware_master.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Length", HFILL }},
        
    { &hf_artnet_firmware_master_spare,
      { "spare",             
        "artnet.firmware_master.spare",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "spare", HFILL }},
        
    { &hf_artnet_firmware_master_data,
      { "data",             
        "artnet.firmware_master.data",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "data", HFILL }},
        
    /* ArtFirmwareReply */

    { &hf_artnet_firmware_reply,
      { "ArtFirmwareReply packet", 
        "artnet.firmware_reply",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtFirmwareReply packet", HFILL }},

    { &hf_artnet_firmware_reply_protver,
      { "ProVers",             
        "artnet.firmware_reply.protver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ProtVers", HFILL }},

    { &hf_artnet_firmware_reply_filler,
      { "filler",             
        "artnet.firmware_reply.filler",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "filler", HFILL }},
        
    { &hf_artnet_firmware_reply_type,
      { "Type",             
        "artnet.firmware_reply.type",
        FT_UINT8, BASE_HEX, VALS(artnet_firmware_reply_type_vals), 0x0,
        "Number of Ports", HFILL }},

    { &hf_artnet_firmware_reply_spare,
      { "spare",             
        "artnet.firmware_reply.spare",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "spare", HFILL }},
             
    /* ArtVideoSetup */

    { &hf_artnet_video_setup,
      { "ArtVideoSetup packet", 
        "artnet.video_setup",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtVideoSetup packet", HFILL }},

    { &hf_artnet_video_setup_protver,
      { "ProVers",             
        "artnet.video_setup.protver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ProtVers", HFILL }},

    { &hf_artnet_video_setup_filler,
      { "filler",             
        "artnet.video_setup.filler",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "filler", HFILL }},

    { &hf_artnet_video_setup_control,
      { "control",             
        "artnet.video_setup.control",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "control", HFILL }},

    { &hf_artnet_video_setup_font_height,
      { "Font Height",             
        "artnet.video_setup.font_height",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Font Height", HFILL }},

    { &hf_artnet_video_setup_first_font,
      { "First Font",             
        "artnet.video_setup.first_font",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "First Font", HFILL }},

    { &hf_artnet_video_setup_last_font,
      { "Last Font",             
        "artnet.video_setup.last_font",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Last Font", HFILL }},

    { &hf_artnet_video_setup_win_font_name,
      { "Windows Font Name",             
        "artnet.video_setup.win_font_name",
        FT_STRING, BASE_DEC, NULL, 0x0,
        "Windows Font Name", HFILL }},

    { &hf_artnet_video_setup_font_data,
      { "Font data",             
        "artnet.video_setup.font_data",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "Font Date", HFILL }},

    /* ArtVideoPalette */

    { &hf_artnet_video_palette,
      { "ArtVideoPalette packet", 
        "artnet.video_palette",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtVideoPalette packet", HFILL }},

    { &hf_artnet_video_palette_protver,
      { "ProVers",             
        "artnet.video_palette.protver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ProtVers", HFILL }},

    { &hf_artnet_video_palette_filler,
      { "filler",             
        "artnet.video_palette.filler",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "filler", HFILL }},

    { &hf_artnet_video_palette_colour_red,
      { "Colour Red",             
        "artnet.video_palette.colour_red",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "Colour Red", HFILL }},

    { &hf_artnet_video_palette_colour_green,
      { "Colour Green",             
        "artnet.video_palette.colour_green",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "Colour Green", HFILL }},

    { &hf_artnet_video_palette_colour_blue,
      { "Colour Blue",             
        "artnet.video_palette.colour_blue",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "Colour Blue", HFILL }},

    /* ArtVideoData */

    { &hf_artnet_video_data,
      { "ArtVideoData packet", 
        "artnet.video_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtVideoData packet", HFILL }},

    { &hf_artnet_video_data_protver,
      { "ProVers",             
        "artnet.video_data.protver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ProtVers", HFILL }},

    { &hf_artnet_video_data_filler,
      { "filler",             
        "artnet.video_data.filler",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "filler", HFILL }},

    { &hf_artnet_video_data_pos_x,
      { "PosX",             
        "artnet.video_data.pos_x",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "PosX", HFILL }},
        
    { &hf_artnet_video_data_pos_y,
      { "PosY",             
        "artnet.video_data.pos_y",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "PosY", HFILL }},

    { &hf_artnet_video_data_len_x,
      { "LenX",             
        "artnet.video_data.len_x",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "LenX", HFILL }},

    { &hf_artnet_video_data_len_y,
      { "LenY",             
        "artnet.video_data.len_y",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "LenY", HFILL }},

    { &hf_artnet_video_data_data,
      { "Video Data",             
        "artnet.video_data.data",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "Video Data", HFILL }}
  };

  static gint *ett[] = {
    &ett_artnet,
  };

  module_t *artnet_module;

  proto_artnet = proto_register_protocol("ArtNET",
				       "ARTNET","artnet");
  proto_register_field_array(proto_artnet,hf,array_length(hf));
  proto_register_subtree_array(ett,array_length(ett));

  artnet_module = prefs_register_protocol(proto_artnet,
					proto_reg_handoff_artnet);
  prefs_register_uint_preference(artnet_module, "udp_port",
				 "ARTNET UDP Port",
				 "The UDP port on which "
				 "ArtNET "
				 "packets will be sent",
				 10,&global_udp_port_artnet);

}

/* The registration hand-off routing */

void
proto_reg_handoff_artnet(void) {
  static int artnet_initialized = FALSE;
  static dissector_handle_t artnet_handle;

  ip_handle = find_dissector("ip");

  if(!artnet_initialized) {
    artnet_handle = create_dissector_handle(dissect_artnet,proto_artnet);
    artnet_initialized = TRUE;
  } else {
    dissector_delete("udp.port",udp_port_artnet,artnet_handle);
  }

  udp_port_artnet = global_udp_port_artnet;
  
  dissector_add("udp.port",global_udp_port_artnet,artnet_handle);
}

/* Start the functions we need for the plugin stuff */

#ifndef __ETHEREAL_STATIC__

G_MODULE_EXPORT void
plugin_reg_handoff(void){
  proto_reg_handoff_artnet();
}

G_MODULE_EXPORT void
plugin_init(plugin_address_table_t *pat
#ifndef PLUGINS_NEED_ADDRESS_TABLE
_U_
#endif
){
  /* initialise the table of pointers needed in Win32 DLLs */
  plugin_address_table_init(pat);
  /* register the new protocol, protocol fields, and subtrees */
  if (proto_artnet == -1) { /* execute protocol initialization only once */
    proto_register_artnet();
  }
}

#endif

/* End the functions we need for plugin stuff */

