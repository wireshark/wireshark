/* packet-artnet.c
 * Routines for Art-Net packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/strutil.h>

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


#define ARTNET_OP_POLL               0x2000
#define ARTNET_OP_POLL_REPLY         0x2100
#define ARTNET_OP_POLL_SERVER_REPLY  0x2200
#define ARTNET_OP_OUTPUT             0x5000
#define ARTNET_OP_ADDRESS            0x6000
#define ARTNET_OP_INPUT              0x7000
#define ARTNET_OP_VIDEO_SETUP        0xa010
#define ARTNET_OP_VIDEO_PALETTE      0xa020
#define ARTNET_OP_VIDEO_DATA         0xa040

#define ARTNET_OP_TOD_REQUEST        0x8000
#define ARTNET_OP_TOD_DATA           0x8100
#define ARTNET_OP_TOD_CONTROL        0x8200
#define ARTNET_OP_RDM                0x8300

#define ARTNET_OP_MAC_MASTER         0xf000
#define ARTNET_OP_MAC_SLAVE          0xf100
#define ARTNET_OP_FIRMWARE_MASTER    0xf200
#define ARTNET_OP_FIRMWARE_REPLY     0xf300

#define ARTNET_OP_IP_PROG            0xf800
#define ARTNET_OP_IP_PROG_REPLY      0xf900

static const value_string artnet_opcode_vals[] = {
  { ARTNET_OP_POLL,              "ArtPoll packet" },
  { ARTNET_OP_POLL_REPLY,        "ArtPollReply packet" },
  { ARTNET_OP_POLL_SERVER_REPLY, "ArtPollServerReply packet" },
  { ARTNET_OP_OUTPUT,            "ArtDMX data packet" },
  { ARTNET_OP_ADDRESS,           "ArtAddress packet" },
  { ARTNET_OP_INPUT,             "ArtInput packet" },
  { ARTNET_OP_VIDEO_SETUP,       "ArtVideoSetup packet" },
  { ARTNET_OP_VIDEO_PALETTE,     "ArtVideoPalette packet" },
  { ARTNET_OP_VIDEO_DATA,        "ArtVideoData packet" },
  { ARTNET_OP_TOD_REQUEST,       "ArtTodRequest packet" },
  { ARTNET_OP_TOD_DATA,          "ArtTodData packet" },
  { ARTNET_OP_TOD_CONTROL,       "ArtTodControl packet" },
  { ARTNET_OP_RDM,               "ArtRdm packet" },
  { ARTNET_OP_MAC_MASTER,        "ArtMacMaster packet" },
  { ARTNET_OP_MAC_SLAVE,         "ArtMacSlave packet" },
  { ARTNET_OP_FIRMWARE_MASTER,   "ArtFirmwareMaster packet" },
  { ARTNET_OP_FIRMWARE_REPLY,    "ArtFirmwareReply packet" },
  { ARTNET_OP_IP_PROG,           "ArtIpProg packet" },
  { ARTNET_OP_IP_PROG_REPLY,     "ArtIpProgReply packet" },
  { 0,                           NULL }
};

static const value_string artnet_oem_code_vals[] = {
  { 0x0000, "Artistic Licence:DMX-Hub:4x DMX in,4x DMX out" },
  { 0x0001, "ADB:Netgate:4x DMX in,4x DMX out" },
  { 0x0002, "MA Lighting:TBA:4x DMX in,4x DMX out" },
  { 0x0003, "Artistic Licence:Ether-Lynx:2x DMX in,4x DMX out" },
  { 0x0004, "LewLight:Capture v2:TBA" },
  { 0x0005, "High End:TBA:TBA" },
  { 0x0006, "Avolites:TBA:TBA" },
  { 0x0010, "Artistic Licence:Down-Lynx:2x DMX out. Wall Panel." },
  { 0x0011, "Artistic Licence:Up-Lynx:2x DMX in. Wall Panel" },
  { 0x0014, "Artistic Licence:Net-Lynx O/P:2x DMX out. Boxed Product" },
  { 0x0015, "Artistic Licence:Net-Lynx I/P:2x DMX in. Boxed Product" },
  { 0x0030, "Doug Fleenor Design:TBA:2x DMX out" },
  { 0x0031, "Doug Fleenor Design:TBA:2x DMX in" },
  { 0x0050, "Goddard Design:DMX-Link (tm) O/P:2x DMX out" },
  { 0x0051, "Goddard Design:DMX-Link (tm) I/P:2x DMX in" },
  { 0x0070, "ADB:Net-Port O/P:2x DMX out" },
  { 0x0071, "ADB:Net-Port I/P:2x DMX in" },
  { 0x0072, "ADB:Reserved:" },
  { 0x0073, "ADB:Reserved:" },
  { 0x0074, "ADB:Reserved:" },
  { 0x0075, "ADB:Reserved:" },
  { 0x0076, "ADB:Reserved:" },
  { 0x0077, "ADB:Reserved:" },
  { 0x0078, "ADB:Reserved:" },
  { 0x0079, "ADB:Reserved:" },
  { 0x007A, "ADB:Reserved:" },
  { 0x007B, "ADB:Reserved:" },
  { 0x007C, "ADB:Reserved:" },
  { 0x007D, "ADB:Reserved:" },
  { 0x007E, "ADB:Reserved:" },
  { 0x007F, "ADB:Reserved:" },
  { 0x008C, "Zero 88:TBA:2x DMX out" },
  { 0x008D, "Zero 88:TBA:2x DMX in" },
  { 0x008E, "Flying Pig:TBA:2x DMX out" },
  { 0x008F, "Flying Pig:TBA:2x DMX in" },
  { 0x0090, "ELC:ELC 2:2x DMX out" },
  { 0x0091, "ELC:ELC 4:4x DMX in. 4x DMX out" },
  { 0x0180, "Martin:Maxxyz:4x DMX in. 4x DMX out" },
  { 0x0190, "Enttec:Reserved:" },
  { 0x0191, "Enttec:Reserved:" },
  { 0x0192, "Enttec:Reserved:" },
  { 0x0193, "Enttec:Reserved:" },
  { 0x0194, "Enttec:Reserved:" },
  { 0x0195, "Enttec:Reserved:" },
  { 0x0196, "Enttec:Reserved:" },
  { 0x0197, "Enttec:Reserved:" },
  { 0x0198, "Enttec:Reserved:" },
  { 0x0199, "Enttec:Reserved:" },
  { 0x019A, "Enttec:Reserved:" },
  { 0x019B, "Enttec:Reserved:" },
  { 0x019C, "Enttec:Reserved:" },
  { 0x019D, "Enttec:Reserved:" },
  { 0x019E, "Enttec:Reserved:" },
  { 0x019F, "Enttec:Reserved:" },
  { 0x8000, "ADB:Netgate XT:Video output and trigger inputs" },
  { 0x8001, "Artistic Licence:Net-Patch:TBA" },
  { 0x8002, "Artistic Licence:DMX-Hub XT:Video output and trigger inputs" },
  { 0x8003, "Artistic Licence:No-Worries XT:Real time data record - playback" },
  { 0,      NULL }
};

static const value_string artnet_esta_man_vals[] = {
  { 0x414C, "Artistic Licence" },
  { 0,      NULL }
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

static const value_string artnet_tod_request_command_vals[] = {
  { 0,                   NULL }
};

#define ARTNET_TDC_TOD_FULL    0x00
#define ARTNET_TDC_TOD_NAK     0xFF

static const value_string artnet_tod_data_command_vals[] = {
  { ARTNET_TDC_TOD_FULL,    "TodFull" },
  { ARTNET_TDC_TOD_NAK,     "TodNak" },
  { 0,                      NULL }
};

#define ARTNET_TCC_ATC_NONE  0x00
#define ARTNET_TCC_ATC_FLUSH 0x01

static const value_string artnet_tod_control_command_vals[] = {
  { ARTNET_TCC_ATC_NONE,  "AtcNone" },
  { ARTNET_TCC_ATC_FLUSH, "AtcFlush" },
  { 0,                    NULL }
};

#define ARTNET_RC_AR_PROCESS  0x00

static const value_string artnet_rdm_command_vals[] = {
  { ARTNET_RC_AR_PROCESS,  "ArProcess" },
  { 0,                     NULL }
};

void proto_reg_handoff_artnet(void);

/* Define the artnet proto */
static int proto_artnet = -1;


/* general */
static int hf_artnet_filler = -1;
static int hf_artnet_spare = -1;

/* Header */
static int hf_artnet_header = -1;
static int hf_artnet_header_id = -1;
static int hf_artnet_header_opcode = -1;
static int hf_artnet_header_protver = -1;

/* ArtPoll */
static int hf_artnet_poll = -1;
static int hf_artnet_poll_talktome = -1;
static int hf_artnet_poll_talktome_reply_dest = -1;
static int hf_artnet_poll_talktome_reply_type = -1;
static int hf_artnet_poll_talktome_unused = -1;

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
static int hf_artnet_poll_reply_mac = -1;

/* ArtOutput */
static int hf_artnet_output = -1;
static int hf_artnet_output_sequence = -1;
static int hf_artnet_output_physical = -1;
static int hf_artnet_output_universe = -1;
static int hf_artnet_output_length = -1;
static int hf_artnet_output_data = -1;
static int hf_artnet_output_dmx_data = -1;
static int hf_artnet_output_data_filter = -1;

/* ArtAddress */
static int hf_artnet_address = -1;
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
static int hf_artnet_input_num_ports = -1;
static int hf_artnet_input_input = -1;
static int hf_artnet_input_input_1 = -1;
static int hf_artnet_input_input_2 = -1;
static int hf_artnet_input_input_3 = -1;
static int hf_artnet_input_input_4 = -1;

/* ArtFirmwareMaster */
static int hf_artnet_firmware_master = -1;
static int hf_artnet_firmware_master_type = -1;
static int hf_artnet_firmware_master_block_id = -1;
static int hf_artnet_firmware_master_length = -1;
static int hf_artnet_firmware_master_data = -1;

/* ArtFirmwareReply */
static int hf_artnet_firmware_reply = -1;
static int hf_artnet_firmware_reply_type = -1;

/* ArtVideoSetup */
static int hf_artnet_video_setup = -1;
static int hf_artnet_video_setup_control = -1;
static int hf_artnet_video_setup_font_height = -1;
static int hf_artnet_video_setup_first_font = -1;
static int hf_artnet_video_setup_last_font = -1;
static int hf_artnet_video_setup_win_font_name = -1;
static int hf_artnet_video_setup_font_data = -1;

/* ArtVideoPalette */
static int hf_artnet_video_palette = -1;
static int hf_artnet_video_palette_colour_red = -1;
static int hf_artnet_video_palette_colour_green = -1;
static int hf_artnet_video_palette_colour_blue = -1;

/* ArtVideoData */
static int hf_artnet_video_data = -1;
static int hf_artnet_video_data_pos_x = -1;
static int hf_artnet_video_data_pos_y = -1;
static int hf_artnet_video_data_len_x = -1;
static int hf_artnet_video_data_len_y = -1;
static int hf_artnet_video_data_data = -1;

/* ArtPollServerReply */
static int hf_artnet_poll_server_reply = -1;

/* ArtTodRequest */
static int hf_artnet_tod_request = -1;
static int hf_artnet_tod_request_command = -1;
static int hf_artnet_tod_request_ad_count = -1;
static int hf_artnet_tod_request_address = -1;

/* ArtTodData */
static int hf_artnet_tod_data = -1;
static int hf_artnet_tod_data_port = -1;
static int hf_artnet_tod_data_command_response = -1;
static int hf_artnet_tod_data_address = -1;
static int hf_artnet_tod_data_uid_total = -1;
static int hf_artnet_tod_data_block_count = -1;
static int hf_artnet_tod_data_uid_count = -1;
static int hf_artnet_tod_data_tod = -1;

/* ArtTodControl */
static int hf_artnet_tod_control = -1;
static int hf_artnet_tod_control_command = -1;
static int hf_artnet_tod_control_address = -1;

/* ArtRdm */
static int hf_artnet_rdm = -1;
static int hf_artnet_rdm_command = -1;
static int hf_artnet_rdm_address = -1;

/* ArtIpProg */
static int hf_artnet_ip_prog = -1;
static int hf_artnet_ip_prog_command = -1;
static int hf_artnet_ip_prog_command_prog_port = -1;
static int hf_artnet_ip_prog_command_prog_sm = -1;
static int hf_artnet_ip_prog_command_prog_ip = -1;
static int hf_artnet_ip_prog_command_reset = -1;
static int hf_artnet_ip_prog_command_unused = -1;
static int hf_artnet_ip_prog_command_prog_enable = -1;
static int hf_artnet_ip_prog_ip = -1;
static int hf_artnet_ip_prog_sm = -1;
static int hf_artnet_ip_prog_port = -1;

/* ArtIpProgReply */
static int hf_artnet_ip_prog_reply = -1;
static int hf_artnet_ip_prog_reply_ip = -1;
static int hf_artnet_ip_prog_reply_sm = -1;
static int hf_artnet_ip_prog_reply_port = -1;

/* Define the tree for artnet */
static int ett_artnet = -1;

/*
 * Here are the global variables associated with the preferences
 * for artnet
 */

static guint global_udp_port_artnet = UDP_PORT_ARTNET;
static gint global_disp_chan_val_type = 0;
static gint global_disp_col_count = 16;
static gint global_disp_chan_nr_type = 0;

/* A static handle for the rdm dissector */
static dissector_handle_t rdm_handle;

static guint
dissect_artnet_poll(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  guint8 talktome;
  proto_tree *flags_tree, *flags_item;

  talktome = tvb_get_guint8(tvb, offset);
  flags_item = proto_tree_add_uint(tree, hf_artnet_poll_talktome, tvb,
	                           offset, 1, talktome);

  flags_tree=proto_item_add_subtree(flags_item, ett_artnet);
  proto_tree_add_item(flags_tree, hf_artnet_poll_talktome_reply_dest, tvb, offset, 1, FALSE);
  proto_tree_add_item(flags_tree, hf_artnet_poll_talktome_reply_type, tvb, offset, 1, FALSE);
  proto_tree_add_item(flags_tree, hf_artnet_poll_talktome_unused, tvb, offset, 1, FALSE);

  offset += 1;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 1, FALSE);
  offset += 1;

  return offset;
}

static guint
dissect_artnet_poll_reply(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree *hi,*si,*ti;
  guint8 swin,swout,swvideo,swmacro,swremote;
  guint8 port_types,good_input,good_output;
  guint16 num_ports;

  proto_tree_add_item(tree, hf_artnet_poll_reply_ip_address, tvb,
                      offset, 4, FALSE);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_poll_reply_port_nr, tvb,
                      offset, 2, TRUE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_versinfo, tvb,
                      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_subswitch, tvb,
                      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_oem, tvb,
                      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_ubea_version, tvb,
                      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_status, tvb,
                      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_esta_man, tvb,
                      offset, 2, TRUE);
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

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 4, FALSE);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_poll_reply_mac,
                        tvb, offset, 6, FALSE);

  offset += 6;

  return offset;
}

static guint
dissect_artnet_output(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree *hi,*si;
  proto_item *item;
  guint16 length,r,c,row_count;
  guint8 v;
  static char string[255];
  char* ptr;
  const char* chan_format[] = {
    "%2u ",
    "%02x ",
    "%3u "
  };
  const char* string_format[] = {
    "%03x: %s",
    "%3u: %s"
  };

  proto_tree_add_item(tree, hf_artnet_output_sequence, tvb,
                      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_output_physical, tvb,
                      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_output_universe, tvb,
                      offset, 2, TRUE);
  offset += 2;

  length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_output_length, tvb,
                      offset, 2, length);
  offset += 2;

  hi = proto_tree_add_item(tree,
                           hf_artnet_output_data,
                           tvb,
                           offset,
                           length,
                           FALSE);

  si = proto_item_add_subtree(hi, ett_artnet);

  row_count = (length/global_disp_col_count) + ((length%global_disp_col_count) == 0 ? 0 : 1);
  ptr = string;
  /* XX: In theory the g_snprintf statements below could store '\0' bytes off the end of the     */
  /*     'string' buffer'. This is so since g_snprint returns the number of characters which     */
  /*     "would have been written" (whether or not there was room) and since ptr is always       */
  /*     incremented by this amount. In practice the string buffer is large enough such that the */
  /*     string buffer size is not exceeded even with the maximum number of columns which might  */
  /*     be displayed.                                                                           */
  /*     ToDo: consider recoding slightly ...                                                    */
  for (r=0; r < row_count;r++) {
    for (c=0;(c < global_disp_col_count) && (((r*global_disp_col_count)+c) < length);c++) {
      if ((c % (global_disp_col_count/2)) == 0) {
        ptr += g_snprintf(ptr, (gulong)(sizeof string - strlen(string)), " ");
      }

      v = tvb_get_guint8(tvb, (offset+(r*global_disp_col_count)+c));
      if (global_disp_chan_val_type == 0) {
        v = (v * 100) / 255;
        if (v == 100) {
          ptr += g_snprintf(ptr, (gulong)(sizeof string - strlen(string)), "FL ");
        } else {
          ptr += g_snprintf(ptr, (gulong)(sizeof string - strlen(string)), chan_format[global_disp_chan_val_type], v);
        }
      } else {
        ptr += g_snprintf(ptr, (gulong)(sizeof string - strlen(string)), chan_format[global_disp_chan_val_type], v);
      }
    }

    proto_tree_add_none_format(si,hf_artnet_output_dmx_data, tvb,
                               offset+(r*global_disp_col_count), c,
                               string_format[global_disp_chan_nr_type], (r*global_disp_col_count)+1, string);
    ptr = string;
  }

  /* Add the real type hidden */
  item = proto_tree_add_item(si, hf_artnet_output_data_filter, tvb,
                      offset, length, FALSE );
  PROTO_ITEM_SET_HIDDEN(item);
  offset += length;

  return offset;
}

static guint
dissect_artnet_address(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  proto_tree *hi,*si,*ti;
  guint8 swin,swout,swvideo,command;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
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
  guint16 num_ports;
  guint8 input;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
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
  guint32 size;
  guint8 control,font_height, last_font,first_font;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
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
dissect_artnet_video_palette(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
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
  guint8 len_x, len_y;
  guint32 size;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_video_data_pos_x, tvb,
                      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_video_data_pos_y, tvb,
                      offset, 1, FALSE);
  offset += 1;

  len_x = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_data_len_x, tvb,
                      offset, 1, len_x);
  offset += 1;

  len_y = tvb_get_guint8(tvb, offset);
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
  guint8 type,block_id;
  guint32 length;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
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

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 20, FALSE );

  offset += 20;

  proto_tree_add_item(tree, hf_artnet_firmware_master_data, tvb,
                      offset, 1024, FALSE );

  offset += 1024;

  return offset;
}

static guint
dissect_artnet_firmware_reply(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  guint8 type;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, FALSE);
  offset += 2;

  type = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_firmware_reply_type, tvb,
                      offset, 1, type);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 21, FALSE );

  offset += 21;

  return offset;
}

static guint
dissect_artnet_tod_request(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  guint8 ad_count;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, FALSE);
  offset += 8;

  proto_tree_add_item(tree, hf_artnet_tod_request_command, tvb,
		      offset, 1, FALSE);
  offset += 1;

  ad_count = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_tod_request_ad_count, tvb,
                      offset, 1, ad_count);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_request_address, tvb,
		      offset, ad_count, FALSE);
  offset += ad_count;

  return offset;
}

static guint
dissect_artnet_tod_data(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  guint8 i,uid_count;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_port, tvb,
		      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, FALSE);
  offset += 8;

  proto_tree_add_item(tree, hf_artnet_tod_data_command_response, tvb,
		      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_address, tvb,
		      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_uid_total, tvb,
		      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_tod_data_block_count, tvb,
		      offset, 1, FALSE);
  offset += 1;

  uid_count = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_tod_data_uid_count, tvb,
                      offset, 1, uid_count);
  offset += 1;

  for( i = 0; i < uid_count; i++)
  {
    proto_tree_add_item(tree, hf_artnet_tod_data_tod, tvb,
                        offset, 6, FALSE);
    offset += 6;
  }

  return offset;
}

static guint
dissect_artnet_tod_control(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, FALSE);
  offset += 8;

  proto_tree_add_item(tree, hf_artnet_tod_control_command, tvb,
		      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_control_address, tvb,
		      offset, 1, FALSE);
  offset += 1;

  return offset;
}

static guint
dissect_artnet_rdm(tvbuff_t *tvb, guint offset, proto_tree *tree,  packet_info *pinfo)
{
  guint size;
  gboolean save_info;
  tvbuff_t *next_tvb = NULL;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, FALSE);
  offset += 8;

  proto_tree_add_item(tree, hf_artnet_rdm_command, tvb,
		      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_rdm_address, tvb,
		      offset, 1, FALSE);
  offset += 1;

  size = tvb_reported_length_remaining(tvb, offset);

  save_info=col_get_writable(pinfo->cinfo);
  col_set_writable(pinfo->cinfo, FALSE);

  if (!next_tvb)
    next_tvb = tvb_new_subset_remaining(tvb, offset);

  call_dissector(rdm_handle, next_tvb, pinfo, tree);

  col_set_writable(pinfo->cinfo, save_info);

  size = tvb_reported_length_remaining(tvb, offset) - size;

  return offset + size;
}

static guint
dissect_artnet_ip_prog(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  guint8 command;
  proto_tree *flags_tree,*flags_item;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 2, FALSE);
  offset += 2;

  command = tvb_get_guint8(tvb, offset);
  flags_item = proto_tree_add_uint(tree, hf_artnet_ip_prog_command, tvb,
	                           offset, 1, command);

  flags_tree=proto_item_add_subtree(flags_item, ett_artnet);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_port, tvb, offset, 1, FALSE);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_sm, tvb, offset, 1, FALSE);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_ip, tvb, offset, 1, FALSE);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_reset, tvb, offset, 1, FALSE);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_unused, tvb, offset, 1, FALSE);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_enable, tvb, offset, 1, FALSE);

  offset += 1;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 1, FALSE);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_ip_prog_ip, tvb,
		      offset, 4, FALSE);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_ip_prog_sm, tvb,
		      offset, 4, FALSE);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_ip_prog_port, tvb,
		      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, FALSE);
  offset += 8;

  return offset;
}

static guint
dissect_artnet_ip_prog_reply(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 4, FALSE);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_ip_prog_reply_ip, tvb,
                      offset, 4, FALSE);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_ip_prog_reply_sm, tvb,
		      offset, 4, FALSE);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_ip_prog_reply_port, tvb,
		      offset, 2, FALSE);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, FALSE);
  offset += 8;

  return offset;
}

static guint
dissect_artnet_poll_server_reply(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  /* no spec released for this packet at the moment */
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 182, FALSE);
  offset += 182;

  return offset;
}


static void
dissect_artnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset = 0;
  guint size;
  guint16 opcode;
  proto_tree *ti,*hi,*si,*artnet_tree=NULL,*artnet_header_tree=NULL;

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ARTNET");

  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);

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
                    tvb_get_ephemeral_string(tvb, offset, 8));
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

  if( opcode != ARTNET_OP_POLL_REPLY && opcode != ARTNET_OP_POLL_SERVER_REPLY ) {
    if( tree ){
      proto_tree_add_item(artnet_header_tree, hf_artnet_header_protver, tvb,
                          offset, 2, FALSE);

      proto_item_set_len(artnet_header_tree, ARTNET_HEADER_LENGTH+2 );
    }
    offset += 2;
  }

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
                                 hf_artnet_firmware_reply,
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

    case ARTNET_OP_TOD_REQUEST:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_tod_request,
				 tvb,
				 offset,
				 0,
				 FALSE);

	si = proto_item_add_subtree(hi, ett_artnet);

	size = dissect_artnet_tod_request( tvb, offset, si );
	size -= offset;

	proto_item_set_len(si, size);
      }
      break;

    case ARTNET_OP_TOD_DATA:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
			         hf_artnet_tod_data,
				 tvb,
				 offset,
				 0,
				 FALSE);

	si = proto_item_add_subtree(hi, ett_artnet );

	size = dissect_artnet_tod_data( tvb, offset, si );
	size -= offset;

	proto_item_set_len(si, size );
      }
      break;

    case ARTNET_OP_TOD_CONTROL:
      if (tree){
	hi = proto_tree_add_item(artnet_tree,
			         hf_artnet_tod_control,
				 tvb,
				 offset,
				 0,
				 FALSE );
	si = proto_item_add_subtree(hi, ett_artnet );

	size = dissect_artnet_tod_control( tvb, offset, si );
	size -= offset;

	proto_item_set_len(si, size );
      }
      break;

    case ARTNET_OP_RDM:
      hi = proto_tree_add_item(artnet_tree,
			         hf_artnet_rdm,
				 tvb,
				 offset,
				 0,
				 FALSE);
      si = proto_item_add_subtree(hi,ett_artnet);

      size = dissect_artnet_rdm( tvb, offset, si, pinfo );
      size -= offset;

      proto_item_set_len( si, size );
      break;

    case ARTNET_OP_IP_PROG:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
			         hf_artnet_ip_prog,
				 tvb,
				 offset,
				 0,
				 FALSE);
	si = proto_item_add_subtree(hi, ett_artnet );

	size = dissect_artnet_ip_prog( tvb, offset, si);
	size -= offset;

	proto_item_set_len(si, size );
      }
      break;

    case ARTNET_OP_IP_PROG_REPLY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
			         hf_artnet_ip_prog_reply,
				 tvb,
				 offset,
				 0,
				 FALSE);
	si = proto_item_add_subtree(hi, ett_artnet );

	size = dissect_artnet_ip_prog_reply( tvb, offset, si );
	size -= offset;

	proto_item_set_len(si, size );
      }
      break;

    case ARTNET_OP_POLL_SERVER_REPLY:
      if (tree) {
	hi = proto_tree_add_item(artnet_tree,
			         hf_artnet_poll_server_reply,
				 tvb,
				 offset,
				 0,
				 FALSE );
	si = proto_item_add_subtree(hi, ett_artnet );

	size = dissect_artnet_poll_server_reply( tvb, offset, si );
	size -= offset;

	proto_item_set_len(si, size );
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

    /* General */

    { &hf_artnet_filler,
      { "filler",
        "artnet.filler",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_spare,
      { "spare",
        "artnet.spare",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* header */

    { &hf_artnet_header,
      { "Descriptor Header",
        "artnet.header",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net Descriptor Header", HFILL }},

    { &hf_artnet_header_id,
      { "ID",
        "artnet.header.id",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "ArtNET ID", HFILL }},

    { &hf_artnet_header_opcode,
      { "Opcode",
        "artnet.header.opcode",
        FT_UINT16, BASE_HEX, VALS(artnet_opcode_vals), 0x0,
        "Art-Net message type", HFILL }},

    { &hf_artnet_header_protver,
      { "ProVer",
        "artnet.header.protver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Protocol revision number", HFILL }},

    /* ArtPoll */

    { &hf_artnet_poll,
      { "ArtPoll packet",
        "artnet.poll",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtPoll packet", HFILL }},

    { &hf_artnet_poll_talktome,
      { "TalkToMe",
        "artnet.poll.talktome",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_talktome_reply_dest,
      { "Reply destination",
        "artnet.poll.talktome_reply_dest",
        FT_UINT8, BASE_HEX, NULL, 0x01,
        NULL, HFILL }},

    { &hf_artnet_poll_talktome_reply_type,
      { "Reply type",
        "artnet.poll.talktome_reply_type",
        FT_UINT8, BASE_HEX, NULL, 0x02,
        NULL, HFILL }},

    { &hf_artnet_poll_talktome_unused,
      { "unused",
        "artnet.poll.talktome_unused",
        FT_UINT8, BASE_HEX, NULL, 0xfc,
        NULL, HFILL }},

    /* ArtPollReply */

    { &hf_artnet_poll_reply,
      { "ArtPollReply packet",
        "artnet.poll_reply",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtPollReply packet", HFILL }},

    { &hf_artnet_poll_reply_ip_address,
      { "IP Address",
        "artnet.poll_reply.ip_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_port_nr,
      { "Port number",
        "artnet.poll_reply.port_nr",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_versinfo,
      { "Version Info",
        "artnet.poll_reply.versinfo",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_subswitch,
      { "SubSwitch",
        "artnet.poll_reply.subswitch",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Subswitch version", HFILL }},

    { &hf_artnet_poll_reply_oem,
      { "Oem",
        "artnet.poll_reply.oem",
        FT_UINT16, BASE_HEX, VALS(artnet_oem_code_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_ubea_version,
      { "UBEA Version",
        "artnet.poll_reply.ubea_version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "UBEA version number", HFILL }},

    { &hf_artnet_poll_reply_status,
      { "Status",
        "artnet.poll_reply.status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_esta_man,
      { "ESTA Code",
        "artnet.poll_reply.esta_man",
        FT_UINT16, BASE_HEX, VALS(artnet_esta_man_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_short_name,
      { "Short Name",
        "artnet.poll_reply.short_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_long_name,
      { "Long Name",
        "artnet.poll_reply.long_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_node_report,
      { "Node Report",
        "artnet.poll_reply.node_report",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_port_info,
      { "Port Info",
        "artnet.poll_reply.port_info",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_num_ports,
      { "Number of Ports",
        "artnet.poll_reply.num_ports",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_port_types,
      { "Port Types",
        "artnet.poll_reply.port_types",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_port_types_1,
      { "Type of Port 1",
        "artnet.poll_reply.port_types_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_port_types_2,
      { "Type of Port 2",
        "artnet.poll_reply.port_types_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_port_types_3,
      { "Type of Port 3",
        "artnet.poll_reply.port_types_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_port_types_4,
      { "Type of Port 4",
        "artnet.poll_reply.port_types_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_input,
      { "Input Status",
        "artnet.poll_reply.good_input",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_input_1,
      { "Input status of Port 1",
        "artnet.poll_reply.good_input_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_input_2,
      { "Input status of Port 2",
        "artnet.poll_reply.good_input_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_input_3,
      { "Input status of Port 3",
        "artnet.poll_reply.good_input_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_input_4,
      { "Input status of Port 4",
        "artnet.poll_reply.good_input_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output,
      { "Output Status",
        "artnet.poll_reply.good_output",
        FT_NONE, BASE_NONE, NULL, 0,
        "Port output status", HFILL }},

    { &hf_artnet_poll_reply_good_output_1,
      { "Output status of Port 1",
        "artnet.poll_reply.good_output_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_2,
      { "Output status of Port 2",
        "artnet.poll_reply.good_output_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_3,
      { "Output status of Port 3",
        "artnet.poll_reply.good_output_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_4,
      { "Output status of Port 4",
        "artnet.poll_reply.good_output_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Outpus status of Port 4", HFILL }},

    { &hf_artnet_poll_reply_swin,
      { "Input Subswitch",
        "artnet.poll_reply.swin",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swin_1,
      { "Input Subswitch of Port 1",
        "artnet.poll_reply.swin_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swin_2,
      { "Input Subswitch of Port 2",
        "artnet.poll_reply.swin_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swin_3,
      { "Input Subswitch of Port 3",
        "artnet.poll_reply.swin_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swin_4,
      { "Input Subswitch of Port 4",
        "artnet.poll_reply.swin_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swout,
      { "Output Subswitch",
        "artnet.poll_reply.swout",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swout_1,
      { "Output Subswitch of Port 1",
        "artnet.poll_reply.swout_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swout_2,
      { "Output Subswitch of Port 2",
        "artnet.poll_reply.swout_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swout_3,
      { "Output Subswitch of Port 3",
        "artnet.poll_reply.swout_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swout_4,
      { "Output Subswitch of Port 4",
        "artnet.poll_reply.swout_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swvideo,
      { "SwVideo",
        "artnet.poll_reply.swvideo",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swmacro,
      { "SwMacro",
        "artnet.poll_reply.swmacro",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swremote,
      { "SwRemote",
        "artnet.poll_reply.swremote",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_mac,
      { "MAC",
        "artnet.poll_reply.mac",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtOutput */

    { &hf_artnet_output,
      { "ArtDMX packet",
        "artnet.output",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtDMX packet", HFILL }},

    { &hf_artnet_output_sequence,
      { "Sequence",
        "artnet.output.sequence",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_output_physical,
      { "Physical",
        "artnet.output.physical",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_output_universe,
      { "Universe",
        "artnet.output.universe",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_output_length,
      { "Length",
        "artnet.output.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_output_data,
      { "DMX data",
        "artnet.output.data",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_output_data_filter,
      { "DMX data filter",
        "artnet.output.data_filter",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_output_dmx_data,
      { "DMX data",
        "artnet.output.dmx_data",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtAddress */

    { &hf_artnet_address,
      { "ArtAddress packet",
        "artnet.address",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtAddress packet", HFILL }},

    { &hf_artnet_address_short_name,
      { "Short Name",
        "artnet.address.short_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_long_name,
      { "Long Name",
        "artnet.address.long_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_swin,
      { "Input Subswitch",
        "artnet.address.swin",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_address_swin_1,
      { "Input Subswitch of Port 1",
        "artnet.address.swin_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_swin_2,
      { "Input Subswitch of Port 2",
        "artnet.address.swin_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_swin_3,
      { "Input Subswitch of Port 3",
        "artnet.address.swin_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_swin_4,
      { "Input Subswitch of Port 4",
        "artnet.address.swin_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_swout,
      { "Output Subswitch",
        "artnet.address.swout",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_address_swout_1,
      { "Output Subswitch of Port 1",
        "artnet.address.swout_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_swout_2,
      { "Output Subswitch of Port 2",
        "artnet.address.swout_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_swout_3,
      { "Output Subswitch of Port 3",
        "artnet.address.swout_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_swout_4,
      { "Output Subswitch of Port 4",
        "artnet.address.swout_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_subswitch,
      { "Subswitch",
        "artnet.address.subswitch",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_swvideo,
      { "SwVideo",
        "artnet.address.swvideo",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_command,
      { "Command",
        "artnet.address.command",
        FT_UINT8, BASE_HEX, VALS(artnet_address_command_vals), 0x0,
        NULL, HFILL }},

    /* ArtInput */

    { &hf_artnet_input,
      { "ArtInput packet",
        "artnet.input",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtInput packet", HFILL }},

    { &hf_artnet_input_num_ports,
      { "Number of Ports",
        "artnet.input.num_ports",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_input_input,
      { "Port Status",
        "artnet.input.input",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_input_input_1,
      { "Status of Port 1",
        "artnet.input.input_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_input_input_2,
      { "Status of Port 2",
        "artnet.input.input_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_input_input_3,
      { "Status of Port 3",
        "artnet.input.input_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_input_input_4,
      { "Status of Port 4",
        "artnet.input.input_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    /* ArtFirmwareMaster */

    { &hf_artnet_firmware_master,
      { "ArtFirmwareMaster packet",
        "artnet.firmware_master",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtFirmwareMaster packet", HFILL }},

    { &hf_artnet_firmware_master_type,
      { "Type",
        "artnet.firmware_master.type",
        FT_UINT8, BASE_HEX, VALS(artnet_firmware_master_type_vals), 0x0,
        "Number of Ports", HFILL }},

    { &hf_artnet_firmware_master_block_id,
      { "Block ID",
        "artnet.firmware_master.block_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_firmware_master_length,
      { "Length",
        "artnet.firmware_master.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_firmware_master_data,
      { "data",
        "artnet.firmware_master.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtFirmwareReply */

    { &hf_artnet_firmware_reply,
      { "ArtFirmwareReply packet",
        "artnet.firmware_reply",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtFirmwareReply packet", HFILL }},

    { &hf_artnet_firmware_reply_type,
      { "Type",
        "artnet.firmware_reply.type",
        FT_UINT8, BASE_HEX, VALS(artnet_firmware_reply_type_vals), 0x0,
        "Number of Ports", HFILL }},

    /* ArtVideoSetup */

    { &hf_artnet_video_setup,
      { "ArtVideoSetup packet",
        "artnet.video_setup",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtVideoSetup packet", HFILL }},

    { &hf_artnet_video_setup_control,
      { "control",
        "artnet.video_setup.control",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_setup_font_height,
      { "Font Height",
        "artnet.video_setup.font_height",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_setup_first_font,
      { "First Font",
        "artnet.video_setup.first_font",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_setup_last_font,
      { "Last Font",
        "artnet.video_setup.last_font",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_setup_win_font_name,
      { "Windows Font Name",
        "artnet.video_setup.win_font_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_setup_font_data,
      { "Font data",
        "artnet.video_setup.font_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Font Date", HFILL }},

    /* ArtVideoPalette */

    { &hf_artnet_video_palette,
      { "ArtVideoPalette packet",
        "artnet.video_palette",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtVideoPalette packet", HFILL }},

    { &hf_artnet_video_palette_colour_red,
      { "Colour Red",
        "artnet.video_palette.colour_red",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_palette_colour_green,
      { "Colour Green",
        "artnet.video_palette.colour_green",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_palette_colour_blue,
      { "Colour Blue",
        "artnet.video_palette.colour_blue",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtVideoData */

    { &hf_artnet_video_data,
      { "ArtVideoData packet",
        "artnet.video_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtVideoData packet", HFILL }},

    { &hf_artnet_video_data_pos_x,
      { "PosX",
        "artnet.video_data.pos_x",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_data_pos_y,
      { "PosY",
        "artnet.video_data.pos_y",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_data_len_x,
      { "LenX",
        "artnet.video_data.len_x",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_data_len_y,
      { "LenY",
        "artnet.video_data.len_y",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_video_data_data,
      { "Video Data",
        "artnet.video_data.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtTodRequest */
    { &hf_artnet_tod_request,
      { "ArtTodRequest packet",
        "artnet.tod_request",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtTodRequest packet", HFILL }},

    { &hf_artnet_tod_request_command,
      { "Command",
        "artnet.tod_request.command",
        FT_UINT8, BASE_HEX, VALS(artnet_tod_request_command_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_request_ad_count,
      { "Address Count",
        "artnet.tod_request.ad_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_request_address,
      { "Address",
        "artnet.tod_request.address",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtTodData */
    { &hf_artnet_tod_data,
      { "ArtTodData packet",
        "artnet.tod_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtTodData packet", HFILL }},

    { &hf_artnet_tod_data_port,
      { "Port",
        "artnet.tod_data.port",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_data_command_response,
      { "Command Response",
        "artnet.tod_data.command_response",
        FT_UINT8, BASE_HEX, VALS(artnet_tod_data_command_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_data_address,
      { "Address",
        "artnet.tod_data.address",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_data_uid_total,
      { "UID Total",
        "artnet.tod_data.uid_total",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_data_block_count,
      { "Block Count",
        "artnet.tod_data.block_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_data_uid_count,
      { "UID Count",
        "artnet.tod_data.uid_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_data_tod,
      { "TOD",
        "artnet.tod_data.tod",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtTodControl */
    { &hf_artnet_tod_control,
      { "ArtTodControl packet",
        "artnet.tod_control",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtTodControl packet", HFILL }},

    { &hf_artnet_tod_control_command,
      { "Command",
        "artnet.tod_control.command",
        FT_UINT8, BASE_HEX, VALS(artnet_tod_control_command_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_control_address,
      { "Address",
        "artnet.tod_request.address",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    /* ArtRdm */
    { &hf_artnet_rdm,
      { "ArtRdm packet",
        "artnet.rdm",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtRdm packet", HFILL }},

    { &hf_artnet_rdm_command,
      { "Command",
        "artnet.rdm.command",
        FT_UINT8, BASE_HEX, VALS(artnet_rdm_command_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_rdm_address,
      { "Address",
        "artnet.rdm.address",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    /* ArtIpProg */
    { &hf_artnet_ip_prog,
      { "ArtIpProg packet",
        "artnet.ip_prog",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArtNET ArtIpProg packet", HFILL }},

    { &hf_artnet_ip_prog_command,
      { "Command",
        "artnet.ip_prog.command",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_prog_port,
      { "Program Port",
        "artnet.ip_prog.command_prog_port",
        FT_UINT8, BASE_HEX, NULL, 0x01,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_prog_sm,
      { "Program Subnet Mask",
        "artnet.ip_prog.command_prog_sm",
        FT_UINT8, BASE_HEX, NULL, 0x02,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_prog_ip,
      { "Program IP",
        "artnet.ip_prog.command_prog_ip",
        FT_UINT8, BASE_HEX, NULL, 0x04,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_reset,
      { "Reset parameters",
        "artnet.ip_prog.command_reset",
        FT_UINT8, BASE_HEX, NULL, 0x08,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_unused,
      { "Unused",
        "artnet.ip_prog.command_unused",
        FT_UINT8, BASE_HEX, NULL, 0x70,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_prog_enable,
      { "Enable Programming",
        "artnet.ip_prog.command_prog_enable",
        FT_UINT8, BASE_HEX, NULL, 0x80,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_ip,
      { "IP Address",
        "artnet.ip_prog.ip",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_sm,
      { "Subnet mask",
        "artnet.ip_prog.sm",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "IP Subnet mask", HFILL }},

    { &hf_artnet_ip_prog_port,
      { "Port",
        "artnet.ip_prog.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* ArtIpProgReply */
    { &hf_artnet_ip_prog_reply,
      { "ArtIpProgReplay packet",
        "artnet.ip_prog_reply",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtIpProgReply packet", HFILL }},

    { &hf_artnet_ip_prog_reply_ip,
      { "IP Address",
        "artnet.ip_prog_reply.ip",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_reply_sm,
      { "Subnet mask",
        "artnet.ip_prog_reply.sm",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "IP Subnet mask", HFILL }},

    { &hf_artnet_ip_prog_reply_port,
      { "Port",
        "artnet.ip_prog_reply.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* ArtPollServerReply */
    { &hf_artnet_poll_server_reply,
      { "ArtPollServerReply packet",
	"artnet.poll_server_reply",
	FT_NONE, BASE_NONE, NULL, 0,
	"Art-Net ArtPollServerReply packet", HFILL }}

  };

  static gint *ett[] = {
    &ett_artnet,
  };

  module_t *artnet_module;

  static enum_val_t disp_chan_val_types[] = {
     { "pro", "Percent", 0 },
     { "hex", "Hexadecimal", 1 },
     { "dec", "Decimal", 2 },
     { NULL, NULL, 0 }
  };

  static enum_val_t disp_chan_nr_types[] = {
     { "hex", "Hexadecimal", 0 },
     { "dec", "Decimal", 1 },
     { NULL, NULL, 0 }
  };

  static enum_val_t col_count[] = {
     { "6", "6", 6 },
     { "10", "10", 10 },
     { "12", "12", 12 },
     { "16", "16", 16 },
     { "24", "24", 24 },
     { NULL, NULL, 0 }
  };

  proto_artnet = proto_register_protocol("Art-Net",
				       "ARTNET","artnet");
  proto_register_field_array(proto_artnet,hf,array_length(hf));
  proto_register_subtree_array(ett,array_length(ett));

  artnet_module = prefs_register_protocol(proto_artnet,
					proto_reg_handoff_artnet);
  prefs_register_uint_preference(artnet_module, "udp_port",
				 "UDP Port",
				 "The UDP port on which "
				 "Art-Net "
				 "packets will be sent",
				 10,&global_udp_port_artnet);

  prefs_register_enum_preference(artnet_module, "dmx_disp_chan_val_type",
            "DMX Display channel value type",
            "The way DMX values are displayed",
				 &global_disp_chan_val_type,
            			 disp_chan_val_types, FALSE);

  prefs_register_enum_preference(artnet_module, "dmx_disp_chan_nr_type",
            "DMX Display channel nr. type",
            "The way DMX channel numbers are displayed",
                                 &global_disp_chan_nr_type,
                                 disp_chan_nr_types, FALSE);

  prefs_register_enum_preference(artnet_module, "dmx_disp_col_count",
            "DMX Display Column Count",
            "The number of columns for the DMX display",
                                 &global_disp_col_count,
                                 col_count, FALSE);
}

/* The registration hand-off routing */

void
proto_reg_handoff_artnet(void) {
  static gboolean artnet_initialized = FALSE;
  static dissector_handle_t artnet_handle;
  static guint udp_port_artnet;

  if(!artnet_initialized) {
    artnet_handle = create_dissector_handle(dissect_artnet,proto_artnet);
    rdm_handle = find_dissector("rdm");
    artnet_initialized = TRUE;
  } else {
    dissector_delete_uint("udp.port",udp_port_artnet,artnet_handle);
  }

  udp_port_artnet = global_udp_port_artnet;

  dissector_add_uint("udp.port",global_udp_port_artnet,artnet_handle);
}
