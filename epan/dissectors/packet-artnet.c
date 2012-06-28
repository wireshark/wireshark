/* packet-artnet.c
 * Routines for Art-Net packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2003, 2011 by Erwin Rol <erwin@erwinrol.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

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
#define ARTNET_OP_POLL_FP_REPLY      0x2200
#define ARTNET_OP_DIAG_DATA          0x2300
#define ARTNET_OP_COMMAND            0x2400

#define ARTNET_OP_OUTPUT             0x5000

#define ARTNET_OP_ADDRESS            0x6000

#define ARTNET_OP_INPUT              0x7000

#define ARTNET_OP_TOD_REQUEST        0x8000
#define ARTNET_OP_TOD_DATA           0x8100
#define ARTNET_OP_TOD_CONTROL        0x8200
#define ARTNET_OP_RDM                0x8300
#define ARTNET_OP_RDM_SUB            0x8400

#define ARTNET_OP_MEDIA              0x9000
#define ARTNET_OP_MEDIA_PATCH        0x9100
#define ARTNET_OP_MEDIA_CONTROL      0x9200
#define ARTNET_OP_MEDIA_CONTRL_REPLY 0x9300
#define ARTNET_OP_TIME_CODE          0x9700
#define ARTNET_OP_TIME_SYNC          0x9800
#define ARTNET_OP_TRIGGER            0x9900

#define ARTNET_OP_DIRECTORY          0x9a00
#define ARTNET_OP_DIRECTORY_REPLY    0x9b00

#define ARTNET_OP_VIDEO_SETUP        0xa010
#define ARTNET_OP_VIDEO_PALETTE      0xa020
#define ARTNET_OP_VIDEO_DATA         0xa040

#define ARTNET_OP_MAC_MASTER         0xf000
#define ARTNET_OP_MAC_SLAVE          0xf100
#define ARTNET_OP_FIRMWARE_MASTER    0xf200
#define ARTNET_OP_FIRMWARE_REPLY     0xf300
#define ARTNET_OP_FILE_TN_MASTER     0xf400
#define ARTNET_OP_FILE_FN_MASTER     0xf500
#define ARTNET_OP_FILE_FN_REPLY      0xf600

#define ARTNET_OP_IP_PROG            0xf800
#define ARTNET_OP_IP_PROG_REPLY      0xf900

static const value_string artnet_opcode_vals[] = {
  { ARTNET_OP_POLL,               "ArtPoll" },
  { ARTNET_OP_POLL_REPLY,         "ArtPollReply" },
  { ARTNET_OP_POLL_FP_REPLY,      "ArtPollFpReply" },
  { ARTNET_OP_DIAG_DATA,          "ArtDiagData" },
  { ARTNET_OP_COMMAND,            "ArtCommand" },
  { ARTNET_OP_OUTPUT,             "ArtDMX" },
  { ARTNET_OP_ADDRESS,            "ArtAddress" },
  { ARTNET_OP_INPUT,              "ArtInput" },
  { ARTNET_OP_TOD_REQUEST,        "ArtTodRequest" },
  { ARTNET_OP_TOD_DATA,           "ArtTodData" },
  { ARTNET_OP_TOD_CONTROL,        "ArtTodControl" },
  { ARTNET_OP_RDM,                "ArtRdm" },
  { ARTNET_OP_RDM_SUB,            "ArtRdmSub" },
  { ARTNET_OP_MEDIA,              "ArtMedia" },
  { ARTNET_OP_MEDIA_PATCH,        "ArtMediaPatch" },
  { ARTNET_OP_MEDIA_CONTROL,      "ArtMediaControl" },
  { ARTNET_OP_MEDIA_CONTRL_REPLY, "ArtMediaContrlReply" },
  { ARTNET_OP_TIME_CODE,          "ArtTimeCode" },
  { ARTNET_OP_TIME_SYNC,          "ArtTimeSync" },
  { ARTNET_OP_TRIGGER,            "ArtTrigger" },
  { ARTNET_OP_DIRECTORY,          "ArtDirectory" },
  { ARTNET_OP_DIRECTORY_REPLY,    "ArtDirectoryReply" },
  { ARTNET_OP_VIDEO_SETUP,        "ArtVideoSetup" },
  { ARTNET_OP_VIDEO_PALETTE,      "ArtVideoPalette" },
  { ARTNET_OP_VIDEO_DATA,         "ArtVideoData" },
  { ARTNET_OP_MAC_MASTER,         "ArtMacMaster" },
  { ARTNET_OP_MAC_SLAVE,          "ArtMacSlave" },
  { ARTNET_OP_FIRMWARE_MASTER,    "ArtFirmwareMaster" },
  { ARTNET_OP_FIRMWARE_REPLY,     "ArtFirmwareReply" },
  { ARTNET_OP_FILE_TN_MASTER,     "ArtfileTnMaster" },
  { ARTNET_OP_FILE_FN_MASTER,     "ArtfileFnMaster" },
  { ARTNET_OP_FILE_FN_REPLY,      "ArtfileFnReply" },
  { ARTNET_OP_IP_PROG,            "ArtIpProg" },
  { ARTNET_OP_IP_PROG_REPLY,      "ArtIpProgReply" },
  { 0,                            NULL }
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


#define ARTNET_CC_DISCOVERY_COMMAND          0x10
#define ARTNET_CC_DISCOVERY_COMMAND_RESPONSE 0x11
#define ARTNET_CC_GET_COMMAND                0x20
#define ARTNET_CC_GET_COMMAND_RESPONSE       0x21
#define ARTNET_CC_SET_COMMAND                0x30
#define ARTNET_CC_SET_COMMAND_RESPONSE       0x31

static const value_string artnet_cc_vals[] = {
  { ARTNET_CC_DISCOVERY_COMMAND,          "Discovery Command" },
  { ARTNET_CC_DISCOVERY_COMMAND_RESPONSE, "Discovery Command Response" },
  { ARTNET_CC_GET_COMMAND,                "Get Command" },
  { ARTNET_CC_GET_COMMAND_RESPONSE,       "Get Command Response" },
  { ARTNET_CC_SET_COMMAND,                "Set Command" },
  { ARTNET_CC_SET_COMMAND_RESPONSE,       "Set Command Response" },
  { 0, NULL },
};

#define ARTNET_FILE_TYPE_FIRST  0x00
#define ARTNET_FILE_TYPE_NORM   0x01
#define ARTNET_FILE_TYPE_LAST   0x02

static const value_string artnet_file_type_vals[] = {
  { ARTNET_FILE_TYPE_FIRST, "First file packet" } ,
  { ARTNET_FILE_TYPE_NORM,  "File packet" } ,
  { ARTNET_FILE_TYPE_LAST,  "Final file packet" } ,
  { 0, NULL },
};

void proto_reg_handoff_artnet(void);

/* Define the artnet proto */
static int proto_artnet = -1;


/* general */
static int hf_artnet_filler = -1;
static int hf_artnet_spare = -1;
static int hf_artnet_excess_bytes = -1;

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

/* ArtPollFpReply */
static int hf_artnet_poll_fp_reply = -1;

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
static int hf_artnet_rdm_sc = -1;

static int hf_artnet_rdm_rdmver = -1;
static int hf_artnet_rdm_net = -1;

/* ArtRdmSub */
static int hf_artnet_rdm_sub = -1;
static int hf_artnet_rdm_sub_uid = -1;
static int hf_artnet_rdm_sub_command_class = -1;
static int hf_artnet_rdm_sub_pid = -1;
static int hf_artnet_rdm_sub_sub_device = -1;
static int hf_artnet_rdm_sub_sub_count = -1;
static int hf_artnet_rdm_sub_data = -1;

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

/* ArtDiagData */
static int hf_artnet_diag_data = -1;
static int hf_artnet_diag_data_priority = -1;
static int hf_artnet_diag_data_index = -1;
static int hf_artnet_diag_data_length = -1;
static int hf_artnet_diag_data_data = -1;

/* ArtCommand */
static int hf_artnet_command = -1;

/* ArtMedia */
static int hf_artnet_media = -1;

/* ArtMediaPatch */
static int hf_artnet_media_patch = -1;

/* ArtMediaControl */
static int hf_artnet_media_control = -1;

/* ArtMediaControlReply */
static int hf_artnet_media_control_reply = -1;

/* ArtTimeCode */
static int hf_artnet_time_code = -1;

/* ArtTimeSync */
static int hf_artnet_time_sync = -1;

/* ArtTrigger */
static int hf_artnet_trigger = -1;

/* ArtDirectory */
static int hf_artnet_directory = -1;
static int hf_artnet_directory_filler = -1;
static int hf_artnet_directory_cmd = -1;
static int hf_artnet_directory_file = -1;

/* ArtDirectoryReply */
static int hf_artnet_directory_reply = -1;
static int hf_artnet_directory_reply_filler = -1;
static int hf_artnet_directory_reply_flags = -1;
static int hf_artnet_directory_reply_file = -1;
static int hf_artnet_directory_reply_name = -1;
static int hf_artnet_directory_reply_desc = -1;
static int hf_artnet_directory_reply_length = -1;
static int hf_artnet_directory_reply_data = -1;

/* ArtMacMaster */
static int hf_artnet_mac_master = -1;

/* ArtMacSlave */
static int hf_artnet_mac_slave = -1;

/* ArtFileTnMaster */
static int hf_artnet_file_tn_master = -1;
static int hf_artnet_file_tn_master_filler = -1;
static int hf_artnet_file_tn_master_type = -1;
static int hf_artnet_file_tn_master_block_id = -1;
static int hf_artnet_file_tn_master_length = -1;
static int hf_artnet_file_tn_master_name = -1;
static int hf_artnet_file_tn_master_checksum = -1;
static int hf_artnet_file_tn_master_spare = -1;
static int hf_artnet_file_tn_master_data = -1;


/* ArtFileFnMaster */
static int hf_artnet_file_fn_master = -1;

/* ArtFileFnReply */
static int hf_artnet_file_fn_reply = -1;


/* Define the tree for artnet */
static int ett_artnet = -1;

/* A static handle for the rdm dissector */
static dissector_handle_t rdm_handle;
static dissector_handle_t dmx_chan_handle;

static guint
dissect_artnet_poll(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  guint8 talktome;
  proto_tree *flags_tree, *flags_item;

  talktome = tvb_get_guint8(tvb, offset);
  flags_item = proto_tree_add_uint(tree, hf_artnet_poll_talktome, tvb,
	                           offset, 1, talktome);

  flags_tree=proto_item_add_subtree(flags_item, ett_artnet);
  proto_tree_add_item(flags_tree, hf_artnet_poll_talktome_reply_dest, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_poll_talktome_reply_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_poll_talktome_unused, tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 1;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 1, ENC_NA);
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
                      offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_poll_reply_port_nr, tvb,
                      offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_versinfo, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_subswitch, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_oem, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_ubea_version, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_status, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_esta_man, tvb,
                      offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_short_name,
                      tvb, offset, 18, ENC_ASCII|ENC_NA);
  offset += 18;

  proto_tree_add_item(tree, hf_artnet_poll_reply_long_name,
                      tvb, offset, 64, ENC_ASCII|ENC_NA);
  offset += 64;

  proto_tree_add_item(tree, hf_artnet_poll_reply_node_report,
                      tvb, offset, 64, ENC_ASCII|ENC_NA);
  offset += 64;


  hi = proto_tree_add_item(tree,
                           hf_artnet_poll_reply_port_info,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_PORT_INFO_LENGTH,
                           ENC_NA);

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
                           ENC_NA);

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
                           ENC_NA);

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
                           ENC_NA);

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
                           ENC_NA);

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
                           ENC_NA);

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
                      offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_poll_reply_mac,
                        tvb, offset, 6, ENC_NA);

  offset += 6;

  return offset;
}

static guint
dissect_artnet_output(tvbuff_t *tvb, guint offset, proto_tree *tree, packet_info *pinfo, proto_tree* base_tree)
{
  tvbuff_t *next_tvb = NULL;
  guint16 length;
  guint size;
  gboolean save_info;

  proto_tree_add_item(tree, hf_artnet_output_sequence, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_output_physical, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_output_universe, tvb,
                      offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_output_length, tvb,
                      offset, 2, length);
  offset += 2;

  size = tvb_reported_length_remaining(tvb, offset);

  save_info=col_get_writable(pinfo->cinfo);
  col_set_writable(pinfo->cinfo, ENC_BIG_ENDIAN);

  if (!next_tvb)
    next_tvb = tvb_new_subset(tvb, offset, length, length);

  call_dissector(dmx_chan_handle, next_tvb, pinfo, base_tree);

  col_set_writable(pinfo->cinfo, save_info);

  return offset + size;
}

static guint
dissect_artnet_address(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  proto_tree *hi,*si,*ti;
  guint8 swin,swout,swvideo,command;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_address_short_name,
                      tvb, offset, 18, ENC_ASCII|ENC_NA);
  offset += 18;

  proto_tree_add_item(tree, hf_artnet_address_long_name,
                      tvb, offset, 64, ENC_ASCII|ENC_NA);
  offset += 64;

  hi = proto_tree_add_item(tree,
                           hf_artnet_address_swin,
                           tvb,
                           offset,
                           ARTNET_ADDRESS_SWIN_LENGTH,
                           ENC_NA);

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
                           ENC_NA);

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
                      offset, 2, ENC_NA);
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
                           ENC_NA);

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
                      offset, 4, ENC_NA);
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
                      tvb, offset, 64, ENC_ASCII|ENC_NA);
  offset += 64;

  size = last_font * font_height;

  proto_tree_add_item(tree, hf_artnet_video_setup_font_data, tvb,
                      offset, size, ENC_NA );

  offset += size;

  return offset;
}

static guint
dissect_artnet_video_palette(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_video_palette_colour_red, tvb,
                      offset, 17, ENC_NA );
  offset += 17;

  proto_tree_add_item(tree, hf_artnet_video_palette_colour_green, tvb,
                      offset, 17, ENC_NA );
  offset += 17;

  proto_tree_add_item(tree, hf_artnet_video_palette_colour_blue, tvb,
                      offset, 17, ENC_NA );
  offset += 17;

  return offset;
}

static guint
dissect_artnet_video_data(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  guint8 len_x, len_y;
  guint32 size;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_video_data_pos_x, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_video_data_pos_y, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
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
                      offset, size, ENC_NA );

  offset += size;

  return offset;
}

static guint
dissect_artnet_firmware_master(tvbuff_t *tvb, guint offset, proto_tree *tree ) {
  guint8 type,block_id;
  guint32 length;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
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
                      offset, 20, ENC_NA );

  offset += 20;

  proto_tree_add_item(tree, hf_artnet_firmware_master_data, tvb,
                      offset, 1024, ENC_NA );

  offset += 1024;

  return offset;
}

static guint
dissect_artnet_firmware_reply(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  guint8 type;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  type = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_firmware_reply_type, tvb,
                      offset, 1, type);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 21, ENC_NA );

  offset += 21;

  return offset;
}

static guint
dissect_artnet_tod_request(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  guint8 ad_count;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, ENC_NA);
  offset += 8;

  proto_tree_add_item(tree, hf_artnet_tod_request_command, tvb,
		      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  ad_count = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_tod_request_ad_count, tvb,
                      offset, 1, ad_count);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_request_address, tvb,
		      offset, ad_count, ENC_NA);
  offset += ad_count;

  return offset;
}

static guint
dissect_artnet_tod_data(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  guint8 i,uid_count;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_port, tvb,
		      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, ENC_NA);
  offset += 8;

  proto_tree_add_item(tree, hf_artnet_tod_data_command_response, tvb,
		      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_address, tvb,
		      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_uid_total, tvb,
		      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_tod_data_block_count, tvb,
		      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  uid_count = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_tod_data_uid_count, tvb,
                      offset, 1, uid_count);
  offset += 1;

  for( i = 0; i < uid_count; i++)
  {
    proto_tree_add_item(tree, hf_artnet_tod_data_tod, tvb,
                        offset, 6, ENC_NA);
    offset += 6;
  }

  return offset;
}

static guint
dissect_artnet_tod_control(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, ENC_NA);
  offset += 8;

  proto_tree_add_item(tree, hf_artnet_tod_control_command, tvb,
		      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_control_address, tvb,
		      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  return offset;
}

static guint
dissect_artnet_rdm(tvbuff_t *tvb, guint offset, proto_tree *tree,  packet_info *pinfo, proto_tree *base_tree)
{
  guint8 rdmver;
  guint8 sc;
  guint size;
  gboolean save_info;
  tvbuff_t *next_tvb = NULL;

  rdmver = tvb_get_guint8(tvb, offset);
  if (rdmver == 0x00) {
    proto_tree_add_item(tree, hf_artnet_filler, tvb,
		        offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_item(tree, hf_artnet_spare, tvb,
		        offset, 8, ENC_NA);
    offset += 8;
  } else {
    proto_tree_add_item(tree, hf_artnet_rdm_rdmver, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_artnet_filler, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_artnet_spare, tvb,
                        offset, 7, ENC_NA);
    offset += 7;

    proto_tree_add_item(tree, hf_artnet_rdm_net, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
  }

  proto_tree_add_item(tree, hf_artnet_rdm_command, tvb,
		      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_rdm_address, tvb,
		      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  
  /* check for old version that included the 0xCC startcode
   * The 0xCC will never be the first byte of the RDM packet
   */
  sc = tvb_get_guint8(tvb, offset);

  if (sc == 0xCC) {
    proto_tree_add_item(tree, hf_artnet_rdm_sc, tvb,
		      offset, 1, ENC_BIG_ENDIAN); 
    offset += 1;
  }
  
  size = tvb_reported_length_remaining(tvb, offset);

  save_info=col_get_writable(pinfo->cinfo);
  col_set_writable(pinfo->cinfo, ENC_BIG_ENDIAN);

  if (!next_tvb)
    next_tvb = tvb_new_subset_remaining(tvb, offset);

  call_dissector(rdm_handle, next_tvb, pinfo, base_tree);

  col_set_writable(pinfo->cinfo, save_info);

  return offset + size;
}


static guint
dissect_artnet_rdm_sub(tvbuff_t *tvb, guint offset, proto_tree *tree,  packet_info *pinfo _U_)
{
  guint8 cc;
  gint size;

  proto_tree_add_item(tree, hf_artnet_rdm_rdmver, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_rdm_sub_uid, tvb,
                        offset, 6, ENC_NA);
  offset += 6;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                        offset, 1, ENC_NA);
  offset += 1;

  cc = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_artnet_rdm_sub_command_class, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_rdm_sub_pid, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_rdm_sub_sub_device, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_rdm_sub_sub_count, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                        offset, 4, ENC_NA);
  offset += 4;

  switch(cc) {
  case ARTNET_CC_SET_COMMAND:
  case ARTNET_CC_GET_COMMAND_RESPONSE:
    size = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(tree, hf_artnet_rdm_sub_data, tvb,
                        offset, size, ENC_NA);
    offset += size;
    break;

  case ARTNET_CC_DISCOVERY_COMMAND:
  case ARTNET_CC_DISCOVERY_COMMAND_RESPONSE:
  case ARTNET_CC_GET_COMMAND:
  case ARTNET_CC_SET_COMMAND_RESPONSE:
  default:
    break;
  }

  return offset;
}

static guint
dissect_artnet_ip_prog(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  guint8 command;
  proto_tree *flags_tree,*flags_item;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 2, ENC_NA);
  offset += 2;

  command = tvb_get_guint8(tvb, offset);
  flags_item = proto_tree_add_uint(tree, hf_artnet_ip_prog_command, tvb,
	                           offset, 1, command);

  flags_tree=proto_item_add_subtree(flags_item, ett_artnet);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_port, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_sm, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_ip, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_reset, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_enable, tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 1;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_ip_prog_ip, tvb,
		      offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_ip_prog_sm, tvb,
		      offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_ip_prog_port, tvb,
		      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, ENC_NA);
  offset += 8;

  return offset;
}

static guint
dissect_artnet_ip_prog_reply(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_ip_prog_reply_ip, tvb,
                      offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_ip_prog_reply_sm, tvb,
		      offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_ip_prog_reply_port, tvb,
		      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
		      offset, 8, ENC_NA);
  offset += 8;

  return offset;
}

static guint
dissect_artnet_poll_fp_reply(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}


/* ArtDiagData */
static guint
dissect_artnet_diag_data(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  guint16 length;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 1, ENC_NA);
  offset++;

  proto_tree_add_item(tree, hf_artnet_diag_data_priority, tvb,
                      offset, 1, ENC_NA);
  offset++;

  proto_tree_add_item(tree, hf_artnet_diag_data_index, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

	length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_artnet_diag_data_length, tvb,
											offset, 2, ENC_NA);
	offset+=2;

  proto_tree_add_item(tree, hf_artnet_diag_data_data, tvb,
                      offset, length, ENC_NA);
  offset += length;

  return offset;
}

/* ArtCommand */
static guint
dissect_artnet_command(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtMedia */
static guint
dissect_artnet_media(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtMediaPatch */
static guint
dissect_artnet_media_patch(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtMediaControl */
static guint
dissect_artnet_media_control(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtMediaControlReply */
static guint
dissect_artnet_media_control_reply(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtTimeCode */
static guint
dissect_artnet_time_code(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtTimeSync */
static guint
dissect_artnet_time_sync(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtTrigger */
static guint
dissect_artnet_trigger(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtDirectory */
static guint
dissect_artnet_directory(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_directory_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_directory_cmd, tvb,
                      offset, 1, ENC_NA);
  offset++;

  proto_tree_add_item(tree, hf_artnet_directory_file, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  return offset;
}

/* ArtDirectoryReply */
static guint
dissect_artnet_directory_reply(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_directory_reply_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_directory_reply_flags, tvb,
                      offset, 1, ENC_NA);
  offset++;

  proto_tree_add_item(tree, hf_artnet_directory_reply_file, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_directory_reply_name, tvb,
                      offset, 16, ENC_NA);
  offset += 16;

  proto_tree_add_item(tree, hf_artnet_directory_reply_desc, tvb,
                      offset, 64, ENC_NA);
  offset += 64;

  proto_tree_add_item(tree, hf_artnet_directory_reply_length, tvb,
                      offset, 8, ENC_NA);
  offset += 8;

  proto_tree_add_item(tree, hf_artnet_directory_reply_data, tvb,
                      offset, 64, ENC_NA);
  offset += 64;

  return offset;
}

/* ArtMacMaster */
static guint
dissect_artnet_mac_master(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtMacSlave */
static guint
dissect_artnet_mac_slave(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtFileTnMaster */
static guint
dissect_artnet_file_tn_master(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_file_tn_master_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_file_tn_master_type, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_file_tn_master_block_id, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_file_tn_master_length, tvb,
                      offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_file_tn_master_name, tvb,
                      offset, 14, ENC_NA);
  offset += 14;

  proto_tree_add_item(tree, hf_artnet_file_tn_master_checksum, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_file_tn_master_spare, tvb,
                      offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_file_tn_master_data, tvb,
                      offset, 512, ENC_NA);
  offset += 512;

  return offset;
}

/* ArtFileFnMaster */
static guint
dissect_artnet_file_fn_master(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtFileFnReply */
static guint
dissect_artnet_file_fn_reply(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

static void
dissect_artnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset = 0;
  guint size;
  guint16 opcode;
  proto_tree *ti = NULL,*hi = NULL,*si = NULL,*artnet_tree=NULL,*artnet_header_tree=NULL;

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ARTNET");

  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);


  if (tree) {
    ti = proto_tree_add_item(tree, proto_artnet, tvb, offset, -1, ENC_NA);
    artnet_tree = proto_item_add_subtree(ti, ett_artnet);

    hi = proto_tree_add_item(artnet_tree,
                             hf_artnet_header,
                             tvb,
                             offset,
                             ARTNET_HEADER_LENGTH ,
                             ENC_NA);

    artnet_header_tree = proto_item_add_subtree(hi, ett_artnet);
  }

  col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
                  tvb_get_ephemeral_string(tvb, offset, 8));
  if( tree ){
    proto_tree_add_item(artnet_header_tree, hf_artnet_header_id,
                        tvb, offset, 8, ENC_ASCII|ENC_NA);
  }
  offset += 8;

  opcode = tvb_get_letohs(tvb, offset);
  /* set the info column */
  col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%04x)",
    val_to_str(opcode, artnet_opcode_vals, "Unknown"), opcode);

  if( tree ){
    proto_tree_add_uint(artnet_header_tree, hf_artnet_header_opcode, tvb,
                        offset, 2, opcode);

    proto_item_append_text(ti, ", Opcode: %s (0x%04x)", val_to_str(opcode, artnet_opcode_vals, "Unknown"), opcode);
  }
  offset += 2;

  if( opcode != ARTNET_OP_POLL_REPLY && opcode != ARTNET_OP_POLL_FP_REPLY ) {
    if( tree ){
      proto_tree_add_item(artnet_header_tree, hf_artnet_header_protver, tvb,
                          offset, 2, ENC_BIG_ENDIAN);

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
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_poll( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_POLL_REPLY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_poll_reply,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_poll_reply( tvb, offset, si);
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_POLL_FP_REPLY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_poll_fp_reply,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA );
        si = proto_item_add_subtree(hi, ett_artnet );

				size = dissect_artnet_poll_fp_reply( tvb, offset, si );
				size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_DIAG_DATA:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_diag_data,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA );
        si = proto_item_add_subtree(hi, ett_artnet );

				size = dissect_artnet_diag_data( tvb, offset, si );
				size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_COMMAND:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_command,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA );
        si = proto_item_add_subtree(hi, ett_artnet );

				size = dissect_artnet_command( tvb, offset, si );
				size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_OUTPUT:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_output,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_output( tvb, offset, si, pinfo, tree);
        size -= offset;
        proto_item_set_len(si, size );
        offset += size;
      }
      break;


    case ARTNET_OP_ADDRESS:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_address,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_address( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_INPUT:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_input,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_input( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_TOD_REQUEST:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_tod_request,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

				size = dissect_artnet_tod_request( tvb, offset, si );
				size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_TOD_DATA:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_tod_data,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet );

				size = dissect_artnet_tod_data( tvb, offset, si );
				size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_TOD_CONTROL:
      if (tree){
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_tod_control,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA );
        si = proto_item_add_subtree(hi, ett_artnet );

				size = dissect_artnet_tod_control( tvb, offset, si );
				size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_RDM:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_rdm,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_rdm( tvb, offset, si, pinfo, tree);
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_RDM_SUB:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_rdm_sub,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_rdm_sub( tvb, offset, si, pinfo );
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_MEDIA:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_media,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_media( tvb, offset, si);
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_MEDIA_PATCH:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_media_patch,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_media_patch( tvb, offset, si);
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_MEDIA_CONTROL:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_media_control,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_media_control( tvb, offset, si);
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_MEDIA_CONTRL_REPLY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_media_control_reply,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_media_control_reply( tvb, offset, si);
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_TIME_CODE:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_time_code,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_time_code( tvb, offset, si);
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_TIME_SYNC:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_time_sync,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_time_sync( tvb, offset, si);
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_TRIGGER:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_trigger,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_trigger( tvb, offset, si);
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_DIRECTORY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_directory,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_directory( tvb, offset, si);
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_DIRECTORY_REPLY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_directory_reply,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi,ett_artnet);

        size = dissect_artnet_directory_reply( tvb, offset, si);
        size -= offset;

        proto_item_set_len( si, size );
        offset += size;
      }
      break;


    case ARTNET_OP_VIDEO_SETUP:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_input,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_video_setup( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_VIDEO_PALETTE:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_input,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_video_palette( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_VIDEO_DATA:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_input,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_video_data( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_MAC_MASTER:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_mac_master,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_mac_master( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_MAC_SLAVE:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_mac_slave,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_mac_slave( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_FIRMWARE_MASTER:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_firmware_master,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_firmware_master( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_FIRMWARE_REPLY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_firmware_reply,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size = dissect_artnet_firmware_reply( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size);
        offset += size;
      }
      break;

    case ARTNET_OP_FILE_TN_MASTER:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_file_tn_master,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi, ett_artnet );

				size = dissect_artnet_file_tn_master( tvb, offset, si);
				size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_FILE_FN_MASTER:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_file_fn_master,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi, ett_artnet );

				size = dissect_artnet_file_fn_master( tvb, offset, si);
				size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_FILE_FN_REPLY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_file_fn_reply,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi, ett_artnet );

				size = dissect_artnet_file_fn_reply( tvb, offset, si);
				size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_IP_PROG:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_ip_prog,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi, ett_artnet );

				size = dissect_artnet_ip_prog( tvb, offset, si);
				size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_IP_PROG_REPLY:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_ip_prog_reply,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);
        si = proto_item_add_subtree(hi, ett_artnet );

				size = dissect_artnet_ip_prog_reply( tvb, offset, si );
				size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;


    default:
      if (tree) {
        proto_tree_add_text(artnet_tree, tvb, offset, -1,
          "Data (%d bytes)", tvb_reported_length_remaining(tvb, offset));
        offset += tvb_reported_length_remaining(tvb, offset);
      }
      break;
  }

  if (tree) {
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_item(artnet_tree, hf_artnet_excess_bytes, tvb,
            offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
    }
  }
}

void
proto_register_artnet(void) {
  static hf_register_info hf[] = {

    /* General */
    { &hf_artnet_excess_bytes,
      { "Excess Bytes",
        "artnet.excess_bytes",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

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
    
    { &hf_artnet_rdm_sc,
      { "Startcode",
        "artnet.rdm.sc",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
	
    { &hf_artnet_rdm_rdmver,
      { "RDM Version",
        "artnet.rdm.rdmver",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_rdm_net,
      { "Address High",
        "artnet.rdm.net",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    /* ArtRdmSub */
    { &hf_artnet_rdm_sub,
      { "ArtRdmSub packet",
        "artnet.rdm_sub",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtRdmSub packet", HFILL }},

    { &hf_artnet_rdm_sub_uid,
      { "UID",
        "artnet.rdm_sub.uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_rdm_sub_command_class,
      { "Command Class",
        "artnet.rdm_sub.command_class",
        FT_UINT8, BASE_HEX, VALS(artnet_cc_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_rdm_sub_pid,
      { "Parameter ID",
        "artnet.rdm_sub.param_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_rdm_sub_sub_device,
      { "Sub Device",
        "artnet.rdm_sub.sub_device",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_rdm_sub_sub_count,
      { "Sub Count",
        "artnet.rdm_sub.sub_count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_rdm_sub_data,
      { "Data",
        "artnet.rdm_sub.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
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
    { &hf_artnet_poll_fp_reply,
      { "ArtPollFpReply packet",
        "artnet.poll_fp_reply",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtPollFpReply packet", HFILL }},

    /* ArtDiagData */
    { &hf_artnet_diag_data,
      { "ArtDiagData packet",
        "artnet.diag_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtDiagData packet", HFILL }},

    { &hf_artnet_diag_data_priority,
      { "Priotity",
        "artnet.diag_data.priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_diag_data_index,
      { "Index",
        "artnet.diag_data.index",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_diag_data_length,
      { "Length",
        "artnet.diag_data.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_diag_data_data,
      { "Data",
        "artnet.diag_data.data",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtCommand */
    { &hf_artnet_command,
      { "ArtCommand packet",
        "artnet.command",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtCommand packet", HFILL }},

    /* ArtMedia */
    { &hf_artnet_media,
      { "ArtMedia packet",
        "artnet.media",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtMedia packet", HFILL }},

    /* ArtMediaPatch */
    { &hf_artnet_media_patch,
      { "ArtMediaPatch packet",
        "artnet.media_patch",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtMediaPatch packet", HFILL }},

    /* ArtMediaControl */
    { &hf_artnet_media_control,
      { "ArtMediaControl packet",
        "artnet.media_control",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtMediaControl packet", HFILL }},

    /* ArtMediaControlReply */
    { &hf_artnet_media_control_reply,
      { "ArtMediaControlReply packet",
        "artnet.media_control_reply",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtMediaControlReply packet", HFILL }},

    /* ArtTimeCode */
    { &hf_artnet_time_code,
      { "ArtTimeCode packet",
        "artnet.time_code",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtTimeCode packet", HFILL }},

    /* ArtTimeSync */
    { &hf_artnet_time_sync,
      { "ArtTimeSync packet",
        "artnet.time_sync",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtTimeSync packet", HFILL }},

    /* ArtTrigger */
    { &hf_artnet_trigger,
      { "ArtTrigger packet",
        "artnet.trigger",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtTrigger packet", HFILL }},

    /* ArtDirectory */
    { &hf_artnet_directory,
      { "ArtDirectory packet",
        "artnet.directory",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtDirectory packet", HFILL }},

    { &hf_artnet_directory_filler,
      { "Filler",
        "artnet.directory.filler",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_directory_cmd,
      { "Command",
        "artnet.directory.cmd",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_directory_file,
      { "File Nr.",
        "artnet.directory.file",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* ArtDirectoryReply */
    { &hf_artnet_directory_reply,
      { "ArtDirectoryReply packet",
        "artnet.directory_reply",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtDirectoryReply packet", HFILL }},

    { &hf_artnet_directory_reply_filler,
      { "Filler",
        "artnet.directory_reply.filler",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_directory_reply_flags,
      { "Flags",
        "artnet.directory_reply.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_directory_reply_file,
      { "File",
        "artnet.directory_reply.file",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_directory_reply_name,
      { "Name",
        "artnet.directory_reply.name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_directory_reply_desc,
      { "Description",
        "artnet.directory_reply.desc",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_directory_reply_length,
      { "Lenght",
        "artnet.directory_reply.length",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_directory_reply_data,
      { "Data",
        "artnet.directory_reply.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtMacMaster */
    { &hf_artnet_mac_master,
      { "ArtMacMaster packet",
        "artnet.mac_master",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtMacMaster packet", HFILL }},

    /* ArtMacSlave */
    { &hf_artnet_mac_slave,
      { "ArtMacSlave packet",
        "artnet.mac_slave",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtMacSlave packet", HFILL }},

    /* ArtFileTnMaster */
    { &hf_artnet_file_tn_master,
      { "ArtFileTnMaster packet",
        "artnet.file_tn_master",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtFileTnMaster packet", HFILL }},

    { &hf_artnet_file_tn_master_filler,
      { "Filler",
        "artnet.file_tn_master.filler",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_file_tn_master_type,
      { "Type",
        "artnet.file_tn_master.type",
        FT_UINT8, BASE_HEX,  VALS(artnet_file_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_file_tn_master_block_id,
      { "Block ID",
        "artnet.file_tn_master.block_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_file_tn_master_length,
      { "Length",
        "artnet.file_tn_master.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_file_tn_master_name,
      { "Name",
        "artnet.file_tn_master.name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_file_tn_master_checksum,
      { "Checksum",
        "artnet.file_tn_master.checksum",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_file_tn_master_spare,
      { "Spare",
        "artnet.file_tn_master.spare",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_file_tn_master_data,
      { "Data",
        "artnet.file_tn_master.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtFileFnMaster */
    { &hf_artnet_file_fn_master,
      { "ArtFileFnMaster packet",
        "artnet.file_fn_master",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtFileFnMaster packet", HFILL }},

    /* ArtFileFnReply */
    { &hf_artnet_file_fn_reply,
      { "ArtFileFnReply packet",
        "artnet.file_fn_reply",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtFileFnReply packet", HFILL }}

  };

  static gint *ett[] = {
    &ett_artnet,
  };

  proto_artnet = proto_register_protocol("Art-Net",
                                         "ARTNET","artnet");
  proto_register_field_array(proto_artnet,hf,array_length(hf));
  proto_register_subtree_array(ett,array_length(ett));
}

/* Heuristic dissector */
static gboolean
dissect_artnet_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  static const char artnet_packet_id[] = "Art-Net\0";

  /* check if we atleast have the 8 byte header */
  if (tvb_length(tvb) < sizeof(artnet_packet_id))
    return FALSE;

  /* Check the 8 byte header */
  if (tvb_memeql(tvb, 0, artnet_packet_id, sizeof(artnet_packet_id) - 1) != 0)
    return FALSE;

  /* if the header matches, dissect it */
  dissect_artnet(tvb, pinfo, tree);
  
  return TRUE;
}


/* The registration hand-off routing */

void
proto_reg_handoff_artnet(void) {
  static gboolean artnet_initialized = FALSE;
  static dissector_handle_t artnet_handle;
 
  if(!artnet_initialized) {
	artnet_handle = create_dissector_handle(dissect_artnet,proto_artnet);
	dissector_add_handle("udp.port", artnet_handle);
    rdm_handle = find_dissector("rdm");
    dmx_chan_handle = find_dissector("dmx-chan");
    artnet_initialized = TRUE;
  }

  heur_dissector_add("udp", dissect_artnet_heur, proto_artnet);
}
