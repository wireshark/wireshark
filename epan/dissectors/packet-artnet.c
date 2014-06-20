/* packet-artnet.c
 * Routines for Art-Net packet disassembly
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

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

/*
 * See
 *
 *	http://www.artisticlicence.com/WebSiteMaster/User%20Guides/art-net.pdf
 */

void proto_register_artnet(void);
void proto_reg_handoff_artnet(void);

/* Define udp_port for ArtNET */

#define UDP_PORT_ARTNET 0x1936

#define ARTNET_HEADER_LENGTH                   10
#define ARTNET_POLL_LENGTH                      4
#define ARTNET_POLL_REPLY_LENGTH              197
#define ARTNET_POLL_REPLY_PORT_INFO_LENGTH     22
#define ARTNET_POLL_REPLY_PORT_TYPES_LENGTH     4
#define ARTNET_POLL_REPLY_GOOD_INPUT_LENGTH     4
#define ARTNET_POLL_REPLY_GOOD_OUTPUT_LENGTH    4
#define ARTNET_POLL_REPLY_SWIN_LENGTH           4
#define ARTNET_POLL_REPLY_SWOUT_LENGTH          4
#define ARTNET_ADDRESS_LENGTH                  97
#define ARTNET_ADDRESS_SWIN_LENGTH              4
#define ARTNET_ADDRESS_SWOUT_LENGTH             4
#define ARTNET_OUTPUT_LENGTH                    1
#define ARTNET_INPUT_LENGTH                    10
#define ARTNET_INPUT_INPUT_LENGTH               4
#define ARTNET_FIRMWARE_MASTER_LENGTH        1035
#define ARTNET_FIRMWARE_REPLY_LENGTH           26
#define ARTNET_VIDEO_SETUP_LENGTH              74
#define ARTNET_VIDEO_PALETTE_LENGTH            55
#define ARTNET_VIDEO_DATA_LENGTH                8

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
  { 0x0007, "2 output Art-Net II processor chip. No RDM" },
  { 0x0010, "Artistic Licence:Down-Lynx:2x DMX out. Wall Panel." },
  { 0x0011, "Artistic Licence:Up-Lynx:2x DMX in. Wall Panel" },
  { 0x0012, "Artistic Licence:Truss-Link O/P:" },
  { 0x0013, "Artistic Licence:Truss-Link I/P:" },
  { 0x0014, "Artistic Licence:Net-Lynx O/P:2x DMX out. Boxed Product" },
  { 0x0015, "Artistic Licence:Net-Lynx I/P:2x DMX in. Boxed Product" },
  { 0x0016, "Artistic Licence:Radio-Link O/P:" },
  { 0x0017, "Artistic Licence:Radio-Link I/P:" },
  { 0x0030, "Doug Fleenor Design:TBA:2x DMX out" },
  { 0x0031, "Doug Fleenor Design:TBA:2x DMX in" },
  { 0x0050, "Goddard Design:DMX-Link (tm) O/P:2x DMX out" },
  { 0x0051, "Goddard Design:DMX-Link (tm) I/P:2x DMX in" },
  { 0x0070, "ADB:Net-Port O/P:2x DMX out" },
  { 0x0071, "ADB:Net-Port I/P:2x DMX in" },
  { 0x0072, "ADB:Adb WiFi remote control:" },
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
  { 0x009F, "ELC:Reserved:" },
  { 0x0100, "Ether-Lynx:Reserved:" },
  { 0x0101, "Ether-Lynx:Reserved:" },
  { 0x0102, "Ether-Lynx:Reserved:" },
  { 0x0103, "Ether-Lynx:Reserved:" },
  { 0x0104, "Ether-Lynx:Reserved:" },
  { 0x0105, "Ether-Lynx:Reserved:" },
  { 0x0106, "Ether-Lynx:Reserved:" },
  { 0x0107, "Ether-Lynx:Reserved:" },
  { 0x0108, "Ether-Lynx:Reserved:" },
  { 0x0109, "Ether-Lynx:Reserved:" },
  { 0x010A, "Ether-Lynx:Reserved:" },
  { 0x010B, "Ether-Lynx:Reserved:" },
  { 0x010C, "Ether-Lynx:Reserved:" },
  { 0x010D, "Ether-Lynx:Reserved:" },
  { 0x010E, "Ether-Lynx:Reserved:" },
  { 0x010F, "Ether-Lynx:Reserved:" },
  { 0x0110, "Cata-Lynx:Reserved:" },
  { 0x0111, "Cata-Lynx:Reserved:" },
  { 0x0112, "Cata-Lynx:Reserved:" },
  { 0x0113, "Cata-Lynx:Reserved:" },
  { 0x0114, "Cata-Lynx:Reserved:" },
  { 0x0115, "Cata-Lynx:Reserved:" },
  { 0x0116, "Cata-Lynx:Reserved:" },
  { 0x0117, "Cata-Lynx:Reserved:" },
  { 0x0118, "Cata-Lynx:Reserved:" },
  { 0x0119, "Cata-Lynx:Reserved:" },
  { 0x011A, "Cata-Lynx:Reserved:" },
  { 0x011B, "Cata-Lynx:Reserved:" },
  { 0x011C, "Cata-Lynx:Reserved:" },
  { 0x011D, "Cata-Lynx:Reserved:" },
  { 0x011E, "Cata-Lynx:Reserved:" },
  { 0x011F, "Cata-Lynx:Reserved:" },
  { 0x0120, "Artistic Licence:Pixi-Power F1:2 x DMX O/P (emulated) + RDM Support" },
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
  { 0x01A0, "Ies:PBX:Uses 1 logical universe" },
  { 0x01A1, "Ies:Executive:Uses 2 logical universe" },
  { 0x01A2, "Ies:Matrix:Uses 2 logical universe" },
  { 0x01A3, "Ies:Reserved:" },
  { 0x01A4, "Ies:Reserved:" },
  { 0x01A5, "Ies:Reserved:" },
  { 0x01A6, "Ies:Reserved:" },
  { 0x01A7, "Ies:Reserved:" },
  { 0x01A8, "Ies:Reserved:" },
  { 0x01A9, "Ies:Reserved:" },
  { 0x01AA, "Ies:Reserved:" },
  { 0x01AB, "Ies:Reserved:" },
  { 0x01AC, "Ies:Reserved:" },
  { 0x01AD, "Ies:Reserved:" },
  { 0x01AE, "Ies:Reserved:" },
  { 0x01AF, "Ies:Reserved:" },
  { 0x01B0, "EDI:Edig:4 in, 4 out" },
  { 0x01C0, "Nondim Enterprises:Openlux:4 in, 4 out" },
  { 0x01D0, "Green Hippo:Hippotizer:emulates 1 in" },
  { 0x01E0, "VNR:Merger-Booster:4in 4out" },
  { 0x01f0, "RobeShow Lighting:ILE:1in 1out" },
  { 0x01f1, "RobeShow Lighting:Controller:4in 4out" },
  { 0x0210, "Artistic Licence:Down-Lynx 2 (RDM Version):" },
  { 0x0211, "Artistic Licence:Up-Lynx 2 (RDM Version):" },
  { 0x0212, "Artistic Licence:Truss-Lynx O/P (RDM Version):" },
  { 0x0213, "Artistic Licence:Truss-Lynx I/P (RDM Version):" },
  { 0x0214, "Artistic Licence:Net-Lynx O/P (RDM Version):" },
  { 0x0215, "Artistic Licence:Net-Lynx I/P (RDM Version):" },
  { 0x0216, "Artistic Licence:Radio-Lynx O/P (RDM Version):" },
  { 0x0217, "Artistic Licence:Radio-Lynx I/P (RDM Version):" },
  { 0x0230, "Doug Fleenor Design:Down-Lynx (RDM Version):" },
  { 0x0231, "Doug Fleenor Design:Up-Lynx (RDM Version):" },
  { 0x0250, "Goddard Design:Down-Lynx (RDM Version):" },
  { 0x0251, "Goddard Design:Up-Lynx (RDM Version):" },
  { 0x0270, "ADB:Down-Lynx (RDM Version):" },
  { 0x0271, "ADB:Up-Lynx (RDM Version):" },
  { 0x0280, "LSC:Down-Lynx (RDM version):" },
  { 0x0281, "LSC:Up-Lynx (RDM version):" },
  { 0x0300, "Goldstage:DMX-net/O:2 x dmx out" },
  { 0x0301, "Goldstage:DMX-net/I:2 x dmx in" },
  { 0x0302, "Goldstage:Reserved:" },
  { 0x0303, "Goldstage:Reserved:" },
  { 0x0304, "Goldstage:GT-96:1 dmx out, auditorium dimmer" },
  { 0x0305, "Goldstage:III Light Concole:1xdmx out, with remote control" },
  { 0x0306, "Goldstage:Reserved:" },
  { 0x0307, "Goldstage:Reserved:" },
  { 0x0308, "Goldstage:KTG-5S Dimmer:2xdmx in" },
  { 0x0309, "Goldstage:Reserved:" },
  { 0x030A, "Goldstage:Reserved:" },
  { 0x030B, "Goldstage:Reserved:" },
  { 0x030C, "Goldstage:Reserved:" },
  { 0x030D, "Goldstage:Reserved:" },
  { 0x030E, "Goldstage:Reserved:" },
  { 0x030F, "Goldstage:Reserved:" },
  { 0x0310, "Sunset Dynamics:StarGateDMX:4 in, 4 out, no RDM" },
  { 0x0320, "Luminex LCE:Ethernet-DMX8:4x DMX in. 4x DMX out. No RDM" },
  { 0x0321, "Luminex LCE:Ethernet-DMX2:2x DMX in. 2x DMX out. No RDM" },
  { 0x0322, "Luminex LCE:Ethernet-DMX4:4x DMX in. 4x DMX out. No RDM" },
  { 0x0323, "Luminex LCE:LumiNet Monitor:network monitor tool with RDM" },
  { 0x0330, "Invisible Rival:Blue Hysteria:2x DMX In, 2 x DMX out, No RDM" },
  { 0x0340, "Avolites:Diamond 4 Vision:8 DMX out" },
  { 0x0341, "Avolites:Diamond 4 elite:8 DMX out" },
  { 0x0342, "Avolites:Peal offline:4 DMX out" },
  { 0x0343, "Avolites:Titan:Number of DMX outputs - 12 (4 physical, 8 emulated), No RDM" },
  { 0x0344, "Avolites:Reserved:" },
  { 0x0345, "Avolites:Reserved:" },
  { 0x0346, "Avolites:Reserved:" },
  { 0x0347, "Avolites:Reserved:" },
  { 0x0348, "Avolites:Reserved:" },
  { 0x0349, "Avolites:Reserved:" },
  { 0x034A, "Avolites:Reserved:" },
  { 0x034B, "Avolites:Reserved:" },
  { 0x034C, "Avolites:Reserved:" },
  { 0x034D, "Avolites:Reserved:" },
  { 0x034E, "Avolites:Reserved:" },
  { 0x034F, "Avolites:Reserved:" },
  { 0x0350, "Bigfoot:EtherMux Remote:1 DMX in" },
  { 0x0351, "Bigfoot:EtherMux Server:1 DMX in 1 DMX out" },
  { 0x0352, "Bigfoot:EtherMux Desktop:1 DMX out" },
  { 0x0360, "Ecue:512 output device:" },
  { 0x0361, "Ecue:1024 output device:" },
  { 0x0362, "Ecue:2048 output device:" },
  { 0x0370, "Kiss-Box:DMX Box:1 in 1 out RDM support by utilities" },
  { 0x0380, "Arkaos:V J DMX:1 x DMX in. No o/p. No RDM" },
  { 0x0390, "Digital Enlightenment:ShowGate:4x dmx in, 4x dmx out, no rdm" },
  { 0x03a0, "DES:NELI:6,12,24 chan. 1x dmx in, 1x dmx out, no rdm" },
  { 0x03b0, "SunLite:Easy Standalone IP:1 x DMX out" },
  { 0x03b1, "SunLite:Magic 3D Easy View:4 x DMX out" },
  { 0x03c0, "Catalyst:Reserved:" },
  { 0x03d0, "Bleasdale:PixelMad:" },
  { 0x03e0, "Lehigh Electric Products Co:DX2 Dimming rack:2 in, 1 out, no rdm" },
  { 0x03f0, "Horizon:Controller:" },
  { 0x0400, "Audio Scene::2 x out + no rdm" },
  { 0x0401, "Audio Scene::2 x in + no rdm" },
  { 0x0410, "Pathport::2 x out" },
  { 0x0411, "Pathport::2 x in" },
  { 0x0412, "Pathport::1 x out" },
  { 0x0413, "Pathport::1 x in" },
  { 0x0420, "Botex::2 in - 2 out" },
  { 0x0430, "Simon Newton:LibArtNet:4 in. 4 out." },
  { 0x0431, "Simon Newton:LLA Live:4 in. 4 out." },
  { 0x0440, "XLNT:Team Projects:2 x DMX Input Node" },
  { 0x0441, "XLNT:Team Projects:2 x DMX Output Node" },
  { 0x0450, "Schnick-Schnack-Systems:Systemnetzteil:2 x DMX Input Node" },
  { 0x0451, "Schnick-Schnack-Systems:SysOne:2 DMX Out, 0 DMX In, No RDM" },
  { 0x0452, "Schnick-Schnack-Systems:SysOnePixGate:0 DMX Out, 0 DMX In, No RDM" },
  { 0x0460, "Dom Dv:NetDmx - User configured functionality:Max 1 in / 1 out" },
  { 0x0470, "Sean Christopher:Projection Pal:1 x i/p + RDM" },
  { 0x0471, "Sean Christopher:The Lighting Remote:4 x i/p + 4 x O/P no RDM" },
  { 0x0472, "LSS Lighting:MasterGate:Profibus interface" },
  { 0x0473, "LSS Lighting:Rail Controller:Profibus interface" },
  { 0x0474, "LSS Lighting:Master Port Mini:1 dmx out with RDM and PoE" },
  { 0x0475, "LSS Lighting:Powerdim:2 dmx out with RDM" },
  { 0x0490, "Open Clear:Reserved:" },
  { 0x0491, "Open Clear:Reserved:" },
  { 0x0492, "Open Clear:Reserved:" },
  { 0x0493, "Open Clear:Reserved:" },
  { 0x0494, "Open Clear:Reserved:" },
  { 0x0495, "Open Clear:Reserved:" },
  { 0x0496, "Open Clear:Reserved:" },
  { 0x0497, "Open Clear:Reserved:" },
  { 0x0498, "Open Clear:Reserved:" },
  { 0x0499, "Open Clear:Reserved:" },
  { 0x049A, "Open Clear:Reserved:" },
  { 0x049B, "Open Clear:Reserved:" },
  { 0x049C, "Open Clear:Reserved:" },
  { 0x049D, "Open Clear:Reserved:" },
  { 0x049E, "Open Clear:Reserved:" },
  { 0x049F, "Open Clear:Reserved:" },
  { 0x04B0, "MA:2 port node:programmable i/o" },
  { 0x04B1, "MA:Network signal processor:" },
  { 0x04B2, "MA:Network dimmer processor:" },
  { 0x04B3, "MA:GrandMA network input:Single port - not configurable" },
  { 0x04B4, "MA:Reserved:" },
  { 0x04B5, "MA:Reserved:" },
  { 0x04B6, "MA:Reserved:" },
  { 0x04B7, "MA:Reserved:" },
  { 0x04B8, "MA:Reserved:" },
  { 0x04B9, "MA:Reserved:" },
  { 0x04BA, "MA:Reserved:" },
  { 0x04BB, "MA:Reserved:" },
  { 0x04BC, "MA:Reserved:" },
  { 0x04BD, "MA:Reserved:" },
  { 0x04BE, "MA:Reserved:" },
  { 0x04BF, "MA:Reserved:" },
  { 0x04C0, "Inoage:Madrix 1:1 x emulated dmx out, no rdm" },
  { 0x04C1, "Inoage:Ion.control.pc:1 x emulated dmx out, no rdm" },
  { 0x04C2, "Inoage:ArtNetSnuffler:4 x dmx in, no rdm" },
  { 0x04C3, "Inoage:Plexus:2xOut 2xIn RDM" },
  { 0x04C4, "Inoage:Madrix3.X:4 x emulated dmx out, no rdm" },
  { 0x04C5, "Inoage:Reserved:" },
  { 0x04C6, "Inoage:Reserved:" },
  { 0x04C7, "Inoage:Reserved:" },
  { 0x04C8, "Inoage:Reserved:" },
  { 0x04C9, "Inoage:Reserved:" },
  { 0x04CA, "Inoage:Reserved:" },
  { 0x04CB, "Inoage:Reserved:" },
  { 0x04CC, "Inoage:Reserved:" },
  { 0x04CD, "Inoage:Reserved:" },
  { 0x04CE, "Inoage:Reserved:" },
  { 0x04CF, "Inoage:Reserved:" },
  { 0x04d0, "Team Projects:Xilver Controller:1 x DMX out" },
  { 0x04e0, "Wybron:PSU:2 x dmx out emulated" },
  { 0x04F0, "Pharos Architectural Controls:LPCX:1 x dmx i/p. 1-200 emulated x DMX o/p. No RDM" },
  { 0x04F1, "Pharos Architectural Controls:LPC1:0 DmxIn, 1 DmxOut (emulated)" },
  { 0x04F2, "Pharos Architectural Controls:LPC2:0 DmxIn, 2 DmxOut (emulated)" },
  { 0x04F3, "Pharos Architectural Controls:Reserved:" },
  { 0x04F4, "Pharos Architectural Controls:Reserved:" },
  { 0x04F5, "Pharos Architectural Controls:Reserved:" },
  { 0x04F6, "Pharos Architectural Controls:Reserved:" },
  { 0x04F7, "Pharos Architectural Controls:Reserved:" },
  { 0x04F8, "Pharos Architectural Controls:Reserved:" },
  { 0x04F9, "Pharos Architectural Controls:Reserved:" },
  { 0x04FA, "Pharos Architectural Controls:Reserved:" },
  { 0x04FB, "Pharos Architectural Controls:Reserved:" },
  { 0x04FC, "Pharos Architectural Controls:Reserved:" },
  { 0x04FD, "Pharos Architectural Controls:Reserved:" },
  { 0x04FE, "Pharos Architectural Controls:Reserved:" },
  { 0x04FF, "Pharos Architectural Controls:Reserved:" },
  { 0x0500, "HES:DP8000:16 Universe Art-Net source" },
  { 0x0501, "HES:DP8000:12 Universe Art-Net source" },
  { 0x0502, "HES:DP2000:4 Universe Art-Net source" },
  { 0x0600, "Spectrum Manufacturing Chroma:S-Q PSU32:" },
  { 0x0610, "DmxDesign:EthDec2:Eth to 2 x DMX out, no RDM" },
  { 0x0620, "WodieLite:ArtMedia:Var emulated dmx i/p 0-4. Var emulated dmx o/p 0-4. Rdm not supported" },
  { 0x0800, "Element Labs:Vizomo:1 x DMX emulated I/P. 1 x DMX emulated O/P. No RDM" },
  { 0x0810, "Dataton:Watchout:1 x DMX emulated I/P. 1 x DMX emulated O/P. No RDM" },
  { 0x0820, "Barco:DML-1200:1 x DMX i/p" },
  { 0x0821, "Barco:FLM:0 DMX Inputs, 0 DMX Outputs, emulated, no RDM" },
  { 0x0822, "Barco:CLM:1 DMX Inputs, 0 DMX Outputs, physical, no RDM" },
  { 0x0830, "City Theatrical:SHoW DMX Transmitter:1 x DMX o/p over wifi. RDM Standard" },
  { 0x0831, "City Theatrical:SHoW DMX Neo Transceiver:0 DMX Inputs, 2 DMX Outputs, physical, RDM support" },
  { 0x0840, "Quantukm Logic:DMX Ethernet Node:2 x DMX o/p. 2 x DMX i/p. No RDM" },
  { 0x0850, "LSS Lighting:MasterSwitch:1 x DMX out, 2 x DMX in. No RDM" },
  { 0x0851, "LSS Lighting:MasterPort:4 x DMX out/ in user select. No RDM" },
  { 0x0852, "LSS Lighting:MasterPortPSU:4 x DMX out/ in user select. No RDM" },
  { 0x0853, "LSS Lighting:DMX-View:0 x DMX out/ 1 x DMX in. No RDM" },
  { 0x0860, "Future Design ApS:FD ART-NET-Trio:1 DMX Inputs, 2 DMX Outputs, physical, RDM support" },
  { 0x0870, "Qmaxz Lighting:QME700P:1 DMX Inputs, 1 DMX Outputs, physical, RDM support" },
  { 0x0871, "Lux Lumen:Lux Node:0 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x0880, "Martin:Ether2DMX8:0 DMX Inputs, 8 DMX Outputs, physical, No RDM" },
  { 0x0890, "PHOENIXstudios:PC_DIMMER ShowGate:4 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0891, "LaserAnimation:Lasergraph DSP:1 DMX Inputs, 0 DMX Outputs, No RDM" },
  { 0x0892, "LaserAnimation:Lasergraph DSP:0 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x08A0, "COEMAR:Infinity Spot S:1 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x08A1, "COEMAR:Infinity Wash S:1 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x08A2, "COEMAR:Infinity ACL S:1 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x08A3, "COEMAR:Infinity Spot XL:1 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x08A4, "COEMAR:Infinity Wash XL:1 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x08A5, "COEMAR:DR1+:2 DMX Inputs, 2 DMX Outputs, No RDM" },
  { 0x08A6, "COEMAR:Infinity Spot M:1 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x08A7, "COEMAR:Infinity Wash M:1 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x08A8, "COEMAR:Infinity ACL M:1 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x08b0, "DMXControl:DMXControl:1 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x08b1, "DMXControl:AvrArtNode:1 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x08c0, "ChamSys:MagicQ:Console" },
  { 0x08d0, "Fisher Technical Services Inc:Navigator Automation System:4 DMX Inputs, 4 DMX Outputs, emulated, RDM support" },
  { 0x08e0, "Electric Spark:VPIX40:1 DMX Inputs, 3 DMX Outputs, emulated, RDM support" },
  { 0x08f0, "JSC:ArtGate Pro 1P:1 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x08f1, "JSC:ArtGate Pro 2P:2 DMX Inputs, 2 DMX Outputs, physical, No RDM" },
  { 0x08f2, "JSC:ArtGate Pro 4P:4 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0900, "EQUIPSON S.A.:WORK LM-3R:0 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x0901, "EQUIPSON S.A.:WORK LM-3E:1 DMX Inputs, 0 DMX Outputs, physical, No RDM" },
  { 0x0910, "TecArt Lighting:1CH Node:1 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x0911, "TecArt Lighting:Ethernet Merger:1 DMX Inputs, 0 DMX Outputs, physical, No RDM" },
  { 0x0912, "TecArt Lighting:2CH Node:2 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x0920, "Cooper Controls:ORB:1 DMX Inputs, 4 DMX Outputs, No RDM" },
  { 0x0921, "Cooper Controls:ORBxf:1 DMX Inputs, 4 DMX Outputs, No RDM" },
  { 0x0922, "Cooper Controls:Zero-Wire CRMX TX:0 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0923, "Cooper Controls:Solution:1 DMX Inputs, 4 DMX Outputs, No RDM" },
  { 0x0924, "Cooper Controls:Solution XL:1 DMX Inputs, 4 DMX Outputs, No RDM" },
  { 0x0925, "Cooper Controls:EtherN.2:0 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x0926, "Cooper Controls:EtherN.8:0 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x0930, "EQUIPSON S.A.:WORK LM-4:0 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x0940, "Laser Technology Ltd:LasNet:2 DMX Inputs, 2 DMX Outputs, physical, No RDM" },
  { 0x0950, "LSS Lighting:Discovery:4 DMX Inputs, 4 DMX Outputs, No RDM" },
  { 0x0960, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0961, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0962, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0963, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0964, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0965, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0966, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0967, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0968, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0969, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x096A, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x096B, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x096C, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x096D, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x096E, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x096F, "JPK Systems Limited:JPK*:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0970, "Fresnel / Strong:Power 12-3 TR-Net:0 DMX Inputs, 0 DMX Outputs, emulated, No RDM" },
  { 0x0971, "Fresnel / Strong:Nocturne Stage Control:0 DMX Inputs, 0 DMX Outputs, emulated, No RDM" },
  { 0x0972, "Fresnel / Strong:Ethernet-DMX:1 DMX Inputs, 2 DMX Outputs, emulated, No RDM" },
  { 0x0980, "Prism Projection:RevEAL:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0990, "Moving Art:M-NET:1 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x09a0, "HPL LIGHT COMPANY:DIMMER POWER LIGHT:1 DMX Inputs, 0 DMX Outputs, physical, No RDM" },
  { 0x09b0, "Engineering Solutions Inc:Tripix controller:0 DMX Inputs, 2 DMX Outputs, emulated, No RDM" },
  { 0x09b1, "Engineering Solutions Inc:E16 RGB Node Driver:0 DMX Inputs, 4 DMX Outputs, emulated, No RDM" },
  { 0x09b2, "Engineering Solutions Inc:E8 RGB Node Driver:0 DMX Inputs, 2 DMX Outputs, emulated, No RDM" },
  { 0x09b3, "Engineering Solutions Inc:E4 RGB Node Driver:0 DMX Inputs, 1 DMX Outputs, emulated, No RDM" },
  { 0x09c0, "SAND Network Systems:SandPort/SandBox:2 DMX Inputs, 2 DMX Outputs, physical, No RDM" },
  { 0x09d0, "Oarw:Screen Monkey:0 DMX Inputs, 1 DMX Outputs, emulated, No RDM" },
  { 0x09e0, "Mueller Elektronik:NetLase:2 DMX Inputs, 3 DMX Outputs, No RDM" },
  { 0x09f0, "LumenRadio AB:CRMX Nova TX2:2 DMX Inputs, 2 DMX Outputs, physical, No RDM" },
  { 0x09f1, "LumenRadio AB:CRMX Nova TX2 RDM:2 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x09f2, "LumenRadio AB:CRMX Nova FX:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x09f3, "LumenRadio AB:CRMX Nova FX2:2 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x09f4, "LumenRadio AB:CRMX Outdoor F1ex:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0a00, "SRS Light Design:NDP12 - Network Dimmer Pack:2 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x0a10, "VYV Corporation:Photon:1 DMX Inputs, 0 DMX Outputs, emulated, No RDM" },
  { 0x0a20, "CDS:LanBox-LCX:4 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x0a21, "CDS:LanBox-LCE:2 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x0a22, "CDS:LanBox-LCP:2 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x0a30, "Total Light:ArtMx Single:1 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x0a31, "Total Light:ArtMx Dual:2 DMX Inputs, 2 DMX Outputs, No RDM" },
  { 0x0a40, "Shanghai SeaChip Electronics Co.,Ltd:SC-DMX-2000:2 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x0a50, "Synthe FX:Luminair:1 DMX Inputs, 1 DMX Outputs, emulated, No RDM" },
  { 0x0a51, "Synthe FX:Luminair:1 DMX Inputs, 0 DMX Outputs, emulated, No RDM" },
  { 0x0aa0, "Raven Systems Design, Inc:AquaDuct Fountain Control:1 DMX Inputs, 0 DMX Outputs, No RDM" },
  { 0x0aa1, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aa2, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aa3, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aa4, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aa5, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aa6, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aa7, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aa8, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aa9, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aaa, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aab, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aac, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aad, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aae, "Raven Systems Design, Inc:Reserved:" },
  { 0x0aaf, "Raven Systems Design, Inc:Reserved:" },
  { 0x0ab0, "Theatrelight New Zealand:TLED2- Ethernet to isolated DMX converter:0 DMX Inputs, 2 DMX Outputs" },
  { 0x0ab1, "Theatrelight New Zealand:TLDE2- Isolated DMX to Ethernet converter:2 DMX Inputs, 0 DMX Outputs" },
  { 0x0ab2, "Theatrelight New Zealand:TLPID II 60- Plugin Dimmer Cabinet 60 chn:0 DMX Inputs, (internal - direct to dimmers) DMX Outputs" },
  { 0x0ab3, "Theatrelight New Zealand:TLPID II 96- Plugin Dimmer Cabinet 96 chn:0 DMX Inputs, (internal - direct to dimmers) DMX Outputs" },
  { 0x0ab4, "Theatrelight New Zealand:TLPID II 120- Plugin Dimmer Cabinet 120 chn:0 DMX Inputs, (internal - direct to dimmers) DMX Outputs" },
  { 0x0ab5, "Theatrelight New Zealand:TLPID II 192- Plugin Dimmer Cabinet 192 chn:0 DMX Inputs, (internal - direct to dimmers) DMX Outputs" },
  { 0x0ac0, "Cinetix Medien und Interface GmbH:Ethernet/DMX512 Control Box:1 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x0ac1, "Cinetix Medien und Interface GmbH:Ethernet/DMX512 Generator:0 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x0ac2, "Cinetix Medien und Interface GmbH:Ethernet/DMX512 GenIO:0 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x0ad0, "WERPAX:MULTI-DMX:2 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x0ae0, "chainzone:RoundTable:0 DMX Inputs, 1 DMX Outputs, emulated, No RDM" },
  { 0x0af0, "City Theatrical, Inc.:PDS-750TRX:0 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0af1, "City Theatrical, Inc.:PDS-375TRX:0 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0b00, "STC Mecatronica:DDR 2404 Digital Dimmer Rack:2 DMX Inputs, 0 DMX Outputs, physical, RDM supported" },
  { 0x0b10, "LSC:LSC*:0 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x0b11, "LSC:LSC*:1 DMX Inputs, 0 DMX Outputs, No RDM" },
  { 0x0b12, "LSC:LSC*:0 DMX Inputs, 4 DMX Outputs, No RDM" },
  { 0x0b13, "LSC:LSC*:4 DMX Inputs, 0 DMX Outputs, No RDM" },
  { 0x0b20, "EUROLITE:Node 8 Artnet/DMX:0 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0b30, "Absolute FX Pte Ltd:Showtime:1 DMX Inputs, 4 DMX Outputs, emulated, No RDM" },
  { 0x0b40, "Mediamation Inc:Virtual Fountain:4 DMX Inputs, 0 DMX Outputs, emulated, No RDM" },
  { 0x0b50, "Vanilla Internet Ltd:Chameleon:4 DMX Inputs, 4 DMX Outputs, emulated, No RDM" },
  { 0x0b60, "LightWild LC:LightWild DataBridge:4 DMX Inputs, 4 DMX Outputs, physical, RDM supported" },
  { 0x0b70, "Flexvisual:FlexNode:4 DMX Inputs, 0 DMX Outputs, emulated, No RDM" },
  { 0x0b80, "Digi Network::physical, No RDM" },
  { 0x0b90, "DMX4ALL GmbH:ArtNet-DMX-UNIVERSE 4.1:1 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0b91, "DMX4ALL GmbH:ArtNet-DMX STAGE-PROFI 1.1:1 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x0b92, "DMX4ALL GmbH:MagiarLED II flex PixxControl:0 DMX Inputs, 8 DMX Outputs, No RDM" },
  { 0x0ba0, "Beijing Xingguang Film & TV Equipment Technologies:3 DMX Inputs, 3 DMX Outputs, No RDM" },
  { 0x0bb0, "medien technik cords:MGate4:4 DMX Inputs, 4 DMX Outputs, RDM supported" },
  { 0x0bc0, "Joshua 1 Systems Inc:ECG-M32MX:" },
  { 0x0bc1, "Joshua 1 Systems Inc:ECG-DR2:2 DMX Inputs, 2 DMX Outputs, physical, No RDM" },
  { 0x0bc2, "Joshua 1 Systems Inc:ECG-DR4:4 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0bc3, "Joshua 1 Systems Inc:ECG-PIX8:8 DMX Inputs, 0 DMX Outputs, physical, No RDM" },
  { 0x0bc4, "Joshua 1 Systems Inc:ECGPro-D1:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0bc5, "Joshua 1 Systems Inc:ECGPro-D4:8 DMX Inputs, 8 DMX Outputs, physical, RDM supported" },
  { 0x0bc6, "Joshua 1 Systems Inc:ECGPro-D8:8 DMX Inputs, 8 DMX Outputs, physical, RDM supported" },
  { 0x0bd0, "Astera:AC4:0 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0be0, "MARUMO ELECTRIC Co.,Ltd:MBK-350E:0 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0be1, "MARUMO ELECTRIC Co.,Ltd:MBK-360E:0 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0be2, "MARUMO ELECTRIC Co.,Ltd:MBK-370E:4 DMX Inputs, 0 DMX Outputs, physical, No RDM" },
  { 0x0bf0, "Weigl Elektronik & Mediaprojekte:WEMC-1 ProCommander:1 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x0c00, "GLP German Light Products GmbH:Impression Spot:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0c01, "GLP German Light Products GmbH:Impression Wash:1 DMX Inputs, 1 DMX Outputs, physical, RDM supported" },
  { 0x0c10, "s-jaekel:DmxScreen:0 DMX Inputs, 16 DMX Outputs, physical, No RDM" },
  { 0x0c11, "s-jaekel:TimecodeSender:0 DMX Inputs, 0 DMX Outputs, No RDM" },
  { 0x0c12, "s-jaekel:TimecodeViewer:0 DMX Inputs, 0 DMX Outputs, No RDM" },
  { 0x0c13, "s-jaekel:DmxSnuffler:1 DMX Inputs, 1 DMX Outputs, No RDM" },
  { 0x0c14, "s-jaekel:DmxConsole:4 DMX Inputs, 4 DMX Outputs, No RDM" },
  { 0x0c15, "s-jaekel:TimecodeSyncAudioPlayer:0 DMX Inputs, 0 DMX Outputs, No RDM" },
  { 0x0d00, "Peter Maes Technology:EtherDmxLinkDuo:2 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x0d10, "SOUNDLIGHT:USBDMX-TWO:2 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x0d20, "IBH:loox:0 DMX Inputs, 1 DMX Outputs, emulated, No RDM" },
  { 0x0d30, "Thorn Lighting Ltd:SensaPro eDMX:0 DMX Inputs, 2 DMX Outputs, physical, RDM supported" },
  { 0x0d40, "Chromateq SARL:LED Player:0 DMX Inputs, 4 DMX Outputs, emulated, RDM supported" },
  { 0x0d41, "Chromateq SARL:Pro DMX:0 DMX Inputs, 4 DMX Outputs, emulated, RDM supported" },
  { 0x0d50, "KiboWorks:KiboNode 16 Port:0 DMX Inputs, 4 DMX Outputs, physical, RDM supported" },
  { 0x0d60, "The White Rabbit Company, Inc:MCM - Mini-Communications Module:4 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0d70, "TMB:ProPlex IQ:4 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0d80, "Celestial Audio:EtherDMXArt8-Simple:0 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0d81, "Celestial Audio:EtherDMXArt8-Pro:0 DMX Inputs, 4 DMX Outputs, physical, No RDM" },
  { 0x0d82, "Celestial Audio:DMX36:1 DMX Inputs, 1 DMX Outputs, physical, No RDM" },
  { 0x0d90, "Doug Fleenor Design Inc:Node4:" },
  { 0x8000, "ADB:Netgate XT:Video output and trigger inputs" },
  { 0x8001, "Artistic Licence:Net-Patch:TBA" },
  { 0x8002, "Artistic Licence:DMX-Hub XT:Video output and trigger inputs" },
  { 0x8003, "Artistic Licence:No-Worries XT:Real time data record - playback" },
  { 0,      NULL }
};
value_string_ext artnet_oem_code_vals_ext = VALUE_STRING_EXT_INIT(artnet_oem_code_vals);

static const value_string artnet_esta_man_vals[] = {
  { 0x0000, "ESTA" },
/* ???  { 0x0000, "PLASA" }, */
  { 0x0001, "GEE" },
  { 0x00A1, "Creative Lighting And Sound Systems Pty Ltd." },
  { 0x0101, "St. Anne Engineering GmbH" },
  { 0x0102, "Bortis Elektronik" },
  { 0x016C, "LGR" },
  { 0x0242, "ABLELITE INTERNATIONAL" },
  { 0x026F, "Acuity Brands Lighting Inc." },
  { 0x02D0, "Winona Lighting" },
  { 0x0303, "Shanghai Moons' Automation Control Co., Ltd" },
  { 0x032C, "Carallon Ltd." },
  { 0x033A, "Lux Lumen" },
  { 0x034B, "Rosstech Signals Inc." },
  { 0x038F, "Strich Labs" },
  { 0x0391, "Alcorn McBride Inc." },
  { 0x0394, "Prism Projection" },
  { 0x039B, "Lightforce Lasertechnik" },
  { 0x03D5, "eX Systems" },
  { 0x0424, "FLUX ECLAIRAGE" },
  { 0x044E, "Birdbrain Labs LLC" },
  { 0x050A, "ChamSys Ltd." },
  { 0x056C, "Lumascape Lighting Industries" },
  { 0x0573, "JIAXING XINHUALI LIGHTING & SOUNDING CO., LTD." },
  { 0x05D3, "D-LED Illumination Technologies Ltd." },
  { 0x060B, "Lighting Science Group (formerly LED Effects, Inc.)" },
  { 0x0808, "Zero 88" },
  { 0x0916, "ACTOR-MATE CO., LTD." },
  { 0x1234, "ESTA" },
  { 0x1337, "Raven Systems Design, Inc." },
  { 0x134D, "VT-Control" },
  { 0x1888, "GUANZHOU KAVON STAGE EQUIPMENT CO., LTD." },
  { 0x1998, "PLS Electronics Ltd." },
  { 0x1AFA, "TMB" },
  { 0x1BC0, "ALS Stanislaw Binkiewicz" },
  { 0x1BC6, "Studio S Music City" },
  { 0x2011, "Darklight: Precision Lighting System" },
  { 0x20A6, "ALADIN Architekturlicht GmbH" },
  { 0x20AD, "AZ e-lite Pte Ltd" },
  { 0x20B6, "Alkalite LED Technology Corp" },
  { 0x20B9, "ARRI -- Arnold & Richter Cine Technik GmbH & Co. Betriebs KG" },
  { 0x20BA, "AusChristmasLighting" },
  { 0x2121, "Brother,Brother & Sons Aps" },
  { 0x2122, "BEGLEC NV" },
  { 0x2130, "Bart van Stiphout Electronics & Software" },
  { 0x21A1, "Culture Crew bvba" },
  { 0x21A4, "CHAUVET Lighting" },
  { 0x21A9, "CaptSystemes" },
  { 0x21B3, "Coolon Pty Ltd" },
  { 0x21B4, "CHROMLECH" },
  { 0x21B5, "ChromaCove LLC" },
  { 0x2216, "D-Light Designs, LLC" },
  { 0x2222, "D.E.F. Srl" },
  { 0x2224, "DAS Integrator Pte Ltd" },
  { 0x2239, "Dream Solutions Ltd." },
  { 0x22A0, "EAS SYSTEMS" },
  { 0x22A6, "Elation Lighting" },
  { 0x22A9, "Engineering Solutions Inc." },
  { 0x22AA, "EUTRAC - Intelligent Lighting GmbH" },
  { 0x22AB, "EVC" },
  { 0x22B9, "Etherlight" },
  { 0x2337, "Focon Showtechnic" },
  { 0x23B2, "Gekko Technology Ltd." },
  { 0x2421, "HB-Laserkomponenten GmbH" },
  { 0x242A, "Hungaroflash" },
  { 0x2432, "Helvar Ltd" },
  { 0x24A3, "Lighting Innovation Group AG" },
  { 0x24AA, "IT Ihme" },
  { 0x2621, "LEADER LIGHT s.r.o." },
  { 0x2622, "LDDE Vertriebs Gmbh" },
  { 0x2623, "Leonh Hardware Enterprise Inc." },
  { 0x2624, "Lisys Fenyrendszer Zrt." },
  { 0x2626, "LLT Lichttechnik GmbH&CO.KG" },
  { 0x2630, "Laservision Pty Ltd" },
  { 0x2632, "Lehigh Electric Products" },
  { 0x2635, "LjusDesign AB" },
  { 0x2636, "Lumonic Limited" },
  { 0x2637, "Loxone Electronics GmbH" },
  { 0x263A, "Lumenec Pty. Ltd." },
  { 0x263C, "I-Pix Digital Light Ltd." },
  { 0x26A2, "MEGATECHNICS Ltd." },
  { 0x26B4, "Milford Instruments Ltd." },
  { 0x2724, "Nila Inc." },
  { 0x2734, "Nixer Ltd." },
  { 0x27A8, "Callegenix LLC" },
  { 0x2821, "Pioneer Corporation" },
  { 0x2826, "Peter Maes Technology" },
  { 0x2827, " Peternet Electronics BVBA " },
  { 0x2829, "PR-Electronic" },
  { 0x2836, "Planungsbuero" },
  { 0x2927, "ROAL Electronics SpA" },
  { 0x2999, "ALL-DO INTERNATIONAL CO., LTD." },
  { 0x29A1, "Sturdy Corporation" },
  { 0x29A9, "SRS Light Design" },
  { 0x29AA, "Steinigke Showtechnic GmbH" },
  { 0x29B2, "Selectron Bvba" },
  { 0x29B4, "Showtec (Highlite International B.V.)" },
  { 0x29B7, "Sundrax, LLC" },
  { 0x29B8, "Spotlight s.r.l." },
  { 0x29BA, "State Automation Pty Ltd." },
  { 0x29E8, "Stroytsirk LLC" },
  { 0x2A25, "Thorn Lighting Limited" },
  { 0x2A26, "Toni Maroni Gmb" },
  { 0x2AAB, "Urban Visuals & Effects Ltd." },
  { 0x2B28, "Visual Productions" },
  { 0x2BA2, "WERPAX bvba" },
  { 0x2BA9, "The White Rabbit Company, Inc." },
  { 0x2BB4, "Williams Electronic Design Ltd." },
  { 0x2C1A, "DMX4ALL GmbH" },
  { 0x2C2A, "XTBA" },
  { 0x3235, "de koster Special Effects" },
  { 0x3388, "Macostar International Ltd." },
  { 0x3434, "Global Design Solutions, Ltd." },
  { 0x361D, "Lumishore Ltd. UK" },
  { 0x3638, "Lumenpulse Lighting Inc." },
  { 0x3805, "Yifeng Lighting Co., Ltd." },
  { 0x3806, "ACME EFFECTS LTD." },
  { 0x3868, "LanBolight Technology Co., LTD." },
  { 0x3888, "Fly Dragon Lighting Equipment Co.,ltd" },
  { 0x388A, "Guangzhou Yajiang (Yagang - Silver Star) Photoelectric Equipment Ltd." },
  { 0x3A37, "TheOlymp - Networking & InterNet Services" },
  { 0x3B10, "NXP Semiconductors B.V." },
  { 0x3D30, "zactrack Lighting Technologies Gmbh" },
  { 0x4051, "SAN JACK ANALOG HOUSE CO., LTD." },
  { 0x4131, "Altman Stage Lighting" },
  { 0x4141, "AVAB America, Inc." },
  { 0x4144, "ADB - TTV Technologies nv" },
  { 0x4145, "ADE ELETTRONICA srl " },
  { 0x4149, "ANIDEA ENGINEERING, INC." },
  { 0x414C, "Artistic Licence Engineering Ltd." },
  { 0x414D, "Amptown Lichttechnik GmbH" },
  { 0x414E, "Anytronics Ltd." },
  { 0x4150, "Apogee Lighting" },
  { 0x4153, "Audio Scene" },
  { 0x4154, "Arnold Tang Productions" },
  { 0x4156, "Audio Visual Devices P/L" },
  { 0x4164, "Adelto Limited" },
  { 0x416C, "Alenco BV" },
  { 0x4172, "ARNOLD LICHTTECHNIK" },
  { 0x4173, "Astera LED Technology GmbH" },
  { 0x4179, "AYRTON" },
  { 0x4241, "BECKHOFF Automation GmbH" },
  { 0x4243, "Bill Coghill Company : Bill Coghill Design" },
  { 0x4245, "Bytecraft Entertainment Pty Ltd" },
  { 0x424F, "BOTEX" },
  { 0x4253, "Barco" },
  { 0x42A2, "Birket Engineering, Inc." },
  { 0x4344, "CDCA Ltd." },
  { 0x4347, "CAST Software" },
  { 0x4349, "C.I.Tronics Lighting Designers Ltda" },
  { 0x434B, "Color Kinetics Inc." },
  { 0x434D, "Coemar Spa" },
  { 0x4350, "CLAY PAKY S.p.A" },
  { 0x4353, "Capricorn Software" },
  { 0x4354, "City Theatrical, Inc." },
  { 0x4358, "Connex GmbH" },
  { 0x4369, "Cinetix Medien u. Interface GmbH" },
  { 0x436F, "CODEM MUSIC S.r.l." },
  { 0x4441, "DIGITAL ART SYSTEM" },
  { 0x4442, "ELETTROLAB S.r.l." },
  { 0x4443, "Claudio Dal Cero Engineering" },
  { 0x4444, "D.O.M. Datenverarbeitung GmbH" },
  { 0x4445, "Dezelectric Kft." },
  { 0x4446, "Doug Fleenor Design, Inc." },
  { 0x4449, "Durand Interstellar, Inc." },
  { 0x444C, "Dove Lighting Systems, Inc." },
  { 0x444D, "Digimedia Multimedia Lighting Solutions" },
  { 0x444E, "DALCNET SRL" },
  { 0x4450, "DMXPROFI.EU GmbH i.G." },
  { 0x4456, "Devantech Ltd." },
  { 0x4466, "DF elettronica s.r.l." },
  { 0x4469, "Diamante Lighting Srl" },
  { 0x453A, "E:cue Control GmbH" },
  { 0x4541, "Engineering Arts" },
  { 0x4543, "EC Elettronica Srl" },
  { 0x4544, "Electronics Diversified LLC" },
  { 0x454C, "Ingenieurbuero fuer Nachrichtentechnik in der Studio und Veranstaltungstechnik" },
  { 0x454E, "ENTTEC Pty Ltd" },
  { 0x4552, "EREA" },
  { 0x4554, "Entertainment Technology" },
  { 0x4563, "Les Eclairages Lou Inc." },
  { 0x456C, "Element Labs Inc." },
  { 0x4631, "OKEROAB AB" },
  { 0x464C, "Flashlight/Ampco Holding" },
  { 0x4656, "Flexvisual" },
  { 0x4744, "Goddard Design Co." },
  { 0x4745, "GPE srl" },
  { 0x474C, "G-LEC Europe GmbH" },
  { 0x4750, "DES" },
  { 0x4753, "Golden Sea Disco Light Manufacturer" },
  { 0x476C, "General Luminaire (Shanghai) Ltd." },
  { 0x4843, "Horizon Control Inc." },
  { 0x4844, "HxDx" },
  { 0x4845, "Howard Eaton Lighting Ltd." },
  { 0x484C, "HBE Lighting Systems" },
  { 0x484F, "Hollywood Controls Inc." },
  { 0x4856, "Enfis Ltd" },
  { 0x4881, "Rena Electronica B.V." },
  { 0x4941, "inoage GmbH" },
  { 0x4942, "IBEX UK Limited" },
  { 0x4945, "Insta Elektro GmbH" },
  { 0x4947, "IGuzzini illuminazione spa" },
  { 0x4948, "Ice House Productions" },
  { 0x494C, "I-Lum" },
  { 0x494E, "Interactive Technologies, Inc." },
  { 0x4950, "Interesting Products, Inc." },
  { 0x4952, "Invisible Rival Incorporated" },
  { 0x4953, "Integrated System Technologies Ltd." },
  { 0x4954, "Integrated Theatre, Inc." },
  { 0x4973, "Innovation Solutions Ltd." },
  { 0x4A31, "Joshua 1 Systems Inc." },
  { 0x4A41, "JANUS srl" },
  { 0x4A42, "JB-lighting GmbH" },
  { 0x4A4C, "Johnsson Lighting Technologies AB" },
  { 0x4A53, "JSC 'MFG'" },
  { 0x4A54, "James Thomas Engineering" },
  { 0x4A61, "Jands Pty Ltd." },
  { 0x4B42, "KissBox" },
  { 0x4B46, "Kino Flo, Inc." },
  { 0x4B4C, "KLH Electronics PLC" },
  { 0x4B4D, "KMX Inc." },
  { 0x4B55, "kuwatec, Inc." },
  { 0x4C20, "LAM32 srl" },
  { 0x4C41, "LaserAnimation Sollinger GmbH" },
  { 0x4C45, "Leviton Manufacturing Co., Inc." },
  { 0x4C4C, "LUMINEX Lighting Control Equipment bvba" },
  { 0x4C4D, "Lemaitre Special Effects Inc" },
  { 0x4C50, "LightProcessor Ltd" },
  { 0x4C52, "High End Systems Inc." },
  { 0x4C53, "Licht-, Steuer- und Schaltanlagenbau GmbH (LSS GmbH)" },
  { 0x4C54, "Licht-Technik" },
  { 0x4C55, "LumenRadio AB" },
  { 0x4C56, "LEDValley Technologies Sdn Bhd" },
  { 0x4C57, "LightWild LC" },
  { 0x4C58, "Lex Products Corp." },
  { 0x4C59, "Laser Technology Ltd." },
  { 0x4C5A, "LightMinded Industries, Inc." },
  { 0x4C5B, "LightLife, Gesellschaft fur audiovisuelle Erlebnisse mbH" },
  { 0x4C64, "LED Team" },
  { 0x4C65, "Legargeant and Associates" },
  { 0x4C69, "LIGHTOLIER" },
  { 0x4C6C, "Lampo Lighting Designers" },
  { 0x4C73, "LSC Lighting Systems (Aust) Pty. Ltd." },
  { 0x4CE5, "LED Company s.r.o." },
  { 0x4D41, "MA Lighting Technology GmbH" },
  { 0x4D42, "LAN Systems--Midibox project" },
  { 0x4D44, "Les Generateurs de brouillard MDG Fog Generators Ltd." },
  { 0x4D4C, "Mode Lighting (UK) Ltd." },
  { 0x4D50, "Martin Professional A/S" },
  { 0x4D54, "medien technik cords" },
  { 0x4D56, "Avolites Ltd." },
  { 0x4D58, "MX design" },
  { 0x4D61, "MARTINI S.p.A." },
  { 0x4D75, "Muller Elektronik" },
  { 0x4E41, "Company NA" },
  { 0x4E4A, "NJD Electronics" },
  { 0x4E4C, "NOVALIGHT S.r.l." },
  { 0x4E57, "AIM Northwest" },
  { 0x4E69, "Niko" },
  { 0x4F41, "Oase GmbH" },
  { 0x4F4C, "DDS Elettronica" },
  { 0x4F75, "Outsight Pty Ltd." },
  { 0x5041, "Philips Entertainment Lighting Asia" },
  { 0x5043, "Pathway Connectivity Inc." },
  { 0x504C, "Peperoni Lighting-Solutions" },
  { 0x5052, "Production Resource Group" },
  { 0x5053, "Philips Selecon" },
  { 0x5058, "PXM s.c." },
  { 0x5062, "LED, Inc." },
  { 0x5065, "Peradise" },
  { 0x5066, "Pfannenberg GmbH" },
  { 0x5068, "Philips Lighting BV" },
  { 0x5075, "Pulsar Light of Cambridge Ltd." },
  { 0x512D, "DJPOWER ELECTRONIC STAGE LIGHTING FIXTURE FACTORY (GUANGZHOU)" },
  { 0x5149, "JAP Optoelectronic Ltd." },
  { 0x514D, "QMAXZ lighting" },
  { 0x5153, "QuickSilver Controls, Inc." },
  { 0x516C, "Quicklights" },
  { 0x5244, "Revolution Display" },
  { 0x524C, "Radical Lighting Ltd." },
  { 0x524D, "RUIZ TECH" },
  { 0x524E, "RNC Systems Inc." },
  { 0x5252, "RoscoLab Ltd" },
  { 0x5253, "Robe Show Lighting s.r.o." },
  { 0x5341, "Stage Technologies Limited" },
  { 0x5342, "Industrias Sola Basic S.A. de C.V." },
  { 0x5343, "Ocean Thin Films Inc." },
  { 0x5344, "Stardraw.com Ltd." },
  { 0x5345, "Selador" },
  { 0x5346, "Synthe FX, LLC" },
  { 0x5347, "SGM Technology For Lighting SPA" },
  { 0x5348, "Schreder" },
  { 0x5349, "Soundsculpture Incorporated" },
  { 0x534A, "SAS Productions" },
  { 0x534B, "SK-Software" },
  { 0x534C, "SOUNDLIGHT" },
  { 0x534E, "Sand Network Systems" },
  { 0x5354, "Stagetronics Ltda" },
  { 0x5356, "OOO SAMLIGHT" },
  { 0x5363, "SpaceCannon vH" },
  { 0x5368, "ShowCAD Control Systems Ltd." },
  { 0x536C, "StageLine Electronic" },
  { 0x5370, "Spectrum Manufacturing Inc." },
  { 0x5374, "STG-Beikirch Industrieelektronik + Sicherheitstechnik GmbH & Co. KG" },
  { 0x5376, "SV-wtu eU" },
  { 0x5377, "SWISSON AG" },
  { 0x53A8, "Simon Tech" },
  { 0x5431, "AUTOLUX Handels- und ProduktionsgmbH" },
  { 0x5441, "TecArt  Lighting " },
  { 0x5444, "Technographic Displays Ltd." },
  { 0x5445, "TESI Elettronica srl" },
  { 0x544C, "Tempest Lighting Inc." },
  { 0x5453, "TalentStorm Enterprises, Inc." },
  { 0x5454, "TamaTech Labo Company Ltd," },
  { 0x5550, "UP-LUX Eletronica Ltda." },
  { 0x5555, "Martin Sukale Medientechnik GbR" },
  { 0x564C, "Vari-Lite, Inc." },
  { 0x5651, "Vision Quest Lighting Inc." },
  { 0x5653, "Viso Systems Aps" },
  { 0x5744, "W-DEV" },
  { 0x5746, "Wildfire, Inc." },
  { 0x5753, "Wireless Solution Sweden AB" },
  { 0x5759, "Wybron, Inc." },
  { 0x584D, "Xtraordinary Musical Accolade Systems" },
  { 0x5865, "XENON ARCHITECTURAL LIGHTING" },
  { 0x586D, "www.doityourselfchristmas.com hobbyists" },
  { 0x5888, "Plsao Optoelectronics Technology Co., Ltd." },
  { 0x614C, "Alektra AB" },
  { 0x6164, "Apollo Design Technology, Inc" },
  { 0x616C, "Advanced Lighting Systems" },
  { 0x6364, "CDS advanced technology bv" },
  { 0x641A, "Heliospectra AB" },
  { 0x6461, "Digilin Australia" },
  { 0x6464, "Dangeross Design" },
  { 0x646C, "dilitronics GmbH" },
  { 0x646F, "eldoLED BV" },
  { 0x6542, "eBrain GmbH" },
  { 0x6547, "euroGenie" },
  { 0x656C, "ELC lighting" },
  { 0x6573, "Environmental Lighting Solutions" },
  { 0x6574, "Electronic Theatre Controls, Inc." },
  { 0x6576, "eventa Aktiengesellschaft" },
  { 0x6673, "Freescale Semiconductor U.K. Ltd." },
  { 0x676C, "GLP German Light Products GmbH" },
  { 0x6816, "ChamberPlus Co., Ltd" },
  { 0x6864, "James Embedded Systems Engineering (JESE Ltd)" },
  { 0x6865, "Hubbell Entertainment, Inc." },
  { 0x694C, "iLight Technologies Inc" },
  { 0x6974, "Ittermann electronic GmbH" },
  { 0x6A6B, "JPK Systems Limited" },
  { 0x6B64, "Key Delfin" },
  { 0x6C6D, "Zumtobel Lighting GmbH" },
  { 0x6D61, "MAL Effekt-Technik GmbH" },
  { 0x6D62, "MBN GmbH" },
  { 0x6D63, "Sein & Schein GmbH" },
  { 0x7068, "Pharos Architectural Controls" },
  { 0x7072, "Pr-Lighting Ltd." },
  { 0x7078, "PixelRange Inc." },
  { 0x7151, "The Light Source, Inc." },
  { 0x7363, "Sean Christopher FX" },
  { 0x736C, "Strand Lighting Ltd." },
  { 0x7764, "WET" },
  { 0x786C, "XLN-t bvba" },
  { 0x7A70, "Open Lighting" },
  { 0xFFFF, "ESTA" },

  { 0,      NULL }
};
value_string_ext artnet_esta_man_vals_ext = VALUE_STRING_EXT_INIT(artnet_esta_man_vals);


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
static int hf_artnet_video_setup_control = -1;
static int hf_artnet_video_setup_font_height = -1;
static int hf_artnet_video_setup_first_font = -1;
static int hf_artnet_video_setup_last_font = -1;
static int hf_artnet_video_setup_win_font_name = -1;
static int hf_artnet_video_setup_font_data = -1;

/* ArtVideoPalette */
static int hf_artnet_video_palette_colour_red = -1;
static int hf_artnet_video_palette_colour_green = -1;
static int hf_artnet_video_palette_colour_blue = -1;

/* ArtVideoData */
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
  proto_tree *flags_tree, *flags_item;

  flags_item = proto_tree_add_item(tree, hf_artnet_poll_talktome,     tvb, offset, 1, ENC_BIG_ENDIAN);
  flags_tree = proto_item_add_subtree(flags_item, ett_artnet);

  proto_tree_add_item(flags_tree, hf_artnet_poll_talktome_reply_dest, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_poll_talktome_reply_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_poll_talktome_unused,     tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 1;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  return offset;
}

static guint
dissect_artnet_poll_reply(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree *hi, *si, *ti;

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

  proto_tree_add_item(si, hf_artnet_poll_reply_num_ports, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_port_types,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_PORT_TYPES_LENGTH,
                           ENC_NA);

  ti = proto_item_add_subtree(hi, ett_artnet);

  proto_tree_add_item(ti, hf_artnet_poll_reply_port_types_1, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_port_types_2, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_port_types_3, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_port_types_4, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_good_input,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_GOOD_INPUT_LENGTH,
                           ENC_NA);

  ti = proto_item_add_subtree(hi, ett_artnet);

  proto_tree_add_item(ti, hf_artnet_poll_reply_good_input_1, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_good_input_2, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_good_input_3, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_good_input_4, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_good_output,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_GOOD_OUTPUT_LENGTH,
                           ENC_NA);

  ti = proto_item_add_subtree(hi, ett_artnet);

  proto_tree_add_item(ti, hf_artnet_poll_reply_good_output_1, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_good_output_2, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_good_output_3, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_good_output_4, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_swin,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_SWIN_LENGTH,
                           ENC_NA);

  ti = proto_item_add_subtree(hi, ett_artnet);

  proto_tree_add_item(ti, hf_artnet_poll_reply_swin_1, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swin_2, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swin_3, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swin_4, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_swout,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_SWOUT_LENGTH,
                           ENC_NA);

  ti = proto_item_add_subtree(hi, ett_artnet);

  proto_tree_add_item(ti, hf_artnet_poll_reply_swout_1, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swout_2, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swout_3, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swout_4, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_swvideo, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_swmacro, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_swremote, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
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
  tvbuff_t *next_tvb;
  guint16   length;
  guint     size;
  gboolean  save_info;

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

  save_info = col_get_writable(pinfo->cinfo);
  col_set_writable(pinfo->cinfo, FALSE);

  next_tvb = tvb_new_subset_length(tvb, offset, length);

  /* XXX: Assumption: OK to call dmx-chan dissector under 'if (tree)' */
  call_dissector(dmx_chan_handle, next_tvb, pinfo, base_tree);

  col_set_writable(pinfo->cinfo, save_info);

  return offset + size;
}

static guint
dissect_artnet_address(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  proto_tree *hi, *si, *ti;

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

  proto_tree_add_item(ti, hf_artnet_address_swin_1, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_address_swin_2, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_address_swin_3, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_address_swin_4, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  hi = proto_tree_add_item(tree,
                           hf_artnet_address_swout,
                           tvb,
                           offset,
                           ARTNET_ADDRESS_SWOUT_LENGTH,
                           ENC_NA);

  si = proto_item_add_subtree(hi, ett_artnet);

  proto_tree_add_item(si, hf_artnet_address_swout_1, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(si, hf_artnet_address_swout_2, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(si, hf_artnet_address_swout_3, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(si, hf_artnet_address_swout_4, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_address_swvideo, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_address_command, tvb,
                      offset, 1, ENC_BIG_ENDIAN);

  offset += 1;

  return offset;
}

static guint
dissect_artnet_input(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  proto_tree *hi, *si;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_input_num_ports, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  hi = proto_tree_add_item(tree,
                           hf_artnet_input_input,
                           tvb,
                           offset,
                           ARTNET_INPUT_INPUT_LENGTH,
                           ENC_NA);

  si = proto_item_add_subtree(hi, ett_artnet);

  proto_tree_add_item(si, hf_artnet_input_input_1, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(si, hf_artnet_input_input_2, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(si, hf_artnet_input_input_3, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(si, hf_artnet_input_input_4, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  return offset;
}

static guint
dissect_artnet_video_setup(tvbuff_t *tvb, guint offset, proto_tree *tree ) {
  guint32 size;
  guint8  font_height, last_font;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_video_setup_control, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  font_height = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_setup_font_height, tvb,
                      offset, 1, font_height);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_video_setup_first_font, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
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
  guint8  len_x, len_y;
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
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_firmware_master_type, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_firmware_master_block_id, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_firmware_master_length, tvb,
                      offset, 4, ENC_BIG_ENDIAN);
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
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_firmware_reply_type, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
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
  guint8 i, uid_count;

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
  guint8    rdmver;
  guint8    sc;
  guint     size;
  gboolean  save_info;
  tvbuff_t *next_tvb;

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

  save_info = col_get_writable(pinfo->cinfo);
  col_set_writable(pinfo->cinfo, FALSE);

  next_tvb = tvb_new_subset_remaining(tvb, offset);

  /* XXX: Assumption: OK to call rdm dissector under 'if (tree)' */
  call_dissector(rdm_handle, next_tvb, pinfo, base_tree);

  col_set_writable(pinfo->cinfo, save_info);

  return offset + size;
}


static guint
dissect_artnet_rdm_sub(tvbuff_t *tvb, guint offset, proto_tree *tree,  packet_info *pinfo _U_)
{
  guint8 cc;
  gint   size;

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

  switch (cc) {
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
  proto_tree *flags_tree, *flags_item;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
		      offset, 2, ENC_NA);
  offset += 2;

  flags_item = proto_tree_add_item(tree, hf_artnet_ip_prog_command, tvb,
	                           offset, 1, ENC_BIG_ENDIAN);

  flags_tree = proto_item_add_subtree(flags_item, ett_artnet);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_port,   tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_sm,     tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_prog_ip,     tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_reset,       tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flags_tree, hf_artnet_ip_prog_command_unused,      tvb, offset, 1, ENC_BIG_ENDIAN);
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
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_diag_data_priority, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_diag_data_index, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

	length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_artnet_diag_data_length, tvb,
											offset, 2, ENC_NA);
	offset+=2;

  proto_tree_add_item(tree, hf_artnet_diag_data_data, tvb,
                      offset, length, ENC_ASCII|ENC_NA);
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
  offset += 1;

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
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_directory_reply_file, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_directory_reply_name, tvb,
                      offset, 16, ENC_ASCII|ENC_NA);
  offset += 16;

  proto_tree_add_item(tree, hf_artnet_directory_reply_desc, tvb,
                      offset, 64, ENC_ASCII|ENC_NA);
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
                      offset, 14, ENC_ASCII|ENC_NA);
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
  gint        offset = 0;
  guint       size;
  guint16     opcode;
  proto_tree *ti = NULL, *hi = NULL, *si = NULL, *artnet_tree = NULL, *artnet_header_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ARTNET");
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
                  tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 8, ENC_ASCII|ENC_NA));
  if (tree) {
    proto_tree_add_item(artnet_header_tree, hf_artnet_header_id,
                        tvb, offset, 8, ENC_ASCII|ENC_NA);
  }
  offset += 8;

  opcode = tvb_get_letohs(tvb, offset);

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%04x)",
    val_to_str_const(opcode, artnet_opcode_vals, "Unknown"), opcode);

  if (tree) {
    proto_tree_add_uint(artnet_header_tree, hf_artnet_header_opcode, tvb,
                        offset, 2, opcode);

    proto_item_append_text(ti, ", Opcode: %s (0x%04x)", val_to_str_const(opcode, artnet_opcode_vals, "Unknown"), opcode);
  }
  offset += 2;

  if (opcode != ARTNET_OP_POLL_REPLY && opcode != ARTNET_OP_POLL_FP_REPLY) {
    if (tree) {
      proto_tree_add_item(artnet_header_tree, hf_artnet_header_protver, tvb,
                          offset, 2, ENC_BIG_ENDIAN);

      proto_item_set_len(artnet_header_tree, ARTNET_HEADER_LENGTH+2 );
    }
    offset += 2;
  }

  switch (opcode) {

    case ARTNET_OP_POLL:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_poll,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA);

        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_poll( tvb, offset, si );
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

        size  = dissect_artnet_poll_reply( tvb, offset, si);
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

        size  = dissect_artnet_poll_fp_reply( tvb, offset, si );
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

        size  = dissect_artnet_diag_data( tvb, offset, si );
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

        size  = dissect_artnet_command( tvb, offset, si );
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

        size  = dissect_artnet_output( tvb, offset, si, pinfo, tree);
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

        size  = dissect_artnet_address( tvb, offset, si );
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

        size  = dissect_artnet_input( tvb, offset, si );
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

        size  = dissect_artnet_tod_request( tvb, offset, si );
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

        size  = dissect_artnet_tod_data( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;

    case ARTNET_OP_TOD_CONTROL:
      if (tree) {
        hi = proto_tree_add_item(artnet_tree,
                                 hf_artnet_tod_control,
                                 tvb,
                                 offset,
                                 0,
                                 ENC_NA );
        si = proto_item_add_subtree(hi, ett_artnet );

        size  = dissect_artnet_tod_control( tvb, offset, si );
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
        si = proto_item_add_subtree(hi, ett_artnet);
        size  = dissect_artnet_rdm(tvb, offset, si, pinfo, tree);
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
        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_rdm_sub( tvb, offset, si, pinfo );
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
        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_media( tvb, offset, si);
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
        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_media_patch( tvb, offset, si);
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
        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_media_control( tvb, offset, si);
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
        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_media_control_reply( tvb, offset, si);
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
        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_time_code( tvb, offset, si);
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
        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_time_sync( tvb, offset, si);
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
        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_trigger( tvb, offset, si);
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
        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_directory( tvb, offset, si);
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
        si = proto_item_add_subtree(hi, ett_artnet);

        size  = dissect_artnet_directory_reply( tvb, offset, si);
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

        size  = dissect_artnet_video_setup( tvb, offset, si );
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

        size  = dissect_artnet_video_palette( tvb, offset, si );
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

        size  = dissect_artnet_video_data( tvb, offset, si );
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

        size  = dissect_artnet_mac_master( tvb, offset, si );
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

        size  = dissect_artnet_mac_slave( tvb, offset, si );
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

        size  = dissect_artnet_firmware_master( tvb, offset, si );
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

        size  = dissect_artnet_firmware_reply( tvb, offset, si );
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

        size  = dissect_artnet_file_tn_master( tvb, offset, si);
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

        size  = dissect_artnet_file_fn_master( tvb, offset, si);
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

        size  = dissect_artnet_file_fn_reply( tvb, offset, si);
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

        size  = dissect_artnet_ip_prog( tvb, offset, si);
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

        size  = dissect_artnet_ip_prog_reply( tvb, offset, si );
        size -= offset;

        proto_item_set_len(si, size );
        offset += size;
      }
      break;


    default:
      if (tree && tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_text(artnet_tree, tvb, offset, -1,
          "Data (%d bytes)", tvb_reported_length_remaining(tvb, offset));
      }
      return;
  }

  if (tree && tvb_reported_length_remaining(tvb, offset) > 0) {
    proto_tree_add_item(artnet_tree, hf_artnet_excess_bytes, tvb,
      offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
  }
}

/* Heuristic dissector */
static gboolean
dissect_artnet_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint64     qword;

  /* check if we atleast have the 8 byte header */
  if (tvb_length(tvb) < 8)
    return FALSE;

  /* Check the 8 byte header "Art-Net\0" = 0x4172742d4e7400*/
  qword = tvb_get_ntoh64(tvb,0);
  if(qword != G_GUINT64_CONSTANT (0x4172742d4e7400))
    return FALSE;

  /* if the header matches, dissect it */
  dissect_artnet(tvb, pinfo, tree);

  return TRUE;
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
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_oem_code_vals_ext, 0x0,
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
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_esta_man_vals_ext, 0x0,
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

  proto_artnet = proto_register_protocol("Art-Net", "ARTNET", "artnet");
  proto_register_field_array(proto_artnet, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_artnet(void) {
  dissector_handle_t artnet_handle;

  artnet_handle   = create_dissector_handle(dissect_artnet, proto_artnet);
  dissector_add_for_decode_as("udp.port", artnet_handle);
  rdm_handle      = find_dissector("rdm");
  dmx_chan_handle = find_dissector("dmx-chan");

  heur_dissector_add("udp", dissect_artnet_heur, proto_artnet);
}
