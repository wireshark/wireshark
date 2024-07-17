/* packet-artnet.c
 * Routines for Art-Net packet disassembly
 *
 * Copyright (c) 2003, 2011 by Erwin Rol <erwin@erwinrol.com>
 * Copyright (c) 2014 by Claudius Zingerli <czingerl@gmail.com>
 * Copyright (c) 2022-2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <stdlib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-rdm.h"

/*
 * See
 *
 *     Protocol Spec: http://www.artisticlicence.com/WebSiteMaster/User%20Guides/art-net.pdf
 *     OEM Codes: https://artisticlicence.com/WebSiteMaster/Software/Art-Net/Art-NetOemCodes.h
 *     ESTA Codes: https://tsp.esta.org/tsp/working_groups/CP/mfctrIDs.php
 */

void proto_register_artnet(void);
void proto_reg_handoff_artnet(void);

static dissector_handle_t artnet_handle;

/* Define udp_port for ArtNET */

#define UDP_PORT_ARTNET 0x1936

#define ARTNET_HEADER_LENGTH                   10
#define ARTNET_POLL_LENGTH                      4
#define ARTNET_POLL_REPLY_LENGTH              197
#define ARTNET_POLL_REPLY_PORT_INFO_LENGTH     22
#define ARTNET_POLL_REPLY_PORT_TYPES_LENGTH     4
#define ARTNET_POLL_REPLY_GOOD_INPUT_LENGTH     4
#define ARTNET_POLL_REPLY_GOOD_OUTPUT_LENGTH    4
#define ARTNET_POLL_REPLY_GOOD_OUTPUT_B_LENGTH  4
#define ARTNET_POLL_REPLY_SWIN_LENGTH           4
#define ARTNET_POLL_REPLY_SWOUT_LENGTH          4
#define ARTNET_ADDRESS_LENGTH                  95
#define ARTNET_ADDRESS_SWIN_LENGTH              4
#define ARTNET_ADDRESS_SWOUT_LENGTH             4
#define ARTNET_OUTPUT_LENGTH                    1
#define ARTNET_INPUT_LENGTH                    10
#define ARTNET_INPUT_INPUT_LENGTH               4
#define ARTNET_FIRMWARE_MASTER_LENGTH        1035
#define ARTNET_FIRMWARE_REPLY_LENGTH           27
#define ARTNET_VIDEO_SETUP_LENGTH              74
#define ARTNET_VIDEO_PALETTE_LENGTH            55
#define ARTNET_VIDEO_DATA_LENGTH                8

#define ARTNET_OP_POLL               0x2000
#define ARTNET_OP_POLL_REPLY         0x2100
#define ARTNET_OP_POLL_FP_REPLY      0x2200
#define ARTNET_OP_DIAG_DATA          0x2300
#define ARTNET_OP_COMMAND            0x2400

#define ARTNET_OP_DATA_REQUEST       0x2700
#define ARTNET_OP_DATA_REPLY         0x2800

#define ARTNET_OP_OUTPUT             0x5000
#define ARTNET_OP_NZS                0x5100
#define ARTNET_OP_SYNC               0x5200

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
  { ARTNET_OP_DATA_REQUEST,       "ArtDataRequest" },
  { ARTNET_OP_DATA_REPLY,         "ArtDataReply" },
  { ARTNET_OP_OUTPUT,             "ArtDMX" },
  { ARTNET_OP_NZS,                "ArtNzs" },
  { ARTNET_OP_SYNC,               "ArtSync" },
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
static value_string_ext artnet_opcode_vals_ext = VALUE_STRING_EXT_INIT(artnet_opcode_vals);

/*
 * OEM code database date: 2024-01-24
 *
 * String format:
 * <MANUFACTURER>: <PRODUCT>
 */
static const value_string artnet_oem_code_vals[] = {
  { 0x0000, "Artistic Licence Engineering Ltd: Dmx Hub" },
  { 0x0001, "ADB: Netgate" },
  { 0x0002, "Artistic Licence Engineering Ltd: MAHub" },
  { 0x0003, "Artistic Licence Engineering Ltd: Ether Lynx I" },
  { 0x0004, "Lew Light: Lew Light" },
  { 0x0005, "High End Systems: High End Systems" },
  { 0x0006, "Avolites: Dimmer" },
  { 0x0007, "Artistic Licence Engineering Ltd: Art Net II Processor" },
  { 0x0010, "Artistic Licence Engineering Ltd: Down Link" },
  { 0x0011, "Artistic Licence Engineering Ltd: Up Link" },
  { 0x0012, "Artistic Licence Engineering Ltd: Truss Link OP" },
  { 0x0013, "Artistic Licence Engineering Ltd: Truss Link IP" },
  { 0x0014, "Artistic Licence Engineering Ltd: Net Link OP" },
  { 0x0015, "Artistic Licence Engineering Ltd: Net Link IP" },
  { 0x0016, "Artistic Licence Engineering Ltd: Radio Link OP" },
  { 0x0017, "Artistic Licence Engineering Ltd: Radio Link IP" },
  { 0x0030, "Doug Fleenor Design Inc: DFD DL" },
  { 0x0031, "Doug Fleenor Design Inc: DFD UL" },
  { 0x0050, "Goddard Design Company: GDC DL" },
  { 0x0051, "Goddard Design Company: GDC UL" },
  { 0x0070, "ADB: ADB Down Link" },
  { 0x0071, "ADB: ADB Up Link" },
  { 0x0072, "ADB: ADB WiFi" },
  { 0x0080, "Artistic Licence Engineering Ltd: AL 0 Down" },
  { 0x0081, "Artistic Licence Engineering Ltd: AL 0 Up" },
  { 0x0082, "Artistic Licence Engineering Ltd: AL 1 Down" },
  { 0x0083, "Artistic Licence Engineering Ltd: AL 1 Up" },
  { 0x0084, "Artistic Licence Engineering Ltd: AL 2 Down" },
  { 0x0085, "Artistic Licence Engineering Ltd: AL 2 Up" },
  { 0x0086, "Artistic Licence Engineering Ltd: AL 3 Down" },
  { 0x0087, "Artistic Licence Engineering Ltd: AL 3 Up" },
  { 0x0088, "Artistic Licence Engineering Ltd: AL 4 Down" },
  { 0x0089, "Artistic Licence Engineering Ltd: AL 4 Up" },
  { 0x008A, "Artistic Licence Engineering Ltd: AL 5 Down" },
  { 0x008B, "Artistic Licence Engineering Ltd: AL 5 Up" },
  { 0x008C, "Zero 88: Zero Out2" },
  { 0x008D, "Zero 88: Zero In2" },
  { 0x008E, "Flying Pig Systems: FP Out2" },
  { 0x008F, "Flying Pig Systems: FP In2" },
  { 0x0090, "ELC: Two Port Node" },
  { 0x0091, "ELC: Four Port Node" },
  { 0x00FF, "Artistic Licence Engineering Ltd: OemUnknown" },
  { 0x0100, "Artistic Licence Engineering Ltd: Ether Lynx Exp 0" },
  { 0x0101, "Artistic Licence Engineering Ltd: Ether Lynx Exp 1" },
  { 0x0102, "Artistic Licence Engineering Ltd: Ether Lynx Exp 2" },
  { 0x0103, "Artistic Licence Engineering Ltd: Ether Lynx Exp 3" },
  { 0x0104, "Artistic Licence Engineering Ltd: Ether Lynx Exp 4" },
  { 0x0105, "Artistic Licence Engineering Ltd: Ether Lynx Exp 5" },
  { 0x0106, "Artistic Licence Engineering Ltd: Ether Lynx Exp 6" },
  { 0x0107, "Artistic Licence Engineering Ltd: Ether Lynx Exp 7" },
  { 0x0108, "Artistic Licence Engineering Ltd: Ether Lynx Exp 8" },
  { 0x0109, "Artistic Licence Engineering Ltd: Ether Lynx Exp 9" },
  { 0x010A, "Artistic Licence Engineering Ltd: Ether Lynx Exp a" },
  { 0x010B, "Artistic Licence Engineering Ltd: Ether Lynx Exp b" },
  { 0x010C, "Artistic Licence Engineering Ltd: Ether Lynx Exp c" },
  { 0x010D, "Artistic Licence Engineering Ltd: Ether Lynx Exp d" },
  { 0x010E, "Artistic Licence Engineering Ltd: Ether Lynx Exp e" },
  { 0x010F, "Artistic Licence Engineering Ltd: Ether Lynx Exp f" },
  { 0x0110, "Artistic Licence Engineering Ltd: Cata Lynx" },
  { 0x0111, "Artistic Licence Engineering Ltd: Cata Lynx Exp 1" },
  { 0x0112, "Artistic Licence Engineering Ltd: Cata Lynx Exp 2" },
  { 0x0113, "Artistic Licence Engineering Ltd: Cata Lynx Exp 3" },
  { 0x0114, "Artistic Licence Engineering Ltd: Cata Lynx Exp 4" },
  { 0x0115, "Artistic Licence Engineering Ltd: Cata Lynx Exp 5" },
  { 0x0116, "Artistic Licence Engineering Ltd: Cata Lynx Exp 6" },
  { 0x0117, "Artistic Licence Engineering Ltd: Cata Lynx Exp 7" },
  { 0x0118, "Artistic Licence Engineering Ltd: Cata Lynx Exp 8" },
  { 0x0119, "Artistic Licence Engineering Ltd: Cata Lynx Exp 9" },
  { 0x011A, "Artistic Licence Engineering Ltd: Cata Lynx Exp a" },
  { 0x011B, "Artistic Licence Engineering Ltd: Cata Lynx Exp b" },
  { 0x011C, "Artistic Licence Engineering Ltd: Cata Lynx Exp c" },
  { 0x011D, "Artistic Licence Engineering Ltd: Cata Lynx Exp d" },
  { 0x011E, "Artistic Licence Engineering Ltd: Cata Lynx Exp e" },
  { 0x011F, "Artistic Licence Engineering Ltd: Cata Lynx Exp f" },
  { 0x0120, "Artistic Licence Engineering Ltd: Pixi Power F1a" },
  { 0x0180, "Martin: Maxxyz Node" },
  { 0x0181, "Martin: P3 System Controller" },
  { 0x0190, "Enttec: Enttec 0" },
  { 0x0191, "Enttec: Enttec 1" },
  { 0x0192, "Enttec: Enttec 2" },
  { 0x0193, "Enttec: Enttec 3" },
  { 0x0194, "Enttec: Enttec 4" },
  { 0x0195, "Enttec: Enttec 5" },
  { 0x0196, "Enttec: Enttec 6" },
  { 0x0197, "Enttec: Enttec 7" },
  { 0x0198, "Enttec: Enttec 8" },
  { 0x0199, "Enttec: Enttec 9" },
  { 0x019A, "Enttec: Enttec a" },
  { 0x019B, "Enttec: Enttec b" },
  { 0x019C, "Enttec: Enttec c" },
  { 0x019D, "Enttec: Enttec d" },
  { 0x019E, "Enttec: Enttec e" },
  { 0x019F, "Enttec: Enttec f" },
  { 0x01A0, "LES: PBX" },
  { 0x01A1, "LES: Executive" },
  { 0x01A2, "LES: Matrix" },
  { 0x01A3, "LES: LES 3" },
  { 0x01A4, "LES: LES 4" },
  { 0x01A5, "LES: LES 5" },
  { 0x01A6, "LES: LES 6" },
  { 0x01A7, "LES: LES 7" },
  { 0x01A8, "LES: LES 8" },
  { 0x01A9, "LES: LES 9" },
  { 0x01AA, "LES: LES a" },
  { 0x01AB, "LES: LES b" },
  { 0x01AC, "LES: LES c" },
  { 0x01AD, "LES: LES d" },
  { 0x01AE, "LES: LES e" },
  { 0x01AF, "LES: LES f" },
  { 0x01B0, "EDI: Edig" },
  { 0x01C0, "Nondim Enterprises: Openlux" },
  { 0x01D0, "Green Hippo: Hippotizer" },
  { 0x01E0, "VNR: Merger Booster" },
  { 0x01F0, "Robe: ILE" },
  { 0x01F1, "Robe: Robe 4 4" },
  { 0x0210, "Artistic Licence Engineering Ltd: Down Lynx 2" },
  { 0x0211, "Artistic Licence Engineering Ltd: Up Lynx 2" },
  { 0x0212, "Artistic Licence Engineering Ltd: Truss Lynx 2" },
  { 0x0213, "Artistic Licence Engineering Ltd: Truss Lynx 2" },
  { 0x0214, "Artistic Licence Engineering Ltd: Net Lynx OP 2" },
  { 0x0215, "Artistic Licence Engineering Ltd: Net Lynx IP 2" },
  { 0x0216, "Artistic Licence Engineering Ltd: Radio Lynx OP 2" },
  { 0x0217, "Artistic Licence Engineering Ltd: Radio Lynx IP 2" },
  { 0x0230, "Doug Fleenor Design Inc: DFD Dlynx 2" },
  { 0x0231, "Doug Fleenor Design Inc: DFD Ulynx 2" },
  { 0x0250, "Goddard Design Company: GDC Dlynx 2" },
  { 0x0251, "Goddard Design Company: GDC Ulynx 2" },
  { 0x0270, "ADB: ADB Down Lynx 2" },
  { 0x0271, "ADB: ADB Up Lynx 2" },
  { 0x0280, "LSC: LSC Down Lynx 2" },
  { 0x0281, "LSC: LSC Up Lynx 2" },
  { 0x0282, "Artistic Licence Engineering Ltd: AL OEM D1" },
  { 0x0283, "Artistic Licence Engineering Ltd: AL OEM U1" },
  { 0x0284, "Artistic Licence Engineering Ltd: AL OEM D2" },
  { 0x0285, "Artistic Licence Engineering Ltd: AL OEM U2" },
  { 0x0286, "Artistic Licence Engineering Ltd: AL OEM D3" },
  { 0x0287, "Artistic Licence Engineering Ltd: AL OEM U3" },
  { 0x0288, "Artistic Licence Engineering Ltd: AL OEM D4" },
  { 0x0289, "Artistic Licence Engineering Ltd: AL OEM U4" },
  { 0x028A, "Artistic Licence Engineering Ltd: AL OEM D5" },
  { 0x028B, "Artistic Licence Engineering Ltd: AL OEM U5" },
  { 0x0300, "Gold Stage: DMX net O" },
  { 0x0301, "Gold Stage: DMX net I" },
  { 0x0302, "Gold Stage: OemGold2" },
  { 0x0303, "Gold Stage: OemGold3" },
  { 0x0304, "Gold Stage: GT 96" },
  { 0x0305, "Gold Stage: Goldstage III Light Console" },
  { 0x0306, "Gold Stage: OemGold6" },
  { 0x0307, "Gold Stage: OemGold7" },
  { 0x0308, "Gold Stage: KTG 55 Dimmer" },
  { 0x0309, "Gold Stage: OemGold9" },
  { 0x030A, "Gold Stage: OemGolda" },
  { 0x030B, "Gold Stage: OemGoldb" },
  { 0x030C, "Gold Stage: OemGoldc" },
  { 0x030D, "Gold Stage: OemGoldd" },
  { 0x030E, "Gold Stage: OemGolde" },
  { 0x030F, "Gold Stage: OemGoldf" },
  { 0x0310, "Sunset Dynamics: StarGateDMX" },
  { 0x0320, "Luminex LCE: Ethernet DMX8" },
  { 0x0321, "Luminex LCE: Ethernet DMX2" },
  { 0x0322, "Luminex LCE: Ethernet DMX4" },
  { 0x0323, "Luminex LCE: LumiNet Monitor" },
  { 0x0330, "Invisible Rival: Blue Hysteria" },
  { 0x0340, "Avolites: Diamond 4 Vision" },
  { 0x0341, "Avolites: Diamond 4 elite" },
  { 0x0342, "Avolites: Peal offline" },
  { 0x0343, "Avolites: Titan" },
  { 0x0350, "Bigfoot: EtherMux Remote" },
  { 0x0351, "Bigfoot: EtherMux Server" },
  { 0x0352, "Bigfoot: EtherMux Desktop" },
  { 0x0360, "Ecue: Ecue 512" },
  { 0x0361, "Ecue: Ecue 1024" },
  { 0x0362, "Ecue: Ecue 2048" },
  { 0x0370, "Kiss Box: DMX Box" },
  { 0x0380, "Arkaos: V J DMX" },
  { 0x0390, "Digital Enlightenment: ShowGate" },
  { 0x03A0, "DES: NELI" },
  { 0x03B0, "Nicolaudie: Easy" },
  { 0x03B1, "Nicolaudie: Magic 3D" },
  { 0x03C0, "Catalyst: Catalyst" },
  { 0x03D0, "Bleasdale: PixelMad" },
  { 0x03E0, "Lehigh Electric Products Co: DX2 Dimming Rack" },
  { 0x03F0, "Horizon: Horizon Controller" },
  { 0x0400, "Audio Scene: OemAudioSceneO" },
  { 0x0401, "Audio Scene: OemAudioSceneI" },
  { 0x0410, "Pathport: 2 out" },
  { 0x0411, "Pathport: 2 in" },
  { 0x0412, "Pathport: 1 out" },
  { 0x0413, "Pathport: 1 in" },
  { 0x0420, "Botex: OemBotex1" },
  { 0x0430, "Simon Newton: LibArtNet" },
  { 0x0431, "Simon Newton: LLA Live" },
  { 0x0440, "XLNT: OemTeamXlntIp" },
  { 0x0441, "XLNT: OemTeamXlntOp" },
  { 0x0450, "Schnick Schnack Systems: Systemnetzteil 4E" },
  { 0x0451, "Schnick Schnack Systems: SysOne" },
  { 0x0452, "Schnick Schnack Systems: Pix Gate" },
  { 0x0460, "Dom Dv: NetDmx" },
  { 0x0470, "Sean Christopher: Projection Pal" },
  { 0x0471, "Sean Christopher: The Lighting Remote" },
  { 0x0472, "LSS Lighting: MasterGate Profibus interface" },
  { 0x0473, "LSS Lighting: Rail Controller Profibus" },
  { 0x0474, "LSS Lighting: Master Port Mini" },
  { 0x0475, "LSS Lighting: Powerdim" },
  { 0x0490, "Open Clear: OemOpenClear0" },
  { 0x0491, "Open Clear: OemOpenClear1" },
  { 0x0492, "Open Clear: OemOpenClear2" },
  { 0x0493, "Open Clear: OemOpenClear3" },
  { 0x0494, "Open Clear: OemOpenClear4" },
  { 0x0495, "Open Clear: OemOpenClear5" },
  { 0x0496, "Open Clear: OemOpenClear6" },
  { 0x0497, "Open Clear: OemOpenClear7" },
  { 0x0498, "Open Clear: OemOpenClear8" },
  { 0x0499, "Open Clear: OemOpenClear9" },
  { 0x049A, "Open Clear: OemOpenCleara" },
  { 0x049B, "Open Clear: OemOpenClearb" },
  { 0x049C, "Open Clear: OemOpenClearc" },
  { 0x049D, "Open Clear: OemOpenCleard" },
  { 0x049E, "Open Clear: OemOpenCleare" },
  { 0x049F, "Open Clear: OemOpenClearf" },
  { 0x04B0, "MA Lighting: 2 Port Node" },
  { 0x04B1, "MA Lighting: Nsp" },
  { 0x04B2, "MA Lighting: Ndp" },
  { 0x04B3, "MA Lighting: Remote" },
  { 0x04B4, "MA Lighting: GrandMA2 Consoles and OnPC" },
  { 0x04B5, "MA Lighting: VPU" },
  { 0x04B6, "MA Lighting: MA 2 4 8 Port Node programmable io" },
  { 0x04B7, "MA Lighting: Dot2 console and Dot2OnPC" },
  { 0x04B8, "MA Lighting: Dot2 VPU" },
  { 0x04B9, "MA Lighting: Dot2 X Port nodes" },
  { 0x04BA, "MA Lighting: OemMaa" },
  { 0x04BB, "MA Lighting: OemMab" },
  { 0x04BC, "MA Lighting: OemMac" },
  { 0x04BD, "MA Lighting: OemMad" },
  { 0x04BE, "MA Lighting: OemMae" },
  { 0x04BF, "MA Lighting: OemMaf" },
  { 0x04C0, "inoage: Madrix 2" },
  { 0x04C1, "GLP: Ion control pc" },
  { 0x04C2, "inoage: Snuffler" },
  { 0x04C3, "inoage: PLEXUS" },
  { 0x04C4, "inoage: MADRIX 3" },
  { 0x04C5, "inoage: LUNA 8" },
  { 0x04C6, "inoage: OemMadrix6" },
  { 0x04C7, "inoage: LUNA 4" },
  { 0x04C8, "inoage: LUNA 16" },
  { 0x04C9, "inoage: Nebula" },
  { 0x04CA, "inoage: Stella" },
  { 0x04CB, "inoage: Orion" },
  { 0x04CC, "inoage: Madrix5" },
  { 0x04CD, "inoage: OemMadrixd" },
  { 0x04CE, "inoage: Aura" },
  { 0x04CF, "inoage: OemMadrixf" },
  { 0x04D0, "Team Projects: Xilver Controller" },
  { 0x04E0, "Wybron: PSU 2" },
  { 0x04F0, "Pharos Architectural Controls: LPCX" },
  { 0x04F1, "Pharos Architectural Controls: OemPharosLpc1" },
  { 0x04F2, "Pharos Architectural Controls: OemPharosLpc2" },
  { 0x04F3, "Pharos Architectural Controls: OemPharos3" },
  { 0x04F4, "Pharos Architectural Controls: OemPharos4" },
  { 0x04F5, "Pharos Architectural Controls: OemPharos5" },
  { 0x04F6, "Pharos Architectural Controls: OemPharos6" },
  { 0x04F7, "Pharos Architectural Controls: OemPharos7" },
  { 0x04F8, "Pharos Architectural Controls: OemPharos8" },
  { 0x04F9, "Pharos Architectural Controls: OemPharos9" },
  { 0x04FA, "Pharos Architectural Controls: OemPharosa" },
  { 0x04FB, "Pharos Architectural Controls: OemPharosb" },
  { 0x04FC, "Pharos Architectural Controls: OemPharosc" },
  { 0x04FD, "Pharos Architectural Controls: OemPharosd" },
  { 0x04FE, "Pharos Architectural Controls: OemPharose" },
  { 0x04FF, "Pharos Architectural Controls: OemPharosf" },
  { 0x0500, "HES: DP8000 16" },
  { 0x0501, "HES: DP8000 12" },
  { 0x0502, "HES: DP2000" },
  { 0x0600, "Spectrum Manufacturing: Chroma Q PSU32" },
  { 0x0610, "DmxDesign: EthDec2" },
  { 0x0620, "WodieLite: ArtMedia" },
  { 0x0800, "Element Labs: Vizomo" },
  { 0x0810, "Dataton: Watchout" },
  { 0x0820, "Barco: Barco DML 120" },
  { 0x0821, "Barco: FLM" },
  { 0x0822, "Barco: CLM" },
  { 0x0830, "City Theatrical: SHoW DMX Transmitter" },
  { 0x0831, "City Theatrical: SHoW DMX Neo Transceiver" },
  { 0x0840, "Quantukm Logic: DMX Ethernet Node" },
  { 0x0850, "LSS Lighting: MasterSwitch" },
  { 0x0851, "LSS Lighting: MasterPort4" },
  { 0x0852, "LSS Lighting: MasterPortPSU" },
  { 0x0853, "LSS Lighting: DMX View" },
  { 0x0860, "Future Design ApS: FD Trio" },
  { 0x0870, "Qmaxz Lighting: QME700P" },
  { 0x0871, "Lux Lumen: Lux Node" },
  { 0x0880, "Martin: Ether2DMX8 Node" },
  { 0x0890, "PHOENIXstudios Remsfeld: DIMMER ShowGate" },
  { 0x0891, "LaserAnimation Sollinger GmbH: Lasergraph DSP" },
  { 0x0892, "LaserAnimation Sollinger GmbH: Lasergraph DSP" },
  { 0x08A0, "COEMAR: Infinity Spot S" },
  { 0x08A1, "COEMAR: Infinity Wash S" },
  { 0x08A2, "COEMAR: Infinity ACL S" },
  { 0x08A3, "COEMAR: Infinity Spot XL" },
  { 0x08A4, "COEMAR: Infinity Wash XL" },
  { 0x08A5, "COEMAR: DR1+" },
  { 0x08A6, "COEMAR: Infinity Spot M" },
  { 0x08A7, "COEMAR: Infinity Wash M" },
  { 0x08A8, "COEMAR: Infinity ACL M" },
  { 0x08B0, "DMXControl: DMXControl" },
  { 0x08B1, "DMXControl: AvrNode" },
  { 0x08C0, "ChamSys: MagicQ" },
  { 0x08D0, "Fisher Technical Services Inc: Navigator Automation System" },
  { 0x08E0, "Electric Spark: VPIX40" },
  { 0x08F0, "JSC: Gate Pro 1P" },
  { 0x08F1, "JSC: Gate Pro 2P" },
  { 0x08F2, "JSC: Gate Pro 4P" },
  { 0x0900, "EQUIPSON S A: WORK LM 3R" },
  { 0x0901, "EQUIPSON S A: WORK LM 3E" },
  { 0x0910, "TecArt Lighting: 1CH Node" },
  { 0x0911, "TecArt Lighting: Ethernet Merger" },
  { 0x0912, "TecArt Lighting: 2CH Node" },
  { 0x0920, "Zero 88: ORB" },
  { 0x0921, "Zero 88: ORBxf" },
  { 0x0922, "Zero 88: Zero Wire CRMX TX RDM" },
  { 0x0923, "Zero 88: Solution" },
  { 0x0924, "Zero 88: Solution XL" },
  { 0x0925, "Zero 88: EtherN 2 RDM" },
  { 0x0926, "Zero 88: EtherN 8 RDM" },
  { 0x0927, "Zero 88: G4" },
  { 0x0928, "Zero 88: G8" },
  { 0x0930, "EQUIPSON S A: WORK LM 4" },
  { 0x0940, "Laser Technology Ltd: LasNet" },
  { 0x0950, "LSS Lighting: Discovery" },
  { 0x0960, "JPK Systems Limited: OemJpk1" },
  { 0x0961, "JPK Systems Limited: OemJpk2" },
  { 0x0962, "JPK Systems Limited: OemJpk3" },
  { 0x0963, "JPK Systems Limited: OemJpk4" },
  { 0x0964, "JPK Systems Limited: OemJpk5" },
  { 0x0965, "JPK Systems Limited: OemJpk6" },
  { 0x0966, "JPK Systems Limited: OemJpk7" },
  { 0x0967, "JPK Systems Limited: OemJpk8" },
  { 0x0968, "JPK Systems Limited: OemJpk9" },
  { 0x0969, "JPK Systems Limited: OemJpk10" },
  { 0x096A, "JPK Systems Limited: OemJpk11" },
  { 0x096B, "JPK Systems Limited: OemJpk12" },
  { 0x096C, "JPK Systems Limited: OemJpk13" },
  { 0x096D, "JPK Systems Limited: OemJpk14" },
  { 0x096E, "JPK Systems Limited: OemJpk15" },
  { 0x096F, "JPK Systems Limited: OemJpk16" },
  { 0x0970, "Fresnel Strong: Power 12 3 TR Net" },
  { 0x0971, "Fresnel S A Strong: Nocturne Stage Control" },
  { 0x0972, "Fresnel S A Strong: Ethernet DMX" },
  { 0x0980, "Prism Projection: RevEAL" },
  { 0x0990, "Moving Art: M NET" },
  { 0x09A0, "HPL LIGHT COMPANY: DIMMER POWER LIGHT" },
  { 0x09B0, "Engineering Solutions Inc: Tripix controller" },
  { 0x09B1, "Engineering Solutions Inc: E16 RGB Node Driver" },
  { 0x09B2, "Engineering Solutions Inc: E8 RGB Node Driver" },
  { 0x09B3, "Engineering Solutions Inc: E4 RGB Node Driver" },
  { 0x09C0, "SAND Network Systems: SandPort SandBox" },
  { 0x09D0, "Oarw: Screen Monkey" },
  { 0x09E0, "Mueller Elektronik: NetLase" },
  { 0x09F0, "LumenRadio AB: CRMX Nova TX2" },
  { 0x09F1, "LumenRadio AB: CRMX Nova TX2 RDM" },
  { 0x09F2, "LumenRadio AB: CRMX Nova FX" },
  { 0x09F3, "LumenRadio AB: CRMX Nova FX2" },
  { 0x09F4, "LumenRadio AB: CRMX Outdoor F1ex" },
  { 0x09F5, "LumenRadio AB: SuperNova" },
  { 0x0A00, "SRS Light Design: NDP12 Network Dimmer Pack" },
  { 0x0A10, "VYV Corporation: Photon" },
  { 0x0A20, "CDS: LanBox LCX" },
  { 0x0A21, "CDS: LanBox LCE" },
  { 0x0A22, "CDS: LanBox LCP" },
  { 0x0A30, "Total Light: Mx Single" },
  { 0x0A31, "Total Light: Mx Dual" },
  { 0x0A40, "Shanghai SeaChip Electronics Co Ltd: SC DMX 2000" },
  { 0x0A50, "Synthe FX: Luminair" },
  { 0x0A51, "Synthe FX: Pixelnode" },
  { 0x0A60, "Goddard Design Company: OemGodAL5001" },
  { 0x0A61, "Goddard Design Company: OemGodDataLynxOp" },
  { 0x0A62, "Goddard Design Company: OemGodRailLynxOp" },
  { 0x0A63, "Goddard Design Company: OemGodDownLynx4" },
  { 0x0A64, "Goddard Design Company: OemGodNetLynxOp4" },
  { 0x0A65, "Goddard Design Company: OemGodAL5002" },
  { 0x0A66, "Goddard Design Company: OemGodDataLynxIp" },
  { 0x0A67, "Goddard Design Company: OemGodCataLynxNt" },
  { 0x0A68, "Goddard Design Company: OemGodRailLynxIp" },
  { 0x0A69, "Goddard Design Company: OemGodUpLynx4" },
  { 0x0A6A, "Goddard Design Company: OemGodNetLynxIp4" },
  { 0x0A6B, "Goddard Design Company: OemGodArtBoot" },
  { 0x0A6C, "Goddard Design Company: OemGodArtLynxOp" },
  { 0x0A6D, "Goddard Design Company: OemGodArtLynxIp" },
  { 0x0A6E, "Goddard Design Company: OemGodEtherLynxII" },
  { 0x0A80, "CLAYPAKY: Alpha Spot HPE 700" },
  { 0x0A81, "CLAYPAKY: Alpha Beam 700" },
  { 0x0A82, "CLAYPAKY: Alpha Wash 700" },
  { 0x0A83, "CLAYPAKY: Alpha Profile 700" },
  { 0x0A84, "CLAYPAKY: Alpha Beam 1500" },
  { 0x0A85, "CLAYPAKY: Alpha Wash LT1500" },
  { 0x0A86, "CLAYPAKY: Alpha Spot HPE 1500" },
  { 0x0A87, "CLAYPAKY: Alpha Profile 1500" },
  { 0x0A88, "CLAYPAKY: Alpha Wash 1500" },
  { 0x0A89, "CLAYPAKY: Sharpy" },
  { 0x0A8A, "CLAYPAKY: Shot Light Wash" },
  { 0x0A8B, "CLAYPAKY: Alpha Spot QWO800" },
  { 0x0A8C, "CLAYPAKY: Alpha Profile 1500Q" },
  { 0x0A8D, "CLAYPAKY: Alpha Profile 800" },
  { 0x0A8E, "CLAYPAKY: Aleda K5" },
  { 0x0A8F, "CLAYPAKY: Aleda K10" },
  { 0x0A90, "CLAYPAKY: Aleda K20" },
  { 0x0A91, "CLAYPAKY: Sharpy Wash" },
  { 0x0A92, "CLAYPAKY: Aleda K10 B Eye Easy" },
  { 0x0A93, "CLAYPAKY: Aleda K20 B Eye" },
  { 0x0A94, "CLAYPAKY: Aleda K10 B Eye" },
  { 0x0A95, "CLAYPAKY: SuperSharpy" },
  { 0x0A96, "CLAYPAKY: Mythos" },
  { 0x0A97, "CLAYPAKY: Sharpy Wash PC" },
  { 0x0A98, "CLAYPAKY: SCENIUS PROFILE" },
  { 0x0A99, "CLAYPAKY: SCENIUS SPOT" },
  { 0x0A9A, "CLAYPAKY: SPHERISCAN" },
  { 0x0A9B, "CLAYPAKY: SPHERLIGHT" },
  { 0x0A9C, "CLAYPAKY: HEPIKOS" },
  { 0x0A9D, "CLAYPAKY: SHOWBATTEN" },
  { 0x0A9E, "CLAYPAKY: SHAR BAR" },
  { 0x0A9F, "CLAYPAKY: MYTHOS2" },
  { 0x0AA0, "Raven Systems Design Inc: AquaDuct Fountain" },
  { 0x0AA1, "Raven Systems Design Inc: OemRaven1" },
  { 0x0AA2, "Raven Systems Design Inc: OemRaven2" },
  { 0x0AA3, "Raven Systems Design Inc: OemRaven3" },
  { 0x0AA4, "Raven Systems Design Inc: OemRaven4" },
  { 0x0AA5, "Raven Systems Design Inc: OemRaven5" },
  { 0x0AA6, "Raven Systems Design Inc: OemRaven6" },
  { 0x0AA7, "Raven Systems Design Inc: OemRaven7" },
  { 0x0AA8, "Raven Systems Design Inc: OemRaven8" },
  { 0x0AA9, "Raven Systems Design Inc: OemRaven9" },
  { 0x0AAA, "Raven Systems Design Inc: OemRavena" },
  { 0x0AAB, "Raven Systems Design Inc: OemRavenb" },
  { 0x0AAC, "Raven Systems Design Inc: OemRavenc" },
  { 0x0AAD, "Raven Systems Design Inc: OemRavend" },
  { 0x0AAE, "Raven Systems Design Inc: OemRavene" },
  { 0x0AAF, "Raven Systems Design Inc: OemRavenf" },
  { 0x0AB0, "Theatrelight New Zealand: TLED2 Ethernet to isolated DMX converter" },
  { 0x0AB1, "Theatrelight New Zealand: TLDE2 Isolated DMX to Ethernet converter" },
  { 0x0AB2, "Theatrelight New Zealand: TLPID II 60 Plugin Dimmer Cabinet" },
  { 0x0AB3, "Theatrelight New Zealand: TLPID II 96 Plugin Dimmer Cabinet" },
  { 0x0AB4, "Theatrelight New Zealand: TLPID II 120 Plugin Dimmer Cabinet" },
  { 0x0AB5, "Theatrelight New Zealand: TLPID II 192 Plugin Dimmer Cabinet" },
  { 0x0AC0, "Cinetix Medien und Interface GmbH: Ethernet DMX512 Control Box" },
  { 0x0AC1, "Cinetix Medien und Interface GmbH: Ethernet DMX512 Generator" },
  { 0x0AC2, "Cinetix Medien und Interface GmbH: Ethernet DMX512 GenIO" },
  { 0x0AD0, "WERPAX bvba: MULTI DMX" },
  { 0x0AE0, "chainzone: RoundTable" },
  { 0x0AF0, "City Theatrical Inc: PDS 750TRX" },
  { 0x0AF1, "City Theatrical Inc: PDS 375TRX" },
  { 0x0B00, "STC Mecatronica: DDR 2404 Digital Dimmer Rack" },
  { 0x0B10, "LSC: OemLscOut1" },
  { 0x0B11, "LSC: OemLscIn1" },
  { 0x0B12, "LSC: OemLscOut4" },
  { 0x0B13, "LSC: OemLscIn4" },
  { 0x0B20, "EUROLITE: Node 8" },
  { 0x0B30, "Absolute FX Pte Ltd: Showtime" },
  { 0x0B40, "Mediamation Inc: Virtual Fountain" },
  { 0x0B50, "Vanilla Internet Ltd: Chameleon" },
  { 0x0B60, "LightWild LC: LightWild DataBridge" },
  { 0x0B70, "Flexvisual: FlexNode" },
  { 0x0B80, "Company NA: Digi Network" },
  { 0x0B81, "Company NA: Mozart PSU 4" },
  { 0x0B82, "Company NA: DigiNet 416" },
  { 0x0B90, "DMX4ALL GmbH: DMX UNIVERSE 4 1" },
  { 0x0B91, "DMX4ALL GmbH: DMX STAGE PROFI 1 1" },
  { 0x0B92, "DMX4ALL GmbH: MagiarLED II flex PixxControl" },
  { 0x0BA0, "Starlighting: Net DMX Notes" },
  { 0x0BB0, "medien technik cords: MGate4" },
  { 0x0BC0, "Joshua 1 Systems Inc: ECG M32MX" },
  { 0x0BC1, "Joshua 1 Systems Inc: ECG DR2" },
  { 0x0BC2, "Joshua 1 Systems Inc: ECG DR4" },
  { 0x0BC3, "Joshua 1 Systems Inc: ECG PIX8" },
  { 0x0BC4, "Joshua 1 Systems Inc: ECGPro D1" },
  { 0x0BC5, "Joshua 1 Systems Inc: ECGPro D4" },
  { 0x0BC6, "Joshua 1 Systems Inc: ECGPro D8" },
  { 0x0BD0, "Astera: AC4" },
  { 0x0BE0, "MARUMO ELECTRIC Co Ltd: MBK 350E" },
  { 0x0BE1, "MARUMO ELECTRIC Co Ltd: MBK 360E" },
  { 0x0BE2, "MARUMO ELECTRIC Co Ltd: MBK 370E" },
  { 0x0BF0, "Weigl Elektronik Mediaprojekte: Pro IO" },
  { 0x0C00, "GLP German Light Products GmbH: Impression Spot one" },
  { 0x0C01, "GLP German Light Products GmbH: Impression Wash one" },
  { 0x0C10, "s jaekel: DmxScreen" },
  { 0x0C11, "s jaekel: TimecodeSender" },
  { 0x0C12, "s jaekel: TimecodeViewer" },
  { 0x0C13, "s jaekel: DmxSnuffler" },
  { 0x0C14, "s jaekel: DmxConsole" },
  { 0x0C15, "s jaekel: TimecodeSyncAudioPlayer" },
  { 0x0D00, "Peter Maes Technology: EtherDmxLinkDuo" },
  { 0x0D10, "SOUNDLIGHT: USBDMX TWO" },
  { 0x0D20, "IBH: loox" },
  { 0x0D30, "Thorn Lighting Ltd: SensaPro eDMX" },
  { 0x0D40, "Chromateq SARL: LED Player" },
  { 0x0D41, "Chromateq SARL: Pro DMX" },
  { 0x0D50, "KiboWorks: KiboNode 16 Port" },
  { 0x0D60, "The White Rabbit Company Inc: MCM Mini Communications Module" },
  { 0x0D70, "TMB: ProPlex IQ" },
  { 0x0D71, "TMB: Mozart MZ 40" },
  { 0x0D80, "Celestial Audio: EtherDMX8 Simple" },
  { 0x0D81, "Celestial Audio: EtherDMX8 Pro" },
  { 0x0D82, "Celestial Audio: DMX36" },
  { 0x0D90, "Doug Fleenor Design Inc: Node4" },
  { 0x0DA0, "Lex: AL5003 Lex" },
  { 0x0DB0, "Revolution Display Inc: Navigator" },
  { 0x0DC0, "Visual Productions: CueCore" },
  { 0x0DC1, "Visual Productions: IoCore" },
  { 0x0DD0, "LLT Lichttechnik GmbH Co KG: SMS 28A" },
  { 0x0DE0, "Chromlech: Elidy S" },
  { 0x0DE1, "Chromlech: Elidy S RDM" },
  { 0x0DE2, "Chromlech: Elidy" },
  { 0x0DE3, "Chromlech: Elidy RDM" },
  { 0x0DF0, "Integrated System Technologies Ltd: iDrive Thor 36" },
  { 0x0DF1, "Integrated System Technologies Ltd: iDrive White Knight 36" },
  { 0x0DF2, "Integrated System Technologies Ltd: iDrive Force 12" },
  { 0x0DF3, "Integrated System Technologies Ltd: iDrive Thor 16" },
  { 0x0E00, "RayComposer R Adams: RayComposer Software" },
  { 0x0E01, "RayComposer R Adams: RayComposer NET" },
  { 0x0E10, "eldoLED: PowerBOX Addresser" },
  { 0x0E20, "coolux GmbH: Pandoras Box Mediaserver" },
  { 0x0E21, "coolux GmbH: Widget Designer" },
  { 0x0E30, "ELETTROLAB Srl: Accendo Smart Light Power" },
  { 0x0E40, "Philips: ColorBlaze TRX" },
  { 0x0E70, "XiamenGreenTao Opto Electronics Co Ltd: GT DMX 2000" },
  { 0x0E71, "XiamenGreenTao Opto Electronics Co Ltd: GT DMX 4000" },
  { 0x0E80, "Rnet: Rnet 8" },
  { 0x0E81, "Rnet: Rnet 6" },
  { 0x0E82, "Rnet: Rnet 4" },
  { 0x0E83, "Rnet: Rnet 2" },
  { 0x0E84, "Rnet: Rnet 1" },
  { 0x0E90, "Dmx4All: Player AN" },
  { 0x0E91, "Dmx4All: AN Led Dimmer AN" },
  { 0x0EA0, "EQUIPSON S A: WORK LM 5" },
  { 0x0EA1, "EQUIPSON S A: WORK LM 3R2" },
  { 0x0EA2, "EQUIPSON S A: WORK LM 5W" },
  { 0x0EA3, "EQUIPSON S A: WORK DMXNET 4" },
  { 0x0EA4, "EQUIPSON S A: WORK DMXNET 8" },
  { 0x0EB0, "SanDevices: E680 pixel controllers" },
  { 0x0EB1, "SanDevices: E681 pixel controllers" },
  { 0x0EB2, "SanDevices: E682 pixel controllers" },
  { 0x0EB3, "SanDevices: E6804 pixel controllers" },
  { 0x0EC0, "BRAINSALT MEDIA GMBH: BSM Conductor PRO" },
  { 0x0ED0, "ELETTROLAB Srl: Avvio 04" },
  { 0x0ED1, "ELETTROLAB Srl: Remoto" },
  { 0x0EE0, "PRO SOLUTIONS: DMX PRO Net 02" },
  { 0x0EE1, "PRO SOLUTIONS: DMX PRO Net 01" },
  { 0x0EE2, "PRO SOLUTIONS: DMX PRO Net 10" },
  { 0x0EE3, "PRO SOLUTIONS: DMX PRO Net 11" },
  { 0x0EE4, "PRO SOLUTIONS: DMX PRO Net 04" },
  { 0x0EE5, "PRO SOLUTIONS: DMX PRO Net 14" },
  { 0x0EF0, "eIdea Creative Technology: EtherShow 2" },
  { 0x0F00, "Brink Electronics: net node 01" },
  { 0x0F01, "Brink Electronics: net node 10" },
  { 0x0F02, "Brink Electronics: net node 11" },
  { 0x0F10, "deskontrol electronics: Pixel controller II" },
  { 0x0F11, "deskontrol electronics: Pixel controller III" },
  { 0x0F12, "deskontrol electronics: DMX controller" },
  { 0x0F20, "Kirron light components: IDycoLED Control" },
  { 0x0F30, "Visual Productions: B Station" },
  { 0x0F31, "Visual Productions: F Station" },
  { 0x0F40, "LSS GmbH: MasterPort RM" },
  { 0x0F50, "kuwatec Inc: EtherMX" },
  { 0x0F60, "Integrated System Technologies Ltd: iDrive PixelLED" },
  { 0x0F61, "Integrated System Technologies Ltd: iDrive Gateway 12" },
  { 0x0F70, "Philips Large Luminous Surfaces: Luminous Textile Panel" },
  { 0x0F80, "VT Control: WRDM V1 0" },
  { 0x0F90, "Panasonic Corporation: EMIT AX" },
  { 0x0F91, "Panasonic Corporation: Projector" },
  { 0x0FA0, "Diamante Lighting: DMNet Out" },
  { 0x0FB0, "Glow Motion Technologies LLC: Ghostband Transmitter" },
  { 0x0FC0, "Sigma Net: AM 8" },
  { 0x0FD0, "DiGidot: DiGidot C 4" },
  { 0x0FE0, "techKnow Design: techNodeTx1" },
  { 0x0FE1, "techKnow Design: techNodeTx2" },
  { 0x0FE2, "techKnow Design: techNodeRx1" },
  { 0x0FE3, "techKnow Design: techNodeRx2" },
  { 0x0FF0, "Total Light: Ether Quad" },
  { 0x1000, "IP DMX Control: ip dmx dx 1 2" },
  { 0x1010, "TNF Concept: RTS DMX 512" },
  { 0x1020, "Nico Technology: Nico DMX interface 4504" },
  { 0x1030, "Highendled Electronics Company Limited: EZK456" },
  { 0x1031, "Highendled Electronics Company Limited: PIX101" },
  { 0x1032, "Highendled Electronics Company Limited: FLA472" },
  { 0x1033, "Highendled Electronics Company Limited: ULT538" },
  { 0x1034, "Highendled Electronics Company Limited: PSU 10A" },
  { 0x1040, "Visual Productions: Cuety" },
  { 0x1041, "Visual Productions: QuadCore" },
  { 0x1050, "Ackerman Computer Sciences: CFSound IV - Compact Flash Sound Player IV" },
  { 0x1051, "Ackerman Computer Sciences: Color LCD 320x240 Terminal" },
  { 0x1060, "Innovation LED Limited: Ilumo Zoom Spot" },
  { 0x1061, "Innovation LED Limited: Ilumo Cyc 1" },
  { 0x1062, "Innovation LED Limited: Ilumo ARC Gateway" },
  { 0x1063, "Innovation LED Limited: Ether DMX 1" },
  { 0x1064, "Innovation LED Limited: Ether DMX 2" },
  { 0x1065, "Innovation LED Limited: Ether DMX 4" },
  { 0x1070, "LightAct d o o: reActor" },
  { 0x1080, "wupperTec: iMerge" },
  { 0x1090, "Integrated System Technologies Ltd: iMune" },
  { 0x10A0, "Advatek Lighting: PixLite 16" },
  { 0x10A1, "Advatek Lighting: PixLite 4" },
  { 0x10B0, "ACME: XP 1000 SZ" },
  { 0x10C0, "AV Stumpfl GmbH: Wings AV Suite" },
  { 0x10D0, "Lumax: LumaxNET ILDA Interface" },
  { 0x10E0, "Zingerli Show Engineering: Katlait" },
  { 0x10E1, "Zingerli Show Engineering: Kailua" },
  { 0x10E2, "Zingerli Show Engineering: Kailua 2" },
  { 0x10E3, "Zingerli Show Engineering: Pina" },
  { 0x10E4, "Zingerli Show Engineering: Sina" },
  { 0x10E5, "Zingerli Show Engineering: Tukra" },
  { 0x10F0, "kuwatec Inc: DIAheart" },
  { 0x1100, "Sigma Net: E NODE 8 1" },
  { 0x1110, "Radig Hard Software: EDC 01" },
  { 0x1120, "Mogees Ltd: Mogees" },
  { 0x1130, "GuangZhou MCSWE Technologies: MCSWE 1024" },
  { 0x1131, "GuangZhou MCSWE Technologies: MCSWE 2048" },
  { 0x1140, "Dynamic Projection Institute Herstellungs und Vertriebs GmbH: Mirror Head" },
  { 0x1150, "Steinigke Showtechnic GmbH: PSU 8A" },
  { 0x1151, "Steinigke Showtechnic GmbH: Node 1" },
  { 0x1152, "Steinigke Showtechnic GmbH: Pixel Ball" },
  { 0x1153, "Steinigke Showtechnic GmbH: Zeitgeist PMC 16" },
  { 0x1154, "Steinigke Showtechnic GmbH: Stage Bar 5" },
  { 0x1155, "Steinigke Showtechnic GmbH: Stage Bar 10" },
  { 0x1160, "BEGLEC: BT NODE28" },
  { 0x1161, "BEGLEC: POWERMATRIX5x5 RGB Mk2" },
  { 0x1162, "BEGLEC: BEAM MATRIX5x5 RGBW" },
  { 0x1170, "Fineline Solutions Ltd: 16 Channel Stepper Controller" },
  { 0x1171, "Fineline Solutions Ltd: Fineline product 1" },
  { 0x1172, "Fineline Solutions Ltd: Fineline product 2" },
  { 0x1173, "Fineline Solutions Ltd: Fineline product 3" },
  { 0x1174, "Fineline Solutions Ltd: Fineline product 4" },
  { 0x1175, "Fineline Solutions Ltd: Fineline product 5" },
  { 0x1176, "Fineline Solutions Ltd: Fineline product 6" },
  { 0x1177, "Fineline Solutions Ltd: Fineline product 7" },
  { 0x1178, "Fineline Solutions Ltd: Fineline product 8" },
  { 0x1179, "Fineline Solutions Ltd: Fineline product 9" },
  { 0x117A, "Fineline Solutions Ltd: Fineline product 10" },
  { 0x117B, "Fineline Solutions Ltd: Fineline product 11" },
  { 0x117C, "Fineline Solutions Ltd: Fineline product 12" },
  { 0x117D, "Fineline Solutions Ltd: Fineline product 13" },
  { 0x117E, "Fineline Solutions Ltd: Fineline product 14" },
  { 0x117F, "Fineline Solutions Ltd: Fineline product 15" },
  { 0x1180, "Rocrail: Rocrail DMX Daylight" },
  { 0x1190, "PXM: Px314" },
  { 0x1191, "PXM: Px357" },
  { 0x11A0, "OTTEC Technology GmbH: Fogmachine" },
  { 0x11B0, "Claude Bigonoff: Interface LT Open source" },
  { 0x11C0, "Rena Electronica B V: Bits2Power Power Data Controller" },
  { 0x11D0, "LIGHT SKY: OemSkyHub" },
  { 0x11E0, "HDL: DMXNode4" },
  { 0x11F0, "Pangolin Laser Systems Inc: FB4 SE" },
  { 0x11F1, "Pangolin Laser Systems Inc: AVR Ethernet DMX" },
  { 0x1200, "ShenZhen HuaCanXing Technology Co Ltd: H801RT" },
  { 0x1210, "Highendled Electronics Company Limited: FLA308" },
  { 0x1211, "Highendled Electronics Company Limited: FLA320" },
  { 0x1220, "Pacific Northwest National Laboratory: PNNL Connected Lighting System Testbed" },
  { 0x1230, "Ed Keefe Design: Advanced Laser Router" },
  { 0x1240, "Guangzhou Hongcai Stage Equipment co: Q 5 Turbo" },
  { 0x1250, "Claude Heintz Design: LXConsole" },
  { 0x1260, "Immersive Design Studios: Canvas" },
  { 0x1270, "Visual Productions: LPU 1" },
  { 0x1271, "Visual Productions: LPU 2" },
  { 0x1272, "Visual Productions: QuadCore" },
  { 0x1273, "Visual Productions: CueCore2" },
  { 0x1280, "ARC Solid State Lighting Corporation: DMX Converter" },
  { 0x1290, "Peter Meyer Project Management Adviser GmbH: PMA DMX Driver" },
  { 0x12A0, "Robert Juliat: Dalis Reference : 860" },
  { 0x12A1, "Robert Juliat: Merlin" },
  { 0x12B0, "Briteq: BEAMBAR5 RGBW" },
  { 0x12B1, "Briteq: BEAMBAR10 RGBW" },
  { 0x12B2, "Briteq: BEAM WIZARD5x5" },
  { 0x12B3, "Briteq: BEAM MATRIX5x5 RGBW" },
  { 0x12C0, "JMS Pro Light: WLAN2DMX" },
  { 0x12D0, "Interactive Technologies Inc: CueServer 2" },
  { 0x12E0, "Strand Lighting: Single Gang Node PN 65161" },
  { 0x12E1, "Strand Lighting: 3 Port Node PN 65163" },
  { 0x12E2, "Strand Lighting: 3 Port DIN PCB PN 97 0387" },
  { 0x12E3, "Strand Lighting: 3 Port Embedded PCB PN 74261" },
  { 0x12E4, "Strand Lighting: 8 Port Node PN 65168" },
  { 0x12E5, "Strand Lighting: 2 Port Node PN 65162" },
  { 0x12F0, "Chauvet Professional: Epix Drive 900" },
  { 0x12F1, "Chauvet Professional: Epix Drive 642" },
  { 0x12F2, "Chauvet Professional: Net X" },
  { 0x12F3, "Chauvet Professional: Nexus 4x4" },
  { 0x12F4, "Chauvet Professional: Nexus 2x2" },
  { 0x12F5, "Chauvet Professional: Nexus 4x1" },
  { 0x12F6, "Chauvet Professional: Maverick Mk2" },
  { 0x12F7, "Chauvet Professional: Maverick Mk1 Wash" },
  { 0x12F8, "Chauvet Professional: Maverick Mkx1 Wash" },
  { 0x12F9, "Chauvet Professional: Ovation B 565FC" },
  { 0x12FA, "Chauvet Professional: Ovation B 2805FC" },
  { 0x12FB, "Chauvet Professional: VIP Drive 43s" },
  { 0x1300, "HPL Company: Delta 8 Node" },
  { 0x1310, "Steinigke Showtechnic GmbH: PSU 4A" },
  { 0x1320, "Lumenpulse Lighting Inc: Lumencove XT Ethernet Enabled" },
  { 0x1321, "Lumenpulse Lighting Inc: CBOX Ethernet" },
  { 0x1330, "deskontrol electronics: deskontroller" },
  { 0x1331, "deskontrol electronics: deskontroller pro" },
  { 0x1340, "Seiko Epson Corporation: Projector" },
  { 0x1350, "Image Engineering: Beam Composer" },
  { 0x1360, "Arnold Richter Cine Technik GmbH: ARRI" },
  { 0x1370, "NISCON Inc: RAYNOK Motion Control System" },
  { 0x1380, "Immersive Design Studios inc: Canvas" },
  { 0x1390, "ADJ Products: Flash Kling Panel" },
  { 0x13A0, "Callegenix LLC: DMX Commander" },
  { 0x13A1, "Callegenix LLC: Pixel Driver" },
  { 0x13B0, "ARC Solid State Lighting Corporation: Constant Voltage Driver" },
  { 0x13B1, "ARC Solid State Lighting Corporation: LF75 Flood Light" },
  { 0x13B2, "ARC Solid State Lighting Corporation: LF150 Flood Light" },
  { 0x13C0, "Licht Team: LT1" },
  { 0x13C1, "SGH: Martin" },
  { 0x13C2, "ADJ Products: Airstream DMX Bridge" },
  { 0x13C3, "DMG Technologies DMG Lumiere: Universal battery box" },
  { 0x13C4, "SWGroup: Easydim" },
  { 0x13C5, "GLP German Light Products GmbH: GT 1" },
  { 0x13C6, "ADL Electronics Ltd: ADL DMX NetGate" },
  { 0x13C7, "ADL Electronics Ltd: ADL DMX NetGate +" },
  { 0x13C8, "ADL Electronics Ltd: ADL DMX NetGate RDM" },
  { 0x13C9, "ADL Electronics Ltd: ADL DMX NetGate+ RDM" },
  { 0x13CA, "ADL Electronics Ltd: ADL DMX NetGate DIN" },
  { 0x13CB, "ADL Electronics Ltd: ADL DMX NetGate ALARM" },
  { 0x13CC, "ADL Electronics Ltd: ADL DC PU 24" },
  { 0x13CD, "ADL Electronics Ltd: ADL DC PU 24C" },
  { 0x13CE, "ADL Electronics Ltd: ADL DC PU 6" },
  { 0x13CF, "ADL Electronics Ltd: ADL DC WSO operator workstation" },
  { 0x13D0, "ADL Electronics Ltd: ADL DC IKB" },
  { 0x13D1, "ADL Electronics Ltd: ADL DimmerCabinet CPU" },
  { 0x13D2, "ADL Electronics Ltd: ADL Dimmer 220 12d x" },
  { 0x13D3, "ADL Electronics Ltd: ADL MediaPlayer" },
  { 0x13D4, "Opito Labs GmbH: Opito Converter Toolkit" },
  { 0x13D5, "Opito Labs GmbH: Opito Video Controller" },
  { 0x13D6, "Swisson AG: XND 4" },
  { 0x13D7, "ROF Electronics: Multi4verse" },
  { 0x13D8, "d3 Technologies Ltd: Pro Plus range" },
  { 0x13D9, "Integrated System Technologies Ltd: Sensor Hub" },
  { 0x13DA, "LKE Lasershow: H2O Motion" },
  { 0x13DB, "LKE Lasershow: eXtreme Motion Jet" },
  { 0x13DC, "LeMaitre Ltd: G300 Smart" },
  { 0x13DD, "Company NA: DigiNet Manager" },
  { 0x13DE, "TMB: ProPlex IQ Manager" },
  { 0x13DF, "Exalux: Connect One" },
  { 0x13E0, "MTH: MED LDMX512" },
  { 0x13E1, "MTH: MED LDMX512HUB" },
  { 0x13E2, "AC Lasers: SuperNova" },
  { 0x13E3, "AC Lasers: W Lux" },
  { 0x13F0, "Batmink Ltd: OEMVISAGEVISIONMAPPER" },
  { 0x13F1, "LEDTUNE COM: ABOX 01" },
  { 0x13F2, "Vertigo ApS: BlackLED" },
  { 0x13F3, "Ingham Designs LLC: Hunt Node" },
  { 0x13F4, "GuangZhou LiDang Technology Co Ltd: LD NET 1024" },
  { 0x13F5, "GuangZhou LiDang Technology Co Ltd: LD NET 2028" },
  { 0x13F6, "RGBlink: Venus X7" },
  { 0x13F7, "RGBlink: G 3 Net" },
  { 0x13F8, "Imimot Kft: Mitti" },
  { 0x13F9, "MCSWE Technologies INC: MCSWE LUNA 8" },
  { 0x13FA, "MCSWE Technologies INC: MCSWE LUNA 16" },
  { 0x13FB, "Digital Sputnik Lighting: DSL1" },
  { 0x13FC, "SRS Light Design: ANGS4" },
  { 0x13FD, "Chauvet DJ: DMX AN" },
  { 0x13FE, "Rosstech Signals: DMXBridge" },
  { 0x13FF, "LSC Lighting Systems Aust Pty Ltd: Mantra Lite" },
  { 0x1400, "DMT: Pixelstrip controller MKII" },
  { 0x1401, "Elation Lighting: TVL Panel DW" },
  { 0x1402, "RGBlink: Venus X2" },
  { 0x1403, "Elation Lighting: TVL Panel DW" },
  { 0x1404, "Elation Lighting: eNode4" },
  { 0x1405, "Elation Lighting: eNode8 Pro" },
  { 0x1406, "Exalux: Connect Plus" },
  { 0x1407, "Foshan YiFeng Electric Industrial Co ltd: CA EN28S" },
  { 0x1408, "Foshan YiFeng Electric Industrial Co ltd: CA AN28" },
  { 0x1409, "Foshan YiFeng Electric Industrial Co ltd: CA EN28" },
  { 0x140A, "Foshan YiFeng Electric Industrial Co ltd: CA AN08" },
  { 0x140B, "Foshan YiFeng Electric Industrial Co ltd: CA AN04" },
  { 0x140C, "Soundlight: Soundlight 4port node" },
  { 0x2000, "Artistic Licence Engineering Ltd: AL5001" },
  { 0x2001, "Artistic Licence Engineering Ltd: artLynx duo" },
  { 0x2002, "Artistic Licence Engineering Ltd: artLynx uno" },
  { 0x2010, "Artistic Licence Engineering Ltd: Data Lynx OP" },
  { 0x2020, "Artistic Licence Engineering Ltd: Rail Lynx OP" },
  { 0x2030, "Artistic Licence Engineering Ltd: Down Lynx G4" },
  { 0x2040, "Artistic Licence Engineering Ltd: Net Lynx OP G4" },
  { 0x2050, "Artistic Licence Engineering Ltd: AL5002" },
  { 0x2060, "Artistic Licence Engineering Ltd: Data Lynx IP" },
  { 0x2070, "Artistic Licence Engineering Ltd: Cata Lynx IP G4" },
  { 0x2075, "Artistic Licence Engineering Ltd: Cata Lynx OP G4" },
  { 0x2080, "Artistic Licence Engineering Ltd: Rail Lynx IP" },
  { 0x2090, "Artistic Licence Engineering Ltd: Up Lynx G4" },
  { 0x20A0, "Artistic Licence Engineering Ltd: Net Lynx IP G4" },
  { 0x20B0, "Artistic Licence Engineering Ltd: Art Play" },
  { 0x20D0, "Artistic Licence Engineering Ltd: Art Demux" },
  { 0x20E0, "Artistic Licence Engineering Ltd: Art Relay" },
  { 0x20F0, "Artistic Licence Engineering Ltd: Art Pipe" },
  { 0x2100, "Artistic Licence Engineering Ltd: Art Media" },
  { 0x2110, "Artistic Licence Engineering Ltd: Art Boot" },
  { 0x2120, "Artistic Licence Engineering Ltd: Art Lynx OP" },
  { 0x2130, "Artistic Licence Engineering Ltd: Art Lynx IP" },
  { 0x2140, "Artistic Licence Engineering Ltd: Ether Lynx II" },
  { 0x2150, "Artistic Licence Engineering Ltd: Multichrome E2" },
  { 0x2160, "Artistic Licence Engineering Ltd: Art Monitor Base" },
  { 0x2170, "Artistic Licence Engineering Ltd: Multichrome E1" },
  { 0x2200, "Artistic Licence Engineering Ltd: Micro Scope 5" },
  { 0x2210, "Artistic Licence Engineering Ltd: Two Play" },
  { 0x2211, "Artistic Licence Engineering Ltd: Two Play XT" },
  { 0x2212, "Artistic Licence Engineering Ltd: Multi Play" },
  { 0x2220, "Artistic Licence Engineering Ltd: Diamond" },
  { 0x2221, "Artistic Licence Engineering Ltd: Quartz" },
  { 0x2222, "Artistic Licence Engineering Ltd: Zircon" },
  { 0x2223, "Artistic Licence Engineering Ltd: Graphite" },
  { 0x2224, "Artistic Licence Engineering Ltd: Opal" },
  { 0x2225, "Artistic Licence Engineering Ltd: Mica" },
  { 0x2230, "Artistic Licence Engineering Ltd: eSense" },
  { 0x2231, "Artistic Licence Engineering Ltd: eSense XT" },
  { 0x2240, "Artistic Licence Engineering Ltd: dVnet" },
  { 0x2241, "Artistic Licence Engineering Ltd: versaSplit EthB" },
  { 0x2242, "Artistic Licence Engineering Ltd: versaSplit EthA" },
  { 0x2250, "Artistic Licence Engineering Ltd: AL5003" },
  { 0x2258, "Artistic Licence Engineering Ltd: daliGate uno" },
  { 0x2259, "Artistic Licence Engineering Ltd: daliGate duo" },
  { 0x225A, "Artistic Licence Engineering Ltd: daliGate quad" },
  { 0x2260, "Artistic Licence Engineering Ltd: lightJuice CV4" },
  { 0x2261, "Artistic Licence Engineering Ltd: lightJuice DC24" },
  { 0x2262, "Artistic Licence Engineering Ltd: lightJuice CC2" },
  { 0x2263, "Artistic Licence Engineering Ltd: lightJuice OL1" },
  { 0x2264, "Artistic Licence Engineering Ltd: lightJuice PX1" },
  { 0x2265, "Artistic Licence Engineering Ltd: lightJuice DALI" },
  { 0x2266, "Artistic Licence Engineering Ltd: lightJuice Dmx" },
  { 0x2267, "Artistic Licence Engineering Ltd: artLynx quad" },
  { 0x2268, "Artistic Licence Engineering Ltd: dataLynx II" },
  { 0x2269, "Singularity (UK) Ltd: DMX Workshop" },
  { 0x226A, "Singularity (UK) Ltd: ACT" },
  { 0x226B, "Artistic Licence Engineering Ltd: Colour Tramp Input" },
  { 0x226C, "Singularity (UK) Ltd: DmxToolBox" },
  { 0x226D, "Artistic Licence Engineering Ltd: pixiLynx 4x4" },
  { 0x226E, "Artistic Licence Engineering Ltd: artLynx rj45" },
  { 0x226F, "Artistic Licence Engineering Ltd: netLynx quad" },
  { 0x2270, "Artistic Licence Engineering Ltd: downLynx quad" },
  { 0x2271, "Artistic Licence Engineering Ltd: rackLynxOcto" },
  { 0x2272, "Artistic Licence Engineering Ltd: oemGate quad" },
  { 0x2801, "Gearbox Solutions: LC1" },
  { 0x2802, "Licht en Geluid Team: DMXDisplay" },
  { 0x2803, "Lycht: Lycht Hub" },
  { 0x2804, "Elation Lighting: TVL Softlight DW" },
  { 0x2805, "ELETTROLAB Srl: Avvio Mini WiFi" },
  { 0x2806, "CLAYPAKY: SUPERSHARPY²" },
  { 0x2807, "JMS Pro Light: AIR2DMX" },
  { 0x2808, "Steinigke Showtechnic GmbH: Node 8 MK2" },
  { 0x2809, "W A Benjamin Electric Co: Integrity RDM Conformance Test" },
  { 0x280A, "DMX4ALL GmbH: Wireless DMX4ALL Device" },
  { 0x280B, "DMX4ALL GmbH: DMX4ALL PixxDevice" },
  { 0x280C, "DMX4ALL GmbH: DMX4ALL PlayerDevice" },
  { 0x280D, "DMX4ALL GmbH: DMX4ALL MuxDevice" },
  { 0x280E, "DMX4ALL GmbH: DMX4ALL WirelessDevice" },
  { 0x280F, "DMX4ALL GmbH: DMX4ALL WirelessPixxDevice" },
  { 0x2810, "Steinigke Showtechnic GmbH: LED TMH X25 XL" },
  { 0x2811, "Elation Lighting: eNode 2POE" },
  { 0x2812, "Elation Lighting: TVL Panel DW" },
  { 0x2813, "BLS: c21550820" },
  { 0x2814, "Elation Lighting: TVL Softlight DW" },
  { 0x2815, "ImageCue LLC: ImageCue NEV" },
  { 0x2816, "NightStarry Electronics Co LTD: Net Dmx" },
  { 0x2817, "NightStarry Electronics Co LTD: Net Node:32" },
  { 0x2818, "NightStarry Electronics Co LTD: Net Node:16" },
  { 0x2819, "NightStarry Electronics Co LTD: Net Node:8" },
  { 0x281A, "NightStarry Electronics Co LTD: Net Node:4" },
  { 0x281B, "Showtec: Pixel Bubble 80 MKII" },
  { 0x281C, "Colordreamer Technology Co Limited: Titan A16" },
  { 0x281D, "Showtec: White PIX" },
  { 0x281E, "Showtec: Node 1" },
  { 0x281F, "DMT: Pixel Tile P25 MKII" },
  { 0x2820, "DMT: PixelBatten P25 MKII" },
  { 0x2821, "Showtec: Phantom 300 LED Matrix" },
  { 0x2822, "Infinity: iW 1915 Pixel" },
  { 0x2823, "Infinity: iS 400" },
  { 0x2824, "Infinity: iPW 150 LED Sunpanel" },
  { 0x2825, "Infinity: Chimp 300" },
  { 0x2826, "Infinity: Chimp 100" },
  { 0x2827, "Infinity: iM 2515" },
  { 0x2828, "Resolume: Arena" },
  { 0x2829, "LED concept: LED Pixel Director 4" },
  { 0x282A, "LED concept: LED Pixel Director 8" },
  { 0x282B, "DMX4ALL GmbH: DMX4ALL DMXDevice" },
  { 0x282C, "kuwatec Inc: Ex8" },
  { 0x282D, "DMX4ALL GmbH: DMX4ALL SoftwareDevice" },
  { 0x282E, "XING YE DIAN ZI: NS NET ONE" },
  { 0x282F, "XING YE DIAN ZI: NS NET03" },
  { 0x2830, "XING YE DIAN ZI: NS NET02" },
  { 0x2831, "XING YE DIAN ZI: NS NET01" },
  { 0x2832, "ExMachina: Winch Dynamic" },
  { 0x2833, "Schnick Schnack Systems GmbH: DMX Pixel Router" },
  { 0x2834, "Schnick Schnack Systems GmbH: DPB Pixel Router" },
  { 0x2835, "Stage Eyes: Tri Engine" },
  { 0x2836, "Colordreamer Technology Co Limited: Titan AS4" },
  { 0x2837, "Colordreamer Technology Co Limited: Titan A2" },
  { 0x2838, "Colordreamer Technology Co Limited: Titan A4" },
  { 0x2839, "Colordreamer Technology Co Limited: Titan A8" },
  { 0x283A, "eIdea Creative Technology: AuNode" },
  { 0x283B, "LIGHTSKY: IP3000" },
  { 0x283C, "colordreamer: Colordreamer Update Boot" },
  { 0x283D, "Digital Sputnik Lighting Oü: DS Control DMX" },
  { 0x283E, "Colordreamer Technology Co Limited: Titan A8 Pro" },
  { 0x283F, "LED concept: LED PIXEL DIRECTOR 24" },
  { 0x2840, "LED concept: LED PIXEL DIRECTOR 16" },
  { 0x2841, "LED concept: LED PIXEL DIRECTOR 12" },
  { 0x2842, "HMB TEC GmbH: CC512 Pix" },
  { 0x2843, "ROF Electronics: Big Foot IV" },
  { 0x2844, "ROF Electronics: Big Foot II" },
  { 0x2845, "ROF Electronics: TNT" },
  { 0x2846, "ROF Electronics: Multi8verse" },
  { 0x2847, "ROF Electronics: Multi6verse" },
  { 0x2848, "ROF Electronics: Multi2verse" },
  { 0x2849, "AC3 Studio: Kinetic Stepper Interface" },
  { 0x284A, "AYRTON: AyrtonFixtureNode" },
  { 0x284B, "DMLITE: SOLEIL" },
  { 0x284C, "M Light: Mini Display 16" },
  { 0x284D, "LEDsistem Technology LTD: Cloud Drive" },
  { 0x284E, "ROBERT JULIAT: SpotME" },
  { 0x284F, "ROBERT JULIAT: ALICE 1469" },
  { 0x2850, "ROBERT JULIAT: OZ 1169" },
  { 0x2851, "ROBERT JULIAT: DALIS 862" },
  { 0x2852, "ROBERT JULIAT: DALIS 861" },
  { 0x2853, "Chauvet Professional: Epix Drive 2000 IP" },
  { 0x2854, "LIGHTSKY: IP2000" },
  { 0x2855, "SmoothLUX B V: SmoothDMX 128" },
  { 0x2856, "SmoothLUX B V: SmoothDMX 512" },
  { 0x2857, "Big Dipper Laser Science and Technology Co Ltd: BP 440BSW" },
  { 0x2858, "Eurolumen shanghai Lighting Co LTD: s100" },
  { 0x2859, "Total Light: Etherstrip 8" },
  { 0x285A, "Total Light: Ether Dual A" },
  { 0x285B, "Total Light: Ether Dual B" },
  { 0x285C, "Infinity: iW 1240" },
  { 0x285D, "Infinity: iW 740" },
  { 0x285E, "Infinity: iW 340" },
  { 0x285F, "Digital Sputnik Lighting Oü: DSL3" },
  { 0x2860, "Digital Sputnik Lighting Oü: DSL2" },
  { 0x2861, "Visual Productions: IoCore2" },
  { 0x2862, "Visual Productions: TimeCore" },
  { 0x2863, "Bright Sound: Bright Mapper" },
  { 0x2864, "atit no: NorseDMX Wi Fi Node II" },
  { 0x2865, "Tian Hai BeiFang: AMX" },
  { 0x2866, "Starlight: XNET 8" },
  { 0x2867, "Starlight: XNET 4" },
  { 0x2868, "Starlight: XNET 2" },
  { 0x2869, "Xian NovaStar Tech Co Ltd: NOVA DMX11" },
  { 0x286A, "LED concept: SWITCHMAN 2 1" },
  { 0x286B, "LED concept: SWITCHMAN 4 1" },
  { 0x286C, "LED concept: SWITCHMAN 0 4" },
  { 0x286D, "LED concept: SWITCHMAN 3 1" },
  { 0x286E, "LED concept: SWITCHMAN 1 1" },
  { 0x286F, "LED concept: SWITCHMAN 8" },
  { 0x2870, "LED concept: SWITCHMAN 2" },
  { 0x2871, "LED concept: SWITCHMAN 2a" },
  { 0x2872, "LED concept: SWITCHMAN 1" },
  { 0x2873, "LED concept: SWITCHMAN 4" },
  { 0x2874, "PXM: Px724" },
  { 0x2875, "Showtec: Pixel Tube Set 96" },
  { 0x2876, "Showtec: NET 8 3" },
  { 0x2877, "Showtec: NET 8 5" },
  { 0x2878, "Showtec: NET 8 3a" },
  { 0x2879, "Showtec: RT 200" },
  { 0x287A, "OpenLX SP Ltd: EasyDMX" },
  { 0x287B, "Signblazer Ltd: SopraText" },
  { 0x287C, "Sam light: Forte 150" },
  { 0x287D, "Yarilo Pro: LANdmx4" },
  { 0x287E, "Key Delfin: WI Net 1" },
  { 0x287F, "Key Delfin: RJ Net 1" },
  { 0x2880, "Illum Technology LLC: Xstream" },
  { 0x2881, "Jjj: Bou" },
  { 0x2882, "GIP Innovation Tools: LIGEO Gateway" },
  { 0x2883, "EastSun Technology CO Ltd: NET4D01" },
  { 0x2884, "EastSun Technology CO Ltd: NET1D01" },
  { 0x2885, "Amptown System Company: ControLite VIGOR DINRail Switch" },
  { 0x2886, "Elation Professional: 4 Cast DMX Bridge" },
  { 0x2887, "WLPS: Remote FollowSpot" },
  { 0x2888, "ADDiCTiON bOx: FrEEdOsE WLaN" },
  { 0x2889, "ADDiCTiON bOx: FuLLdOsE 8 Port" },
  { 0x288A, "ADDiCTiON bOx: TrUssdOsE 4 Port" },
  { 0x288B, "ADDiCTiON bOx: HaLFdOsE 4 Port" },
  { 0x288C, "ADDiCTiON bOx: HaLFdOsE 8 Port" },
  { 0x288D, "Kontrolcla Show Control S L: Rdm assistant" },
  { 0x288E, "Integrated System Technologies Limited: Thor 8" },
  { 0x288F, "Integrated System Technologies Limited: Thor8" },
  { 0x2890, "Yarilo Pro: LANdmx2" },
  { 0x2891, "HMB TEC GmbH: RR512" },
  { 0x2892, "HMB TEC GmbH: CC512" },
  { 0x2893, "ElectroTAS: TH 8U" },
  { 0x2894, "ElectroTAS: TH 6U" },
  { 0x2895, "electroTAS: TH 4U" },
  { 0x2896, "ElectroTAS: TH 2U" },
  { 0x2897, "ElectroTAS: TH 1U" },
  { 0x2898, "showjockey: SJ DMX E16" },
  { 0x2899, "Qdot Lighting Limited: QNET 16W" },
  { 0x289A, "Qdot Lighting Limited: QNET 8W" },
  { 0x289B, "Qdot Lighting Limited: QNET 2048" },
  { 0x289C, "Qdot Lighting Limited: QNET 1024" },
  { 0x289D, "Chauvet Professional: NET X 2 0" },
  { 0x289E, "Elation Lighting: eNode 2 POE" },
  { 0x289F, "LEON: LEONGRECO" },
  { 0x28A0, "ElectroTAS: TH AIO" },
  { 0x28A1, "AK LIGHT: DMX 4" },
  { 0x28A2, "LIGHTSKY: DMX BOX" },
  { 0x28A3, "CLAYPAKY: SCENIUS UNICO" },
  { 0x28A4, "AB DMX: A512 node" },
  { 0x28A5, "NuDelta Digital: LogiCue" },
  { 0x28A6, "iColor Led Shenzhen Co Ltd: SC1712" },
  { 0x28A7, "iColor Led Shenzhen Co Ltd: SC1711" },
  { 0x28A8, "Elation Professional: Show Designer" },
  { 0x28A9, "UNT: SLNS" },
  { 0x28AA, "X Laser: Mercury" },
  { 0x28AB, "LuxCena Iumina: LuxCena WiFi DMX" },
  { 0x28AC, "BRITEQ: BT NODE24" },
  { 0x28AD, "TLS INTERNATIONAL: TLS DIGITAL PIXEL CONTROLLER" },
  { 0x28AE, "Apollo Security: ENI 110" },
  { 0x28AF, "Showtacle Ltd: SPI Matrix" },
  { 0x28B0, "Showtacle Ltd: LEC3" },
  { 0x28B1, "Argent Data Systems Inc: Hyperion Hoop" },
  { 0x28B2, "EQUIPSON S A: LS Core" },
  { 0x28B3, "CLAYPAKY: AXCOR SPOT HPE 300" },
  { 0x28B4, "EQUIPSON S A: WORK LS 1" },
  { 0x28B5, "CLAYPAKY: AXCOR WASH 300" },
  { 0x28B6, "CLAYPAKY: AXCOR BEAM 300" },
  { 0x28B7, "CLAYPAKY: ALEDA K EYE K20 HCR" },
  { 0x28B8, "CLAYPAKY: ALEDA K EYE K10 HCR" },
  { 0x28B9, "CLAYPAKY: AXCOR PROFILE 900 3K" },
  { 0x28BA, "CLAYPAKY: AXCOR PROFILE 900 6K" },
  { 0x28BB, "CLAYPAKY: AXCOR PROFILE 900 8K" },
  { 0x28BC, "LIGHTSKY: LED0760" },
  { 0x28BD, "LIGHTSKY: LED0960" },
  { 0x28BE, "Elation Lighting: Pixel Driver 4000" },
  { 0x28BF, "Voidcorp: VirtualPanel" },
  { 0x28C0, "AUTOLUX Handels und ProduktionsgmbH: ALX MEDIAWALL" },
  { 0x28C1, "Swisson AG: XND 8" },
  { 0x28C2, "LumenRadio: ARRI Skylink Base Station" },
  { 0x28C3, "Cameo: EVOS W7" },
  { 0x28C4, "Cameo: EVOS S3" },
  { 0x28C5, "Infinity: TF 300 Fresnel" },
  { 0x28C6, "Infinity: TS 200C7 Profile" },
  { 0x28C7, "Infinity: TS 300 Profile" },
  { 0x28C8, "Infinity: TS 150 Profile" },
  { 0x28C9, "Illum Technology LLC: XStream" },
  { 0x28CA, "Biamino and Figli S p A: BIALEDA01" },
  { 0x28CB, "Shenzhen Yuming Vision Technology Co Ltd: YM RX803" },
  { 0x28CC, "ADJ Products: Par Z100 5K" },
  { 0x28CD, "ADJ Products: Par Z100 3K" },
  { 0x28CE, "ADJ Products: VIZI CMY 300" },
  { 0x28CF, "Stage Team: MagicNode" },
  { 0x28D0, "GLP German Light Products GmbH: Impression S350" },
  { 0x28D1, "CLAYPAKY: K EYE S10 HCR" },
  { 0x28D2, "CLAYPAKY: K EYE S20 HCR" },
  { 0x28D3, "Steinigke Showtechnic GmbH: Sunbar 10" },
  { 0x28D4, "ERAL s r l: Paseo Pixel Box Controller" },
  { 0x28D5, "Savant Systems LLC: SmartDMX" },
  { 0x28D6, "BOOQlight BV: WiFi DMX RDM Module" },
  { 0x28D7, "Dynamic Projection Institute Herstellungs und Vertriebs GmbH: JCD" },
  { 0x28D8, "Conceptinectics Technologies and Consultancy Limited: CTC NEXT" },
  { 0x28D9, "Conceptinetics Technologies and Consultancy Limited: CTC MUFIC" },
  { 0x28DA, "Elation Lighting: Eclipse" },
  { 0x28DB, "Jumptronic GmbH: ProtocolController" },
  { 0x28DC, "Acme: Acme LED" },
  { 0x28DD, "Acme: Acme LS" },
  { 0x28DE, "Acme: Acme MP" },
  { 0x28DF, "Acme: Acme CM" },
  { 0x28E0, "Acme: Acme TS" },
  { 0x28E1, "Acme: Acme XA" },
  { 0x28E2, "Acme: Acme XP" },
  { 0x28E3, "Acme: CM S6" },
  { 0x28E4, "Acme: XP 1000FS" },
  { 0x28E5, "Acme: XP 1000SZF" },
  { 0x28E6, "Acme: XP 5000NF" },
  { 0x28E7, "Acme: XP 5000WZ" },
  { 0x28E8, "Acme: TS 150M WW CW" },
  { 0x28E9, "Acme: TS 150 WW CW" },
  { 0x28EA, "Acme: TS 300 WW CW" },
  { 0x28EB, "Acme: TS 300 WW C" },
  { 0x28EC, "Acme: TS 300M WW CW" },
  { 0x28ED, "Acme: LED MTX36 HEX" },
  { 0x28EE, "Acme: LED MTX36" },
  { 0x28EF, "Acme: LP F2000" },
  { 0x28F0, "Acme: LP F1000" },
  { 0x28F1, "Acme: XP 1000WZ" },
  { 0x28F2, "Music Lights S R L: DIAMOND37" },
  { 0x28F3, "Music Lights S R L: STARK1000" },
  { 0x28F4, "Steinigke Showtechnic GmbH: EYE 37" },
  { 0x28F5, "Acme: TB 1230QW" },
  { 0x28F6, "ABLELITE INTERNATIONAL: EVA3715Z" },
  { 0x28F7, "ADJ PRODUCTS: VIZI WASH PRO" },
  { 0x28F8, "Vsevolod Kozlov: Show Box" },
  { 0x28F9, "Tom Bland: Q SYS Plugin" },
  { 0x28FA, "Kinescope: Bridge" },
  { 0x28FB, "SLS: atmani" },
  { 0x28FC, "Daniel Large: STATIS" },
  { 0x28FD, "Douglas Heriot: DMX Assistant" },
  { 0x28FE, "Douglas Heriot: Diode Control" },
  { 0x28FF, "ADJ PRODUCTS: ENCORE BURST 200b" },
  { 0x2900, "Integrated System Technologies Ltd: Quattro CVL" },
  { 0x2901, "Integrated System Technologies Ltd: iDrive Thor 4" },
  { 0x2902, "Jata Tech Ltd: FX Engine" },
  { 0x2903, "Integrated System Technologies Ltd: iDrive White knight 24" },
  { 0x2904, "Integrated System Technologies Ltd: iDrive White knight 48" },
  { 0x2905, "X Laser: Skywriter HPX M 20" },
  { 0x2906, "X Laser: Skywriter HPX M 10" },
  { 0x2907, "X Laser: Skywriter HPX M 5" },
  { 0x2908, "margau: dmxnet" },
  { 0x2909, "feno GmbH: fe stile 1312 LED Matrix" },
  { 0x290A, "Steinigke Showtechnic GmbH: Stage Pixel Bar 10 WW" },
  { 0x290B, "ADJ Products: Encore Burst 200" },
  { 0x290C, "Key Lab: BlackTrax Extender" },
  { 0x290D, "DJSI SCHINSTAD: Northern Star Polaris v1 5" },
  { 0x290E, "ADB STAGELIGHT: LEXPERT FRESNEL M WW" },
  { 0x290F, "ADB STAGELIGHT: LEXPERT FRESNEL M CW" },
  { 0x2910, "ADB STAGELIGHT: LEXPERT PROFILE L WW" },
  { 0x2911, "ADB STAGELIGHT: LEXPERT PROFILE L CW" },
  { 0x2912, "ADB STAGELIGHT: LEXPERT PROFILE L" },
  { 0x2913, "ChengDuChenyuDianZiKeji: DMX2048CH PRO1" },
  { 0x2914, "ChengDuChenyuDianZiKeji: DMX2048CH PRO2" },
  { 0x2915, "MLBA Team: Stagehand Live" },
  { 0x2916, "Acme: XA 1000F" },
  { 0x2917, "xuri: xur" },
  { 0x2918, "Infinity: FURION S601 PROFILE" },
  { 0x2919, "Infinity: FURION S401 SPOT" },
  { 0x291A, "Infinity: FURION S201 SPOT" },
  { 0x291B, "Steinigke Showtechnic GmbH: DMX AIO" },
  { 0x291C, "HYCL: DMX_SYNC" },
  { 0x291D, "HYCL: DMX_Player_32" },
  { 0x291E, "HYCL: DMX_Player_16" },
  { 0x291F, "HYCL: DMX_Player_8" },
  { 0x2920, "HYCL: DMX_Player_1" },
  { 0x2921, "HYCL: DMX_Player_4" },
  { 0x2922, "ainetauto: LJ" },
  { 0x2923, "ADJ Products: Par Z100 RGBW" },
  { 0x2924, "LEDBLADE: Creon HD" },
  { 0x2925, "Guangzhou Chaoran Computer Co Ltd: EtherNode8" },
  { 0x2926, "German Light Products GmbH: impression E350" },
  { 0x2927, "Arrigo Lighting: AL A4RGB" },
  { 0x2928, "Rosstech Signals: Smart16" },
  { 0x2929, "Arrigo Lighting: Arrigo Lighting Liberty 22" },
  { 0x292A, "Matthias Bauch Software: LiveLight" },
  { 0x292B, "JB Lighting Lichtanlagentechnik GmbH: JB LightingFixtureNode" },
  { 0x292C, "Bandhaus Straubing eV: Wireless2DMX Bridge" },
  { 0x292D, "ETC Audiovisuel: OnlyView" },
  { 0x292E, "RGBlink: TTWO" },
  { 0x292F, "RGBlink: TONE" },
  { 0x2930, "RGBlink: FLEX 256" },
  { 0x2931, "RGBlink: FLEX 128" },
  { 0x2932, "RGBlink: FLEX 64" },
  { 0x2933, "RGBlink: FLEX 32" },
  { 0x2934, "RGBlink: FLEX 16" },
  { 0x2935, "RGBlink: FLEX 8" },
  { 0x2936, "RGBlink: FLEX RS1" },
  { 0x2937, "RGBlink: FLEX 4" },
  { 0x2938, "ADJ Products: Flash Kling Strip" },
  { 0x2939, "ADJ Products: Flash Kling Batten" },
  { 0x293A, "Elation Lighting: EZ Kling" },
  { 0x293B, "Qdot Lighting Limited: QNET APP" },
  { 0x293C, "X Laser: Mobile Beat Mercury" },
  { 0x293D, "X Laser: Skywriter HPX M_2" },
  { 0x293E, "dbnetsoft: VirtualDmxLib" },
  { 0x293F, "JCSKJ: JC_Controller_X" },
  { 0x2940, "ADB STAGELIGHT: KLEMANTIS AS500" },
  { 0x2941, "ADB STAGELIGHT: KLEMANTIS AS1000" },
  { 0x2942, "CLAYPAKY: AXCOR SPOT 400 HC" },
  { 0x2943, "CLAYPAKY: AXCOR SPOT 400" },
  { 0x2944, "CLAYPAKY: AXCOR PROFILE 400 HC" },
  { 0x2945, "CLAYPAKY: AXCOR PROFILE 400" },
  { 0x2946, "CLAYPAKY: AXCOR PROFILE 600 HC" },
  { 0x2947, "CLAYPAKY: AXCOR PROFILE 600" },
  { 0x2948, "Luminxa: Luminxa1" },
  { 0x2949, "Luminxa: Luminxa2" },
  { 0x294A, "audioligh: HD217 1" },
  { 0x294B, "audioligh: HD217 2" },
  { 0x294C, "KWMATIK: PROMYK v1 0" },
  { 0x294D, "Rnet Lighting technology limited: R NET DMX Rack" },
  { 0x294E, "Astera LED Technology GmbH: 10way Titan Powersupply" },
  { 0x294F, "Buehler electronic GmbH LSdigital: DMX Light Interface" },
  { 0x2950, "atomica peru: arri skypanel" },
  { 0x2951, "GIP Innovation Tools GmbH: LIGEO SL WiFi" },
  { 0x2952, "Rethink DMX: node1" },
  { 0x2953, "Elation Lighting: CUEPIX PANEL" },
  { 0x2954, "Elation Lighting: SIXBAR 1000" },
  { 0x2955, "Elation Lighting: SEVEN BATTEN 72" },
  { 0x2956, "Hera Led: Hera Ether Node4" },
  { 0x2957, "Chauvet Professional: Rogue R1 FXB" },
  { 0x2958, "Chauvet Professional: Maverick MK 1 Hybrid" },
  { 0x2959, "Chauvet Professional: Maverick MK Pyxis" },
  { 0x295A, "Chauvet Professional: Maverick MK2 Profile" },
  { 0x295B, "Chauvet Professional: Maverick MK3 Wash" },
  { 0x295C, "Chauvet Professional: Maverick MK2 Wash" },
  { 0x295D, "Chauvet Professional: Maverick MK1 Spot" },
  { 0x295E, "SSG Technology Ltd: SD980 AN" },
  { 0x295F, "LKE Lasershow: Frequency Unit" },
  { 0x2960, "JUAN FRANCISCO CAMPOS SAA: BM LIGHTS 1 UNIVERSE" },
  { 0x2961, "Zboxes Intelligent Technology Shanghai Co Ltd: Zboxes 8" },
  { 0x2962, "Guangzhou Ming Jing Stage Light: King Kong Controller" },
  { 0x2963, "Fiberli: Node8X" },
  { 0x2964, "GLP German Light Products GmbH: KNV Arc" },
  { 0x2965, "GLP German Light Products GmbH: KNV Cube" },
  { 0x2966, "SmartShow UK: NetTWIN" },
  { 0x2967, "SmartShow UK: AirDMXout" },
  { 0x2968, "SmartShow UK: AirPixel Quad" },
  { 0x2969, "SmartShow UK: AirPixel Mini" },
  { 0x296A, "SmartShow UK: AirPixel Micro" },
  { 0x296B, "SmartShow UK: NetPixel Quad" },
  { 0x296C, "SmartShow UK: NetWS 2040" },
  { 0x296D, "SmartShow UK: NetWS 340" },
  { 0x296E, "SmartShow UK: NetBuddy" },
  { 0x296F, "SmartShow UK: NetDMX" },
  { 0x2970, "Pulsar: Node1" },
  { 0x2971, "PXM: Px760" },
  { 0x2972, "PXM: Px314" },
  { 0x2973, "Ambion Gmbh Ambrain: Flex Led Gate" },
  { 0x2974, "Guangzhou ChaiYi Light CO Ltd: DMXGate" },
  { 0x2975, "Digital Projection: Titan Laser Projector" },
  { 0x2976, "CLAYPAKY: ALEDA BEAM 200" },
  { 0x2977, "CLAYPAKY: SHARPY PLUS" },
  { 0x2978, "Chauvet Professional: Epix Flex Drive" },
  { 0x2979, "Arrigo Lighting: AL WS2812B" },
  { 0x297A, "Roleds: RTG180" },
  { 0x297B, "Audiowerk: LC1" },
  { 0x297C, "NOVA: LED" },
  { 0x297D, "Martin: MAC Allure Profile" },
  { 0x297E, "Lifetime Music Academy: Light SPECTRUM" },
  { 0x297F, "City Theatrical: Multiverse Gateway" },
  { 0x2980, "City Theatrical: Multiverse Transmitter" },
  { 0x2981, "Rosstech Signals: MatrixView" },
  { 0x2982, "CLAYPAKY: AXCOR PROFILE 900 6K LN" },
  { 0x2983, "CLAYPAKY: AXCOR PROFILE 900 8K LN" },
  { 0x2984, "CLAYPAKY: HY_B EYE K25" },
  { 0x2985, "CLAYPAKY: HY_B EYE K15" },
  { 0x2986, "D5 systems: Lighting Network Toolset" },
  { 0x2987, "ADB STAGELIGHT: OKSALIS FL20" },
  { 0x2988, "ADB STAGELIGHT: OKSALIS FL10" },
  { 0x2989, "CLAYPAKY: AXCOR WASH 600 HC" },
  { 0x298A, "CLAYPAKY: AXCOR WASH 600" },
  { 0x298B, "CLAYPAKY: AXCOR PROFILE 600 HC ST" },
  { 0x298C, "CLAYPAKY: AXCOR PROFILE 600 ST" },
  { 0x298D, "atmosphere media gmbH: atmosphere media player" },
  { 0x298E, "DTS Illuminazione srl: DRIVENET 1664" },
  { 0x298F, "DTS Illuminazione srl: DRIVENET 416 POWER" },
  { 0x2990, "DTS Illuminazione srl: DRIVENET 416" },
  { 0x2991, "DTS Illuminazione srl: DRIVENET 832 POWER" },
  { 0x2992, "DTS Illuminazione srl: DRIVENET 832" },
  { 0x2993, "DTS Illuminazione srl: SYNERGY 5 SPOT" },
  { 0x2994, "DTS Illuminazione srl: SYNERGY 5 PROFILE" },
  { 0x2995, "Guangzhou JinZhiHui Electronic Technology Co: TOP 1440 LED RGB STROBE" },
  { 0x2996, "Creative Lighting: eDIDIO 8 pole" },
  { 0x2997, "Creative Lighting: eDIDIO 4 pole" },
  { 0x2998, "ADB STAGELIGHT: ORKIS FOCUS SPOT" },
  { 0x2999, "Waves System: Event Video Player" },
  { 0x299A, "SQD lighting Co Limited: LED lighting fixtures series" },
  { 0x299B, "BSL BV: Epikon" },
  { 0x299C, "Shenzhen Lei Fei Lighting Technology Co Ltd: LiteMeta Controller 2" },
  { 0x299D, "Shenzhen Lei Fei Lighting Technology Co Ltd: LiteMeta Controller 16" },
  { 0x299E, "Shenzhen Lei Fei Lighting Technology Co Ltd: LiteMeta Controller 8" },
  { 0x299F, "Pulsar: Luxinode" },
  { 0x29A0, "Integrated System Technology Ltd: White Knight 24 Emergency" },
  { 0x29A1, "Integrated System Technology Ltd: White Knight 36_1600" },
  { 0x29A2, "EMP Designs Ltd: EMP1" },
  { 0x29A3, "MCINTIRE ENTERPRISES INC: 24 CH Dimmer" },
  { 0x29A4, "AMOLVIN: DMX NODE" },
  { 0x29A5, "Guangzhou HuaYong Intelligent Technology Co Ltd: HuaYong Controller" },
  { 0x29A6, "Philips Controller 32: Signify China Investment Co Ltd" },
  { 0x29A7, "Signify Investment Co Ltd: Philips Controller 24" },
  { 0x29A8, "Signify Investment Co Ltd: Philips Controller 16" },
  { 0x29A9, "Signify Investment Co Ltd: Philips Controller 8" },
  { 0x29AA, "Signify Investment Co Ltd: Philips Controller 2" },
  { 0x29AB, "ER Productions: ER Display V1" },
  { 0x29AC, "Shenzhen Leifei Lighting Technology Co Ltd: LiteMeta Controller 32" },
  { 0x29AD, "Impolux GmbH: ULTIM8 ST16 O" },
  { 0x29AE, "Martin Professional: MAC Allure Wash PC" },
  { 0x29AF, "Shenzhen Leifei Lighting Technology Co Ltd: LiteMeta Controller 24" },
  { 0x29B0, "Guangzhou ChaiYi Light CO Ltd: TEKMAND Node" },
  { 0x29B1, "Alex Sagias: PixLed" },
  { 0x29B2, "GLP German Light Products GmbH: Highlander" },
  { 0x29B3, "Edelmann Electronics: Enigma2Kxx" },
  { 0x29B4, "PR LIGHTING LTD: PR Lighting 1" },
  { 0x29B5, "Wiktor Kaluzny: DMX BOX" },
  { 0x29B6, "GLP German Light Products GmbH: Impression W350" },
  { 0x29B7, "nox multimedia GmbH: NAN 8" },
  { 0x29B8, "ON LX Limited: Ctrl" },
  { 0x29B9, "HYCL: DMX Player Super 4" },
  { 0x29BA, "HYCL: DMX Player Super 8" },
  { 0x29BB, "HYCL: DMX Player Super 16" },
  { 0x29BC, "Guangzhou ChaiYi Light CO Ltd: TEKMAND Node 4P OD" },
  { 0x29BD, "Guangzhou ChaiYi Light CO Ltd: TEKMAND Node 8P" },
  { 0x29BE, "Guangzhou ChaiYi Light CO Ltd: TEKMAND Node 4P" },
  { 0x29BF, "HYCL: dmx player 512" },
  { 0x29C0, "HYCL: dmx player 256" },
  { 0x29C1, "HYCL: dmx player 64" },
  { 0x29C2, "HYCL: dmx player 2" },
  { 0x29C3, "PR LIGHTING LTD: PR Lighting 2" },
  { 0x29C4, "Spacelights: spacenet1i" },
  { 0x29C5, "Spacelights: spacenet2o" },
  { 0x29C6, "Event Imagineering Group: ShowKontrol" },
  { 0x29C7, "Brink Ventures LLC: Blackout Lighting Console" },
  { 0x29C8, "Integrated System Technology Ltd: White Knight 48 DC" },
  { 0x29C9, "Integrated System Technology Ltd: White Knight 24 DC" },
  { 0x29CA, "Integrated System Technology Ltd: Thor16 Silent 500W" },
  { 0x29CB, "Integrated System Technology Ltd: White Knight 24 Silent 500W" },
  { 0x29CC, "THELIGHT Luminary for Cine and TV SL: EVO 2x2 STUDIO" },
  { 0x29CD, "THELIGHT Luminary for Cine and TV SL: EVO 2x2 WEATHERPROOF" },
  { 0x29CE, "THELIGHT Luminary for Cine and TV SL: EVO 2 STUDIO" },
  { 0x29CF, "THELIGHT Luminary for Cine and TV SL: EVO 2 WEATHERPROOF" },
  { 0x29D0, "THELIGHT Luminary for Cine and TV SL: EVO 1 STUDIO" },
  { 0x29D1, "THELIGHT Luminary for Cine and TV SL: EVO 1 WEATHERPROOF" },
  { 0x29D2, "Exacta: CCL PC" },
  { 0x29D3, "Light Converse Ltd: LIGHTCONVERSE TOOLS" },
  { 0x29D4, "Lumos Design: Lumos Node 4" },
  { 0x29D5, "CLAYPAKY: XTYLOS" },
  { 0x29D6, "SZe Schneider Zirr engineering GmbH: CF Player A FullHD2 0" },
  { 0x29D7, "VL software: Arthur Maxi" },
  { 0x29D8, "eX Systems: RGB Floodlight" },
  { 0x29D9, "DCLX Ltd: Pixel Sabre" },
  { 0x29DA, "HDL: DMXNode8" },
  { 0x29DB, "Luminex Lighting Control Equipment: LumiNode 12" },
  { 0x29DC, "Luminex Lighting Control Equipment: LumiNode 4" },
  { 0x29DD, "Luminex Lighting Control Equipment: LumiNode 2" },
  { 0x29DE, "Luminex lighting Control Equipment: LumiNode 1" },
  { 0x29DF, "MaNiMa Technologies BV: MaNiMa LED interface" },
  { 0x29E0, "xinqidian: ganelight" },
  { 0x29E1, "LIGHTLINE Lasertechnik GmbH: Laserlink" },
  { 0x29E2, "HYCL: BootLoader" },
  { 0x29E3, "Disguise: Disguise Production Toolkit" },
  { 0x29E4, "Equivalent: LSEthernetToDMX" },
  { 0x29E5, "Equivalent: EtherConDMX8" },
  { 0x29E6, "Equivalent: LSDW_2435E" },
  { 0x29E7, "Equivalent: LSDR 123E" },
  { 0x29E8, "Equivalent: LSDR 65E" },
  { 0x29E9, "Chauvet Lighting: Ovation B 1965FC" },
  { 0x29EA, "Chauvet Lighting: Ovation B 1965FC" },
  { 0x29EB, "WangMing: WangMing" },
  { 0x29EC, "ADJ PRODUCTS: ALLEGRO Z6" },
  { 0x29ED, "EQUIPSON S A: LSNODE4" },
  { 0x29EE, "EQUIPSON S A: LSNODE2" },
  { 0x29EF, "EQUIPSON S A: LSNODE1" },
  { 0x29F0, "Chauvet Professional: Maverick MK3 Profile CX" },
  { 0x29F1, "Chauvet Professional: Maverick MK3 Spot" },
  { 0x29F2, "Chauvet Professional: Maverick MK3 Profile" },
  { 0x29F3, "Chauvet Professional: Colorado Solo Batten 4" },
  { 0x29F4, "Chauvet Professional: Colorado Solo Batten" },
  { 0x29F5, "Light Converse Ltd: LIGTHCONVERSE TOOLS" },
  { 0x29F6, "DP Lumi: DP Lumi Pro" },
  { 0x29F7, "Martin Professional: VDO Atomic Dot WRM" },
  { 0x29F8, "Martin Professional: VDO Atomic Dot CLD" },
  { 0x29F9, "GLP German Light Products GmbH: KNV PSU" },
  { 0x29FA, "GLP German Light Products GmbH: Impression FR10 Bar" },
  { 0x29FB, "Guangzhou ChaiYi Light CO Ltd: Replay Server" },
  { 0x29FC, "DTS Illuminazione srl: Alchemy5" },
  { 0x29FD, "Vibesta BV: RTX1" },
  { 0x29FE, "Echoic Tech LLC: Mach1 LED Controller" },
  { 0x29FF, "GuangZhou Ming jing stage lighting equipment co LTD: KingKongBaton" },
  { 0x2A00, "Blue Ridge Concepts Inc: EladniDesktop" },
  { 0x2A01, "DTS Illuminazione srl: Alchemy3" },
  { 0x2A02, "Crew Light: VController" },
  { 0x2A03, "KappaStyle Productions: KappaNode2" },
  { 0x2A04, "Blinkinlabs: SuperSweet" },
  { 0x2A05, "Coretronic Corporation: Projector" },
  { 0x2A06, "Guangzhou ChaiYi Light CO Ltd: General Purpose Device" },
  { 0x2A07, "Sharp NEC Display Solutions LTD: Projector" },
  { 0x2A08, "Sharp NEC Display Solutions LTD: Flat Panel Display" },
  { 0x2A09, "WA Benjamin: PMP Power Metering Panel" },
  { 0x2A0A, "HYCL: IOT Update" },
  { 0x2A0B, "HYCL: RDM Player 1" },
  { 0x2A0C, "HYCL: RDM Player 2" },
  { 0x2A0D, "HYCL: RDM Player 4" },
  { 0x2A0E, "HYCL: RDM Player 8" },
  { 0x2A0F, "Elation Lighting: Pixel Driver 1000IP" },
  { 0x2A10, "Integrated System Technology Ltd: White Knight 12" },
  { 0x2A11, "Sigma Net: BlueDMX" },
  { 0x2A12, "BonKon: DMX Link Pro1" },
  { 0x2A13, "VANRAY: DMX LINK PRO" },
  { 0x2A14, "Chauvet Professional: Maverick Silens 2 Profile" },
  { 0x2A15, "Fiberli: Node4X" },
  { 0x2A16, "Ocular BVBA: Ocularium" },
  { 0x2A17, "Showtacle Ltd: THE UPGRADE" },
  { 0x2A18, "Showtacle Ltd: Moncha2" },
  { 0x2A19, "zhsj: Video control" },
  { 0x2A1A, "Archon: Archon Dev" },
  { 0x2A1B, "Tristan Leonid Zoltan Thiltges: Lightsculptures" },
  { 0x2A1C, "Elation Lighting: RDM 6XL" },
  { 0x2A1D, "Elation Lighting: RDM 645" },
  { 0x2A1E, "Elation Lighting: RDM 10" },
  { 0x2A1F, "Elation Lighting: EP4" },
  { 0x2A20, "Elation Lighting: EN4" },
  { 0x2A21, "Elation Lighting: EN12" },
  { 0x2A22, "Kyle Hensel: Node js API" },
  { 0x2A23, "Showart: DMXrecorder" },
  { 0x2A24, "ON LX Limited: CommsKit" },
  { 0x2A25, "Guangzhou ChaiYi Light CO Ltd: Air Gate" },
  { 0x2A26, "SmartShow UK: NetPixel ONE" },
  { 0x2A27, "SmartShow UK: AirPixel ONE" },
  { 0x2A28, "Pixout SIA: Pixout Controller" },
  { 0x2A29, "Steinigke Showtechnic GmbH: EYE 740" },
  { 0x2A2A, "ADJ Group: Pixie Driver 2K" },
  { 0x2A2B, "Belayingpin com: BPC Video Server" },
  { 0x2A2C, "Lucenti: Blackwave PixlDrive" },
  { 0x2A2D, "Integrated System Technologies: iDrive Workshop" },
  { 0x2A2E, "R S Schwarze Elektrotechnik Moderne Industrieelektronik GmbH: SG 4" },
  { 0x2A2F, "Sigma Net: Light Magic" },
  { 0x2A30, "Paulo Macedo: WIFIpixel" },
  { 0x2A31, "DATALED: DATALED NET" },
  { 0x2A32, "ADB STAGELIGHT: ORKIS PROFILE M" },
  { 0x2A33, "CLAYPAKY: REFLECTXION" },
  { 0x2A34, "Offstage Controls: Unlicensed OCPE" },
  { 0x2A35, "PXM: Px786" },
  { 0x2A36, "PXM: Px785" },
  { 0x2A37, "Suga koubou Co Ltd: DMX Recorder" },
  { 0x2A38, "CLAYPAKY: ALQIMYA" },
  { 0x2A39, "Offstage Controls: Kilo Gate I" },
  { 0x2A3A, "Offstage Controls: Kilo Gate O" },
  { 0x2A3B, "Offstage Controls: Kilo Gate IO" },
  { 0x2A3C, "JAH Audio Corp: JAH 8 Port Node" },
  { 0x2A3D, "JAH Audio Corp: JAH Lighting Engine" },
  { 0x2A3E, "ADJ Products: TrussHub U1" },
  { 0x2A3F, "Integrated System Technologies: Sentinel 24" },
  { 0x2A40, "BSL BV: PowerNode 8" },
  { 0x2A41, "BSL BV: Node 2" },
  { 0x2A42, "DTS Illuminazione srl: SYNERGY 7 PROFILE" },
  { 0x2A43, "DTS Illuminazione srl: ALCHEMY 7" },
  { 0x2A44, "LaserNet: LiveFeedback" },
  { 0x2A45, "Focus Technologies BV: Focus3D" },
  { 0x2A46, "Exalux: Connect Plus" },
  { 0x2A47, "Bafa Elektronik ve Isik Tasarimlari Sanayii Ticaret Sti: Zerolight16" },
  { 0x2A48, "Fiberli: Node2X" },
  { 0x2A49, "WizzuLED: Matrix LED Modules" },
  { 0x2A4A, "Kifo: Kifo Lightcontroller" },
  { 0x2A4B, "Digital Projection: Digital Projection Projector" },
  { 0x2A4C, "tx: plamp1" },
  { 0x2A4D, "tx: plamp2" },
  { 0x2A4E, "tongxinkeji: plamp3" },
  { 0x2A4F, "Kloeckner EDV Service BK Tec Audio: Audiostack" },
  { 0x2A50, "kuwatec Inc: Valencia" },
  { 0x2A51, "Luxeos Luminaires Ltd: Luxnode" },
  { 0x2A52, "ADJ PRODUCTS: HYDRO WASH X19" },
  { 0x2A53, "guangzhou hongcai stage equipment co ltd: x7 coupe" },
  { 0x2A54, "Zinc Event Production Ltd: Wireless LED controller" },
  { 0x2A55, "CLAYPAKY: HY B EYE K25 TEATRO" },
  { 0x2A56, "CLAYPAKY: AXCOR PROFILE 600 TEATRO" },
  { 0x2A57, "Luminex Lighting Control Equipment: LumiCore" },
  { 0x2A58, "Equivalent: LSSR 123E" },
  { 0x2A59, "Steinigke Showtechnic GmbH: Node IV" },
  { 0x2A5A, "Steinigke Showtechnic GmbH: Pixel Node II" },
  { 0x2A5B, "Steinigke Showtechnic GmbH: freeDMX AP" },
  { 0x2A5C, "Visual Productions: CueCore3" },
  { 0x2A5D, "Visual Productions: B Station2" },
  { 0x2A5E, "Visual Productions: DaliCore" },
  { 0x2A5F, "Litefocus: Node8" },
  { 0x2A60, "Litefocus: Node4" },
  { 0x2A61, "Litefocus: Node24" },
  { 0x2A62, "Litefocus: Node12" },
  { 0x2A63, "Litefocus: Node10" },
  { 0x2A64, "Litefocus: Node8a" },
  { 0x2A65, "Litefocus: Node4a" },
  { 0x2A66, "Litefocus: Node2" },
  { 0x2A67, "Litefocus: Node1" },
  { 0x2A68, "CLAYPAKY: XTYLOS AQUA" },
  { 0x2A69, "CLAYPAKY: AXCOR PROFILE 600 HC TEATRO" },
  { 0x2A6A, "Modern Stage Service Pvt Ltd: MSSP DMX4" },
  { 0x2A6B, "Chengdu Chengyu Electronic Technology Co Ltd: CYT LightShow Controller" },
  { 0x2A6C, "Chengdu Chengyu Electronic Technology Co Ltd: CYT LED Controller" },
  { 0x2A6D, "Chengdu Chengyu Electronic Technology Co Ltd: CYT DMX512 Controller" },
  { 0x2A6E, "stage design technology co Ltd nanchang: multifunction network processing unit" },
  { 0x2A6F, "LiteLEES: SUPER HERO 470 PRO" },
  { 0x2A70, "LiteLEES: BIG EYE L4025" },
  { 0x2A71, "LiteLEES: BIG EYE L4019" },
  { 0x2A72, "Dizzy D Productions: DAn Controller" },
  { 0x2A73, "Martin Professional: MAC Aura PXL" },
  { 0x2A74, "sziton: mess light" },
  { 0x2A75, "CLAYPAKY: AROLLA SPOT MP" },
  { 0x2A76, "CLAYPAKY: AROLLA PROFILE MP" },
  { 0x2A77, "CLAYPAKY: AROLLA PROFILE HP" },
  { 0x2A78, "CLAYPAKY: MIDIB" },
  { 0x2A79, "CLAYPAKY: TAMBORA BATTEN K25" },
  { 0x2A7A, "CLAYPAKY: MINIB PARLED AQUA" },
  { 0x2A7B, "CLAYPAKY: SHARPY PLUS AQUA" },
  { 0x2A7C, "Acme: TRUSSHUB U1" },
  { 0x2A7D, "Acme: LEO" },
  { 0x2A7E, "Acme: DARKMOON" },
  { 0x2A7F, "Acme: SILVERMOON" },
  { 0x2A80, "Acme: GEIST BSWF" },
  { 0x2A81, "Acme: GEIST BEAM" },
  { 0x2A82, "Acme: SUNRISE" },
  { 0x2A83, "Acme: TRUSSHUB U" },
  { 0x2A84, "Acme: TRUSSHUB S" },
  { 0x2A85, "Foshan YiFeng Electric Industrial Co ltd: SOLAR IMPULSE" },
  { 0x2A86, "MODUS: ARL 01 8CH RELAY" },
  { 0x2A87, "LSC Lighting Systems Aust Pty Ltd: MantraMini" },
  { 0x2A88, "LSC Lighting Systems Aust Pty Ltd: UniTour" },
  { 0x2A89, "LSC Lighting Systems Aust Pty Ltd: Unity" },
  { 0x2A8A, "ProtoPixel: 1 Channel WiFi Controller" },
  { 0x2A8B, "Integrated System Technology Limited: iMune multiGate" },
  { 0x2A8C, "ShoCobra: FX1" },
  { 0x2A8D, "ShoCobra: ELD4" },
  { 0x2A8E, "ROBERT JULIAT: CHARLES 960SX" },
  { 0x2A8F, "ROBERT JULIAT: DALIS 864" },
  { 0x2A90, "ROBERT JULIAT: DALIS 863" },
  { 0x2A91, "ROBERT JULIAT: TIBO HE 553" },
  { 0x2A92, "ROBERT JULIAT: SULLY 1156" },
  { 0x2A93, "ROBERT JULIAT: SULLY 305L" },
  { 0x2A94, "ROBERT JULIAT: SULLY 650SX" },
  { 0x2A95, "ROBERT JULIAT: ARTHUR 1014" },
  { 0x2A96, "Colordeve International: NETnode22" },
  { 0x2A97, "Colordeve International: NETnode14" },
  { 0x2A98, "Colordeve International: NETnode18" },
  { 0x2A99, "ShenZhen ChuanTian QuanCai Technology Co ltd: CT 3072 1CH" },
  { 0x2A9A, "ShenZhen ChuanTian QuanCai Technology Co ltd: CT 16384 16CH" },
  { 0x2A9B, "ShenZhen ChuanTian QuanCai Technology Co ltd: CT 8192 8CH" },
  { 0x2A9C, "jin ye Electronics: JY KZQ" },
  { 0x2A9D, "Paai: PAAI Ethernet node" },
  { 0x2A9E, "iion: MNM" },
  { 0x2A9F, "ALA Equipment Company Ltd: PowerNet" },
  { 0x2AA0, "ChromaTech: ThunderOne" },
  { 0x2AA1, "Aputure Imaging Industries Co Ltd: LS 600 LS 1500" },
  { 0x2AA2, "Aputure Imaging Industries Co Ltd: SQ NET" },
  { 0x2AA3, "Guangzhou Mingyan Electronic Technology Co Ltd: Mingyan motherboard" },
  { 0x2AA4, "Guangzhou Mingyan Electronic Technology Co Ltd: Par light motherboard" },
  { 0x2AA5, "Guangzhou Mingyan Electronic Technology Co Ltd: Wifi controller" },
  { 0x2AA6, "Fiilex: Fiilex Color" },
  { 0x2AA7, "Cameo: Evos W3" },
  { 0x2AA8, "Cameo: Opus H5" },
  { 0x2AA9, "Cameo: Opus X" },
  { 0x2AAA, "Cameo: Opus SP5 FC" },
  { 0x2AAB, "Cameo: XNODE 8" },
  { 0x2AAC, "cameo: Opus SP5" },
  { 0x2AAD, "Cameo: Opus S5" },
  { 0x2AAE, "Cameo: XNODE 4" },
  { 0x2AAF, "Chromatech: ThunderPanel" },
  { 0x2AB0, "AC Power Distribution ACT Lighting Inc: PDXND41" },
  { 0x2AB1, "AVW Controls Ltd: QAxis Stage automation integration with LX" },
  { 0x2AB2, "CPOINT: Ledogen" },
  { 0x2AB3, "CPOINT: DMXplorer" },
  { 0x2AB4, "Lichtmanufaktur Berlin GmbH: Casambi Gateway" },
  { 0x2AB5, "ShenZhen ChuanTian QuanCai Technology Co ltd: CT3276832CH" },
  { 0x2AB6, "Ether Dream: Ether Dream 2" },
  { 0x2AB7, "Chauvet Professional: Maverick MK3 Profile CX 2" },
  { 0x2AB8, "Chauvet Professional: Maverick Force 3 Spot" },
  { 0x2AB9, "Chauvet Professional: Maverick Force 3 Profile" },
  { 0x2ABA, "Chauvet Professional: Maverick Force 2 Profile" },
  { 0x2ABB, "Chauvet Professional: Maverick Force 1 Spot" },
  { 0x2ABC, "Chauvet Professional: Maverick Silens 1 Profile" },
  { 0x2ABD, "Chauvet Professional: onAir Panel 2 IP" },
  { 0x2ABE, "Chauvet Professional: onAir Panel 1 IP" },
  { 0x2ABF, "Insight Lighting: CDS RDM PoE" },
  { 0x2AC0, "nicolaudie: Sunlite Suite 2 FC plus" },
  { 0x2AC1, "PLS LLC: Platinum Dimmer System" },
  { 0x2AC2, "ecue: Sympl Bridge Node" },
  { 0x2AC3, "ecue: Bridge8" },
  { 0x2AC4, "ecue: SYMPHOLIGHT" },
  { 0x2AC5, "LED CONTROL PTE LTD: MX96" },
  { 0x2AC6, "ShenZhen ChuanTian QuanCai Technology Co ltd: CT 1020X16" },
  { 0x2AC7, "Advatek Lighting: PixLite A16 S Mk3" },
  { 0x2AC8, "Advatek Lighting: PixLite A4 W Mk3" },
  { 0x2AC9, "Advatek Lighting: PixLite A4 S Mk3" },
  { 0x2ACA, "Advatek Lighting: PixLite T8 S Mk3" },
  { 0x2ACB, "Advatek Lighting: PixLite A16 S Mk2" },
  { 0x2ACC, "Advatek Lighting: PixLite A4 S Mk2" },
  { 0x2ACD, "Advatek Lighting: PixLite T8 S Mk2" },
  { 0x2ACE, "Advatek Lighting: PixLite 16 Plug Play Mk2 plus" },
  { 0x2ACF, "Advatek Lighting: PixLite 16 Plug Play Mk2" },
  { 0x2AD0, "Advatek Lighting: PixLite 4 Mk2 Rugged" },
  { 0x2AD1, "Advatek Lighting: PixLite 16 Mk2 Long Range" },
  { 0x2AD2, "Advatek Lighting: PixLite 16 Mk2 ECO" },
  { 0x2AD3, "Advatek Lighting: PixLite 16 Mk2" },
  { 0x2AD4, "Advatek Lighting: PixLite 4 Mk2 ECO" },
  { 0x2AD5, "Advatek Lighting: PixLite 4 Mk2" },
  { 0x2AD6, "LAMP Aydinlatma: OPUS 16" },
  { 0x2AD7, "LAMP Aydinlatma: OPUS 8" },
  { 0x2AD8, "LAMP Aydinlatma: OPUS 4" },
  { 0x2AD9, "Stage Gear: AUM" },
  { 0x2ADA, "DLL ltd: AC 404" },
  { 0x2ADB, "MODUS: ACTION FX MODUS" },
  { 0x2ADC, "MODUS: ACTION LAB MODUS" },
  { 0x2ADD, "MODUS: ALM MODUS" },
  { 0x2ADE, "MODUS: AV PLAYER MODUS" },
  { 0x2ADF, "MODUS: ALC MODUS" },
  { 0x2AE0, "MODUS: ACW MODUS" },
  { 0x2AE1, "MODUS: ASC MODUS" },
  { 0x2AE2, "MODUS: ADL 16 MODUS" },
  { 0x2AE3, "MODUS: ADL 02 MODUS" },
  { 0x2AE4, "MODUS: ADAC MODUS" },
  { 0x2AE5, "MODUS: E GATE MODUS" },
  { 0x2AE6, "MODUS: AADC MODUS" },
  { 0x2AE7, "MODUS: ADMX MODUS" },
  { 0x2AE8, "MODUS: ARS MODUS" },
  { 0x2AE9, "Chromateq SARL: Chromateq Node" },
  { 0x2AEA, "SIRS E: Pilotino WIFI PCB" },
  { 0x2AEB, "able: PRIME RGB 5300" },
  { 0x2AEC, "TDE Lighttech: IZI Access" },
  { 0x2AED, "Nuvolight GmbH Co KG: SMARTsplitter" },
  { 0x2AEE, "Chauvet Professional: Logic Drive 2X" },
  { 0x2AEF, "Vivitek: Projector" },
  { 0x2AF0, "Sensation Lighting Technology Co Ltd: Tungsten cubic" },
  { 0x2AF1, "Eon lighting: Eonport4" },
  { 0x2AF2, "Eon lighting: Eonport2" },
  { 0x2AF3, "Eon lighting: Eonport1" },
  { 0x2AF4, "LSC Lighting Systems Aust Pty Ltd: Houston X" },
  { 0x2AF5, "INTILED: U BOX 8" },
  { 0x2AF6, "Foshan city Yanyao lighting Equipment Factory: X_NODE_8U" },
  { 0x2AF7, "Foshan city Yanyao lighting Equipment Factory: X_NODE_4U" },
  { 0x2AF8, "Foshan city Yanyao lighting Equipment Factory: X_NODE_PIXEL_2U" },
  { 0x2AF9, "Foshan city Yanyao lighting Equipment Factory: X_NODE_PIXEL" },
  { 0x2AFA, "S4 Lights: Motherline Main Board" },
  { 0x2AFB, "Laserworld Group: ShowNET" },
  { 0x2AFC, "HYCL: Super RdmController 16" },
  { 0x2AFD, "HYCL: Super RdmController 1" },
  { 0x2AFE, "HYCL: Super RdmController 2" },
  { 0x2AFF, "HYCL: Super RdmController 4" },
  { 0x2B00, "HYCL: Super RdmController 8" },
  { 0x2B01, "Showtacle Ltd: Reactivo" },
  { 0x2B02, "Advatek Lighting: PixLite E16 S Mk3" },
  { 0x2B03, "Advatek Lighting: PixLite E4 S Mk3" },
  { 0x2B04, "EagleLight: Node16S" },
  { 0x2B05, "EagleLight: Node8S" },
  { 0x2B06, "EagleLight: Node4S" },
  { 0x2B07, "EagleLight: Node2S" },
  { 0x2B08, "EagleLight: Node1S" },
  { 0x2B09, "EagleLight: Node16D" },
  { 0x2B0A, "EagleLight: Node8D" },
  { 0x2B0B, "EagleLight: Node4D" },
  { 0x2B0C, "EagleLight: Node2D" },
  { 0x2B0D, "EagleLight: Node1D" },
  { 0x2B0E, "PXM: QRay Console 36" },
  { 0x2B0F, "PXM: QRay Console 24" },
  { 0x2B10, "CLAYPAKY: MINI XTYLOS" },
  { 0x2B11, "Acme: TRUSSHUB UG" },
  { 0x2B12, "Acme: THUNDER BREAKER" },
  { 0x2B13, "Acme: CALORIE" },
  { 0x2B14, "Acme: JOULES" },
  { 0x2B15, "Acme: PASCAL" },
  { 0x2B16, "Acme: GRAVITRON" },
  { 0x2B17, "Acme: NEWTON" },
  { 0x2B18, "Acme: GEMINI" },
  { 0x2B19, "TELMICNeo: QUADTRA2" },
  { 0x2B1A, "TrasMaTech: TrasMaTech Led Panel" },
  { 0x2B1B, "Yarilo Pro: PixelDIN" },
  { 0x2B1C, "CLAYPAKY: MINI XTYLOS HPE" },
  { 0x2B1D, "WizzuLED: WizzuLED WiFi Link Pro Optoisolated" },
  { 0x2B1E, "WizzuLED: WizzuLED WiFi Link" },
  { 0x2B1F, "WizzuLED: WizzuLED Matrix Display Module v2" },
  { 0x2B20, "CLAYPAKY: SINFONYA PROFILE 600" },
  { 0x2B21, "IMMOLAS: IMMO GATE x4 ISO" },
  { 0x2B22, "Chauvet Professional: Logic POE X" },
  { 0x2B23, "Chauvet Professional: Logic AR111 DN 24W" },
  { 0x2B24, "Chauvet Professional: Logic AR111 DN 12W" },
  { 0x2B25, "Chauvet Professional: Logic MR16 DN 6W" },
  { 0x2B26, "Chauvet Professional: Logic GZ 48W" },
  { 0x2B27, "Chauvet Professional: Logic GZ 12W" },
  { 0x2B28, "Chauvet Professional: Logic CV 24W" },
  { 0x2B29, "Chauvet Professional: Logic CV 12W" },
  { 0x2B2A, "Chauvet Professional: Logic Drive 2Xb" },
  { 0x2B2B, "Control Pro Kft: CubeOS" },
  { 0x2B2C, "LightnTec GmbH: ledTec flex wallpaper" },
  { 0x2B2D, "Luminex Lighting Control Equipment: LumiNode 12 RJ45" },
  { 0x2B2E, "Luminex Lighting Control Equipment: LumiNode 4 DIN" },
  { 0x2B2F, "Colordeve International: MissionBAR" },
  { 0x2B30, "Chauvet Professional: Maverick Force S Profile" },
  { 0x2B31, "Chauvet Professional: Maverick Force S Spot" },
  { 0x2B32, "Integrated System Technology Limited: Tendo Pod PoE" },
  { 0x2B33, "Integrated System Technologies: POE LED Driver 2" },
  { 0x2B34, "Integrated System Technologies: POE LED Driver 4" },
  { 0x2B35, "Integrated System Technologies: Well building Environmental Sensor" },
  { 0x2B36, "Nastedt VA Technik: PixelLedDriver" },
  { 0x2B37, "Chauvet Professional: Color STRIKE M" },
  { 0x2B38, "Sidus Link Ltd: Sidus QNet Jupiter" },
  { 0x2B39, "CLAYPAKY: VOLERO BATTEN AQUA" },
  { 0x2B3A, "CLAYPAKY: VOLERO WAVE" },
  { 0x2B3B, "CLAYPAKY: ACTORIS PARLED" },
  { 0x2B3C, "CLAYPAKY: PANIFY" },
  { 0x2B3D, "CLAYPAKY: SHARPY X FRAME" },
  { 0x2B3E, "CLAYPAKY: MIDIB WW" },
  { 0x2B3F, "CLAYPAKY: MINIB PARLED AQUA WW" },
  { 0x2B40, "CLAYPAKY: MINIB WW" },
  { 0x2B41, "Hypar Collective: HyparDrive" },
  { 0x2B42, "Uniquenterprice: Unique" },
  { 0x2B43, "Martin Professional: MAC Ultra Wash" },
  { 0x2B44, "Martin Professional: MAC Ultra Performance" },
  { 0x2B45, "Akatsuki: Node 10" },
  { 0x2B46, "NEWSUBSTANCE Ltd: Timecode Receiver" },
  { 0x2B47, "NEWSUBSTANCE Ltd: LED Pixel Driver" },
  { 0x2B48, "Licht Technik Hagenbach Grill: MB Yoke" },
  { 0x2B49, "Stops Mops GmbH: Desk Dough Beam" },
  { 0x2B4A, "elements: DEX 8" },
  { 0x2B4B, "LumiOS: eDLC4" },
  { 0x2B4C, "LumiOS: eDLC1" },
  { 0x2B4D, "LumiOS: eDMX1" },
  { 0x2B4E, "LumiOS: eDMX12" },
  { 0x2B4F, "LumiOS: eDMX4" },
  { 0x2B50, "ADL Electronics Ltd: ADL NET SERVER" },
  { 0x2B51, "ADL Electronics Ltd: ADL DIM SW 220 6 5" },
  { 0x2B52, "ADL Electronics Ltd: ADL DIM SW 220 6 3" },
  { 0x2B53, "ADL Electronics Ltd: ADL DIM SW 220 24 3" },
  { 0x2B54, "ADL Electronics Ltd: ADL DIM SW 220 12 3" },
  { 0x2B55, "ADL Electronics Ltd: ADL SW 220 6 5" },
  { 0x2B56, "ADL Electronics Ltd: ADL SW 220 12 3" },
  { 0x2B57, "ADL Electronics Ltd: ADL DIM 220 6 5" },
  { 0x2B58, "ADL Electronics Ltd: ADL DIM 220 6 1 LED" },
  { 0x2B59, "ADL Electronics Ltd: ADL DIM 220 12 1 LED" },
  { 0x2B5A, "ADL Electronics Ltd: ADL DIM 220 12 3" },
  { 0x2B5B, "ADL Electronics Ltd: ADL DC WSO Note" },
  { 0x2B5C, "ADL Electronics Ltd: ADL DMX NetGate Mini" },
  { 0x2B5D, "ADL Electronics Ltd: ADL DMX NetGate SPI" },
  { 0x2B5E, "ADL Electronics Ltd: ADL DMX NetGate DALI" },
  { 0x2B5F, "LRS Solutions: LRS ControlBridge" },
  { 0x2B60, "Pioneer lighting solutions india pvt ltd: PL NODE 8" },
  { 0x2B61, "AECO 10: AECO 10" },
  { 0x2B62, "Acme: AECO 12" },
  { 0x2B63, "Acme: AECO 5" },
  { 0x2B64, "Acme: AECO 20" },
  { 0x2B65, "Acme: AECO 8" },
  { 0x2B66, "Acme: AECO 22" },
  { 0x2B67, "CLAYPAKY: TAMBORA BATTEN SQUARE" },
  { 0x2B68, "CLAYPAKY: TAMBORA BATTEN ROUND" },
  { 0x2B69, "WHITEvoid: Comms Module" },
  { 0x2B6A, "Martin Professional: PDE Junction Box Active" },
  { 0x2B6B, "Martin Professional: VDO Atomic Bold" },
  { 0x2B6C, "SLLCP: NodeSTereo" },
  { 0x2B6D, "Acme: NEOZONE" },
  { 0x2B6E, "Acme: FLASHBOLT" },
  { 0x2B6F, "Acme: OCTOPUS 8" },
  { 0x2B70, "SLLCP: NodeSTereo2" },
  { 0x2B71, "Tavlintsev Timofey: LedMapper" },
  { 0x2B72, "Tyler Ward: POE stack light" },
  { 0x2B73, "Alexin Smart Integrations: RTI colorpicker driver" },
  { 0x2B74, "Wireless Solution Sweden AB: W DMX WiFi Bridge F 2" },
  { 0x2B75, "Wireless Solution Sweden AB: W DMX WiFi Bridge F 1" },
  { 0x2B76, "LumenRadio: CRMX Aurora" },
  { 0x2B77, "LumenRadio AB: CRMX Stardust" },
  { 0x2B78, "Schnick Schnack Systems GmbH: Pixel Gate Mini" },
  { 0x2B79, "LIGEO GmbH: LIGEO GATEWAY G2" },
  { 0x2B7A, "Strike Theatre Electronics LLC: Hellbender Console" },
  { 0x2B7B, "Elation Lighting: EP2" },
  { 0x2B7C, "Locimation Pty Ltd: LX Toolkit" },
  { 0x2B7D, "NEWSUBSTANCE Ltd: Media Server" },
  { 0x2B7E, "Yarilo Pro: Pixel Mini" },
  { 0x2B7F, "StrongLED Lighting Systems Suzhou Co Ltd: IP Controller" },
  { 0x2B80, "Wattle IT: Kanet" },
  { 0x2B81, "kuwatec Inc: PrefLight" },
  { 0x2B82, "kuwatec Inc: Ex2" },
  { 0x2B83, "Chauvet Professional: COLORado PXL BAR 16" },
  { 0x2B84, "Chauvet Professional: COLORado PXL BAR 8" },
  { 0x2B85, "Falcon Christmas: FPP" },
  { 0x2B86, "LIGEO GmbH: LIGEO WIFI G1" },
  { 0x2B87, "Imlight Electronics: Netline 2" },
  { 0x2B88, "Imlight Electronics: Netline 8" },
  { 0x2B89, "Imlight Electronics: Netline 4" },
  { 0x2B8A, "Imlight Electronics: DimRack 96" },
  { 0x2B8B, "Imlight Electronics: DimRack 48" },
  { 0x2B8C, "DTS Illuminazione srl: ALCHEMY 7 F" },
  { 0x2B8D, "Steinigke Showtechnic GmbH: DXT PoE Node I" },
  { 0x2B8E, "Chauvet Professional: Maverick Storm 2 BeamWash" },
  { 0x2B8F, "Arkaos: MediaMaster6" },
  { 0x2B90, "ALPHA LITE: ALPHA LITE" },
  { 0x2B91, "LED CONTROL PTE LTD: MX96 v2" },
  { 0x2B92, "LED CTRL: LED CTRL" },
  { 0x2B93, "control8r: MIDIMonster" },
  { 0x2B94, "StageTubes: MatrixEngine" },
  { 0x2B95, "Pippin Technical Service: PTS Limelight" },
  { 0x2B96, "Emporio On Stage: EosOemController" },
  { 0x2B97, "Integrated System Technologies Ltd: iDrive Eco 12" },
  { 0x2B98, "MakePro X: Glue" },
  { 0x2B99, "GODOX PHOTO EQUIPMENT CO LTD: LED Light" },
  { 0x2B9A, "Lucenti: Blackwave PixlDrive8 Pro" },
  { 0x2B9B, "LSC ControlSystems Pty Ltd: TRS Rack" },
  { 0x2B9C, "Acme: HAIL" },
  { 0x2B9D, "Acme: PIXEL LINE IP" },
  { 0x2B9E, "L4S GmbH: ETH Controller 10x1024" },
  { 0x2B9F, "CLAYPAKY: TAMBORA FLASH" },
  { 0x2BA0, "CLAYPAKY: TAMBORA LINEAR 100" },
  { 0x2BA1, "Luminex Lighting Control Equipment: LumiNode 4 Wall" },
  { 0x2BA2, "CLAYPAKY: MINIB" },
  { 0x2BA3, "Vari Lite: VL internal node" },
  { 0x2BA4, "Pixsper: LXMax" },
  { 0x2BA5, "Steinigke Showtechnic GmbH: IP PLH 420 Moving Head SpotBeam" },
  { 0x2BA6, "Steinigke Showtechnic GmbH: IP PLB420 Moving Head Beam" },
  { 0x2BA7, "Integrated System Technologies Ltd: iDrive Atlas 36" },
  { 0x2BA8, "Integrated System Technologies Ltd: iDrive Atlas 12" },
  { 0x2BA9, "equivalent: LSSR 65" },
  { 0x2BAA, "White Wing Logic: Ethersplitter" },
  { 0x2BAB, "LUXIBEL: B BLAST" },
  { 0x2BAC, "LUXIBEL: B BLAST PRO" },
  { 0x2BAD, "JentonDimaco: VeriPACK" },
  { 0x2BAE, "AhojPepo eu: Node1w1" },
  { 0x2BAF, "Schannherz Elektronikai Mahely: MUEB 4" },
  { 0x2BB0, "Shenzhen ImagineVision Technology Limited: ZOLAR Toliman 30C" },
  { 0x2BB1, "Yarilo Pro: LanDMX8DIN" },
  { 0x2BB2, "SoundSwitch: SoundSwitch" },
  { 0x2BB3, "Shenzhen ImagineVision Technology Limited: ZOLAR Vega 30C" },
  { 0x2BB4, "Shenzhen ImagineVision Technology Limited: ZOLAR Toliman 30Cb" },
  { 0x2BB5, "Shenzhen ImagineVision Technology Limited: ZOLAR Toliman 30S" },
  { 0x2BB6, "Lichtmanufaktur Berlin GmbH: Lithernet Casambi Gateway" },
  { 0x2BB7, "Tank Serbatoio Culturale: TASV" },
  { 0x2BB8, "L4S GmbH: ETH Controller 10x1024b" },
  { 0x2BB9, "expanseElectronics: soloWiFi" },
  { 0x2BBA, "expanseElectronics: dualETH" },
  { 0x2BBB, "Chauvet Professional: Maverick Storm 4 Profile" },
  { 0x2BBC, "Chauvet Professional: Maverick Storm 2 Profile" },
  { 0x2BBD, "Adkins Professional Lighting: 6x6 Watt RGBAW UV FlatPar" },
  { 0x2BBE, "Shenzhen ImagineVision Technology Limited: ZOLAR" },
  { 0x2BBF, "Manu: Enttec" },
  { 0x2BC0, "GVA Lighting Inc: PDC5" },
  { 0x2BC1, "Subsomav Lda: MyPocketNode" },
  { 0x2BC2, "Krypton: P800 IP" },
  { 0x2BC3, "Krypton: BRUTE" },
  { 0x2BC4, "SUPER CAN Light: HDMI Video Player" },
  { 0x2BC5, "SUPER CAN Industry Growing Co LTD: ETA Node" },
  { 0x2BC6, "Krypton: X Treme 1100" },
  { 0x2BC7, "Skaarhoj: BluePill" },
  { 0x2BC8, "ADJ Products: Pixie Driver 8000" },
  { 0x2BC9, "riccarf: asa" },
  { 0x2BCA, "ON LX Limited: Ctrl Engine" },
  { 0x2BCB, "nicoleaudio: daslight4" },
  { 0x2BCC, "Briteq: BTX LIGHTSTRIKE" },
  { 0x2BCD, "Company 235 LLC: OpenLCP" },
  { 0x2BCE, "Guangzhou ChaiYi Light CO Ltd: TEKMAND Node 2P" },
  { 0x2BCF, "CHAUVET: DMX AN" },
  { 0x2BD0, "Automatic Devices Company: ADC Clear Path Controller" },
  { 0x2BD1, "edelkrone: LightONE" },
  { 0x2BD2, "JPK Systems Limited: LeDMX4 MAX" },
  { 0x2BD3, "JPK Systems Limited: LeDMX2 MAX" },
  { 0x2BD4, "JPK Systems Limited: eDMX4 MAX ISODIN11" },
  { 0x2BD5, "JPK Systems Limited: eDMX4 MAX DIN" },
  { 0x2BD6, "JPK Systems Limited: ultraDMX MAX" },
  { 0x2BD7, "MLH Electronics: LEDstrip controller" },
  { 0x2BD8, "FixtureMapper: FixtureMapper" },
  { 0x2BD9, "Mantic Lighting Appliance Co Ltd: Matrix M801" },
  { 0x2BDA, "Litegear Inc: LiteDimmer" },
  { 0x2BDB, "Litegear Inc: Litemat" },
  { 0x2BDC, "TORRES: DMXAN" },
  { 0x2BDD, "HongYuan: HY001" },
  { 0x2BDE, "Chauvet Professional: STRIKE Bolt" },
  { 0x2BDF, "Chauvet Professional: Color STRIKE L" },
  { 0x2BE0, "USHIO LIGHTING INC: Amata2" },
  { 0x2BE1, "Mate LLC: MEL" },
  { 0x2BE2, "Litegear Inc: LiteDimmerB" },
  { 0x2BE3, "CLAYPAKY: MINI B SPOT" },
  { 0x2BE4, "CLAYPAKY: ACTORIS PARLED RGBW" },
  { 0x2BE5, "CLAYPAKY: TAMBORA LINEAR 60" },
  { 0x2BE6, "arpschuino: arpschuino32" },
  { 0x2BE7, "xiaoxu: DMX512 Expander" },
  { 0x2BE8, "MODUS: Wi Fi ColorBox" },
  { 0x2BE9, "Home Assistant Core Team and Community: Home Assistant" },
  { 0x2BEA, "LKE Lasershow: LED Driver" },
  { 0x2BEB, "Jorge Lighting: Obsidian EN4" },
  { 0x2BEC, "Guangdong Nanguang Photo Video Systems Co Ltd: NANLUX" },
  { 0x2BED, "Martin Professional: MAC Aura XIP" },
  { 0x2BEE, "mad: ks910p" },
  { 0x2BEF, "allroundDigital: cuewise Audio" },
  { 0x2BF0, "Aircoookie: WLED" },
  { 0x2BF1, "JPK Systems Limited: eDMX4 MAX" },
  { 0x2BF2, "JPK Systems Limited: eDMX2 MAX" },
  { 0x2BF3, "JPK Systems Limited: eDMX1 MAX" },
  { 0x2BF4, "JPK Systems Limited: eDMX4 MAX ISODIN22" },
  { 0x2BF5, "Fufeng lighting: EN8" },
  { 0x2BF6, "PH Lighting: LCI WiFi MINI" },
  { 0x2BF7, "PH Lighting: LCI WiFi MAX" },
  { 0x2BF8, "Steinigke Showtechnic GmbH: LED IP Atmo Blinder 9" },
  { 0x2BF9, "Astera: AsteraBox Wifi" },
  { 0x2BFA, "Ex Machina: lonestar" },
  { 0x2BFB, "Showtacle Ltd: SPI LED 2" },
  { 0x2BFC, "JPK Systems Limited: eDMX1 MAX DIN" },
  { 0x2BFD, "Vari Lite: Neo" },
  { 0x2BFE, "Vari Lite: ZerOS" },
  { 0x2BFF, "NEWSUBSTANCE Ltd: Wireless LED Pixel Driver" },
  { 0x2C00, "gobo ws: IoT lighting gateway" },
  { 0x2C01, "United Protocols: UP8420" },
  { 0x2C02, "United Protocols: UP8410" },
  { 0x2C03, "PIONEER LIGHTING SOLUTIONS INDIA PVT LTD: PL NODE 4" },
  { 0x2C04, "Chauvet Professional: onAir IP Panel 3" },
  { 0x2C05, "Lumascape: Lumascape PSync 010" },
  { 0x2C06, "Lumascape: Lumascape PSync 009" },
  { 0x2C07, "Lumascape: Lumascape PSync 008" },
  { 0x2C08, "Lumascape: Lumascape PSync 007" },
  { 0x2C09, "Lumascape: Lumascape PSync 006" },
  { 0x2C0A, "Lumascape: Lumascape PSync 005" },
  { 0x2C0B, "Lumascape: Lumascape PSync 004" },
  { 0x2C0C, "Lumascape: Lumascape PSync 003" },
  { 0x2C0D, "Lumascape: Lumascape PSync 002" },
  { 0x2C0E, "Lumascape: Lumascape PSync 001" },
  { 0x2C0F, "CLAYPAKY: SKYLOS" },
  { 0x2C10, "Showtacle Ltd: Reactivo 2" },
  { 0x2C11, "PXM: Px914" },
  { 0x2C12, "Cronic Industries: FlexNode S1" },
  { 0x2C13, "Chauvet Professional: onAir Panel 4 IP Hard" },
  { 0x2C14, "Chauvet Professional: Strike Array 1" },
  { 0x2C15, "rosdi ab latiff: TouchDesigner" },
  { 0x2C16, "VINGTQUATREVOLTS: D Light" },
  { 0x2C17, "Synthesis LED: Synthesis Pro" },
  { 0x2C18, "AULIOS GmbH: AULIOS" },
  { 0x2C19, "St Andrews: Dot 2" },
  { 0x2C1A, "Digipet: Win Digipet" },
  { 0x2C1B, "Chauvet Professional: Maverick Storm 3 BeamWash" },
  { 0x2C1C, "Chauvet Professional: Maverick Force 3 Profile" },
  { 0x2C1D, "Chauvet Professional: Maverick Force 2 Beam" },
  { 0x2C1E, "Chauvet Professional: COLORado PXL Curve 12" },
  { 0x2C1F, "Chauvet Professional: Maverick Storm 1 Beam" },
  { 0x2C20, "Chauvet Professional: Maverick Storm 1 Hybrid" },
  { 0x2C21, "Steinigke Showtechnic GmbH: LED IP Atmo Bar 10" },
  { 0x2C22, "Acme: LIGHTNING" },
  { 0x2C23, "CLAYPAKY: MIDIB FX" },
  { 0x2C24, "CLAYPAKY: SHARPY X SPOT" },
  { 0x2C25, "CLAYPAKY: AROLLA AQUA" },
  { 0x2C26, "CLAYPAKY: K15 AQUA" },
  { 0x2C27, "CLAYPAKY: ACTORIS PROFILE FC" },
  { 0x2C28, "CLAYPAKY: MINI B AQUA" },
  { 0x2C29, "Steinigke Showtechnic GmbH: DXT Pixel Node IV" },
  { 0x2C2A, "Vivalyte BV: LEDLogix" },
  { 0x2C2B, "PXL Lighting: B1" },
  { 0x2C2C, "Pyrodigy Production: DAC" },
  { 0x2C2D, "Chauvet Professional: Strike Array 2 FC" },
  { 0x2C2E, "Chauvet Professional: Strike Array 4 FC" },
  { 0x2C2F, "Chauvet Professional: Color Strike Duo" },
  { 0x2C30, "Plura: SPT" },
  { 0x2C31, "ARGETRON: Norval" },
  { 0x2C32, "PXM: Rh836" },
  { 0x2C33, "Plura: TRC" },
  { 0x2C34, "Plura: ELC" },
  { 0x2C35, "Plura: TCUH1D" },
  { 0x2C36, "Plura: SPTH1" },
  { 0x2C37, "Plura: TCUH1" },
  { 0x2C38, "Plura: TCU MTD ID" },
  { 0x2C39, "Plura: TCU" },
  { 0x2C3A, "Plura: SPT MTD ID" },
  { 0x2C3B, "Plura: UD300D" },
  { 0x2C3C, "Plura: UD300" },
  { 0x2C3D, "Plura: UD56S" },
  { 0x2C3E, "Plura: UD56" },
  { 0x2C3F, "Plura: UD56 8" },
  { 0x2C40, "Plura: UD25 8" },
  { 0x2C41, "Plura: UDD25" },
  { 0x2C42, "Plura: UD25" },
  { 0x2C43, "LSC Control Systems Pty Ltd: NEXEN DIN" },
  { 0x2C44, "LSC Control Systems Pty Ltd: NXD4" },
  { 0x2C45, "LSC Control Systems Pty Ltd: NXW2" },
  { 0x2C46, "LSC Control Systems Pty Ltd: NXP2" },
  { 0x2C47, "Acme: XA 2000 BSWF IP" },
  { 0x2C48, "Acme: XA 1000 BW IP" },
  { 0x2C49, "Acme: XA 1000 BSWF IP" },
  { 0x2C4A, "Acme: TS 500 RGBA" },
  { 0x2C4B, "Acme: TS 500 CW WW" },
  { 0x2C4C, "Acme: TB 5 IP" },
  { 0x2C4D, "Acme: TB 5" },
  { 0x2C4E, "Acme: STROBE 7 IP" },
  { 0x2C4F, "Acme: MB 1000" },
  { 0x2C50, "Acme: LP F3000" },
  { 0x2C51, "Acme: HUE 6 IP" },
  { 0x2C52, "Acme: CM S2" },
  { 0x2C53, "Acme: CM 1000Z" },
  { 0x2C54, "Acme: BLINDER BAR IP" },
  { 0x2C55, "Acme: ARC 640" },
  { 0x2C56, "Acme: STROBE 1 IP" },
  { 0x2C57, "Acme: ARC ST200" },
  { 0x2C58, "GLP German Light Products INC: Drixl" },
  { 0x2C59, "GLP German Light Products INC: Scenex PixiPower" },
  { 0x2C5A, "Synthesis LED: Synthesis Assistant tool" },
  { 0x2C5B, "SmartShow UK Ltd: Pro ONE" },
  { 0x2C5C, "Bulldog Lighting and Events: Armani Cobra 4" },
  { 0x2C5D, "Bulldog Lighting and Events: Diesel 12" },
  { 0x2C5E, "Bulldog Lighting and Events: Diesel 24" },
  { 0x2C5F, "Singularity UK Ltd: rdmInspect" },
  { 0x2C60, "ARCTOS Showlasertechnik GmbH: Orbit" },
  { 0x2C61, "CLAYPAKY: RHAPSODY" },
  { 0x2C62, "ChamSys Ltd: QuickQ" },
  { 0x2C63, "PIXILAB Technologies AB: PIXILAB Blocks" },
  { 0x2C64, "JPK Systems Limited: eDMX4 MAX ISODIN" },
  { 0x2C65, "JPK Systems Limited: eDMX8 MAX" },
  { 0x2C66, "CLAYPAKY: SINFONYA PROFILE HP" },
  { 0x2C67, "CLAYPAKY: SINFONYA PROFILE 600EX" },
  { 0x2C68, "CLAYPAKY: RHAPSODYA" },
  { 0x2C69, "CLAYPAKY: SKYLOS NV" },
  { 0x2C6A, "Onderweg Software: Onderweg DMX Library" },
  { 0x2C6B, "ChromaQ: 2inspire 300" },
  { 0x2C6C, "ChromaQ: 2inspire 200" },
  { 0x2C6D, "ChromaQ: 2inspire 100" },
  { 0x2C6E, "DTS Illuminazione srl: SYNERGY 6 PROFILE" },
  { 0x2C6F, "TELMIC Neo: Recoller" },
  { 0x2C70, "CB Electronics: TC 5 Midi Timecode Interface" },
  { 0x2C71, "BRITEQ Beglec NV: BTX SKYRAN" },
  { 0x2C72, "JPK Systems Limited: eDMX8 MAX DIN" },
  { 0x2C73, "Chauvet Professional: onAir B6" },
  { 0x2C74, "Chauvet Professional: onAir B4" },
  { 0x2C75, "Chauvet Professional: onAir B1" },
  { 0x2C76, "Swisson AG: XMT 500" },
  { 0x2C77, "Kino Flo Lighting Systems: Celeb Ikon 12" },
  { 0x2C78, "Kino Flo Lighting Systems: Celeb Ikon 6" },
  { 0x2C79, "Kino Flo Lighting Systems: Diva Lux 4" },
  { 0x2C7A, "Kino Flo Lighting Systems: Diva Lux 2" },
  { 0x2C7B, "Kino Flo Lighting Systems: Diva Lux 1" },
  { 0x2C7C, "Kino Flo Lighting Systems: FreeFrame Control 2" },
  { 0x2C7D, "Kino Flo Lighting Systems: FreeFrame P3" },
  { 0x2C7E, "Kino Flo Lighting Systems: FreeFrame P2" },
  { 0x2C7F, "Kino Flo Lighting Systems: FreeFrame P1" },
  { 0x2C80, "Kino Flo Lighting Systems: LED Fixture" },
  { 0x2C81, "Chauvet Professional: Epix Drive 4000X IP" },
  { 0x2C82, "Briteq Beglec NV: BT NODE24 Mk2" },
  { 0x2C83, "Briteq Beglec NV: BTI LIGHTSTRIKE IP66" },
  { 0x2C84, "ChamSys Ltd: MagicHD" },
  { 0x2C85, "ChamSys Ltd: MagicVis" },
  { 0x2C86, "Lighting Infusion LLC: Streaming Toolkit" },
  { 0x2C87, "Shenzhen Lumi Lime Technology Limited: LA01" },
  { 0x2C88, "Steinigke Showtechnic GmbH: eurolite Light Captain" },
  { 0x2C89, "ADJ Products: Wifi Net 2" },
  { 0x2C8A, "ADJ Products: Net 8" },
  { 0x2C8B, "ADJ Products: Net 4" },
  { 0x2C8C, "Martin Professional: ERA 700 Performance IP" },
  { 0x2C8D, "White WIng Logic: PoE LED controller MW10P" },
  { 0x2C8E, "DALCERO ENGINEERING: OemDalceroGateway04" },
  { 0x2C8F, "DALCERO ENGINEERING: OemDalceroGateway01" },
  { 0x2C90, "Chauvet Professional: Maverick Silens 2X Profile" },
  { 0x2C91, "Chauvet Professional: Maverick Silens 1X Profile" },
  { 0x2C92, "Elation Lighting: EN6 IP" },
  { 0x2C93, "Elation Lighting: EN12i" },
  { 0x2C94, "Elation Lighting: EP1" },
  { 0x2C95, "CLAYPAKY: ORKIS CYC" },
  { 0x2C96, "Emilio Karas: Fixture Visualizer unreleased" },
  { 0x2C97, "Steinigke Showtechnic GmbH: LED Pixel Matrix Panel 5x5 RGBWW" },
  { 0x2C98, "MODUS: MODUS Max08" },
  { 0x2C99, "IQ COMPANY Ltd: DOTIMAGE" },
  { 0x2C9A, "Chauvet Professional: Maverick Storm 4 SoloWash" },
  { 0x2C9B, "CLAYPAKY: Orkis Cyc" },
  { 0x2C9C, "Thomas Neumann Licht und Tontechnik: Levelcheck" },
  { 0x2C9D, "LaserAV: DistroNode" },
  { 0x2C9E, "LumenRadio AB: CRMX Galileo MAX" },
  { 0x2C9F, "Martin Professional: MAC One" },
  { 0x8000, "Artistic Licence Engineering Ltd: Netgate XT" },
  { 0x8001, "Artistic Licence Engineering Ltd: Net Patch" },
  { 0x8002, "Artistic Licence Engineering Ltd: DMX Hub XT" },
  { 0x8003, "Artistic Licence Engineering Ltd: Four Play" },
  { 0xFFFF, "Artistic Licence Engineering Ltd: OemGlobal" },
  { 0,      NULL }
};
static value_string_ext artnet_oem_code_vals_ext = VALUE_STRING_EXT_INIT(artnet_oem_code_vals);

static const value_string artnet_esta_man_vals[] = {
  { 0x0000, "ESTA / PLASA" },
  { 0x0001, "GEE" },
  { 0x0002, "Abstract AVR Ltd." },
  { 0x0003, "Chromatech Lighting Co., Ltd." },
  { 0x0008, "Guangdong Nanguang Photo & Video Systems Co., Ltd." },
  { 0x0009, "Aputure Imaging Industries Co., Ltd." },
  { 0x000A, "Interactive Imagination Ltd." },
  { 0x000B, "Phospec Industries Inc." },
  { 0x000C, "WAC Lighting Co." },
  { 0x000D, "Guangzhou Haoteng Lighting Co., Ltd." },
  { 0x000E, "Yaoxing Lighting Equipment (Guanghzou）Co., Ltd." },
  { 0x000F, "Shenzhen L-Thinker Technology Co., Ltd." },
  { 0x0010, "Dongguan Mi Xing Electronic Technology Co., Ltd." },
  { 0x0011, "Beijing Kedeshengye Technology Service Co., Ltd." },
  { 0x0012, "Apex Pro Light Co., Ltd." },
  { 0x0013, "Litemover BV" },
  { 0x0014, "SIRS Electronics, Inc." },
  { 0x0015, "Lumencraft Lighting Solutions" },
  { 0x0016, "Shenzhen Xuntek Electronics Co., Ltd" },
  { 0x0017, "Ereimul" },
  { 0x0018, "Macroblock, Inc." },
  { 0x0019, "Odelic Co., Ltd." },
  { 0x001A, "DLL Ltd." },
  { 0x001B, "Changsha Sunrise Electronic Technology Co. Ltd." },
  { 0x001C, "Kindwin Technology (HK) Ltd." },
  { 0x001D, "Luminator Technology Group" },
  { 0x001E, "Shenzhen Lumi Lime Technology Limited" },
  { 0x0020, "Wattle IT" },
  { 0x0021, "Electric Foundry Ltd." },
  { 0x0022, "PixelFLEX, LLC" },
  { 0x0057, "Blackbezt Lighting Technology Co., Ltd." },
  { 0x0058, "Big Dipper Laser Science and Technology Co.,Ltd." },
  { 0x0059, "Laysion Lighting Technology Co., Ltd." },
  { 0x005A, "TPD Lighting" },
  { 0x006A, "AIMTECH Electronik Tasarim Ltd. Sti." },
  { 0x006B, "SALZBRENNER media GmbH" },
  { 0x006C, "Flash-Butrym Sp.J." },
  { 0x006D, "AA Tasarim Ltd." },
  { 0x006E, "WHITEvoid GmbH" },
  { 0x006F, "AC Power Distribution/ACT Lighting Inc." },
  { 0x0070, "Instalighting GmbH" },
  { 0x0071, "Guangzhou Huaxinyuan Electronics Co., Ltd." },
  { 0x0072, "Guangzhou Zenith Aurora Lighting Co., Ltd." },
  { 0x0073, "Meijay Technologies Co., Ltd." },
  { 0x0074, "Thomann GmbH" },
  { 0x0075, "ODELI" },
  { 0x0076, "R. S. Schwarze Elektrotechnik Moderne Industrieelektronik GmbH" },
  { 0x0077, "CHAMP Licht" },
  { 0x0078, "Andy Lighting Technology Group Ltd." },
  { 0x0079, "Leyard Opto Electronics Co., Ltd." },
  { 0x007A, "Equivalent" },
  { 0x007B, "alurays lighting technology GmbH" },
  { 0x007C, "Huizhou Desay Intelligent Technology Co., Ltd." },
  { 0x007D, "JMS Pro Light" },
  { 0x007E, "Stichting Hypar Collective" },
  { 0x0080, "Shenzhen AOTO Electronics Co., Ltd." },
  { 0x0081, "Pino Solutions" },
  { 0x0082, "LKE Lasershowtechnik GmbH" },
  { 0x0083, "Guangzhou Bright Moon Technology Co., Ltd." },
  { 0x0084, "LEDIXIS (Exalux brand)" },
  { 0x0085, "Guangzhou Nanshi Light Equipment Co., Ltd." },
  { 0x0086, "Intella System Co., Ltd." },
  { 0x0087, "LMBD" },
  { 0x0088, "Guangzhou YaFeng Optoelectronic Equipment Co., Ltd." },
  { 0x0089, "Vulcan Lighting" },
  { 0x008A, "Guangzhou Lees Electronics Co., Ltd." },
  { 0x008B, "Opto Tech Corporation" },
  { 0x008C, "LRX Lighting (Dwight Crane Ltd.)" },
  { 0x008D, "Guangzhou Minghao Electronic Technology Co., Ltd." },
  { 0x008E, "Guangzhou Ao Mei Di Stage Lighting Equipment Co.,Ltd." },
  { 0x008F, "Jiangmen Coolfish Technology Co., Ltd." },
  { 0x0090, "Cyclops Lighting" },
  { 0x0091, "Guangzhou Shuozhi Optoelectronic Technology Co., Ltd. (Konelite)" },
  { 0x0092, "digiLED (UK) Ltd." },
  { 0x0093, "Luminous Show Technology Ltd." },
  { 0x0094, "Joinmax Display Technology Co., Ltd." },
  { 0x0095, "Ningbo Jeg Lighting Tech Co., Ltd." },
  { 0x0096, "SiChuan YuZhiWei Information Technology Lt., Co." },
  { 0x0097, "AdvancedRay (Beijing) Science & Technology Industries Co., Ltd." },
  { 0x0098, "Dedo Weigert Film GmbH" },
  { 0x009A, "Golden Sea Disco Light Manufacturer" },
  { 0x009B, "Guangzhou Jiawei Electronic Technology Co., Ltd." },
  { 0x009C, "LuxBalance Lighting" },
  { 0x009E, "Guangzhou Flying Butterfly Stage Lighting Equipment Co., Ltd." },
  { 0x009F, "Enedo Power SpA" },
  { 0x00A0, "Shenzhen Dicolor Optoelectronics Co., Ltd." },
  { 0x00A1, "Creative Lighting And Sound Systems Pty Ltd." },
  { 0x00A2, "EMP Designs Ltd." },
  { 0x00A3, "GuangZhou Huanshi Lighting Equipment Co., Limited" },
  { 0x00A4, "SAKMA Electronica Industrial S.A.U." },
  { 0x00A5, "Delta Electronics, Inc." },
  { 0x00A6, "Sensation Lighting Technology Co., Ltd." },
  { 0x00A7, "Syncronorm GmbH" },
  { 0x00A8, "Iwasaki Electric Co., Ltd." },
  { 0x00A9, "Richter Lighting Technologies GmbH" },
  { 0x00AA, "Hangzhou Easun Technology Co., Ltd." },
  { 0x00AB, "MFX Asia Co., Ltd" },
  { 0x00AC, "ZhouChuang Industrial Co. Limited" },
  { 0x00AD, "ColorDeve Co. Limited" },
  { 0x00AE, "Vitrulux Ltd" },
  { 0x00AF, "NanoPLC LLC" },
  { 0x00B0, "ARENA LUCI s.r.l." },
  { 0x00B1, "Guangzhou Omarte Lighting Co., Ltd." },
  { 0x00B2, "unonovesette srl" },
  { 0x00B3, "LANTERN" },
  { 0x00B4, "Lumos Design" },
  { 0x00B5, "Suga koubou Co., Ltd." },
  { 0x00B6, "DiGidot Technologies BV" },
  { 0x00B7, "Bron Elektronik AG" },
  { 0x00B8, "Shenzhen Singba Light Technology Co., Ltd." },
  { 0x00B9, "Guangzhou Baiyun District Sanjie Eletronic Stage Lighting Audio Equipment Factory" },
  { 0x00BA, "LiteGear Inc." },
  { 0x00BB, "Digital Lighting Engineering & Design, LLC" },
  { 0x00BC, "Ambion GmbH (Ambrain)" },
  { 0x00BD, "numeo GmbH" },
  { 0x00BE, "The Light Luminary for Cine and TV S.L. (VELVET LIGHT)" },
  { 0x00BF, "LumiOS (GTR Industries)" },
  { 0x00C0, "Foshan Yinhe Lanjing Lighting & Electrical Co., Ltd." },
  { 0x00C1, "Jingchuang Water Technology" },
  { 0x00C2, "Ledogen" },
  { 0x00C3, "Xicato" },
  { 0x00C4, "Guangzhou Dahe Electronic Technology Co. Ltd." },
  { 0x00C5, "DAGE Stage Lighting Master Co., Ltd." },
  { 0x00C6, "Guangzhou Lantian Electronic Technology Co., Ltd." },
  { 0x00C7, "THOR" },
  { 0x00C8, "Constell8 NV" },
  { 0x00C9, "Pangaea Technology" },
  { 0x0101, "St. Anne Engineering GmbH" },
  { 0x0102, "Bortis Elektronik" },
  { 0x0103, "Fontana Technologies" },
  { 0x0104, "Blizzard Lighting, LLC" },
  { 0x0105, "LIGHTHOW (SHANGHAI) Ltd." },
  { 0x0106, "A.L.A. Equipment Company Ltd." },
  { 0x0107, "Inventronics (Hangzhou), Inc." },
  { 0x0108, "Haya Lighting Equipment Limited" },
  { 0x0109, "V-Productions" },
  { 0x010A, "Elektralite" },
  { 0x010B, "DesignLED Technology (HK) Co., Ltd." },
  { 0x010C, "SES (Entertainment Services) Ltd." },
  { 0x010D, "Lumos / DMLite" },
  { 0x010E, "Guangzhou ATON Lighting Technology Co.,Ltd" },
  { 0x010F, "Saco Technologies Inc." },
  { 0x0110, "APF S.r.l." },
  { 0x0111, "Radig Hard & Software" },
  { 0x0112, "RGB Lighting Equipment Co., Ltd." },
  { 0x0113, "Airstar SAS" },
  { 0x0114, "BSL Lighting" },
  { 0x0115, "Kontrolcla Show Control S.L." },
  { 0x0116, "SmoothLUX B.V." },
  { 0x0117, "AD Toyo Lighting (Guangzhou) Co.,Ltd" },
  { 0x0118, "Vello Light Co., Ltd." },
  { 0x0119, "Peter Schneyder Design Management GmbH" },
  { 0x011A, "Guangzhou Hotion Technology Co., Ltd." },
  { 0x011B, "Jumptronic GmbH" },
  { 0x011C, "Letong Electronic (Guangzhou) Co., Ltd." },
  { 0x011D, "Yangzhou Zhituo Lighting Vision Technology Co., Ltd." },
  { 0x011E, "Master LED" },
  { 0x011F, "STF s.r.l." },
  { 0x016C, "LGR" },
  { 0x016D, "Hive Lighting" },
  { 0x016E, "Artled Technology Corp." },
  { 0x016F, "SQD Lighting Co. Ltd" },
  { 0x018F, "Guangzhou YiCheng Light Industry Ltd." },
  { 0x0190, "Wizlogics Co., Ltd." },
  { 0x0191, "Sycra Technologies" },
  { 0x0199, "Ocean LED Marine Ltd." },
  { 0x019A, "TwoGain Electronics" },
  { 0x019B, "ElectroTAS Soluciones Profesionales" },
  { 0x019C, "Ningbo Snappy Optoelectronics Co., Ltd." },
  { 0x019F, "DaisaLed Ltd." },
  { 0x01A0, "Light With LED" },
  { 0x01A1, "Yuesheng Stage Light Limited" },
  { 0x01A2, "Art Lighting Production, s.r.o." },
  { 0x01A3, "Dongguan Yongya Technology Co., Ltd" },
  { 0x01A4, "Custom Effects LED Solutions Inc." },
  { 0x01A5, "MJ Lighting Co., Ltd." },
  { 0x01A6, "Hengmei Lighting Technology Co., Ltd." },
  { 0x01A8, "ZongDa Photoelectricity Science and Technology Co., Ltd." },
  { 0x01A9, "Shenzhen Uniview LED Ltd. Co." },
  { 0x01AA, "Videndum Production Solutions Inc." },
  { 0x01AB, "Shanghai Euchips Industrial Co., Ltd." },
  { 0x01AC, "DongGuan Phcistar Optoelectronics Technology Co., Ltd." },
  { 0x01AF, "Hunan Minghe Opto Tech Co., Ltd." },
  { 0x01B1, "Lightcare A/S" },
  { 0x01B2, "DJSI Schinstad ANS (Northern Light)" },
  { 0x01B3, "Ricardo Dias" },
  { 0x01B4, "Inventeq B.V." },
  { 0x01B5, "Beijing Soft Rock Technology Development Co., Ltd." },
  { 0x01BE, "BEN-RI Electronica S.A." },
  { 0x01C7, "SCHIEDERWERK GmbH" },
  { 0x01C8, "Guangzhou JINLIN Stage Lighting Equipment Co., Ltd." },
  { 0x01C9, "ALPHA LITE Inc." },
  { 0x01CA, "CASCADE s.a.s." },
  { 0x01CB, "ILT Italy SRL" },
  { 0x01CC, "Portman Custom Lights" },
  { 0x01CD, "Compulite Systems (2000) LTD" },
  { 0x01CE, "Railiks Enterprises" },
  { 0x01CF, "SRM Technik GmbH" },
  { 0x01D0, "Shanghai Semping Electronics Co., Ltd." },
  { 0x01D1, "Yarilo Pro" },
  { 0x01D2, "GIP Innovation Tools GmbH" },
  { 0x01D3, "JSC Aksera" },
  { 0x01D4, "x-labs" },
  { 0x01D5, "Shenzhen Liantronics Co., Ltd" },
  { 0x01D6, "Argent Data Systems, Inc." },
  { 0x01D7, "LIMEDIA" },
  { 0x01D8, "Daniel Large Lighting" },
  { 0x01D9, "Lightronics Inc." },
  { 0x01DA, "Guangzhou Daisy Electronic Technology Co., Ltd." },
  { 0x01DB, "Logen Ltd." },
  { 0x01DC, "LED Linear GmbH" },
  { 0x01DD, "Photonia srl" },
  { 0x01DE, "Guangzhou Baiyun Xinxiang Lighting Equipment Factory (XPRO LIGHT)" },
  { 0x01DF, "GuangZhou Dream Lighting Equipment Co., Ltd." },
  { 0x01E0, "IBN Labs Ltd." },
  { 0x0200, "Lighting Infusion LLC" },
  { 0x0201, "Blinkinlabs, LLC" },
  { 0x0202, "Paul Heuts" },
  { 0x0203, "Artemide S.p.A" },
  { 0x0204, "LIGHTLINE Lasertechnik GmbH" },
  { 0x0205, "SmartShow UK" },
  { 0x0206, "Studio Due Light S.r.l." },
  { 0x0207, "SILL LIGHTS GmbH" },
  { 0x0208, "Shenzhen Yuming Vision Technology Co., Ltd." },
  { 0x0209, "ER Productions" },
  { 0x020A, "Seebacher GmbH" },
  { 0x0210, "Leksa Lighting Technologies Pvt. Ltd." },
  { 0x0211, "Arkaos S.A." },
  { 0x0212, "Frame The Space (FTSLED)" },
  { 0x0213, "Huizhou visionX Technology Co., Ltd." },
  { 0x0214, "Impactrum" },
  { 0x021A, "WizzuLED by Scooon" },
  { 0x0223, "ShenZhen Focus Vision Intelligent System Co., Ltd." },
  { 0x0224, "Vanguard LED Displays" },
  { 0x0225, "Northern Lights Electronic Design, LLC" },
  { 0x0235, "Company 235, LLC" },
  { 0x0242, "ABLELITE INTERNATIONAL" },
  { 0x025B, "Imlight-Showtechnic" },
  { 0x026F, "Acuity Brands Lighting Inc." },
  { 0x0280, "Arrigo Lighting" },
  { 0x0286, "RMLX" },
  { 0x028F, "GRE Alpha Electronics Ltd." },
  { 0x02A0, "LLC Likhoslavl Plant of Lighting Engineering (Svetotehnika)" },
  { 0x02A1, "LLC Moscow Experimental Lighting Plant (TeleMechanic)" },
  { 0x02A2, "OJSC Kadoshkinsky electrotechnical" },
  { 0x02A3, "Big Bang Lightning" },
  { 0x02A4, "McNicoll Entertainment Systems" },
  { 0x02AA, "Jinnax Opto Technology Co., Ltd." },
  { 0x02AB, "Rift Labs" },
  { 0x02AC, "PSL Electronik Sanayi ve Ticaret A.S." },
  { 0x02B0, "DMXControl-Projects e.V." },
  { 0x02BA, "Chainzone Technology (Foshan) Co., Ltd." },
  { 0x02BD, "RE-Engineering" },
  { 0x02C8, "Growflux LLC" },
  { 0x02C9, "Theatrixx Technologies" },
  { 0x02CA, "Acclaim Lighting" },
  { 0x02CB, "GVA Lighting, Inc." },
  { 0x02CC, "Brightix" },
  { 0x02D0, "Winona Lighting" },
  { 0x02D1, "Hoffmeister Leuchten GmbH" },
  { 0x02E1, "Tait Towers Manufacturing Inc." },
  { 0x02E2, "CLF Lighting BV." },
  { 0x02EA, "d3 Technologies Ltd." },
  { 0x02EB, "Amolvin Research & Development Lab." },
  { 0x02EC, "Lutron Electronics" },
  { 0x02ED, "OpenLX SP Ltd." },
  { 0x02EE, "Firma GUTKOWSKI - Gutkowski Jan" },
  { 0x02EF, "ABLETECH Co., Ltd." },
  { 0x02F0, "iColor LED Shenzhen Co., Ltd." },
  { 0x02F1, "Lichtmanufaktur Berlin GmbH" },
  { 0x02FF, "Guangzhou Eway Stage Equipment Technology Co., Ltd." },
  { 0x0302, "Swefog Technology Group AB" },
  { 0x0303, "Shanghai Moons' Automation Control Co., Ltd" },
  { 0x0305, "DiCon Fiberoptics, Inc." },
  { 0x0306, "feno GmbH" },
  { 0x0307, "Ledium Kft." },
  { 0x0308, "ImageCue LLC" },
  { 0x030A, "Shenzhen Colordreamer Tech Ltd." },
  { 0x030B, "Guangzhou Wanrui Stage Light Equipment Co., Ltd." },
  { 0x030F, "Guangzhou Litewise Lighting Equipments Co., Ltd. dba EK Lights" },
  { 0x0311, "Guangzhou PUGUANG Electronic Technology Co., Ltd." },
  { 0x0312, "Guangzhou Xingkong Studio Lighting Co., Ltd." },
  { 0x032C, "Carallon Ltd." },
  { 0x033A, "Lux Lumen" },
  { 0x034B, "Rosstech Signals Inc." },
  { 0x0378, "KASUGA" },
  { 0x038F, "Strich Labs" },
  { 0x0391, "Alcorn McBride Inc." },
  { 0x0393, "i2Systems" },
  { 0x0394, "Prism Projection" },
  { 0x039B, "Lightforce Lasertechnik" },
  { 0x03A1, "INAREX INC." },
  { 0x03A2, "licht.team" },
  { 0x03A8, "ARTFOX" },
  { 0x03AA, "AIGA Electronic (GuangZhou) Co., Ltd." },
  { 0x03AB, "ABMICROLONDON" },
  { 0x03D5, "eX Systems" },
  { 0x03D6, "i-Lumen" },
  { 0x03DA, "QST LED" },
  { 0x03F0, "jpbaye.de" },
  { 0x03FA, "ART-DMX" },
  { 0x0402, "Exato" },
  { 0x0404, "Luminxa" },
  { 0x0411, "SoundSwitch" },
  { 0x0412, "D's DMX" },
  { 0x041C, "IMLIGHT" },
  { 0x0424, "FLUX ECLAIRAGE" },
  { 0x0440, "Guangzhou VAS Lighting Co., Ltd." },
  { 0x044E, "Ben Peoples Industries, LLC" },
  { 0x044F, "B2 Co., Ltd." },
  { 0x0455, "Lamp & Pencil" },
  { 0x047C, "LedsGo" },
  { 0x0480, "ASUSTeK Computer Inc." },
  { 0x048E, "Krisledz Pte. Ltd." },
  { 0x048F, "Grand Canyon LED Lighting System (Suzhou) Co., Ltd." },
  { 0x04A6, "MEB Veranstaltungstechnik GmbH" },
  { 0x04A9, "Edward J. Keefe Jr." },
  { 0x04B2, "Shenzhen Meiyad Optoelectronics Co., Ltd" },
  { 0x04B4, "SKT Inc." },
  { 0x04B5, "Major" },
  { 0x04B6, "IntiLED" },
  { 0x04B8, "Guangzhou Hongcai Stage Equipment Co., Ltd." },
  { 0x04C4, "Ephesus Lighting, Inc." },
  { 0x04D7, "Targetti Sankey Spa" },
  { 0x04D8, "Guangzhou Hong Yuan Electronic Technology Co., LTD." },
  { 0x04DD, "Topstriving Photoelectricity Technology Co., Ltd." },
  { 0x04EE, "Tivoli Lighting" },
  { 0x04F0, "SIGMA NET" },
  { 0x04F4, "Zeraus" },
  { 0x04FC, "Syncrolite LLC" },
  { 0x0504, "MYHP Limited" },
  { 0x050A, "ChamSys Ltd." },
  { 0x051C, "Ambitsel, Inc." },
  { 0x0520, "ANLC Ltd" },
  { 0x0529, "OSRAM" },
  { 0x0537, "TERMINAL-COM" },
  { 0x0540, "EverBrighten Co., Ltd." },
  { 0x0555, "Maresch Electronics" },
  { 0x0556, "RAYSYS" },
  { 0x055F, "PRO-SOLUTIONS" },
  { 0x056B, "COSMOLIGHT SRL" },
  { 0x056C, "Lumascape Lighting Industries" },
  { 0x0573, "JIAXING XINHUALI LIGHTING & SOUNDING CO., LTD." },
  { 0x0580, "Innovation LED Limited" },
  { 0x0586, "K 5600, Inc." },
  { 0x0588, "GuangZhou XiangMing Light Limited" },
  { 0x0592, "MIRAGE B.V." },
  { 0x0596, "ReveLux" },
  { 0x05A0, "Stage Smarts AB" },
  { 0x05A4, "IMMOLAS" },
  { 0x05A8, "Owl Labs" },
  { 0x05AB, "Shenzhen Lesan Lighting Co., Ltd." },
  { 0x05B5, "Turkowski GmbH" },
  { 0x05BC, "CantoUSA" },
  { 0x05C0, "Vertigo" },
  { 0x05CF, "Brighten Technology Development Co., Ltd." },
  { 0x05D3, "D-LED Illumination Technologies Ltd." },
  { 0x05E0, "esp_dmx" },
  { 0x05E2, "KORRO PLUS" },
  { 0x05E8, "Snap One" },
  { 0x05EB, "GUANGZHOU BO WEI TE LIGHTING CO.LTD" },
  { 0x05EF, "Guangzhou Chai Yi Light Co., Ltd." },
  { 0x05F2, "O'Light" },
  { 0x05F7, "Immersive Design Studios Inc." },
  { 0x0600, "TELMIC Neo" },
  { 0x0602, "Guangzhou Jinhong Stage Lighting Equipment.Co.,ltd" },
  { 0x0606, "Guangzhou YiGuang Stage Lighting Co., Ltd." },
  { 0x0609, "Diginet Control Systems Pty Ltd" },
  { 0x060A, "Kindwin Opto Electronic (ShenZhen) Co. Ltd" },
  { 0x060B, "Lighting Science Group (formerly LED Effects, Inc.)" },
  { 0x060D, "HANIL TNC CO.,LTD" },
  { 0x061C, "LEDRAYS INC" },
  { 0x0622, "Lupo SRL" },
  { 0x0623, "JAS LIGHTING & SOUND CO., LTD." },
  { 0x0624, "S4 Lights" },
  { 0x062A, "LEDstructures" },
  { 0x062B, "CKC Lighting Co., Ltd." },
  { 0x063A, "AVM Belgium BVBA" },
  { 0x063C, "LaserNet" },
  { 0x0644, "COLEDER DISPLAY CO., LTD." },
  { 0x0645, "MATSUMURA ELECTRIC MFG. CO. , LTD." },
  { 0x064D, "KXD LIGHTING CO., LIMITED" },
  { 0x0650, "RDC, Inc. d.b.a. LynTec" },
  { 0x0653, "USAI, LLC" },
  { 0x0654, "HUNAN XIANG CAIXU FILM AND TELEVISION CULTURE CO.LTD" },
  { 0x0658, "AZCOLOR LITE CO., LIMITED" },
  { 0x065E, "OFilms" },
  { 0x0660, "QSTECH CO.,LTD" },
  { 0x0668, "Motion FX" },
  { 0x066B, "AVANT-GARDE DE STUDIO FZ LLC" },
  { 0x066F, "GUANGZHOU CY LIGHTING EQUIPMENT CO.,LTD" },
  { 0x067A, "Inster Co, Ltd" },
  { 0x067C, "LOTRONIC SA" },
  { 0x0682, "Beijing Ming Rui Lighting Technology Co., Ltd." },
  { 0x0684, "LEDART LLC" },
  { 0x0685, "IBL/ESD-Datentechnik GmbH" },
  { 0x0687, "INSMARINE LLC" },
  { 0x0689, "GUANGDONG DONE POWER TECHNOLOGY CO" },
  { 0x068C, "Hitmusic SAS" },
  { 0x068E, "GUANGZHOU TEANMA STAGE LIGHTING FACTORY" },
  { 0x068F, "LEDEC GROUP LIMITED" },
  { 0x0696, "SHENZHEN HOION LIGHTING CO.,LTD" },
  { 0x0697, "Shenzhen LED Innovator Technology Co., Ltd" },
  { 0x0698, "Techni-Lux" },
  { 0x06A0, "Light.Audio.Design" },
  { 0x06A1, "ProTec GmbH" },
  { 0x06A3, "RODLIGHT ALBRECHT SILBERBERGER" },
  { 0x06AC, "GOLVER PROJECTS S.L." },
  { 0x06AD, "LEDMAN OPTOELECTRONIC CO.,LTD." },
  { 0x06AE, "CANARA LIGHTING INDUSTRIES PVT LTD" },
  { 0x06AF, "ZHEJIANG JINGRI TECHNOLOGY CO.,LTD" },
  { 0x06B3, "NANOLUMENS, INC." },
  { 0x06B6, "GUANGDONG VSHINE LIGHTING TECHNOLOGY CO.,LTD" },
  { 0x06B9, "GUANGZHOU DASEN LIGHTING CORPORATION LIMITED" },
  { 0x06BB, "IQ COMPANY Ltd." },
  { 0x06C4, "RHENAC Systems GmbH" },
  { 0x06C7, "L&L Luce&Light" },
  { 0x06CE, "American-Pro International" },
  { 0x06D1, "BIRUN ELECTRONIC INDUSTRIAL CO., LTD" },
  { 0x06D2, "LIGHTSTAR (BEIJING) ELECTRONIC CORPORATION" },
  { 0x06D3, "Boerner Distribution International GmbH" },
  { 0x06E0, "SHENZHEN LONGRUN OPTOELECTRONIC CO., LTD" },
  { 0x06E1, "Burck IT GmbH & Co. KG" },
  { 0x06E4, "Dydell B.V." },
  { 0x06E6, "Equipson S.A." },
  { 0x06EC, "SISTEMA Jsc" },
  { 0x06F0, "CTG sp. z o.o." },
  { 0x06F1, "Aqualux Lighting" },
  { 0x06F8, "CHONGQING XINYUANHUI OPTOELECTRONIC TECHNOLOGY CO.,LTD" },
  { 0x0700, "OXYGEN SMD Ltd" },
  { 0x0702, "Drinelec" },
  { 0x0706, "LINEAR TECHNOLOGIE" },
  { 0x0707, "Conceptinetics Technologies and Consultancy Ltd." },
  { 0x0708, "AK-LIGHT" },
  { 0x070C, "Pixout SIA" },
  { 0x070D, "Lumenwerx ULC" },
  { 0x070E, "PragmaLab" },
  { 0x070F, "Theatrelight New Zealand" },
  { 0x0710, "D.T.S. Illuminazione srl" },
  { 0x0712, "Laser Imagineering GmbH" },
  { 0x071A, "YHX Visual" },
  { 0x071F, "Moss LED Inc" },
  { 0x0724, "PHC Lighting & BMS Sp. z o.o." },
  { 0x072B, "NEWSUBSTANCE Ltd." },
  { 0x072C, "SGM A/S" },
  { 0x072D, "Sting Alleman" },
  { 0x072F, "RayComposer - R. Adams" },
  { 0x0732, "Galaxia Electronics" },
  { 0x0734, "CPOINT" },
  { 0x073B, "Corsair Technology Ltd." },
  { 0x0740, "Arkalumen" },
  { 0x0744, "DMX Pro Sales, LLC" },
  { 0x0745, "Guangzhou Wingo Stage Light Co., Ltd" },
  { 0x074F, "Panasonic Corporation" },
  { 0x0753, "F&V Europe B.V." },
  { 0x0758, "IMPOLUX GmbH" },
  { 0x075F, "LEDEngin Inc." },
  { 0x076A, "BeamZ (Tronios B.V.)" },
  { 0x076E, "DecoLed, LLC" },
  { 0x0776, "lumenetix" },
  { 0x077B, "GENLED Brands" },
  { 0x0782, "R9 Lighting" },
  { 0x078A, "FATEC sarl" },
  { 0x078E, "SHENZHEN BGLOPTO TECHNOLOGY Co., LTD." },
  { 0x0792, "MY-Semi Inc." },
  { 0x0797, "ARCPROLED Limited" },
  { 0x079B, "Pro Church Lights" },
  { 0x079F, "VPS Group, LLC" },
  { 0x07A3, "Guangzhou GBR PROLIGHT GROUP CO.,LTD (GBR PROLIGHT)" },
  { 0x07A5, "X LED Systems" },
  { 0x07AD, "CLS LED BV" },
  { 0x07AE, "A-LITE B.V." },
  { 0x07B0, "ADDiCTiON BoX GbR" },
  { 0x07B1, "TBF-PyroTec GmbH" },
  { 0x07B3, "Shenzhen Fabulux Technology Co., Ltd" },
  { 0x07B5, "ARM Automation, Inc" },
  { 0x07B6, "Minleon USA" },
  { 0x07B8, "Zhuhai Demi Technology Co., Ltd." },
  { 0x07BB, "Shenzhen SOSEN Electronics Co., Ltd." },
  { 0x07BE, "Sanko Device Co.Ltd." },
  { 0x07C0, "Code Mercenaries GmbH" },
  { 0x07C2, "BOOQlight BV" },
  { 0x07C5, "SBS Lighting LLC" },
  { 0x07C6, "BK Lighting" },
  { 0x07C8, "Sidus Link Ltd." },
  { 0x07CC, "Griven S.r.l." },
  { 0x07CF, "MH-Sound" },
  { 0x07D1, "Made By Mouse LTD" },
  { 0x07D5, "PHIDA Stage Equipment Co., Ltd" },
  { 0x07D6, "Lite Puter Enterprise Co., Ltd." },
  { 0x07DA, "Flytech s.r.l." },
  { 0x07E8, "ROCKETSIGN Technology HK Ltd" },
  { 0x07E9, "TechLink Co., Ltd." },
  { 0x07EA, "Le Maitre Ltd" },
  { 0x07EF, "Guangzhou V-Show Pro Lighting Co., Ltd." },
  { 0x07F0, "Lifud Technology Co., Ltd" },
  { 0x07F2, "CB Electronics" },
  { 0x07F3, "Sam Light" },
  { 0x07F4, "LED Flex Ltd." },
  { 0x07F5, "Shenzhen ATENTI Technologies Co., Ltd" },
  { 0x07F6, "Electric Distribution Systems" },
  { 0x07F7, "Dakco Technologies Co., Ltd." },
  { 0x07F8, "Ultimate Technology Solutions GmbH" },
  { 0x07F9, "Bion Technologies GmbH" },
  { 0x07FA, "Shenzhen Pony Systems Tech Co., Ltd." },
  { 0x07FD, "THELIGHT Luminary for Cine and TV S.L." },
  { 0x07FE, "Shenzhen Apexls Optoelectronic Co., Ltd." },
  { 0x07FF, "Guangzhou HOMEI LIGHT Manufacturer" },
  { 0x0800, "Hongyeah Light" },
  { 0x0801, "Guangzhou Favolite Stage Lighting Co., Ltd." },
  { 0x0802, "AstralPool" },
  { 0x0803, "Guangzhou FutureColor Electronic Technology Co., Ltd." },
  { 0x0804, "K&G Visual Technology" },
  { 0x0805, "T.C.M. Light-Solutions" },
  { 0x0806, "Air Giants Limited" },
  { 0x0807, "Event Lighting Pty, Ltd." },
  { 0x0808, "Cooper Lighting - Zero 88" },
  { 0x0809, "mumoco GmbH" },
  { 0x080A, "Shenzhen FantaLED Electronics Co., Ltd" },
  { 0x080D, "HBJ Elektronik" },
  { 0x080F, "NavoLabs" },
  { 0x0810, "BDS Studios" },
  { 0x0811, "V-PRO" },
  { 0x0812, "Yamagiwa Corporation" },
  { 0x0813, "Shenzhen Scenico Optoelectronic Co., Ltd." },
  { 0x0814, "squareV" },
  { 0x081C, "MR Electronics Ltd." },
  { 0x081E, "LOBO Electronic GmbH" },
  { 0x0823, "Opito Labs GmbH" },
  { 0x0824, "Almotechnos CO.,LTD." },
  { 0x0827, "PIXREAL" },
  { 0x0832, "Shenzhen EXC-LED Technology Co.,Ltd" },
  { 0x0838, "LaserAV" },
  { 0x083A, "Bright Ideas Custom Electronics Inc." },
  { 0x083C, "TDT Productions" },
  { 0x083E, "Guangdong Hua Chen Film & Television Stage Project Co., Ltd." },
  { 0x083F, "Shenzhen LeiFei Lighting Technologies Co.,Ltd." },
  { 0x0840, "Shenzhen Zwich Science and Technology Co.Ltd." },
  { 0x0841, "Guangzhou ICON Lighting Co.,Ltd" },
  { 0x0845, "Cush Light LLC" },
  { 0x0846, "LDR - Luci della Ribalta Srl" },
  { 0x084B, "Neon Circus Ltd" },
  { 0x084C, "Guangzhou Ba Lin Electronic Technology Co., Ltd." },
  { 0x084D, "Guangzhou NECO Stage Lighting Factory" },
  { 0x0850, "Proland Group, LLC" },
  { 0x0851, "Junction Inc. Ltd" },
  { 0x0854, "Sharp / NEC Display Solutions, Ltd." },
  { 0x0855, "GODOX Photo Equipment Co., Ltd." },
  { 0x0856, "Ctrl Element ehf" },
  { 0x0858, "Juno Lighting Group" },
  { 0x085A, "Guangzhou Ming Jing Stage Light Equipment Co., Ltd." },
  { 0x085B, "Tolifo (Dongguan) Photographic Equipment Co. Ltd" },
  { 0x085E, "MMS Distribution Ltd" },
  { 0x085F, "Media Visions, Inc." },
  { 0x0862, "illuminous" },
  { 0x0863, "XTEC Industries Pte Ltd" },
  { 0x0864, "Hangzhou Youte Power., Co. Ltd" },
  { 0x0865, "Contrade GmbH" },
  { 0x0866, "PAL Lighting" },
  { 0x0868, "Ushio America, Inc." },
  { 0x0869, "Club Cannon LLC" },
  { 0x086A, "Shenzhen Chip Optech Co.,LTD" },
  { 0x086C, "Bafa Elektronik ve Işık Tasarımları Sanayii Ticaret LTD Sti." },
  { 0x086E, "Guangzhou Hi-LTTE Electronics Technology Co.,Ltd" },
  { 0x086F, "MARTINI RUS LLC" },
  { 0x0870, "Hunan YESTECH Optoelectronic Co., Ltd" },
  { 0x0871, "Changsha Maya Special Effects Equipment Co., Ltd" },
  { 0x0873, "Guangzhou BKLite Stage Lighting Equipment Co.,LTD" },
  { 0x0874, "Snow Professional Lighting" },
  { 0x0875, "ARC Solid-State Lighting Corp." },
  { 0x0876, "Power Gems LTD" },
  { 0x0877, "Skaff New Zealand Ltd" },
  { 0x0878, "OTTEC Technology GmbH" },
  { 0x087A, "Dextra Group Plc" },
  { 0x087B, "About Time Technologies" },
  { 0x087C, "Telectran International Pty Ltd." },
  { 0x087D, "TPV Technology Group" },
  { 0x0880, "GuangZhou LiDang Technology Inc." },
  { 0x0883, "CEE Lighting Equipment Co.Ltd" },
  { 0x0884, "Bright Group" },
  { 0x0885, "SIRS-E" },
  { 0x0886, "KLIK Systems" },
  { 0x0888, "Banglux Lighting Technology Co., Ltd." },
  { 0x0889, "Guangzhou Shenghui Electronic Technology Co., Ltd" },
  { 0x088A, "Highendled Electronics Company Limited" },
  { 0x088B, "Shenzhen Doit Vision Co., Ltd" },
  { 0x088C, "Guangzhou Yi Sheng Yuan Electronic Co.,Ltd(Esun)" },
  { 0x088D, "Guangzhou Ling Yang lighting Science and Technology Co.,Ltd" },
  { 0x088E, "Stage One International Co., Ltd." },
  { 0x088F, "First Design System Inc." },
  { 0x0890, "Taurus Light Co.,Limited" },
  { 0x0891, "Feiner Lichttechnik GMBH" },
  { 0x0892, "DongGuan Ruishen Technology Co.,Ltd" },
  { 0x0893, "Brighten LED Lighting Limited" },
  { 0x0894, "Dongguan HCP Technology Co., Ltd." },
  { 0x0896, "CSD Design and Fabrication" },
  { 0x089A, "ADL Electronics Ltd." },
  { 0x089D, "gobo.ws" },
  { 0x08A1, "Shenzhen Gloshine Technology Co., Ltd" },
  { 0x08A2, "Guangzhou Gesida Light Equipment Co., Ltd." },
  { 0x08A3, "Redot Visual Effect Technologies (Shenzhen) Co., Ltd" },
  { 0x08A4, "Adam Hall GmbH" },
  { 0x08A5, "White Wing Logic" },
  { 0x08A6, "impulswerk.de" },
  { 0x08A7, "GuangZhou Deliya Opto-electronic Tech Co., Ltd" },
  { 0x08A8, "Guangzhou Yunpeng Lighting Equipment Co. Ltd." },
  { 0x08AA, "PiXL Factory" },
  { 0x08AB, "Qdot Lighting Limited" },
  { 0x08AC, "Bushveld Labs" },
  { 0x08AD, "Optical Productions LLC" },
  { 0x08AE, "Technical Audio Group Pty Ltd" },
  { 0x08AF, "AAdyn Technology" },
  { 0x08B0, "KIM Lighting" },
  { 0x08B1, "Fujian Starnet Evideo Information System Co.,Ltd." },
  { 0x08B2, "MCI Group" },
  { 0x08B3, "Stealth Light srl" },
  { 0x08B5, "ShenZhen Sunny Xiao Technology Co., Ltd." },
  { 0x08B6, "Graf Lichttechnik UG" },
  { 0x08B9, "Guangzhou Hua Rong Electronic Technology Co., Ltd." },
  { 0x08BA, "Meteor Lighting" },
  { 0x08BB, "Guangzhou CHEN Electronic Technology Co., Ltd." },
  { 0x08BC, "Michael Parkin" },
  { 0x08BD, "Lug Light Factory Sp. z o. o." },
  { 0x08BE, "Shenzhen FloatStone Technology Co., Ltd." },
  { 0x08BF, "Times Square Stage Lighting Inc." },
  { 0x08C0, "Real Tech International LTD." },
  { 0x08C1, "Project SSSHH Incorporated" },
  { 0x08C3, "Guangzhou Spark Stage Equipment Co. Ltd" },
  { 0x08C4, "Jacek Wagner" },
  { 0x08C5, "EHRGEIZ Lichttechnik GmbH" },
  { 0x08C6, "Guangzhou Ever Famous Electronic Co.,Ltd" },
  { 0x08C9, "LEDitgo Videowall Germany GmbH" },
  { 0x08CA, "Foshan City Xuandao Optoelectronics Equipment Co., Ltd" },
  { 0x08CB, "Practical LEDs.com" },
  { 0x08CC, "Guangzhou Santu Stage Lighting Equipment Co.Ltd" },
  { 0x08D0, "Image Engineering" },
  { 0x08D1, "Shenzhen Leqi Network Technology Co., Ltd." },
  { 0x08D3, "SVI Public Company Limited" },
  { 0x08D4, "Sensa-Lite Ltd." },
  { 0x08D5, "Sense Effects" },
  { 0x08D6, "Guangzhou Precision Vision Intelligent Equipment Co, Ltd" },
  { 0x08D7, "PatternAgents, LLC" },
  { 0x08D8, "W.A. Benjamin Electric Co." },
  { 0x08D9, "STILED" },
  { 0x08DA, "PLC Intelligent Technology (Shanghai) Co., Ltd." },
  { 0x08DD, "Matthew Tong" },
  { 0x08E0, "Red Arrow Controls" },
  { 0x08E1, "Shenzhen CLT Electronics Co.,LTD" },
  { 0x08E3, "Guangzhou JinZhiHui Electronic Technology Co.,Ltd." },
  { 0x08E4, "LMP Lichttechnik Vertriebsgesellschaft GmbH & Co KG" },
  { 0x08E6, "Shenzhen VisionMax Technology Co., Ltd" },
  { 0x08E7, "3A Guangzhou Electronics Co., Ltd" },
  { 0x08E8, "North Engineering" },
  { 0x08EA, "Changchun Cedar Electronic Technology Co.,Ltd." },
  { 0x08EB, "Guangzhou Lixin Lighting Co., Ltd." },
  { 0x08EC, "Marvin Nadrowski" },
  { 0x08ED, "ShowLED" },
  { 0x08EE, "Spacelights" },
  { 0x08EF, "Guangzhou RuiYang lighting technology co. LTD." },
  { 0x08F0, "Guang Dong LMJ Lighting Co., Ltd" },
  { 0x08F1, "SanDevices, LLC" },
  { 0x08F2, "Virtualny Agronom Ltd." },
  { 0x08F3, "Outdoor Lasers Ltd." },
  { 0x08F4, "MC Electronic Technology(GZ) Co., Ltd." },
  { 0x08F5, "Fufeng lighting" },
  { 0x08F6, "Eulum Design, LLC" },
  { 0x08F7, "Neotek Lighting" },
  { 0x08F8, "Liberal Logic Inc." },
  { 0x08F9, "ACS - Ackerman Computer Sciences" },
  { 0x08FA, "Phaton Lighting Co., Ltd." },
  { 0x08FB, "RPA Electronic Solutions Inc." },
  { 0x08FC, "Lights By Brian" },
  { 0x08FD, "Koto Electric Co., Ltd." },
  { 0x08FE, "Zhuhai Shengchang Electronics Co., Ltd." },
  { 0x0900, "nox multimedia GmbH" },
  { 0x0901, "GermTec GmbH & Co. KG" },
  { 0x0902, "DongGuan Betterway Lighting Co.,Ltd" },
  { 0x0903, "Shenzhen INFiLED Electronics, Ltd." },
  { 0x0904, "Bigbear Co., Ltd." },
  { 0x0905, "Locimation Pty Ltd" },
  { 0x0906, "Crystal Technica Limited" },
  { 0x0908, "Guangzhou DeLong Stage Equipment Co., Ltd." },
  { 0x0909, "Beijing Starlight Electronics Co., Ltd." },
  { 0x090B, "StarLighting" },
  { 0x090C, "GRE Alpha" },
  { 0x090E, "Sichuan esRadio Technology Co., Ltd" },
  { 0x090F, "Shenzhen Dingli Display Technology Co., Ltd" },
  { 0x0910, "Shenzhen Tecnon EXCO-Vision Technology Co., Ltd." },
  { 0x0911, "Guangzhou Aceda Professional Lighting Co., Ltd." },
  { 0x0912, "ags - Wissenschaftliche Arbeitsgemeinschaft fur Studio- und Senderfragen" },
  { 0x0913, "Guangzhou ECK Light Equipment Company Limited" },
  { 0x0914, "Xenio" },
  { 0x0915, "Guangzhou Chuangfeng Photoelectric Equipment Co., Ltd." },
  { 0x0916, "ACTOR-MATE CO., LTD." },
  { 0x0917, "Gavtronics" },
  { 0x0918, "David O Smith Design" },
  { 0x0919, "Foshan Leiyuan Photoelectric Co., LTD" },
  { 0x091A, "Celex LED Technology Ltd." },
  { 0x091B, "Krislite Pte. Ltd." },
  { 0x091D, "TouchPlate Technologies Inc." },
  { 0x091F, "Yaham Recience Technology Co,. ltd." },
  { 0x0920, "Vexica Technology Limited" },
  { 0x0921, "Guangzhou mengyi stage lighting equipment co., LTD." },
  { 0x0923, "Hangzhou Roleds Lighting System Co., Ltd." },
  { 0x0925, "Guangzhou Aiweidy Lighting Acoustics Equipment Co.,Ltd." },
  { 0x0926, "Elumeros Lighting Limited" },
  { 0x0927, "Guangzhou Mingying Electronic Technology Co., Ltd." },
  { 0x0929, "UPlight stage equipment(GZ) CO., Ltd." },
  { 0x092B, "Guangzhou Lightful Stage Lighting&Sound Equipment Co,.Ltd." },
  { 0x092C, "Guangzhou Chaoran Computer Co., Ltd." },
  { 0x092D, "LG Electronics" },
  { 0x092E, "YouEasy (Dongguan) Electronics Technology Co.,Ltd" },
  { 0x092F, "Guangzhou Shinelight Stage Equipment Factory" },
  { 0x0930, "jiaozuo shengguang film &equipment Co. Ltd" },
  { 0x0931, "Cristal Controles" },
  { 0x0932, "GUANGZHOU BORAY ELECTRON CO.,LTD" },
  { 0x0933, "Beyond Lighting WLL" },
  { 0x0934, "Zenopix Electronic Limited Company" },
  { 0x0935, "Guangzhou Huadu District Richa Lighting Equipment Factory" },
  { 0x0936, "AquaTronic" },
  { 0x0937, "Huizhou Zhonghan Electronic Technology Co., Ltd" },
  { 0x0938, "Guangzhou Vanray Lighting Equipment CO.,Ltd." },
  { 0x0939, "Edelmann Electronics" },
  { 0x093A, "HDT impex s.r.o." },
  { 0x093B, "Guangzhou Hongmingwei Stage Lighting Co., Ltd." },
  { 0x093D, "Sichuan Hushan Electric Co. Ltd" },
  { 0x093F, "Guangzhou Julong Platform Lighting Equipment Factory" },
  { 0x0940, "Shenzhen CreateLED Electronics Co., Ltd" },
  { 0x0941, "Shenzen Zhuoyang Intelligent Technology Co., Ltd." },
  { 0x0943, "Guangzhou Guangying Optoelectronics Co., Ltd" },
  { 0x0945, "Guangzhou Lin Xiang Stage Lighting Equipment CO.,LTD" },
  { 0x0946, "TBE Srl" },
  { 0x0947, "Shenzhen MOSO Electronics Technology Co., Ltd" },
  { 0x0948, "Wisconsin Lighting Lab, Inc. (WiLL)" },
  { 0x0949, "Shenzhen Jiuzhou Optoelectronic Technology" },
  { 0x094A, "Funovation, Inc" },
  { 0x094B, "Invisua Lighting BV" },
  { 0x0951, "Guangzhou GTD Lighting Technology Co., Ltd" },
  { 0x0952, "Guangzhou Sunway Entertainment Equipment Co., Ltd." },
  { 0x0953, "Boumakers Techniek" },
  { 0x0954, "Ledtop Visual Ltd." },
  { 0x0957, "White Light Ltd" },
  { 0x0958, "Illum Technology LLC (previously Verde Designs, Inc.)" },
  { 0x0959, "Urbs Lighting, LLC" },
  { 0x095A, "kLabs Research UK" },
  { 0x095B, "Wuhan Zhongtian Jiaye Mechanical and Electrical Engineering Co. LTD" },
  { 0x095C, "Thomas Neumann Licht und Tontechnik" },
  { 0x095E, "Hondel Lighting Limited" },
  { 0x095F, "Elaborated Networks GmbH" },
  { 0x0960, "Fineline Solutions Ltd." },
  { 0x0962, "Finland Lighting Oy" },
  { 0x0964, "Inventions Guité Inc." },
  { 0x0965, "Fontana Fountains" },
  { 0x0967, "Arcus Licht- und Praesentationstechnik GmbH" },
  { 0x0968, "Guangzhou Beyond Lighting Co., Limited." },
  { 0x096D, "Guangzhou Xin Yilong Stage Lighting Equipment Co., Limited" },
  { 0x096F, "Shenzhen showho technolgy co.,ltd" },
  { 0x0972, "Holochrom GmbH" },
  { 0x0973, "Guangzhou Eagle Wei Photoelectric Technology Co., Ltd." },
  { 0x0974, "Marumo Electric Co., Ltd." },
  { 0x0975, "KB Design" },
  { 0x0977, "Guangzhou HuaYong Intelligent Technology Co., Ltd." },
  { 0x097A, "Teamboyce Limited" },
  { 0x097D, "Brink Electronics" },
  { 0x097E, "Guangzhou Deyi Lighting Co., Ltd." },
  { 0x097F, "RaumZeitLabor e.V." },
  { 0x0980, "Moog Animatics" },
  { 0x0981, "Luxam, Ltd." },
  { 0x0982, "AC Entertainment Products Ltd." },
  { 0x0986, "ROE Visual Co. Ltd." },
  { 0x0987, "mathertel.de" },
  { 0x0989, "YeGrin Liteworks" },
  { 0x098A, "DongGuan JuYang Electric Co., Ltd" },
  { 0x098B, "Glow Motion Technologies, LLC." },
  { 0x098C, "Shenzhen Longrich Energy Sources Technology Co., Ltd." },
  { 0x098D, "Batmink Ltd." },
  { 0x098E, "Ecosense Lighting Inc" },
  { 0x098F, "Digital Sputnik Lighting" },
  { 0x0990, "Stagelight Holding" },
  { 0x0991, "Guangdong Pomelo Photoelectric Equipment Co., Ltd" },
  { 0x0993, "Shenzhen Trigger digital Technology Co., LTD" },
  { 0x0996, "CCI Power Supplies, LLC" },
  { 0x0997, "Star Iluminacao Computadorizada LTDA" },
  { 0x0999, "Concept Smoke Systems Ltd." },
  { 0x099A, "Aixz International (S)" },
  { 0x099E, "LLC Lighting Technologies production" },
  { 0x09A0, "Rnet Lighting Technology Limited" },
  { 0x09A1, "Veranstaltungstechnik König" },
  { 0x09A2, "Fountain People" },
  { 0x09A3, "Shenzhen Lightlink Display Technology Co., Ltd" },
  { 0x09A5, "Prolight Concepts Ltd." },
  { 0x09AA, "Rushstage Show Lighting Limited" },
  { 0x09AD, "Dongguan Ensure Electronic Technology Co., LTD" },
  { 0x09AE, "Robert Juliat" },
  { 0x09AF, "Autotech Co." },
  { 0x09B0, "Luminii" },
  { 0x09B2, "Guangzhou Hedong Electronics Co., LTD" },
  { 0x09B3, "Aquatique Show Int." },
  { 0x09B4, "Brompton Technology Ltd." },
  { 0x09B5, "XBlack Visual Products" },
  { 0x09B7, "inCon-trol water systems" },
  { 0x09B8, "Prolites S.A.L." },
  { 0x09BB, "Guangzhou Yiyi Technology Co., Ltd." },
  { 0x09BD, "Shenzhen Zhongbo Photoelectric Co., Ltd" },
  { 0x09BE, "Arctos Showlasertechnik GmbH" },
  { 0x09C0, "Guangzhou Rainbow Lighting Equipment CO.,LTD" },
  { 0x09C1, "Argetron Elektrik Elektronik Organizasyon Gida San. ve Dis Tic. Ltd. Sti." },
  { 0x09C3, "Velleman nv" },
  { 0x09C4, "Guangzhou XinHuang Industrial Co., Ltd." },
  { 0x09C6, "Photon Manufacturing" },
  { 0x09C7, "ShoCobra" },
  { 0x09C8, "Crystal Fountains Inc." },
  { 0x09CC, "Motomuto Aps" },
  { 0x09D1, "Environmental Lights" },
  { 0x09D2, "Shenzhen Siwelo Technology Co., LTD" },
  { 0x09D3, "WLPS Wodielite Production Services" },
  { 0x09D4, "Guangzhou Yilaiming Photoelectric Technology Co., Ltd" },
  { 0x09D5, "Shenzhen ImagineVision Technology Limited" },
  { 0x09D6, "Mittomakers" },
  { 0x09D7, "Unilumin Group" },
  { 0x09D8, "Pioneer Lighting Solutions India Pvt Ltd" },
  { 0x09DD, "Planet Innovation Products Inc" },
  { 0x09DE, "Matthias Bauch Software" },
  { 0x09E9, "Starway" },
  { 0x09EE, "Suzhou Pinzong Electronic Technology, CO.,Ltd" },
  { 0x09F8, "UberDisplays" },
  { 0x09FC, "deskontrol electronics" },
  { 0x0A01, "Star-Reach Corporation" },
  { 0x0AAA, "AAA-LUX" },
  { 0x0D0E, "DMX Engineering LLC" },
  { 0x1112, "Zhuhai Bincolor Electronic Technology Co., Ltd." },
  { 0x1113, "SiliconCore Technology, Inc." },
  { 0x1200, "Seekway Technology Limited" },
  { 0x1201, "PRICOM Design" },
  { 0x1202, "Ushio Lighting, Inc." },
  { 0x1203, "Movecat GmbH" },
  { 0x1204, "ARES s.r.l. - Socio Unico" },
  { 0x1205, "Carbon Lighting Limited" },
  { 0x1206, "Hangel Technology Co., Ltd." },
  { 0x1207, "BSK Networks GbR" },
  { 0x1208, "Nuvolight GmbH & Co KG" },
  { 0x1209, "Philippe Bergeron Lights" },
  { 0x120A, "Bulldog Lighting and Events, Inc." },
  { 0x120B, "Brilliant Stages Ltd." },
  { 0x120C, "Shanxi Tian Gong Sheng Optoelectronic Equipment Technology Co." },
  { 0x1211, "Recrealab" },
  { 0x1212, "HPL Light Company" },
  { 0x1221, "SAGITTER-SDJ-Proel" },
  { 0x1222, "SM International" },
  { 0x1234, "ESTA" },
  { 0x12DA, "Newlab S.r.l." },
  { 0x12E0, "Luxlight Skandinavien AB" },
  { 0x12EA, "Kolberg Percussion GmbH" },
  { 0x12F4, "Stage Services Ltd." },
  { 0x12FA, "Hollywood Rentals LLC" },
  { 0x12FE, "City Design S.p.A." },
  { 0x131E, "Blossom Communications Corp." },
  { 0x1337, "Raven Systems Design, Inc." },
  { 0x134D, "VT-Control" },
  { 0x1370, "Ingenieurbuero Stahlkopf" },
  { 0x13AE, "Smartpark Creative Solutions" },
  { 0x1460, "SEIKO Epson Corporation" },
  { 0x1464, "HUMAL Elektroonika OU" },
  { 0x1490, "Grid Show Systems Inc." },
  { 0x14A0, "Intense Lighting, LLC" },
  { 0x14AC, "Zaklad Elektroniczny AGAT s.c." },
  { 0x1501, "Artixium France SAS" },
  { 0x1506, "v2 Lighting Group, Inc." },
  { 0x1507, "LC Handels GmbH" },
  { 0x1508, "TommyDMX" },
  { 0x150C, "ACASS SYSTEMS LLC" },
  { 0x152A, "SHOWTACLE Ltd." },
  { 0x154E, "Fire & Magic" },
  { 0x15A0, "GuangZhou MCSWE Technologies, INC" },
  { 0x15A2, "FEIMEX" },
  { 0x15D0, "Music & Lights S.r.l." },
  { 0x161A, "techKnow Design Ltd." },
  { 0x1626, "LEDsistem Teknolojileri Tic. Ltd. Sti." },
  { 0x1627, "Dynamic Visual Solutions LLC" },
  { 0x162A, "Nerd's Meter" },
  { 0x1690, "awaptec GmbH" },
  { 0x16AE, "Electrone Americas Ltd. Co." },
  { 0x16DC, "Traxon Technologies Ltd." },
  { 0x16E4, "Aboutshow Color Light Co., LTD" },
  { 0x1701, "ARTBOX" },
  { 0x170E, "Serva Transport Systems GmbH" },
  { 0x170F, "Kezun Stage Lighting Equipment Co., Ltd." },
  { 0x174E, "Nordgas SNe-lightingsystem" },
  { 0x1750, "Yuesheng International Limited" },
  { 0x1808, "Guangzhou Jinye Electronic Technology Co., Ltd." },
  { 0x1809, "Rotolight" },
  { 0x180A, "Guangdong Longjoin Optoelectronics Technology Co. Ltd." },
  { 0x180B, "Light stream" },
  { 0x1871, "Smoke Factory GmbH" },
  { 0x1872, "Super-Can Industry Growing Co. Ltd." },
  { 0x1873, "Zhongshan Wellmake Electronic Technology Co., Ltd." },
  { 0x1888, "GUANZHOU KAVON STAGE EQUIPMENT CO., LTD." },
  { 0x18A6, "Steadfast Technology" },
  { 0x1900, "ADJ Products LLC" },
  { 0x1901, "Zhongshan Hiline Electronics Co., Ltd." },
  { 0x1938, "Solid State Luminaires" },
  { 0x1998, "PLS Electronics Ltd." },
  { 0x19B9, "Duralamp S.p.A." },
  { 0x19BA, "Guangzhou Xinzhijie Photoelectric Co., Ltd." },
  { 0x19BB, "Panalux Ltd." },
  { 0x19BC, "Newtone AS" },
  { 0x19F8, "CEZOS Spolka z ograniczona odpowiedzialnoscia, sp.k." },
  { 0x1A00, "LIGEO GmbH" },
  { 0x1A0D, "Cineo Lighting" },
  { 0x1A16, "WADAK GmbH" },
  { 0x1A1A, "ValDim Waterfountains Ltd." },
  { 0x1A3D, "Red Lighting s.r.l." },
  { 0x1AFA, "TMB" },
  { 0x1BB1, "PH Lightning AB" },
  { 0x1BC0, "ALS Stanislaw Binkiewicz" },
  { 0x1BC6, "Studio S Music City" },
  { 0x1C80, "Vehtec Tecnologia Ltda" },
  { 0x1E42, "SSE GmbH" },
  { 0x1E8D, "Moda Light" },
  { 0x1ECF, "Masiero s.r.l." },
  { 0x1ED8, "Antari Lighting And Effects Ltd." },
  { 0x2009, "Zboxes Intelligent Technology (Shanghai) Co., Ltd." },
  { 0x200A, "Vault189 Pty. Ltd." },
  { 0x2011, "Gantom Lighting & Controls" },
  { 0x207F, "Padura Elektronik GmbH" },
  { 0x20A6, "ALADIN Architekturlicht GmbH" },
  { 0x20AB, "IlluminaPi SAS" },
  { 0x20AD, "AZ e-lite Pte Ltd" },
  { 0x20B6, "Alkalite LED Technology Corp" },
  { 0x20B8, "Electron SA" },
  { 0x20B9, "ARRI -- Arnold & Richter Cine Technik GmbH & Co. Betriebs KG" },
  { 0x20BA, "AusChristmasLighting" },
  { 0x20BB, "Able Laser Tech Co., Ltd." },
  { 0x20BC, "Beijing Pargolite Technology Co., Ltd." },
  { 0x20BD, "Foshan Yoline Lighting Equipment Co., Ltd." },
  { 0x20BE, "Uranus Lighting Co., Ltd." },
  { 0x20BF, "Guangzhou Taifeng Stage Lighting Audio Equipment Factory" },
  { 0x20C0, "KappaStyle Productions." },
  { 0x20C1, "BrightBeats, LLC" },
  { 0x20C2, "Demilight" },
  { 0x20C3, "PIXILAB Technologies AB" },
  { 0x2121, "Brother,Brother & Sons Aps" },
  { 0x2122, "BEGLEC NV" },
  { 0x2130, "Bart van Stiphout Electronics & Software" },
  { 0x21A1, "Culture Crew bvba" },
  { 0x21A4, "CHAUVET Lighting" },
  { 0x21A9, "CaptSystemes" },
  { 0x21B3, "Coolon Pty Ltd" },
  { 0x21B4, "CHROMLECH" },
  { 0x21B5, "ChromaCove LLC" },
  { 0x2208, "C.I.M.E.S. (Conception Installation Maintenance En Eclairage & Sonorisation)" },
  { 0x2216, "D-Light Designs, LLC" },
  { 0x2222, "D.E.F. Srl" },
  { 0x2224, "DAS Integrator Pte Ltd" },
  { 0x2239, "Dream Solutions Ltd." },
  { 0x22A0, "EAS SYSTEMS" },
  { 0x22A6, "Elation Lighting Inc." },
  { 0x22A9, "Engineering Solutions Inc." },
  { 0x22AA, "EUTRAC - Intelligent Lighting GmbH" },
  { 0x22AB, "EVC" },
  { 0x22B9, "Etherlight" },
  { 0x2337, "Focon Showtechnic" },
  { 0x2338, "Humanlitech Co., Ltd." },
  { 0x2339, "Sky-Skan Europe GmbH" },
  { 0x233A, "4 Frames Lost UG" },
  { 0x23B2, "Gekko Technology Ltd." },
  { 0x2421, "HB-Laserkomponenten GmbH" },
  { 0x242A, "Hungaroflash" },
  { 0x2432, "Helvar Ltd" },
  { 0x2470, "Hale Microsystems LLC" },
  { 0x24A3, "Lighting Innovation Group AG" },
  { 0x24AA, "IT Ihme" },
  { 0x2500, "RATOC Systems, Inc." },
  { 0x2501, "Xero Manufacturing Pty Limited" },
  { 0x2621, "LEADER LIGHT s.r.o." },
  { 0x2622, "LDDE Vertriebs Gmbh" },
  { 0x2623, "Leonh Hardware Enterprise Inc." },
  { 0x2624, "Lisys Fenyrendszer Zrt." },
  { 0x2626, "LLT Lichttechnik GmbH&CO.KG" },
  { 0x2627, "Guangzhou Megota Technology Co., Ltd." },
  { 0x2630, "Laservision" },
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
  { 0x2827, "Peternet Electronics BVBA" },
  { 0x2829, "PR-Electronic" },
  { 0x2836, "Planungsbuero" },
  { 0x28E1, "MTC maintronic GmbH" },
  { 0x2927, "ROAL Electronics SpA" },
  { 0x297E, "Lifetime Music Academy" },
  { 0x2984, "Getlux Ltd." },
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
  { 0x2B29, "MaNima Technologies BV" },
  { 0x2BA2, "WERPAX bvba" },
  { 0x2BA9, "The White Rabbit Company, Inc." },
  { 0x2BB4, "Williams Electronic Design Ltd." },
  { 0x2C1A, "DMX4ALL GmbH" },
  { 0x2C2A, "XTBA" },
  { 0x2CE0, "Lighting Services Inc." },
  { 0x2DC8, "Stellascapes" },
  { 0x2DDD, "Waylight" },
  { 0x2DDE, "Luminlite Electronics Co., Ltd." },
  { 0x2DDF, "Carpetlight GmbH" },
  { 0x3000, "PushingPixels" },
  { 0x3001, "Elemental LED, Inc." },
  { 0x3002, "Siberian Lighting" },
  { 0x3003, "ChamSix" },
  { 0x3235, "de koster Special Effects" },
  { 0x3331, "DMG Lumiere" },
  { 0x3332, "Teclumen s.r.l." },
  { 0x3333, "NightStarry Electronics Co., LTD." },
  { 0x3388, "Macostar International Ltd." },
  { 0x3434, "Global Design Solutions, Ltd." },
  { 0x3534, "Five4, LLC" },
  { 0x3535, "Changsha Spark Technology Electronics Ltd." },
  { 0x3536, "Cindy Professional Lighting Co., Ltd." },
  { 0x3537, "Novacorp Inc." },
  { 0x3538, "Lightnet sp. z o. o." },
  { 0x361D, "Lumishore Ltd. UK" },
  { 0x3638, "Lumenpulse Lighting Inc." },
  { 0x37D0, "Boogy Brothers Showequipment" },
  { 0x37D7, "Lichttechnik & Sonderbau" },
  { 0x37DD, "Sehr gute GmbH" },
  { 0x3800, "OndeLight LTD" },
  { 0x3801, "SFX Controllers Sweden AB" },
  { 0x3805, "Yifeng Lighting Co., Ltd." },
  { 0x3806, "ACME EFFECTS LTD." },
  { 0x3868, "LanBolight Technology Co., LTD." },
  { 0x3888, "Fly Dragon Lighting Equipment Co.,ltd" },
  { 0x388A, "Guangzhou Yajiang (Yagang - Silver Star) Photoelectric Equipment Ltd." },
  { 0x3A37, "TheOlymp - Networking & InterNet Services" },
  { 0x3AFC, "Black Tank Engineering" },
  { 0x3B10, "NXP Semiconductors B.V." },
  { 0x3B88, "Shenzhen Eastar Electronic Co., Ltd." },
  { 0x3D30, "zactrack Lighting Technologies Gmbh" },
  { 0x400D, "Quasar Science LLC" },
  { 0x4051, "SAN JACK ANALOG HOUSE CO., LTD." },
  { 0x4131, "Altman Stage Lighting" },
  { 0x4141, "AVAB America, Inc." },
  { 0x4142, "Filmgear, Inc." },
  { 0x4143, "AC Lasers" },
  { 0x4144, "ADB - TTV Technologies nv" },
  { 0x4145, "ADE ELETTRONICA srl" },
  { 0x4146, "AUS FX" },
  { 0x4149, "Anidea Engineering, Inc." },
  { 0x414C, "Artistic Licence Engineering Ltd." },
  { 0x414D, "Amptown Lichttechnik GmbH" },
  { 0x414E, "Anytronics Ltd." },
  { 0x4150, "Apogee Lighting" },
  { 0x4151, "Aquarii, Inc." },
  { 0x4153, "Audio Scene" },
  { 0x4154, "Arnold Tang Productions" },
  { 0x4156, "Audio Visual Devices P/L" },
  { 0x4164, "Adelto Industries Ltd." },
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
  { 0x4321, "Design Partners of Canada" },
  { 0x4344, "CDCA Ltd." },
  { 0x4347, "CAST Software" },
  { 0x4349, "C.I.Tronics Lighting Designers Ltda" },
  { 0x434B, "Color Kinetics Inc." },
  { 0x434C, "Crealux GmbH & Co. KG" },
  { 0x434D, "Coemar Spa" },
  { 0x434F, "Cortex Design" },
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
  { 0x4453, "Guangzhou Desheng Lighting Industrial Co., Ltd." },
  { 0x4456, "Devantech Ltd." },
  { 0x4466, "DF elettronica s.r.l." },
  { 0x4469, "Diamante Lighting Srl" },
  { 0x446C, "Guangdong Delos Lighting Industrial Co.,Ltd." },
  { 0x4533, "LEDdynamics, Inc." },
  { 0x453A, "E:cue Control GmbH" },
  { 0x4541, "Engineering Arts" },
  { 0x4543, "EC Elettronica Srl" },
  { 0x4544, "Electronics Diversified LLC" },
  { 0x4545, "EastSun Technology Co. Ltd." },
  { 0x454C, "Ingenieurbuero fuer Nachrichtentechnik in der Studio und Veranstaltungstechnik" },
  { 0x454D, "ELM Video Technology, Inc." },
  { 0x454E, "ENTTEC Pty Ltd" },
  { 0x4552, "EREA" },
  { 0x4553, "ERAL srl" },
  { 0x4554, "Entertainment Technology" },
  { 0x4563, "Les Eclairages Lou Inc." },
  { 0x456C, "Element Labs Inc." },
  { 0x4631, "OKEROAB AB" },
  { 0x464C, "Flashlight/Ampco Holding" },
  { 0x4653, "IT & Eventtechnik Fabian Stumpf" },
  { 0x4656, "Flexvisual" },
  { 0x4657, "The Fountain Workshop Ltd." },
  { 0x4658, "MAGIC FX B.V." },
  { 0x4678, "Global Special Effects" },
  { 0x4744, "Goddard Design Co." },
  { 0x4745, "GPE srl" },
  { 0x4747, "G&G LED Lighting" },
  { 0x474C, "G-LEC Europe GmbH" },
  { 0x4750, "DES" },
  { 0x4752, "Greenlite" },
  { 0x4753, "Guangzhou Haoyang Electronic Co., Ltd." },
  { 0x476C, "General Luminaire (Shanghai) Ltd." },
  { 0x4800, "VOD VISUAL.CO. (UK) Ltd." },
  { 0x4801, "Capture Visualisation AB" },
  { 0x4843, "Horizon Control Inc." },
  { 0x4844, "HxDx" },
  { 0x4845, "Howard Eaton Lighting Ltd." },
  { 0x484C, "HBE Lighting Systems" },
  { 0x484F, "Hollywood Controls Inc." },
  { 0x4856, "Enfis Ltd" },
  { 0x4881, "Rena Electronica B.V." },
  { 0x4941, "inoage GmbH" },
  { 0x4942, "IBEX UK Limited" },
  { 0x4944, "Ingham Designs" },
  { 0x4945, "Insta Elektro GmbH" },
  { 0x4947, "IGuzzini illuminazione spa" },
  { 0x4948, "Ice House Productions" },
  { 0x494C, "I-Lum" },
  { 0x494E, "Interactive Technologies, Inc." },
  { 0x4950, "Interesting Products, Inc." },
  { 0x4951, "IQAir AG" },
  { 0x4952, "Invisible Rival Incorporated" },
  { 0x4953, "Integrated System Technologies Ltd." },
  { 0x4954, "Integrated Theatre, Inc." },
  { 0x4973, "Innovation Solutions Ltd." },
  { 0x4A31, "Joshua 1 Systems Inc." },
  { 0x4A41, "JANUS srl" },
  { 0x4A42, "JB-lighting GmbH" },
  { 0x4A48, "James Harris" },
  { 0x4A4C, "Johnsson Lighting Technologies AB" },
  { 0x4A53, "JSC 'MFG'" },
  { 0x4A54, "James Thomas Engineering" },
  { 0x4A61, "Jands Pty Ltd." },
  { 0x4ACC, "RVL techniek" },
  { 0x4B00, "Gabor Galyas Lighting" },
  { 0x4B42, "KissBox" },
  { 0x4B43, "TmTech Electronic Co.,Ltd." },
  { 0x4B46, "Kino Flo, Inc." },
  { 0x4B4C, "KLH Electronics PLC" },
  { 0x4B4D, "KMX Inc." },
  { 0x4B55, "kuwatec, Inc." },
  { 0x4C20, "LAM32 srl" },
  { 0x4C41, "LaserAnimation Sollinger GmbH" },
  { 0x4C44, "LVDIAN PHOTOELECTRIC SCIENCE TECHNOLOGY LIMITED" },
  { 0x4C45, "Leviton Manufacturing Co., Inc." },
  { 0x4C47, "LightGeist Ltd." },
  { 0x4C4C, "LUMINEX Lighting Control Equipment bvba" },
  { 0x4C4D, "Ultratec Special Effects" },
  { 0x4C50, "LightProcessor Ltd" },
  { 0x4C52, "High End Systems Inc." },
  { 0x4C53, "Licht-, Steuer- und Schaltanlagenbau GmbH (LSS GmbH)" },
  { 0x4C54, "Licht-Technik" },
  { 0x4C55, "LumenRadio AB" },
  { 0x4C56, "LEDValley Technologies Sdn Bhd" },
  { 0x4C57, "LightWild LC" },
  { 0x4C58, "Lex Products Corp." },
  { 0x4C59, "Laser Technology Ltd." },
  { 0x4C5A, "Sumolight GmbH / LightMinded Industries, Inc." },
  { 0x4C5B, "LightLife, Gesellschaft fur audiovisuelle Erlebnisse mbH" },
  { 0x4C64, "LED Team" },
  { 0x4C65, "Legargeant and Associates" },
  { 0x4C69, "LIGHTOLIER" },
  { 0x4C6C, "Lampo Lighting Designers" },
  { 0x4C73, "LSC Lighting Systems (Aust) Pty. Ltd." },
  { 0x4CDC, "acdc LED Ltd." },
  { 0x4CE5, "LED Company s.r.o." },
  { 0x4D41, "MA Lighting Technology GmbH" },
  { 0x4D42, "LAN Systems--Midibox project" },
  { 0x4D44, "Les Generateurs de brouillard MDG Fog Generators Ltd." },
  { 0x4D4C, "Mode Lighting (UK) Ltd." },
  { 0x4D50, "Martin Professional A/S" },
  { 0x4D54, "medien technik cords" },
  { 0x4D56, "Avolites Ltd." },
  { 0x4D58, "MX design" },
  { 0x4D5A, "Covert Science GmbH" },
  { 0x4D61, "MARTINI S.p.A." },
  { 0x4D77, "Mueller Elektronik" },
  { 0x4E41, "Company NA" },
  { 0x4E4A, "NJD Electronics" },
  { 0x4E4C, "NOVALIGHT S.r.l." },
  { 0x4E57, "AIM Northwest" },
  { 0x4E69, "Niko" },
  { 0x4F41, "Oase GmbH" },
  { 0x4F43, "Offstage Controls (formerly Obsidian Control)" },
  { 0x4F4C, "DDS Elettronica" },
  { 0x4F75, "Outsight Pty Ltd." },
  { 0x5000, "http://www.orangepi-dmx.org" },
  { 0x5001, "Hua Yuan Ke Tai" },
  { 0x5002, "Shanghai Shylon Optoelectronic Technology Co., Ltd." },
  { 0x5003, "Futlight Optoelectronics Co.,Ltd." },
  { 0x5004, "Shanghai Sansi Electronic Engineering Co.,Ltd" },
  { 0x5005, "MEDIAM Ltd. (Modus brand)" },
  { 0x5006, "ENEDO Power SpA" },
  { 0x5007, "Alfalite" },
  { 0x5008, "Chengdu Chengyu Electronic Technology Co., Ltd." },
  { 0x5009, "Izzro Optoelectronics Technology Co., Ltd." },
  { 0x500A, "AU Optronics Corporation (AUO)" },
  { 0x500B, "WebKat Eletronic's" },
  { 0x500C, "L.E.C. Societe Lyonnaise D' Equipement Et De Controle" },
  { 0x5010, "Shenzhen Viye Technology Co., Ltd." },
  { 0x5011, "Guangzhou Skydance Co., Ltd." },
  { 0x5017, "American Lighting" },
  { 0x5040, "Guangzhou Color Imagination LED Lighting Ltd." },
  { 0x5041, "Philips Entertainment Lighting Asia" },
  { 0x5043, "Pathway Connectivity Inc." },
  { 0x504C, "Peperoni Lighting-Solutions" },
  { 0x504D, "Peter Meyer Project Management Adviser GmbH" },
  { 0x504E, "Uni-Bright nv" },
  { 0x5050, "Newton Engineering and Design Group LLC" },
  { 0x5051, "PDQ Manufacturing, Inc" },
  { 0x5052, "Production Resource Group" },
  { 0x5053, "Philips Selecon" },
  { 0x5058, "PXM s.c." },
  { 0x5062, "LED, Inc." },
  { 0x5065, "Peradise" },
  { 0x5066, "Pfannenberg GmbH" },
  { 0x5068, "Philips Lighting BV" },
  { 0x5070, "Show Light Oy" },
  { 0x5071, "Raindrop-Media" },
  { 0x5072, "ARRI Rental Deutschland GmbH" },
  { 0x5075, "Pulsar Light of Cambridge Ltd." },
  { 0x5099, "Altec Di Gregorio Andrea" },
  { 0x5100, "Luxibel" },
  { 0x5101, "LBT Electronics Pvt. Ltd." },
  { 0x5102, "INDATA d.o.o." },
  { 0x512D, "DJPOWER ELECTRONIC STAGE LIGHTING FIXTURE FACTORY (GUANGZHOU)" },
  { 0x5149, "JAP Optoelectronic Ltd." },
  { 0x514D, "QMAXZ lighting" },
  { 0x5153, "QuickSilver Controls, Inc." },
  { 0x5168, "Shenzhen Sunricher Technology Co.,Ltd." },
  { 0x516C, "Quicklights" },
  { 0x51D7, "Innovative Dimmers LLC (Ratpac dimmers)" },
  { 0x51D8, "Amperor Electronics (Shenzhen) Co., Ltd." },
  { 0x5200, "Shenzhen Aotian Technology Co. , Ltd." },
  { 0x5201, "Crestron Electronics, Inc." },
  { 0x5202, "Shenzhen Lianjin Photoelectricity Co., Ltd." },
  { 0x5244, "Revolution Display" },
  { 0x524C, "Radical Lighting Ltd." },
  { 0x524D, "RUIZ TECH" },
  { 0x524E, "RNC Systems Inc." },
  { 0x5250, "RootPath Ltd." },
  { 0x5252, "RoscoLab Ltd." },
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
  { 0x5353, "Sean Sill" },
  { 0x5354, "Stagetronics Ltda" },
  { 0x5355, "Lochmun Ltd." },
  { 0x5356, "OOO SAMLIGHT" },
  { 0x5363, "SpaceCannon vH" },
  { 0x5368, "ShowCAD Control Systems Ltd." },
  { 0x536C, "StageLine Electronic" },
  { 0x5370, "Chroma-Q" },
  { 0x5374, "STG-Beikirch Industrieelektronik + Sicherheitstechnik GmbH & Co. KG" },
  { 0x5376, "SV-wtu eU" },
  { 0x5377, "SWISSON AG" },
  { 0x5379, "Singularity (UK) Ltd." },
  { 0x53A8, "Simon Tech" },
  { 0x5431, "AUTOLUX Handels- und ProduktionsgmbH" },
  { 0x5441, "TecArt Lighting" },
  { 0x5444, "Technographic Displays Ltd." },
  { 0x5445, "TESI Elettronica srl" },
  { 0x544C, "Tempest Lighting Inc." },
  { 0x5453, "TalentStorm Enterprises, Inc." },
  { 0x5454, "TamaTech Labo Company Ltd," },
  { 0x5459, "TDE-Lighttech B.V." },
  { 0x5550, "UP-LUX Eletronica Ltda." },
  { 0x5555, "Martin Sukale Medientechnik GbR" },
  { 0x55AA, "Emilum GmbH" },
  { 0x564C, "Vari-Lite, Inc." },
  { 0x5651, "Vision Quest Lighting Inc." },
  { 0x5652, "Megapixel Visual Reality" },
  { 0x5653, "Viso Systems Aps" },
  { 0x5655, "Shenzhen CAS VU Technologies Co., Ltd." },
  { 0x5744, "W-DEV" },
  { 0x5746, "Wildfire, Inc." },
  { 0x5747, "Wenger / JR Clancy" },
  { 0x5753, "Wireless Solution Sweden AB" },
  { 0x5754, "LIGHTMAN (Interlite AB)" },
  { 0x5759, "Wybron, Inc." },
  { 0x584C, "X-Laser" },
  { 0x584D, "Xtraordinary Musical Accolade Systems" },
  { 0x5858, "Illuminance Technologies" },
  { 0x5865, "XENON ARCHITECTURAL LIGHTING" },
  { 0x586C, "Eurolumen (Shanghai) Lighting Co., LTD" },
  { 0x586D, "www.doityourselfchristmas.com hobbyists" },
  { 0x5888, "Plsao Optoelectronics Technology Co., Ltd." },
  { 0x5A53, "Zingerli Show Engineering" },
  { 0x5C40, "OXO" },
  { 0x5D00, "L1 Inc." },
  { 0x5D01, "MTS Medientechnik GmbH" },
  { 0x5D02, "Underwater Lights Limited" },
  { 0x5DAC, "Mediatec Group" },
  { 0x5E5D, "Multisenses GmbH" },
  { 0x5E5E, "Converging Systems Inc." },
  { 0x6100, "Krobox Sdn Bhd" },
  { 0x610A, "Visenge Pty. Ltd" },
  { 0x6123, "CMYLight (S) Pte. Ltd." },
  { 0x6124, "Fiilex" },
  { 0x614C, "Alektra AB" },
  { 0x6154, "Advatek Lighting" },
  { 0x6164, "AVID Labs" },
  { 0x616C, "Advanced Lighting Systems" },
  { 0x6200, "LUCITAG Ltd." },
  { 0x6201, "NuDelta Digital, LLC" },
  { 0x6202, "ESCO Sp. z o.o." },
  { 0x6203, "Flektor" },
  { 0x6204, "Shenzhen Absen Optoelectronic Co., Ltd" },
  { 0x6205, "Zhuhai Ltech Technology Co., Ltd." },
  { 0x6206, "Lighting Innovation Company, LLC" },
  { 0x6273, "B&S Elektronische Geräte GmbH" },
  { 0x6342, "Mega Systems Inc." },
  { 0x6364, "CDS advanced technology bv" },
  { 0x641A, "Heliospectra AB" },
  { 0x644C, "bdL KG" },
  { 0x6461, "Digilin Australia" },
  { 0x6464, "Dangeross Design" },
  { 0x646C, "dilitronics GmbH" },
  { 0x646F, "eldoLED BV" },
  { 0x64B9, "Finelite, Inc." },
  { 0x6542, "eBrain GmbH" },
  { 0x6543, "LES-TV Ltd." },
  { 0x6547, "euroGenie" },
  { 0x6553, "EtherShow" },
  { 0x6555, "Shantea Controls" },
  { 0x6565, "Stratus Systems LLC" },
  { 0x656C, "ELC lighting" },
  { 0x6573, "Environmental Lighting Solutions" },
  { 0x6574, "Electronic Theatre Controls, Inc." },
  { 0x6576, "eventa Aktiengesellschaft" },
  { 0x6600, "WANTS Electronics Co. Ltd." },
  { 0x6644, "Sunlab Technologies S.L." },
  { 0x666D, "MAD-Effects" },
  { 0x6673, "Freescale Semiconductor U.K. Ltd." },
  { 0x6756, "Lumisia Co., Ltd." },
  { 0x676C, "GLP German Light Products GmbH" },
  { 0x67F0, "Toshiba Lighting & Technology Corporation" },
  { 0x6816, "ChamberPlus Co., Ltd" },
  { 0x6864, "James Embedded Systems Engineering (JESE Ltd)" },
  { 0x6865, "Hubbell Entertainment, Inc." },
  { 0x686C, "HERA LED" },
  { 0x694C, "iLight Technologies Inc" },
  { 0x6969, "Better Way Lighting" },
  { 0x6974, "Ittermann electronic GmbH" },
  { 0x6A6A, "Roxx GmbH" },
  { 0x6A6B, "JPK Systems Limited" },
  { 0x6B64, "Key Delfin" },
  { 0x6B69, "Magical Fountain SA de CV (Magic Fountain)" },
  { 0x6BEA, "Remoticom BV" },
  { 0x6BED, "Planar Systems, Inc." },
  { 0x6BEE, "Ephesus Lighting" },
  { 0x6BEF, "Shenzhen Ifountain Technology Ltd." },
  { 0x6C6D, "Zumtobel Lighting GmbH" },
  { 0x6C78, "Claude Heintz Design" },
  { 0x6C92, "Ambra Elettronica s.r.l." },
  { 0x6D61, "MAL Effekt-Technik GmbH" },
  { 0x6D62, "MBN GmbH" },
  { 0x6D63, "Sein & Schein GmbH" },
  { 0x6E00, "LEDeco solution, s.r.o." },
  { 0x6F00, "Guangzhou Huaying Stage Lighting Equipment Co. Ltd." },
  { 0x6F01, "DAVAI!JPL" },
  { 0x6F02, "hazebase (Uta Raabe e.K.)" },
  { 0x6FEA, "Lumina Visual Productions" },
  { 0x6FEB, "Insight Lighting" },
  { 0x6FEC, "Arc Lighting Co. Ltd." },
  { 0x6FED, "Explorentis" },
  { 0x6FEE, "fos design sp. z o.o." },
  { 0x7000, "Nippon Ceramic Co., Ltd." },
  { 0x700A, "Guangzhou Leemc Lighting Tech., Co., Ltd." },
  { 0x700B, "Vice Lighting DWC LLC" },
  { 0x7068, "Pharos Architectural Controls" },
  { 0x7070, "SBT GmbH" },
  { 0x7072, "Pr-Lighting Ltd." },
  { 0x7078, "PixelRange Inc." },
  { 0x70F0, "Pangolin Laser Systems, Inc." },
  { 0x7151, "The Light Source, Inc." },
  { 0x7363, "Sean Christopher FX" },
  { 0x7365, "Ballantyne Strong Inc." },
  { 0x736C, "Strand Lighting Ltd." },
  { 0x7400, "Danalux" },
  { 0x7401, "Harvatek Corporation" },
  { 0x7402, "Chris Kallas" },
  { 0x7403, "Yenrich Technology Corporation" },
  { 0x7764, "WET" },
  { 0x7765, "MKT engineering GmbH & Co. KG" },
  { 0x7777, "Develtron A/S" },
  { 0x7788, "DigitaLicht AG" },
  { 0x780E, "Mole-Richardson Co." },
  { 0x783A, "Audiolux Devices LLC" },
  { 0x786C, "XLN-t bvba" },
  { 0x7888, "Tontron Photoelectric Co., Limited" },
  { 0x78B4, "LED Flex Limited" },
  { 0x7900, "Leprecon / CAE, Inc." },
  { 0x79BC, "DC Reactive" },
  { 0x7A70, "Open Lighting" },
  { 0x7AA0, "Anaren Inc." },
  { 0x7AAA, "WEAD (Wagner Electronic and Design)" },
  { 0x7AAB, "Hyundai Fomex Co., Ltd." },
  { 0x7B1B, "DimLight Ltd." },
  { 0x7D00, "expanseElectronics" },
  { 0x7D61, "HMB|TEC GmbH" },
  { 0x7DE7, "Guangzhou ILightings Equipment Co., Ltd." },
  { 0x7DE8, "Shenzhen LAMP Technology Co., Ltd." },
  { 0x7DEA, "RobLight A/S" },
  { 0x7DEB, "Krypton" },
  { 0x7DEE, "zencontrol Pty Ltd" },
  { 0x7EE7, "Arthur Digital Solutions Kft" },
  { 0x7EE8, "Guangzhou Yingfeng Lighting Equipment Co., Ltd." },
  { 0x7EE9, "Technology Kitchen" },
  { 0x7EEA, "Cartwright Engineering" },
  { 0x7EEB, "mylaserpage" },
  { 0x7EEC, "SHENZHEN LP Display" },
  { 0x7EED, "Look Solutions GmbH & Co. KG" },
  { 0x7EEE, "General Lighting Electronic Co., Ltd." },
  { 0x7EEF, "Huizhou Mounteck Technology Co., Ltd." },
  { 0x7FF0, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FF1, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FF2, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FF3, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FF4, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FF5, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FF6, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FF7, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FF8, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FF9, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FFA, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FFB, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FFC, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FFD, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FFE, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0x7FFF, "RESERVED FOR PROTOTYPING/EXPERIMENTAL USE ONLY" },
  { 0xFFFF, "ESTA" },
  { 0,      NULL }
};
static value_string_ext artnet_esta_man_vals_ext = VALUE_STRING_EXT_INIT(artnet_esta_man_vals);

static const value_string artnet_indicator_state_vals[] = {
  { 0x00, "unknown" },
  { 0x01, "Locate Mode" },
  { 0x02, "Mute Mode" },
  { 0x03, "Normal Mode" },
  { 0,      NULL }
};

static const value_string artnet_rom_booted_vals[] = {
  { 0x00, "Normal boot (from flash)" },
  { 0x01, "Booted from ROM" },
  { 0,    NULL }
};

static const value_string artnet_port_prog_auth_vals[] = {
  { 0x00, "unknown" },
  { 0x01, "front panel" },
  { 0x02, "network" },
  { 0x03, "unused" },
  { 0,      NULL }
};

#define ARTNET_PT_DMX512     0x00
#define ARTNET_PT_MIDI       0x01
#define ARTNET_PT_AVAB       0x02
#define ARTNET_PT_CMX        0x03
#define ARTNET_PT_ADB625     0x04
#define ARTNET_PT_ARTNET     0x05
#define ARTNET_PT_DALI       0x06

#define ARTNET_PT_DIR_NONE   0x00
#define ARTNET_PT_DIR_INPUT  0x40
#define ARTNET_PT_DIR_OUTPUT 0x80
#define ARTNET_PT_DIR_BIDIR  0xc0

static const value_string artnet_port_type_vals[] = {
  { ARTNET_PT_DIR_NONE                     , "Not present" },
  { ARTNET_PT_DIR_INPUT  | ARTNET_PT_DMX512, "DMX512 -> Art-Net" },
  { ARTNET_PT_DIR_INPUT  | ARTNET_PT_MIDI,   "MIDI -> Art-Net" },
  { ARTNET_PT_DIR_INPUT  | ARTNET_PT_AVAB,   "Avab -> Art-Net" },
  { ARTNET_PT_DIR_INPUT  | ARTNET_PT_CMX,    "Colortran CMX -> Art-Net" },
  { ARTNET_PT_DIR_INPUT  | ARTNET_PT_ADB625, "ADB 62.5 -> Art-Net" },
  { ARTNET_PT_DIR_INPUT  | ARTNET_PT_ARTNET, "Art-Net -> Art-Net" },
  { ARTNET_PT_DIR_INPUT  | ARTNET_PT_DALI,   "DALI -> Art-Net" },
  { ARTNET_PT_DIR_OUTPUT | ARTNET_PT_DMX512, "Art-Net -> DMX512" },
  { ARTNET_PT_DIR_OUTPUT | ARTNET_PT_MIDI,   "Art-Net -> MIDI" },
  { ARTNET_PT_DIR_OUTPUT | ARTNET_PT_AVAB,   "Art-Net -> Avab" },
  { ARTNET_PT_DIR_OUTPUT | ARTNET_PT_CMX,    "Art-Net -> Colortran CMX" },
  { ARTNET_PT_DIR_OUTPUT | ARTNET_PT_ADB625, "Art-Net -> ADB 62.5" },
  { ARTNET_PT_DIR_OUTPUT | ARTNET_PT_ARTNET, "Art-Net -> Art-Net" },
  { ARTNET_PT_DIR_OUTPUT | ARTNET_PT_DALI,   "Art-Net -> DALI" },
  { ARTNET_PT_DIR_BIDIR  | ARTNET_PT_DMX512, "Art-Net <-> DMX512" },
  { ARTNET_PT_DIR_BIDIR  | ARTNET_PT_MIDI,   "Art-Net <-> MIDI" },
  { ARTNET_PT_DIR_BIDIR  | ARTNET_PT_AVAB,   "Art-Net <-> Avab" },
  { ARTNET_PT_DIR_BIDIR  | ARTNET_PT_CMX,    "Art-Net <-> Colortran CMX" },
  { ARTNET_PT_DIR_BIDIR  | ARTNET_PT_ADB625, "Art-Net <-> ADB 62.5" },
  { ARTNET_PT_DIR_BIDIR  | ARTNET_PT_ARTNET, "Art-Net <-> Art-Net" },
  { ARTNET_PT_DIR_BIDIR  | ARTNET_PT_DALI,   "Art-Net <-> DALI" },
  { 0,      NULL }
};


#define ARTNET_AC_NONE           0x00
#define ARTNET_AC_CANCEL_MERGE   0x01
#define ARTNET_AC_LED_NORMAL     0x02
#define ARTNET_AC_LED_MUTE       0x03
#define ARTNET_AC_LED_LOCATE     0x04
#define ARTNET_AC_RESET_RX_FLAGS 0x05
#define ARTNET_AC_ANALYSIS_ON    0x06
#define ARTNET_AC_ANALYSIS_OFF   0x07
#define ARTNET_AC_FAIL_HOLD      0x08
#define ARTNET_AC_FAIL_ZERO      0x09
#define ARTNET_AC_FAIL_FULL      0x0A
#define ARTNET_AC_FAIL_SCENE     0x0B
#define ARTNET_AC_FAIL_RECORD    0x0C
#define ARTNET_AC_MERGE_LTP0     0x10
#define ARTNET_AC_MERGE_LTP1     0x11
#define ARTNET_AC_MERGE_LTP2     0x12
#define ARTNET_AC_MERGE_LTP3     0x13
#define ARTNET_AC_MERGE_HTP0     0x50
#define ARTNET_AC_MERGE_HTP1     0x51
#define ARTNET_AC_MERGE_HTP2     0x52
#define ARTNET_AC_MERGE_HTP3     0x53
#define ARTNET_AC_ARTNET_SEL0    0x60
#define ARTNET_AC_ARTNET_SEL1    0x61
#define ARTNET_AC_ARTNET_SEL2    0x62
#define ARTNET_AC_ARTNET_SEL3    0x63
#define ARTNET_AC_ACN_SEL0       0x70
#define ARTNET_AC_ACN_SEL1       0x71
#define ARTNET_AC_ACN_SEL2       0x72
#define ARTNET_AC_ACN_SEL3       0x73
#define ARTNET_AC_CLEAR_OP0      0x90
#define ARTNET_AC_CLEAR_OP1      0x91
#define ARTNET_AC_CLEAR_OP2      0x92
#define ARTNET_AC_CLEAR_OP3      0x93
#define ARTNET_AC_STYLE_DELTA0   0xA0
#define ARTNET_AC_STYLE_DELTA1   0xA1
#define ARTNET_AC_STYLE_DELTA2   0xA2
#define ARTNET_AC_STYLE_DELTA3   0xA3
#define ARTNET_AC_STYLE_CONST0   0xB0
#define ARTNET_AC_STYLE_CONST1   0xB1
#define ARTNET_AC_STYLE_CONST2   0xB2
#define ARTNET_AC_STYLE_CONST3   0xB3
#define ARTNET_AC_RDM_ENABLE0    0xC0
#define ARTNET_AC_RDM_ENABLE1    0xC1
#define ARTNET_AC_RDM_ENABLE2    0xC2
#define ARTNET_AC_RDM_ENABLE3    0xC3
#define ARTNET_AC_RDM_DISABLE0   0xD0
#define ARTNET_AC_RDM_DISABLE1   0xD1
#define ARTNET_AC_RDM_DISABLE2   0xD2
#define ARTNET_AC_RDM_DISABLE3   0xD3

static const value_string artnet_address_command_vals[] = {
  { ARTNET_AC_NONE,            "No Action" },
  { ARTNET_AC_CANCEL_MERGE,    "Cancel merge" },
  { ARTNET_AC_LED_NORMAL,      "LED Normal" },
  { ARTNET_AC_LED_MUTE,        "LED Mute" },
  { ARTNET_AC_LED_LOCATE,      "LED Locate" },
  { ARTNET_AC_RESET_RX_FLAGS,  "Reset SIP text" },
  { ARTNET_AC_ANALYSIS_ON,     "Enable analysis/debugging" },
  { ARTNET_AC_ANALYSIS_OFF,    "Disable analysis/debugging" },
  { ARTNET_AC_FAIL_HOLD,       "AcFail: Set outputs to hold last state" },
  { ARTNET_AC_FAIL_ZERO,       "AcFail: Set outputs to zero" },
  { ARTNET_AC_FAIL_FULL,       "AcFail: Set outputs to full" },
  { ARTNET_AC_FAIL_SCENE,      "AcFail: Set outputs to failsafe scene" },
  { ARTNET_AC_FAIL_RECORD,     "AcFail: Record outputs as failsafe scene" },
  { ARTNET_AC_MERGE_LTP0,      "DMX port 1 LTP" },
  { ARTNET_AC_MERGE_LTP1,      "DMX port 2 LTP" },
  { ARTNET_AC_MERGE_LTP2,      "DMX port 3 LTP" },
  { ARTNET_AC_MERGE_LTP3,      "DMX port 4 LTP" },
  { ARTNET_AC_MERGE_HTP0,      "DMX port 1 HTP" },
  { ARTNET_AC_MERGE_HTP1,      "DMX port 2 HTP" },
  { ARTNET_AC_MERGE_HTP2,      "DMX port 3 HTP" },
  { ARTNET_AC_MERGE_HTP3,      "DMX port 4 HTP" },
  { ARTNET_AC_ARTNET_SEL0,     "DMX port 1 Art-Net -> DMX/RDM" },
  { ARTNET_AC_ARTNET_SEL1,     "DMX port 2 Art-Net -> DMX/RDM" },
  { ARTNET_AC_ARTNET_SEL2,     "DMX port 3 Art-Net -> DMX/RDM" },
  { ARTNET_AC_ARTNET_SEL3,     "DMX port 4 Art-Net -> DMX/RDM" },
  { ARTNET_AC_ACN_SEL0,        "DMX port 1 Art-Net -> RDM, sACN -> DMX" },
  { ARTNET_AC_ACN_SEL1,        "DMX port 2 Art-Net -> RDM, sACN -> DMX" },
  { ARTNET_AC_ACN_SEL2,        "DMX port 3 Art-Net -> RDM, sACN -> DMX" },
  { ARTNET_AC_ACN_SEL3,        "DMX port 4 Art-Net -> RDM, sACN -> DMX" },
  { ARTNET_AC_CLEAR_OP0,       "Clear DMX port 1" },
  { ARTNET_AC_CLEAR_OP1,       "Clear DMX port 2" },
  { ARTNET_AC_CLEAR_OP2,       "Clear DMX port 3" },
  { ARTNET_AC_CLEAR_OP3,       "Clear DMX port 4" },
  { ARTNET_AC_STYLE_DELTA0,    "DMX port 1 delta mode" },
  { ARTNET_AC_STYLE_DELTA1,    "DMX port 2 delta mode" },
  { ARTNET_AC_STYLE_DELTA2,    "DMX port 3 delta mode" },
  { ARTNET_AC_STYLE_DELTA3,    "DMX port 4 delta mode" },
  { ARTNET_AC_STYLE_CONST0,    "DMX port 1 constant mode" },
  { ARTNET_AC_STYLE_CONST1,    "DMX port 2 constant mode" },
  { ARTNET_AC_STYLE_CONST2,    "DMX port 3 constant mode" },
  { ARTNET_AC_STYLE_CONST3,    "DMX port 4 constant mode" },
  { ARTNET_AC_RDM_ENABLE0,     "DMX port 1 enable RDM" },
  { ARTNET_AC_RDM_ENABLE1,     "DMX port 2 enable RDM" },
  { ARTNET_AC_RDM_ENABLE2,     "DMX port 3 enable RDM" },
  { ARTNET_AC_RDM_ENABLE3,     "DMX port 4 enable RDM" },
  { ARTNET_AC_RDM_DISABLE0,    "DMX port 1 disable RDM" },
  { ARTNET_AC_RDM_DISABLE1,    "DMX port 2 disable RDM" },
  { ARTNET_AC_RDM_DISABLE2,    "DMX port 3 disable RDM" },
  { ARTNET_AC_RDM_DISABLE3,    "DMX port 4 disable RDM" },
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

#define ARTNET_TRC_TOD_FULL    0x00

static const value_string artnet_tod_request_command_vals[] = {
  { ARTNET_TRC_TOD_FULL,    "TodFull" },
  { 0,                      NULL }
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

static const char * artnet_poll_reply_node_report_regex = "^#([A-Fa-f0-9]+) \\[([0-9]+)\\] (.*)";

static const value_string vals_artnet_poll_reply_style[] = {
  { 0x00, "StNode (Art-Net to DMX device)" },
  { 0x01, "StController (Lighting console)" },
  { 0x02, "StMedia (Medial server)" },
  { 0x03, "StRoute (Network routing device)" },
  { 0x04, "StBackup (Backup device)" },
  { 0x05, "StConfig (Configuration or diagnostic tool)" },
  { 0x06, "StVisual (Visualizer)" },
  { 0x00, NULL },
};

static const value_string vals_artnet_poll_reply_tx_proto[] = {
  { 0x00, "Art-Net" },
  { 0x01, "sACN" },
  { 0x00, NULL },
};

static const value_string artnet_poll_reply_status2_bigaddr_supported_vals[] = {
  { 0x00, "8bit Port-Address" },
  { 0x01, "15bit Port-Address" },
  { 0x00, NULL }
};

static const value_string vals_artnet_poll_reply_output_style[] = {
  { 0x00, "delta" },
  { 0x01, "continuous" },
  { 0x00, NULL }
};

static const value_string vals_artnet_poll_reply_status3_failsafe_state[] = {
  { 0x00, "Hold last state" },
  { 0x01, "All outputs to zero" },
  { 0x02, "All outputs to full" },
  { 0x03, "Playback failsafe scene" },
  { 0x00, NULL }
};

static const value_string vals_artnet_poll_reply_node_report_status_code[] = {
  { 0x0000, "RcDebug" },
  { 0x0001, "RcPowerOk" },
  { 0x0002, "RcPowerFail" },
  { 0x0003, "RcSocketWr1" },
  { 0x0004, "RcParseFail" },
  { 0x0005, "RcUdpFail" },
  { 0x0006, "RcShNameOk" },
  { 0x0007, "RcLoNameOk" },
  { 0x0008, "RcDmxError" },
  { 0x0009, "RcDmxUdpFull" },
  { 0x000A, "RcDmxRxFull" },
  { 0x000B, "RcSwitchErr" },
  { 0x000C, "RcConfigErr" },
  { 0x000D, "RcDmxShort" },
  { 0x000E, "RcFirmwareFail" },
  { 0x000F, "RcUserFail" },
  { 0x0010, "RcFactoryRes" },
  { 0x0000, NULL }
};

/* Define the artnet proto */
static int proto_artnet;
expert_module_t* expert_artnet;

/* general */
static int hf_artnet_filler;
static int hf_artnet_spare;
static int hf_artnet_data;
static int hf_artnet_excess_bytes;

/* Header */
static int hf_artnet_header;
static int hf_artnet_header_id;
static int hf_artnet_header_opcode;
static int hf_artnet_header_protver;

/* ArtPoll */
static int hf_artnet_poll;
static int hf_artnet_poll_talktome;
static int hf_artnet_poll_talktome_reply_change;
static int hf_artnet_poll_talktome_diag;
static int hf_artnet_poll_talktome_diag_unicast;
static int hf_artnet_poll_talktome_vlc;
static int hf_artnet_poll_talktome_targeted;

static int hf_artnet_poll_diag_priority;
static int hf_artnet_poll_target_port_top;
static int hf_artnet_poll_target_port_bottom;
static int hf_artnet_poll_esta_man;
static int hf_artnet_poll_oem;

static int ett_artnet_poll_talktome;

static int * const artnet_poll_talktome_fields[] = {
  &hf_artnet_poll_talktome_reply_change,
  &hf_artnet_poll_talktome_diag,
  &hf_artnet_poll_talktome_diag_unicast,
  &hf_artnet_poll_talktome_vlc,
  &hf_artnet_poll_talktome_targeted,
  NULL
};

static const value_string artnet_talktome_diag_unicast_vals[] = {
  { 0x00, "Broadcast" },
  { 0x01, "Unicast" },
  { 0x00, NULL }
};

static const value_string artnet_talktome_diag_priority_vals[] = {
  { 0x00, "DpAll" },
  { 0x10, "DpLow" },
  { 0x40, "DpMed" },
  { 0x80, "DpHigh" },
  { 0xe0, "DpCritical" },
  { 0xf0, "DpVolatile" },
  { 0x00, NULL }
};

/* ArtPollReply */
static int hf_artnet_poll_reply;
static int hf_artnet_poll_reply_ip_address;
static int hf_artnet_poll_reply_port_nr;
static int hf_artnet_poll_reply_versinfo;
static int hf_artnet_poll_reply_netswitch;
static int hf_artnet_poll_reply_subswitch;
static int hf_artnet_poll_reply_oem;
static int hf_artnet_poll_reply_ubea_version;
static int hf_artnet_poll_reply_status;
static int hf_artnet_poll_reply_status_ubea_present;
static int hf_artnet_poll_reply_status_rdm_supported;
static int hf_artnet_poll_reply_status_rom_booted;
static int hf_artnet_poll_reply_status_port_prog;
static int hf_artnet_poll_reply_status_indicator;

static int hf_artnet_poll_reply_esta_man;
static int hf_artnet_poll_reply_short_name;
static int hf_artnet_poll_reply_long_name;
static int hf_artnet_poll_reply_node_report;
static int hf_artnet_poll_reply_port_info;
static int hf_artnet_poll_reply_num_ports;
static int hf_artnet_poll_reply_port_types;
static int hf_artnet_poll_reply_port_types_1;
static int hf_artnet_poll_reply_port_types_2;
static int hf_artnet_poll_reply_port_types_3;
static int hf_artnet_poll_reply_port_types_4;
static int hf_artnet_poll_reply_good_input;
static int hf_artnet_poll_reply_good_input_1;
static int hf_artnet_poll_reply_good_input_2;
static int hf_artnet_poll_reply_good_input_3;
static int hf_artnet_poll_reply_good_input_4;
static int hf_artnet_poll_reply_good_output;
static int hf_artnet_poll_reply_good_output_1;
static int hf_artnet_poll_reply_good_output_2;
static int hf_artnet_poll_reply_good_output_3;
static int hf_artnet_poll_reply_good_output_4;
static int hf_artnet_poll_reply_good_output_b;
static int hf_artnet_poll_reply_good_output_b_1;
static int hf_artnet_poll_reply_good_output_b_2;
static int hf_artnet_poll_reply_good_output_b_3;
static int hf_artnet_poll_reply_good_output_b_4;
static int hf_artnet_poll_reply_good_output_tx_proto;
static int hf_artnet_poll_reply_good_output_merge_ltp;
static int hf_artnet_poll_reply_good_output_short;
static int hf_artnet_poll_reply_good_output_merge_artnet;
static int hf_artnet_poll_reply_good_output_dmx_text;
static int hf_artnet_poll_reply_good_output_dmx_sip;
static int hf_artnet_poll_reply_good_output_dmx_test;
static int hf_artnet_poll_reply_good_output_data;
static int hf_artnet_poll_reply_good_output_style;
static int hf_artnet_poll_reply_good_output_rdm;
static int hf_artnet_poll_reply_swin;
static int hf_artnet_poll_reply_swin_1;
static int hf_artnet_poll_reply_swin_2;
static int hf_artnet_poll_reply_swin_3;
static int hf_artnet_poll_reply_swin_4;
static int hf_artnet_poll_reply_swin_1_universe;
static int hf_artnet_poll_reply_swin_2_universe;
static int hf_artnet_poll_reply_swin_3_universe;
static int hf_artnet_poll_reply_swin_4_universe;
static int hf_artnet_poll_reply_swout;
static int hf_artnet_poll_reply_swout_1;
static int hf_artnet_poll_reply_swout_2;
static int hf_artnet_poll_reply_swout_3;
static int hf_artnet_poll_reply_swout_4;
static int hf_artnet_poll_reply_swout_1_universe;
static int hf_artnet_poll_reply_swout_2_universe;
static int hf_artnet_poll_reply_swout_3_universe;
static int hf_artnet_poll_reply_swout_4_universe;
static int hf_artnet_poll_reply_sacnprio;
static int hf_artnet_poll_reply_swmacro;
static int hf_artnet_poll_reply_swremote;
static int hf_artnet_poll_reply_style;
static int hf_artnet_poll_reply_mac;
static int hf_artnet_poll_reply_bind_ip_address;
static int hf_artnet_poll_reply_bind_index;
static int hf_artnet_poll_reply_status2;
static int hf_artnet_poll_reply_status2_web_supported;
static int hf_artnet_poll_reply_status2_dhcp_used;
static int hf_artnet_poll_reply_status2_dhcp_supported;
static int hf_artnet_poll_reply_status2_bigaddr_supported;
static int hf_artnet_poll_reply_status2_sacn_supported;
static int hf_artnet_poll_reply_status2_squawking;
static int hf_artnet_poll_reply_status2_output_switching_supported;
static int hf_artnet_poll_reply_status2_control_rdm_supported;
static int hf_artnet_poll_reply_status3;
static int hf_artnet_poll_reply_status3_switching_port_supported;
static int hf_artnet_poll_reply_status3_llrp_supported;
static int hf_artnet_poll_reply_status3_failover_supported;
static int hf_artnet_poll_reply_status3_failsafe_state;
static int hf_artnet_poll_reply_default_responder_uid;
static int hf_artnet_poll_reply_node_report_status_code;
static int hf_artnet_poll_reply_node_report_response_counter;
static int hf_artnet_poll_reply_node_report_status_string;

static int ett_artnet_poll_reply_status;
static int ett_artnet_poll_reply_good_input_1;
static int ett_artnet_poll_reply_good_input_2;
static int ett_artnet_poll_reply_good_input_3;
static int ett_artnet_poll_reply_good_input_4;
static int ett_artnet_poll_reply_good_output_1;
static int ett_artnet_poll_reply_good_output_2;
static int ett_artnet_poll_reply_good_output_3;
static int ett_artnet_poll_reply_good_output_4;
static int ett_artnet_poll_reply_good_output_b_1;
static int ett_artnet_poll_reply_good_output_b_2;
static int ett_artnet_poll_reply_good_output_b_3;
static int ett_artnet_poll_reply_good_output_b_4;
static int ett_artnet_poll_reply_swmacro;
static int ett_artnet_poll_reply_swremote;
static int ett_artnet_poll_reply_status2;
static int ett_artnet_poll_reply_status3;

static int hf_artnet_poll_reply_good_input_recv_error;
static int hf_artnet_poll_reply_good_input_disabled;
static int hf_artnet_poll_reply_good_input_dmx_text;
static int hf_artnet_poll_reply_good_input_dmx_sip;
static int hf_artnet_poll_reply_good_input_dmx_test;
static int hf_artnet_poll_reply_good_input_data;

static int hf_artnet_poll_reply_swmacro_1;
static int hf_artnet_poll_reply_swmacro_2;
static int hf_artnet_poll_reply_swmacro_3;
static int hf_artnet_poll_reply_swmacro_4;
static int hf_artnet_poll_reply_swmacro_5;
static int hf_artnet_poll_reply_swmacro_6;
static int hf_artnet_poll_reply_swmacro_7;
static int hf_artnet_poll_reply_swmacro_8;

static int hf_artnet_poll_reply_swremote_1;
static int hf_artnet_poll_reply_swremote_2;
static int hf_artnet_poll_reply_swremote_3;
static int hf_artnet_poll_reply_swremote_4;
static int hf_artnet_poll_reply_swremote_5;
static int hf_artnet_poll_reply_swremote_6;
static int hf_artnet_poll_reply_swremote_7;
static int hf_artnet_poll_reply_swremote_8;

static int hf_artnet_poll_reply_user;
static int hf_artnet_poll_reply_refreshrate;

static int * const artnet_poll_reply_status_fields[] = {
  &hf_artnet_poll_reply_status_ubea_present,
  &hf_artnet_poll_reply_status_rdm_supported,
  &hf_artnet_poll_reply_status_rom_booted,
  &hf_artnet_poll_reply_status_port_prog,
  &hf_artnet_poll_reply_status_indicator,
  NULL
};

static int * const artnet_poll_reply_good_input_fields[] = {
  &hf_artnet_poll_reply_good_input_recv_error,
  &hf_artnet_poll_reply_good_input_disabled,
  &hf_artnet_poll_reply_good_input_dmx_text,
  &hf_artnet_poll_reply_good_input_dmx_sip,
  &hf_artnet_poll_reply_good_input_dmx_test,
  &hf_artnet_poll_reply_good_input_data,
  NULL
};

static int * const artnet_poll_reply_good_output_fields[] = {
  &hf_artnet_poll_reply_good_output_tx_proto,
  &hf_artnet_poll_reply_good_output_merge_ltp,
  &hf_artnet_poll_reply_good_output_short,
  &hf_artnet_poll_reply_good_output_merge_artnet,
  &hf_artnet_poll_reply_good_output_dmx_text,
  &hf_artnet_poll_reply_good_output_dmx_sip,
  &hf_artnet_poll_reply_good_output_dmx_test,
  &hf_artnet_poll_reply_good_output_data,
  NULL
};

static int * const artnet_poll_reply_good_output_b_fields[] = {
  &hf_artnet_poll_reply_good_output_style,
  &hf_artnet_poll_reply_good_output_rdm,
  NULL
};

static int * const artnet_poll_reply_status2_fields[] = {
  &hf_artnet_poll_reply_status2_web_supported,
  &hf_artnet_poll_reply_status2_dhcp_used,
  &hf_artnet_poll_reply_status2_dhcp_supported,
  &hf_artnet_poll_reply_status2_bigaddr_supported,
  &hf_artnet_poll_reply_status2_sacn_supported,
  &hf_artnet_poll_reply_status2_squawking,
  &hf_artnet_poll_reply_status2_output_switching_supported,
  &hf_artnet_poll_reply_status2_control_rdm_supported,
  NULL
};

static int * const artnet_poll_reply_status3_fields[] = {
  &hf_artnet_poll_reply_status3_switching_port_supported,
  &hf_artnet_poll_reply_status3_llrp_supported,
  &hf_artnet_poll_reply_status3_failover_supported,
  &hf_artnet_poll_reply_status3_failsafe_state,
  NULL
};

static int * const artnet_poll_reply_swmacro_fields[] = {
  &hf_artnet_poll_reply_swmacro_1,
  &hf_artnet_poll_reply_swmacro_2,
  &hf_artnet_poll_reply_swmacro_3,
  &hf_artnet_poll_reply_swmacro_4,
  &hf_artnet_poll_reply_swmacro_5,
  &hf_artnet_poll_reply_swmacro_6,
  &hf_artnet_poll_reply_swmacro_7,
  &hf_artnet_poll_reply_swmacro_8,
  NULL
};

static int * const artnet_poll_reply_swremote_fields[] = {
  &hf_artnet_poll_reply_swremote_1,
  &hf_artnet_poll_reply_swremote_2,
  &hf_artnet_poll_reply_swremote_3,
  &hf_artnet_poll_reply_swremote_4,
  &hf_artnet_poll_reply_swremote_5,
  &hf_artnet_poll_reply_swremote_6,
  &hf_artnet_poll_reply_swremote_7,
  &hf_artnet_poll_reply_swremote_8,
  NULL
};

static expert_field ei_artnet_poll_reply_bind_ip_without_index;
static expert_field ei_artnet_poll_reply_bind_index_without_ip;
static expert_field ei_artnet_poll_reply_node_report_invalid_format;

/* ArtOutput */
static int hf_artnet_output;
static int hf_artnet_output_sequence;
static int hf_artnet_output_physical;
static int hf_artnet_output_universe;
static int hf_artnet_output_length;

/* ArtSync */
static int hf_artnet_sync;
static int hf_artnet_sync_aux;

/* ArtAddress */
static int hf_artnet_address;
static int hf_artnet_address_netswitch_special;
static int hf_artnet_address_netswitch_net;
static int hf_artnet_address_netswitch_write;
static int hf_artnet_address_bind_index;
static int hf_artnet_address_short_name;
static int hf_artnet_address_long_name;
static int hf_artnet_address_swin;
static int hf_artnet_address_swin_1;
static int hf_artnet_address_swin_2;
static int hf_artnet_address_swin_3;
static int hf_artnet_address_swin_4;
static int hf_artnet_address_swout;
static int hf_artnet_address_swout_1;
static int hf_artnet_address_swout_2;
static int hf_artnet_address_swout_3;
static int hf_artnet_address_swout_4;
static int hf_artnet_address_subswitch_special;
static int hf_artnet_address_subswitch_sub;
static int hf_artnet_address_subswitch_write;
static int hf_artnet_address_sacnprio;
static int hf_artnet_address_command;

static int ett_artnet_address_netswitch;
static int ett_artnet_address_subswitch;

static int * const artnet_address_netswitch_fields[] = {
  &hf_artnet_address_netswitch_net,
  &hf_artnet_address_netswitch_write,
  NULL
};

static int * const artnet_address_subswitch_fields[] = {
  &hf_artnet_address_subswitch_sub,
  &hf_artnet_address_subswitch_write,
  NULL
};

static const value_string artnet_address_switch_vals[] = {
  { 0x00, "Reset to Physical Switch" },
  { 0x7f, "No Change" },
  { 0x00, NULL }
};

/* ArtInput */
static int hf_artnet_input;
static int hf_artnet_input_bind_index;
static int hf_artnet_input_num_ports;
static int hf_artnet_input_input;
static int hf_artnet_input_input_1;
static int hf_artnet_input_input_2;
static int hf_artnet_input_input_3;
static int hf_artnet_input_input_4;
static int hf_artnet_input_input_disabled;

static int ett_artnet_input_input_1;
static int ett_artnet_input_input_2;
static int ett_artnet_input_input_3;
static int ett_artnet_input_input_4;

static int * const artnet_input_input_fields[] = {
  &hf_artnet_input_input_disabled,
  NULL
};

/* ArtFirmwareMaster */
static int hf_artnet_firmware_master;
static int hf_artnet_firmware_master_type;
static int hf_artnet_firmware_master_block_id;
static int hf_artnet_firmware_master_length;
static int hf_artnet_firmware_master_data;

/* ArtFirmwareReply */
static int hf_artnet_firmware_reply;
static int hf_artnet_firmware_reply_type;

/* ArtVideoSetup */
static int hf_artnet_video_setup_control;
static int hf_artnet_video_setup_font_height;
static int hf_artnet_video_setup_first_font;
static int hf_artnet_video_setup_last_font;
static int hf_artnet_video_setup_win_font_name;
static int hf_artnet_video_setup_font_data;

/* ArtVideoPalette */
static int hf_artnet_video_palette_colour_red;
static int hf_artnet_video_palette_colour_green;
static int hf_artnet_video_palette_colour_blue;

/* ArtVideoData */
static int hf_artnet_video_data_pos_x;
static int hf_artnet_video_data_pos_y;
static int hf_artnet_video_data_len_x;
static int hf_artnet_video_data_len_y;
static int hf_artnet_video_data_data;

/* ArtPollFpReply */
static int hf_artnet_poll_fp_reply;

/* ArtTodRequest */
static int hf_artnet_tod_request;
static int hf_artnet_tod_request_net;
static int hf_artnet_tod_request_command;
static int hf_artnet_tod_request_ad_count;
static int hf_artnet_tod_request_address;

/* ArtTodData */
static int hf_artnet_tod_data;
static int hf_artnet_tod_data_rdm_ver;
static int hf_artnet_tod_data_bind_index;
static int hf_artnet_tod_data_port;
static int hf_artnet_tod_data_net;
static int hf_artnet_tod_data_command_response;
static int hf_artnet_tod_data_address;
static int hf_artnet_tod_data_uid_total;
static int hf_artnet_tod_data_block_count;
static int hf_artnet_tod_data_uid_count;
static int hf_artnet_tod_data_tod;

/* ArtTodControl */
static int hf_artnet_tod_control;
static int hf_artnet_tod_control_net;
static int hf_artnet_tod_control_command;
static int hf_artnet_tod_control_address;
static int hf_artnet_tod_control_universe;

/* ArtRdm */
static int hf_artnet_rdm;
static int hf_artnet_rdm_command;
static int hf_artnet_rdm_address;
static int hf_artnet_rdm_sc;

static int hf_artnet_rdm_rdmver;
static int hf_artnet_rdm_net;

/* ArtRdmSub */
static int hf_artnet_rdm_sub;
static int hf_artnet_rdm_sub_uid;
static int hf_artnet_rdm_sub_command_class;
static int hf_artnet_rdm_sub_pid;
static int hf_artnet_rdm_sub_sub_device;
static int hf_artnet_rdm_sub_sub_count;
static int hf_artnet_rdm_sub_data;

/* ArtIpProg */
static int hf_artnet_ip_prog;
static int hf_artnet_ip_prog_command;
static int hf_artnet_ip_prog_command_prog_port;
static int hf_artnet_ip_prog_command_prog_sm;
static int hf_artnet_ip_prog_command_prog_ip;
static int hf_artnet_ip_prog_command_reset;
static int hf_artnet_ip_prog_command_gw;
static int hf_artnet_ip_prog_command_unused;
static int hf_artnet_ip_prog_command_dhcp_enable;
static int hf_artnet_ip_prog_command_prog_enable;
static int hf_artnet_ip_prog_ip;
static int hf_artnet_ip_prog_sm;
static int hf_artnet_ip_prog_port;
static int hf_artnet_ip_prog_gw;

static int ett_artnet_ip_prog_command;

static int * const artnet_ip_prog_command_fields[] = {
  &hf_artnet_ip_prog_command_prog_port,
  &hf_artnet_ip_prog_command_prog_sm,
  &hf_artnet_ip_prog_command_prog_ip,
  &hf_artnet_ip_prog_command_reset,
  &hf_artnet_ip_prog_command_gw,
  &hf_artnet_ip_prog_command_unused,
  &hf_artnet_ip_prog_command_dhcp_enable,
  &hf_artnet_ip_prog_command_prog_enable,
  NULL
};

/* ArtIpProgReply */
static int hf_artnet_ip_prog_reply;
static int hf_artnet_ip_prog_reply_ip;
static int hf_artnet_ip_prog_reply_sm;
static int hf_artnet_ip_prog_reply_port;
static int hf_artnet_ip_prog_reply_status;
static int hf_artnet_ip_prog_reply_status_unused;
static int hf_artnet_ip_prog_reply_status_dhcp_enable;
static int hf_artnet_ip_prog_reply_gw;

static int ett_artnet_ip_prog_reply_status;

static int * const artnet_ip_prog_reply_status_fields[] = {
  &hf_artnet_ip_prog_reply_status_unused,
  &hf_artnet_ip_prog_reply_status_dhcp_enable,
  NULL
};

/* ArtDiagData */
static int hf_artnet_diag_data;
static int hf_artnet_diag_data_priority;
static int hf_artnet_diag_data_port;
static int hf_artnet_diag_data_length;
static int hf_artnet_diag_data_data;

/* ArtCommand */
static int hf_artnet_command;
static int hf_artnet_command_esta_man;
static int hf_artnet_command_length;
static int hf_artnet_command_data;

/* ArtDataRequest */
static int hf_artnet_data_request;
static int hf_artnet_data_request_esta_man;
static int hf_artnet_data_request_oem;
static int hf_artnet_data_request_request;
static int hf_artnet_data_request_spare;

#define ARTNET_DR_POLL          0x0000
#define ARTNET_DR_URL_PRODUCT   0x0001
#define ARTNET_DR_URL_USERGUIDE 0x0002
#define ARTNET_DR_URL_SUPPORT   0x0003
#define ARTNET_DR_URL_PERS_UDR  0x0004
#define ARTNET_DR_URL_PERS_GDTF 0x0005
#define ARTNET_DR_MAN_SPEC_LOW  0x8000
#define ARTNET_DR_MAN_SPEC_HIGH 0xFFFF

static const range_string artnet_data_request_vals[] = {
  { ARTNET_DR_POLL,          ARTNET_DR_POLL,          "DrPoll" },
  { ARTNET_DR_URL_PRODUCT,   ARTNET_DR_URL_PRODUCT,   "DrUrlProduct" },
  { ARTNET_DR_URL_USERGUIDE, ARTNET_DR_URL_USERGUIDE, "DrUrlUserGuide" },
  { ARTNET_DR_URL_SUPPORT,   ARTNET_DR_URL_SUPPORT,   "DrUrlSupport" },
  { ARTNET_DR_URL_PERS_UDR,  ARTNET_DR_URL_PERS_UDR,  "DrPersUdr" },
  { ARTNET_DR_URL_PERS_GDTF, ARTNET_DR_URL_PERS_GDTF, "DrPersGdtf" },
  { ARTNET_DR_MAN_SPEC_LOW,  ARTNET_DR_MAN_SPEC_HIGH, "DrManSpec" },
  { 0,                       0,                       NULL }
};

/* ArtDataReply */
static int hf_artnet_data_reply;
static int hf_artnet_data_reply_esta_man;
static int hf_artnet_data_reply_oem;
static int hf_artnet_data_reply_request;
static int hf_artnet_data_reply_payload_length;
static int hf_artnet_data_reply_payload;

/* ArtMedia */
static int hf_artnet_media;

/* ArtMediaPatch */
static int hf_artnet_media_patch;

/* ArtMediaControl */
static int hf_artnet_media_control;

/* ArtMediaControlReply */
static int hf_artnet_media_control_reply;

/* ArtTimeCode */
static int hf_artnet_time_code;
static int hf_artnet_time_code_frames;
static int hf_artnet_time_code_seconds;
static int hf_artnet_time_code_minutes;
static int hf_artnet_time_code_hours;
static int hf_artnet_time_code_type;

static const value_string artnet_time_code_vals[] = {
  { 0x00, "Film (24fps)" },
  { 0x01, "EBU (25fps)" },
  { 0x02, "DF (29.97fps)" },
  { 0x03, "SMPTE (30fps)" },
  { 0x00, NULL }
};

/* ArtTimeSync */
static int hf_artnet_time_sync;

/* ArtTrigger */
#define ARTNET_TRIGGER_NOT_OEM_SPECIFIC 0xFFFF

static int hf_artnet_trigger;
static int hf_artnet_trigger_oem;
static int hf_artnet_trigger_key;
static int hf_artnet_trigger_key_unspecific;
static int hf_artnet_trigger_subkey;
static int hf_artnet_trigger_data;

static const value_string artnet_trigger_key_vals[] = {
  { 0x00, "KeyAscii" },
  { 0x01, "KeyMacro" },
  { 0x02, "KeySoft" },
  { 0x03, "KeyShow" },
  { 0x00, NULL }
};

/* ArtDirectory */
static int hf_artnet_directory;
static int hf_artnet_directory_filler;
static int hf_artnet_directory_cmd;
static int hf_artnet_directory_file;

/* ArtDirectoryReply */
static int hf_artnet_directory_reply;
static int hf_artnet_directory_reply_filler;
static int hf_artnet_directory_reply_flags;
static int hf_artnet_directory_reply_file;
static int hf_artnet_directory_reply_name;
static int hf_artnet_directory_reply_desc;
static int hf_artnet_directory_reply_length;
static int hf_artnet_directory_reply_data;

/* ArtMacMaster */
static int hf_artnet_mac_master;

/* ArtMacSlave */
static int hf_artnet_mac_slave;

/* ArtFileTnMaster */
static int hf_artnet_file_tn_master;
static int hf_artnet_file_tn_master_filler;
static int hf_artnet_file_tn_master_type;
static int hf_artnet_file_tn_master_block_id;
static int hf_artnet_file_tn_master_length;
static int hf_artnet_file_tn_master_name;
static int hf_artnet_file_tn_master_checksum;
static int hf_artnet_file_tn_master_spare;
static int hf_artnet_file_tn_master_data;


/* ArtFileFnMaster */
static int hf_artnet_file_fn_master;

/* ArtFileFnReply */
static int hf_artnet_file_fn_reply;

/* ArtNzs */
static int hf_artnet_nzs;
static int hf_artnet_nzs_sequence;
static int hf_artnet_nzs_start_code;
static int hf_artnet_nzs_subuni;
static int hf_artnet_nzs_net;
static int hf_artnet_nzs_length;
static int hf_artnet_nzs_vlc_man_id;
static int hf_artnet_nzs_vlc_sub_code;
static int hf_artnet_nzs_vlc_flags;
static int hf_artnet_nzs_vlc_flags_ieee;
static int hf_artnet_nzs_vlc_flags_reply;
static int hf_artnet_nzs_vlc_flags_beacon;
static int hf_artnet_nzs_vlc_transaction;
static int hf_artnet_nzs_vlc_slot_addr;
static int hf_artnet_nzs_vlc_payload_size;
static int hf_artnet_nzs_vlc_payload_checksum;
static int hf_artnet_nzs_vlc_mod_depth;
static int hf_artnet_nzs_vlc_mod_freq;
static int hf_artnet_nzs_vlc_mod_type;
static int hf_artnet_nzs_vlc_lang_code;
static int hf_artnet_nzs_vlc_beacon_repeat;
static int hf_artnet_nzs_vlc_payload;
static int hf_artnet_nzs_vlc_payload_beacon_url;
static int hf_artnet_nzs_vlc_payload_beacon_text;
static int hf_artnet_nzs_vlc_payload_beacon_location_id;

static int ett_artnet_nzs_vlc_flags;

static int * const artnet_nzs_vlc_flags_fields[] = {
  &hf_artnet_nzs_vlc_flags_beacon,
  &hf_artnet_nzs_vlc_flags_reply,
  &hf_artnet_nzs_vlc_flags_ieee,
  NULL
};

#define ARTNET_NZS_VLC_START_CODE       0x91
#define ARTNET_NZS_VLC_MAGIC_MAN_ID     0x414C
#define ARTNET_NZS_VLC_MAGIC_SUB_CODE   0x45

static const value_string vals_artnet_nzs_vlc_ieee[] = {
  { 0x00, "Payload language" },
  { 0x01, "IEEE VLC data" },
  { 0x00, NULL }
};

static const value_string vals_artnet_nzs_vlc_beacon[] = {
  { 0x00, "send once" },
  { 0x01, "continuously repeat" },
  { 0x00, NULL }
};

#define ARTNET_NZS_VLC_LANG_CODE_BEACON_URL       0x0000
#define ARTNET_NZS_VLC_LANG_CODE_BEACON_TEXT      0x0001
#define ARTNET_NZS_VLC_LANG_CODE_BEACON_LOCID     0x0002

static const value_string vals_artnet_nzs_vlc_lang_code[] = {
  { ARTNET_NZS_VLC_LANG_CODE_BEACON_URL,   "BeaconURL" },
  { ARTNET_NZS_VLC_LANG_CODE_BEACON_TEXT,  "BeaconText" },
  { ARTNET_NZS_VLC_LANG_CODE_BEACON_LOCID, "BeaconLocationID" },
  { 0x0000, NULL }
};


/* Define the tree for artnet */
static int ett_artnet;

/* A static handle for the rdm dissector */
static dissector_handle_t rdm_handle;
static dissector_handle_t dmx_chan_handle;

static unsigned
dissect_artnet_poll(tvbuff_t *tvb, unsigned offset, proto_tree *tree, packet_info *pinfo)
{

  proto_tree_add_bitmask(tree, tvb, offset, hf_artnet_poll_talktome,
                         ett_artnet_poll_talktome,
                         artnet_poll_talktome_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  col_append_fstr(pinfo->cinfo, COL_INFO, " Prio=%s",
                  val_to_str(tvb_get_uint8(tvb, offset), artnet_talktome_diag_priority_vals, "unknown(%u)"));
  proto_tree_add_item(tree, hf_artnet_poll_diag_priority, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* TargetPort Top/Bottom not present (compatibility, >= Rev. DE) */
  if(tvb_reported_length_remaining(tvb, offset) < 4) {
    return offset;
  }

  proto_tree_add_item(tree, hf_artnet_poll_target_port_top, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_target_port_bottom, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  col_append_fstr(pinfo->cinfo, COL_INFO, " (%d-%d)",
    tvb_get_uint16(tvb, offset-2, ENC_BIG_ENDIAN),
    tvb_get_uint16(tvb, offset-4, ENC_BIG_ENDIAN));

  /* EstaMan/OEM not present (compatibility, >= Rev. DE) */
  if(tvb_reported_length_remaining(tvb, offset) < 4) {
    return offset;
  }

  proto_tree_add_item(tree, hf_artnet_poll_esta_man, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_oem, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  return offset;
}

static unsigned
dissect_artnet_poll_reply(tvbuff_t *tvb, unsigned offset, proto_tree *tree, packet_info *pinfo)
{
  proto_tree *hi, *si, *ti;
  proto_item *tf, *tp;
  uint16_t universe,uni_port;
  uint8_t bind_index;
  uint32_t bind_ip_address;
  GRegex *regex = NULL;
  GMatchInfo *match_info = NULL;

  proto_tree_add_item(tree, hf_artnet_poll_reply_ip_address, tvb,
                      offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_poll_reply_port_nr, tvb,
                      offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_versinfo, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_netswitch, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  universe = (tvb_get_uint8(tvb, offset) & 0x7F) << 8;
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_subswitch, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  universe |= (tvb_get_uint8(tvb, offset) & 0x0F) << 4;
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_oem, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_ubea_version, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_bitmask(tree, tvb, offset, hf_artnet_poll_reply_status,
                         ett_artnet_poll_reply_status,
                         artnet_poll_reply_status_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_esta_man, tvb,
                      offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_short_name,
                      tvb, offset, 18, ENC_ASCII);
  offset += 18;

  proto_tree_add_item(tree, hf_artnet_poll_reply_long_name,
                      tvb, offset, 64, ENC_ASCII);
  offset += 64;

  proto_tree_add_item(tree, hf_artnet_poll_reply_node_report,
                      tvb, offset, 64, ENC_ASCII);

  /* Try to extract node report regex data as generated fields (only if data contained) */
  if(tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN) > 0) {
    regex = g_regex_new(artnet_poll_reply_node_report_regex, (GRegexCompileFlags) G_REGEX_OPTIMIZE, (GRegexMatchFlags) 0, NULL);
    DISSECTOR_ASSERT(regex != NULL);
    g_regex_match(
      regex,
      (const char*)tvb_get_string_enc(pinfo->pool, tvb, offset, 64, ENC_ASCII),
      (GRegexMatchFlags) 0,
      &match_info);

    if(g_match_info_matches(match_info) && g_match_info_get_match_count(match_info) == 4) {
      char *status_code = g_match_info_fetch(match_info, 1);
      char *counter = g_match_info_fetch(match_info, 2);
      char *status_string = g_match_info_fetch(match_info, 3);

      tf = proto_tree_add_uint(tree, hf_artnet_poll_reply_node_report_status_code, tvb, 0, 0, (uint16_t)strtol(status_code, NULL, 16));
      proto_item_set_generated(tf);

      tf = proto_tree_add_uint(tree, hf_artnet_poll_reply_node_report_response_counter, tvb, 0, 0, (uint32_t)strtoul(counter, NULL, 10));
      proto_item_set_generated(tf);

      tf = proto_tree_add_string(tree, hf_artnet_poll_reply_node_report_status_string, tvb, 0, 0, status_string);
      proto_item_set_generated(tf);

      g_free(status_code);
      g_free(counter);
      g_free(status_string);
    } else {
      expert_add_info(pinfo, tree, &ei_artnet_poll_reply_node_report_invalid_format);
    }
    g_regex_unref(regex);
    g_match_info_free(match_info);
  }
  offset += 64;


  hi = proto_tree_add_item(tree,
                           hf_artnet_poll_reply_port_info,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_PORT_INFO_LENGTH,
                           ENC_NA);

  si = proto_item_add_subtree(hi, ett_artnet);

  col_append_fstr(pinfo->cinfo, COL_INFO, " Ports=%d", tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN));
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

  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_input_1,
                         ett_artnet_poll_reply_good_input_1,
                         artnet_poll_reply_good_input_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_input_2,
                         ett_artnet_poll_reply_good_input_2,
                         artnet_poll_reply_good_input_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_input_3,
                         ett_artnet_poll_reply_good_input_3,
                         artnet_poll_reply_good_input_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_input_4,
                         ett_artnet_poll_reply_good_input_4,
                         artnet_poll_reply_good_input_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  hi = proto_tree_add_item(si,
                           hf_artnet_poll_reply_good_output,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_GOOD_OUTPUT_LENGTH,
                           ENC_NA);

  ti = proto_item_add_subtree(hi, ett_artnet);

  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_output_1,
                         ett_artnet_poll_reply_good_output_1,
                         artnet_poll_reply_good_output_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_output_2,
                         ett_artnet_poll_reply_good_output_2,
                         artnet_poll_reply_good_output_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_output_3,
                         ett_artnet_poll_reply_good_output_3,
                         artnet_poll_reply_good_output_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_output_4,
                         ett_artnet_poll_reply_good_output_4,
                         artnet_poll_reply_good_output_fields,
                         ENC_BIG_ENDIAN);
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

  uni_port = tvb_get_uint8(tvb, offset) & 0x0F;
  tf = proto_tree_add_uint(ti,hf_artnet_poll_reply_swin_1_universe,tvb,
                           offset, 0, universe | uni_port);
  proto_item_set_generated(tf);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swin_2, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  uni_port = tvb_get_uint8(tvb, offset) & 0x0F;
  tf = proto_tree_add_uint(ti,hf_artnet_poll_reply_swin_2_universe,tvb,
                           offset, 0, universe | uni_port);
  proto_item_set_generated(tf);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swin_3, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  uni_port = tvb_get_uint8(tvb, offset) & 0x0F;
  tf = proto_tree_add_uint(ti,hf_artnet_poll_reply_swin_3_universe,tvb,
                           offset, 0, universe | uni_port);
  proto_item_set_generated(tf);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swin_4, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  uni_port = tvb_get_uint8(tvb, offset) & 0x0F;
  tf = proto_tree_add_uint(ti,hf_artnet_poll_reply_swin_4_universe,tvb,
                           offset, 0, universe | uni_port);
  proto_item_set_generated(tf);
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
  uni_port = tvb_get_uint8(tvb, offset) & 0x0F;
  tf = proto_tree_add_uint(ti,hf_artnet_poll_reply_swout_1_universe,tvb,
                           offset, 0, universe | uni_port);
  proto_item_set_generated(tf);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swout_2, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  uni_port = tvb_get_uint8(tvb, offset) & 0x0F;
  tf = proto_tree_add_uint(ti,hf_artnet_poll_reply_swout_2_universe,tvb,
                           offset, 0, universe | uni_port);
  proto_item_set_generated(tf);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swout_3, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  uni_port = tvb_get_uint8(tvb, offset) & 0x0F;
  tf = proto_tree_add_uint(ti,hf_artnet_poll_reply_swout_3_universe,tvb,
                           offset, 0, universe | uni_port);
  proto_item_set_generated(tf);
  offset += 1;

  proto_tree_add_item(ti, hf_artnet_poll_reply_swout_4, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  uni_port = tvb_get_uint8(tvb, offset) & 0x0F;
  tf = proto_tree_add_uint(ti,hf_artnet_poll_reply_swout_4_universe,tvb,
                           offset, 0, universe | uni_port);
  proto_item_set_generated(tf);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_sacnprio, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_bitmask(tree, tvb, offset, hf_artnet_poll_reply_swmacro,
                         ett_artnet_poll_reply_swmacro,
                         artnet_poll_reply_swmacro_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_bitmask(tree, tvb, offset, hf_artnet_poll_reply_swremote,
                         ett_artnet_poll_reply_swremote,
                         artnet_poll_reply_swremote_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 3, ENC_NA);
  offset += 3;

  proto_tree_add_item(tree, hf_artnet_poll_reply_style, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_mac,
                        tvb, offset, 6, ENC_NA);
  offset += 6;

  bind_ip_address = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
  tp = proto_tree_add_item(tree, hf_artnet_poll_reply_bind_ip_address, tvb,
                      offset, 4, ENC_BIG_ENDIAN);
  if(bind_ip_address == 0) {
    proto_item_append_text(tp, " (unused)");
  }
  offset += 4;

  bind_index = tvb_get_uint8(tvb, offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, " BindIdx=0x%02x", bind_index);
  tp = proto_tree_add_item(tree, hf_artnet_poll_reply_bind_index, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  if(bind_index == 0) {
    proto_item_append_text(tp, " (unused)");
  } else if(bind_index == 1) {
    proto_item_append_text(tp, " (root device)");
  }
  offset += 1;

  /* If bind IP is non-zero, bind index must also be non-zero */
  if(bind_ip_address != 0 && bind_index == 0) {
    expert_add_info(pinfo, tree, &ei_artnet_poll_reply_bind_ip_without_index);
  }

  /* If bind index is non-zero, bind IP must also be non-zero */
  if(bind_index != 0 && bind_ip_address == 0) {
    expert_add_info(pinfo, tree, &ei_artnet_poll_reply_bind_index_without_ip);
  }

  proto_tree_add_bitmask(tree, tvb, offset, hf_artnet_poll_reply_status2,
                         ett_artnet_poll_reply_status2,
                         artnet_poll_reply_status2_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;


  hi = proto_tree_add_item(tree,
                           hf_artnet_poll_reply_good_output_b,
                           tvb,
                           offset,
                           ARTNET_POLL_REPLY_GOOD_OUTPUT_B_LENGTH,
                           ENC_NA);

  ti = proto_item_add_subtree(hi, ett_artnet);

  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_output_b_1,
                         ett_artnet_poll_reply_good_output_b_1,
                         artnet_poll_reply_good_output_b_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_output_b_2,
                         ett_artnet_poll_reply_good_output_b_2,
                         artnet_poll_reply_good_output_b_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_output_b_3,
                         ett_artnet_poll_reply_good_output_b_3,
                         artnet_poll_reply_good_output_b_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_bitmask(ti, tvb, offset, hf_artnet_poll_reply_good_output_b_4,
                         ett_artnet_poll_reply_good_output_b_4,
                         artnet_poll_reply_good_output_b_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_bitmask(tree, tvb, offset, hf_artnet_poll_reply_status3,
                         ett_artnet_poll_reply_status3,
                         artnet_poll_reply_status3_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_poll_reply_default_responder_uid, tvb, offset, 6, ENC_NA);
  offset += 6;

  proto_tree_add_item(tree, hf_artnet_poll_reply_user, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_poll_reply_refreshrate, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* There are additional 11 bytes filler reserved for future use */
  if (offset < tvb_reported_length(tvb))
  {
    proto_tree_add_item(tree, hf_artnet_filler, tvb, offset, -1, ENC_NA);
    offset = tvb_reported_length(tvb);
  }

  return offset;
}

static unsigned
dissect_artnet_output(tvbuff_t *tvb, unsigned offset, proto_tree *tree, packet_info *pinfo, proto_tree* base_tree)
{
  tvbuff_t *next_tvb;
  uint16_t  length;
  unsigned  size;
  bool      save_info;

  proto_tree_add_item(tree, hf_artnet_output_sequence, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_output_physical, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_output_universe, tvb,
                      offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  col_append_fstr(pinfo->cinfo, COL_INFO, " Seq=%d Port=%d Univ=%d",
    tvb_get_uint8(tvb, offset-4), tvb_get_uint8(tvb, offset-3), tvb_get_uint16(tvb, offset-2, ENC_LITTLE_ENDIAN));

  length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_output_length, tvb,
                      offset, 2, length);
  offset += 2;

  size = tvb_reported_length_remaining(tvb, offset);

  save_info = col_get_writable(pinfo->cinfo, COL_INFO);
  col_set_writable(pinfo->cinfo, COL_INFO, false);

  next_tvb = tvb_new_subset_length(tvb, offset, length);

  call_dissector(dmx_chan_handle, next_tvb, pinfo, base_tree);

  col_set_writable(pinfo->cinfo, COL_INFO, save_info);

  return offset + size;
}

static unsigned
dissect_artnet_sync(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_sync_aux, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  return offset;
}

static unsigned
dissect_artnet_nzs(tvbuff_t *tvb, unsigned offset, proto_tree *tree, packet_info *pinfo, proto_tree* base_tree)
{
  uint16_t length, payload_length, lang_code;
  uint8_t start_code;
  bool save_info;
  tvbuff_t *next_tvb;
  proto_item *pi;

  proto_tree_add_item(tree, hf_artnet_nzs_sequence, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  start_code = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(tree, hf_artnet_nzs_start_code, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_nzs_subuni, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_nzs_net, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_artnet_nzs_length, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;


  /* check if packet is normal ArtNzs or ArtVlc */

  if(tvb_reported_length_remaining(tvb, offset) < 3) {
    return offset;
  }

  if(
    start_code == ARTNET_NZS_VLC_START_CODE &&
    tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) == ARTNET_NZS_VLC_MAGIC_MAN_ID &&
    tvb_get_uint8(tvb, offset + 2) == ARTNET_NZS_VLC_MAGIC_SUB_CODE
  ) {

    /* VLC */

    proto_tree_add_item(tree, hf_artnet_nzs_vlc_man_id, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_artnet_nzs_vlc_sub_code, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_bitmask(tree, tvb, offset, hf_artnet_nzs_vlc_flags,
                          ett_artnet_nzs_vlc_flags,
                          artnet_nzs_vlc_flags_fields,
                          ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_artnet_nzs_vlc_transaction, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_artnet_nzs_vlc_slot_addr, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    payload_length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_artnet_nzs_vlc_payload_size, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_checksum(tree, tvb, offset, hf_artnet_nzs_vlc_payload_checksum, -1, NULL, NULL, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    offset += 2;

    proto_tree_add_item(tree, hf_artnet_spare, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_artnet_nzs_vlc_mod_depth, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_artnet_nzs_vlc_mod_freq, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_artnet_nzs_vlc_mod_type, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    lang_code = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_artnet_nzs_vlc_lang_code, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_artnet_nzs_vlc_beacon_repeat, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_artnet_nzs_vlc_payload, tvb,
                        offset, payload_length, ENC_NA);

    if(lang_code == ARTNET_NZS_VLC_LANG_CODE_BEACON_URL) {
      pi = proto_tree_add_item(tree, hf_artnet_nzs_vlc_payload_beacon_url, tvb, offset, payload_length, ENC_ASCII);
      proto_item_set_generated(pi);
    } else if(lang_code == ARTNET_NZS_VLC_LANG_CODE_BEACON_TEXT) {
      pi = proto_tree_add_item(tree, hf_artnet_nzs_vlc_payload_beacon_text, tvb, offset, payload_length, ENC_ASCII);
      proto_item_set_generated(pi);
    } else if(lang_code == ARTNET_NZS_VLC_LANG_CODE_BEACON_LOCID && tvb_reported_length_remaining(tvb, offset) >= 2) {
      pi = proto_tree_add_item(tree, hf_artnet_nzs_vlc_payload_beacon_location_id, tvb, offset, 2, ENC_BIG_ENDIAN);
      proto_item_set_generated(pi);
    }
    offset += payload_length;

    return offset;

  } else {

    /* Nzs -> DMX data */

    save_info = col_get_writable(pinfo->cinfo, COL_INFO);
    col_set_writable(pinfo->cinfo, COL_INFO, false);

    next_tvb = tvb_new_subset_length(tvb, offset, length);

    call_dissector(dmx_chan_handle, next_tvb, pinfo, base_tree);

    col_set_writable(pinfo->cinfo, COL_INFO, save_info);

    return offset + length;

  }
}

static unsigned
dissect_artnet_address(tvbuff_t *tvb, unsigned offset, proto_tree *tree, packet_info *pinfo) {
  proto_tree *hi, *si, *ti;
  uint8_t net, sub;

  net = tvb_get_uint8(tvb, offset);

  /* Treat the "special" values differently */
  if (net == 0x00 || net == 0x7F) {
    proto_tree_add_uint(tree,hf_artnet_address_netswitch_special, tvb,
                           offset, 0, net);
  } else {
    proto_tree_add_bitmask_text(tree, tvb, offset, 1, "NetSwitch: ",
                  "NetSwitch Error: ", ett_artnet_address_netswitch,
                  artnet_address_netswitch_fields, ENC_BIG_ENDIAN, 0);
  }

  offset += 1;

  col_append_fstr(pinfo->cinfo, COL_INFO, " BindIdx=0x%02x", tvb_get_uint8(tvb, offset));
  proto_tree_add_item(tree, hf_artnet_address_bind_index, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_address_short_name,
                      tvb, offset, 18, ENC_ASCII);
  offset += 18;

  proto_tree_add_item(tree, hf_artnet_address_long_name,
                      tvb, offset, 64, ENC_ASCII);
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

  sub = tvb_get_uint8(tvb, offset);

  /* Treat the "special" values differently */
  if (sub == 0x00 || sub == 0x7F) {
    proto_tree_add_uint(tree,hf_artnet_address_subswitch_special, tvb,
                           offset, 0, sub);
  } else {
    proto_tree_add_bitmask_text(tree, tvb, offset, 1, "SubSwitch: ",
                  "SubSwitch Error: ", ett_artnet_address_subswitch,
                  artnet_address_subswitch_fields, ENC_BIG_ENDIAN, 0);
  }
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_address_sacnprio, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_address_command, tvb,
                      offset, 1, ENC_BIG_ENDIAN);

  offset += 1;

  return offset;
}

static unsigned
dissect_artnet_input(tvbuff_t *tvb, unsigned offset, proto_tree *tree, packet_info *pinfo) {
  proto_tree *hi, *si;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  col_append_fstr(pinfo->cinfo, COL_INFO, " BindIdx=0x%02x", tvb_get_uint8(tvb, offset));
  proto_tree_add_item(tree, hf_artnet_input_bind_index, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  col_append_fstr(pinfo->cinfo, COL_INFO, " Ports=%d", tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN));
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

  proto_tree_add_bitmask(si, tvb, offset, hf_artnet_input_input_1,
                         ett_artnet_input_input_1,
                         artnet_input_input_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_bitmask(si, tvb, offset, hf_artnet_input_input_2,
                         ett_artnet_input_input_2,
                         artnet_input_input_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_bitmask(si, tvb, offset, hf_artnet_input_input_3,
                         ett_artnet_input_input_3,
                         artnet_input_input_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_bitmask(si, tvb, offset, hf_artnet_input_input_4,
                         ett_artnet_input_input_4,
                         artnet_input_input_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  return offset;
}

static unsigned
dissect_artnet_video_setup(tvbuff_t *tvb, unsigned offset, proto_tree *tree ) {
  uint32_t size;
  uint8_t font_height, last_font;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_video_setup_control, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  font_height = tvb_get_uint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_setup_font_height, tvb,
                      offset, 1, font_height);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_video_setup_first_font, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  last_font = tvb_get_uint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_setup_last_font, tvb,
                      offset, 1, last_font);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_video_setup_win_font_name,
                      tvb, offset, 64, ENC_ASCII);
  offset += 64;

  size = last_font * font_height;

  proto_tree_add_item(tree, hf_artnet_video_setup_font_data, tvb,
                      offset, size, ENC_NA );

  offset += size;

  return offset;
}

static unsigned
dissect_artnet_video_palette(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
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

static unsigned
dissect_artnet_video_data(tvbuff_t *tvb, unsigned offset, proto_tree *tree) {
  uint8_t len_x, len_y;
  uint32_t size;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_video_data_pos_x, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_video_data_pos_y, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  len_x = tvb_get_uint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_data_len_x, tvb,
                      offset, 1, len_x);
  offset += 1;

  len_y = tvb_get_uint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_video_data_len_y, tvb,
                      offset, 1, len_y);
  offset += 1;

  size = len_x * len_y * 2;

  proto_tree_add_item(tree, hf_artnet_video_data_data, tvb,
                      offset, size, ENC_NA );

  offset += size;

  return offset;
}

static unsigned
dissect_artnet_firmware_master(tvbuff_t *tvb, unsigned offset, proto_tree *tree ) {
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

static unsigned
dissect_artnet_firmware_reply(tvbuff_t *tvb, unsigned offset, proto_tree *tree) {
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

static unsigned
dissect_artnet_tod_request(tvbuff_t *tvb, unsigned offset, proto_tree *tree, packet_info *pinfo)
{
  uint8_t ad_count;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 7, ENC_NA);
  offset += 7;

  proto_tree_add_item(tree, hf_artnet_tod_request_net, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  col_append_fstr(pinfo->cinfo, COL_INFO, " Cmd=%s", val_to_str(tvb_get_uint8(tvb, offset), artnet_tod_request_command_vals, "unknown(%u)"));
  proto_tree_add_item(tree, hf_artnet_tod_request_command, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  ad_count = tvb_get_uint8(tvb, offset);
  proto_tree_add_uint(tree, hf_artnet_tod_request_ad_count, tvb,
                      offset, 1, ad_count);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_request_address, tvb,
                      offset, ad_count, ENC_NA);
  offset += ad_count;

  return offset;
}

static unsigned
dissect_artnet_tod_data(tvbuff_t *tvb, unsigned offset, proto_tree *tree, packet_info *pinfo)
{
  uint16_t    universe;
  proto_item *tf;
  uint8_t i, uid_count;

  proto_tree_add_item(tree, hf_artnet_tod_data_rdm_ver, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_port, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 6, ENC_NA);
  offset += 6;

  col_append_fstr(pinfo->cinfo, COL_INFO, " BindIdx=0x%02x", tvb_get_uint8(tvb, offset));
  proto_tree_add_item(tree, hf_artnet_tod_data_bind_index, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_net, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  universe = (tvb_get_uint8(tvb, offset) & 0x7F) << 8;
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_command_response, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_address, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  universe |= tvb_get_uint8(tvb, offset);
  tf = proto_tree_add_uint(tree,hf_artnet_tod_control_universe,tvb,
                           offset, 0, universe);
  proto_item_set_generated(tf);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_data_uid_total, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_tod_data_block_count, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  uid_count = tvb_get_uint8(tvb, offset);
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

static unsigned
dissect_artnet_tod_control(tvbuff_t *tvb, unsigned offset, proto_tree *tree, packet_info *pinfo)
{
  uint16_t universe;
  proto_item *tf;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 7, ENC_NA);
  offset += 7;

  proto_tree_add_item(tree, hf_artnet_tod_control_net, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  universe = (tvb_get_uint8(tvb, offset) & 0x7F) << 8;
  offset += 1;

  col_append_fstr(pinfo->cinfo, COL_INFO, " Cmd=%s", val_to_str(tvb_get_uint8(tvb, offset), artnet_tod_control_command_vals, "unknown(%u)"));
  proto_tree_add_item(tree, hf_artnet_tod_control_command, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_tod_control_address, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  universe |= tvb_get_uint8(tvb, offset);
  tf = proto_tree_add_uint(tree,hf_artnet_tod_control_universe,tvb,
                           offset, 0, universe);
  proto_item_set_generated(tf);
  offset += 1;

  return offset;
}

static unsigned
dissect_artnet_rdm(tvbuff_t *tvb, unsigned offset, proto_tree *tree,  packet_info *pinfo, proto_tree *base_tree)
{
  uint16_t    universe;
  proto_item *tf;
  uint8_t   rdmver;
  uint8_t   sc;
  unsigned  size;
  bool      save_info;
  tvbuff_t *next_tvb;

  rdmver = tvb_get_uint8(tvb, offset);
  if (rdmver == 0x00) {
    proto_tree_add_item(tree, hf_artnet_filler, tvb,
                        offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_item(tree, hf_artnet_spare, tvb,
                        offset, 8, ENC_NA);
    offset += 8;
    universe = 0;
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
    universe = (tvb_get_uint8(tvb, offset) & 0x7F) << 8;
    offset += 1;
  }

  proto_tree_add_item(tree, hf_artnet_rdm_command, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_rdm_address, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  universe |= tvb_get_uint8(tvb, offset);
  tf = proto_tree_add_uint(tree,hf_artnet_tod_control_universe,tvb,
                           offset, 0, universe);
  proto_item_set_generated(tf);
  offset += 1;

  /* check for old version that included the 0xCC startcode
   * The 0xCC will never be the first byte of the RDM packet
   */
  sc = tvb_get_uint8(tvb, offset);

  if (sc == 0xCC) {
    proto_tree_add_item(tree, hf_artnet_rdm_sc, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
  }

  size = tvb_reported_length_remaining(tvb, offset);

  save_info = col_get_writable(pinfo->cinfo, COL_INFO);
  col_set_writable(pinfo->cinfo, COL_INFO, false);

  next_tvb = tvb_new_subset_remaining(tvb, offset);

  call_dissector(rdm_handle, next_tvb, pinfo, base_tree);

  col_set_writable(pinfo->cinfo, COL_INFO, save_info);

  return offset + size;
}


static unsigned
dissect_artnet_rdm_sub(tvbuff_t *tvb, unsigned offset, proto_tree *tree,  packet_info *pinfo _U_)
{
  uint8_t cc;
  int    size;

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

  cc = tvb_get_uint8(tvb, offset);
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

static unsigned
dissect_artnet_ip_prog(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_bitmask(tree, tvb, offset, hf_artnet_ip_prog_command,
                         ett_artnet_ip_prog_command,
                         artnet_ip_prog_command_fields,
                         ENC_BIG_ENDIAN);
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

  proto_tree_add_item(tree, hf_artnet_ip_prog_gw, tvb,
                      offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 4, ENC_NA);
  offset += 4;

  return offset;
}

static unsigned
dissect_artnet_ip_prog_reply(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
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

  proto_tree_add_bitmask(tree, tvb, offset, hf_artnet_ip_prog_reply_status,
                         ett_artnet_ip_prog_reply_status,
                         artnet_ip_prog_reply_status_fields,
                         ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_ip_prog_reply_gw, tvb,
                      offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_spare, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  return offset;
}

static unsigned
dissect_artnet_poll_fp_reply(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{
  return offset;
}


/* ArtDiagData */
static unsigned
dissect_artnet_diag_data(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  uint16_t length;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_diag_data_priority, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_diag_data_port, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_artnet_diag_data_length, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset+=2;

  proto_tree_add_item(tree, hf_artnet_diag_data_data, tvb,
                      offset, length, ENC_ASCII);
  offset += length;

  return offset;
}

/* ArtCommand */
static unsigned
dissect_artnet_command(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  uint16_t length;

  proto_tree_add_item(tree, hf_artnet_command_esta_man, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_artnet_command_length, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset+=2;

  proto_tree_add_item(tree, hf_artnet_command_data, tvb,
                      offset, length, ENC_ASCII);
  offset += length;

  return offset;
}

/* ArtDataRequest */
static unsigned
dissect_artnet_data_request(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_data_request_esta_man, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_data_request_oem, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_data_request_request, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_data_request_spare, tvb,
                      offset, 22, ENC_NA);
  offset += 22;

  return offset;
}

/* ArtDataReply */
static unsigned
dissect_artnet_data_reply(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  uint16_t payload_length;

  proto_tree_add_item(tree, hf_artnet_data_reply_esta_man, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_data_reply_oem, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_data_reply_request, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  payload_length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_artnet_data_reply_payload_length, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  if(payload_length == 0) {
    return offset;
  }

  proto_tree_add_item(tree, hf_artnet_data_reply_payload, tvb,
                      offset, payload_length, ENC_ASCII);

  offset += payload_length;

  return offset;
}

/* ArtMedia */
static unsigned
dissect_artnet_media(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtMediaPatch */
static unsigned
dissect_artnet_media_patch(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtMediaControl */
static unsigned
dissect_artnet_media_control(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtMediaControlReply */
static unsigned
dissect_artnet_media_control_reply(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtTimeCode */
static unsigned
dissect_artnet_time_code(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_time_code_frames, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_time_code_seconds, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_time_code_minutes, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_time_code_hours, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_time_code_type, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  return offset;
}

/* ArtTimeSync */
static unsigned
dissect_artnet_time_sync(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtTrigger */
static unsigned
dissect_artnet_trigger(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  uint16_t oem;
  proto_item *pi;

  proto_tree_add_item(tree, hf_artnet_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  oem = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_artnet_trigger_oem, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_trigger_key, tvb,
                      offset, 1, ENC_BIG_ENDIAN);

  if(oem == ARTNET_TRIGGER_NOT_OEM_SPECIFIC) {
    pi = proto_tree_add_item(tree, hf_artnet_trigger_key_unspecific, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
    proto_item_set_generated(pi);
  }
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_trigger_subkey, tvb,
                      offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_trigger_data, tvb,
                      offset, 512, ENC_NA);
  offset += 512;

  return offset;
}

/* ArtDirectory */
static unsigned
dissect_artnet_directory(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_directory_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_directory_cmd, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_directory_file, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  return offset;
}

/* ArtDirectoryReply */
static unsigned
dissect_artnet_directory_reply(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_artnet_directory_reply_filler, tvb,
                      offset, 2, ENC_NA);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_directory_reply_flags, tvb,
                      offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_artnet_directory_reply_file, tvb,
                      offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_artnet_directory_reply_name, tvb,
                      offset, 16, ENC_ASCII);
  offset += 16;

  proto_tree_add_item(tree, hf_artnet_directory_reply_desc, tvb,
                      offset, 64, ENC_ASCII);
  offset += 64;

  proto_tree_add_item(tree, hf_artnet_directory_reply_length, tvb,
                      offset, 8, ENC_BIG_ENDIAN);
  offset += 8;

  proto_tree_add_item(tree, hf_artnet_directory_reply_data, tvb,
                      offset, 64, ENC_NA);
  offset += 64;

  return offset;
}

/* ArtMacMaster */
static unsigned
dissect_artnet_mac_master(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtMacSlave */
static unsigned
dissect_artnet_mac_slave(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtFileTnMaster */
static unsigned
dissect_artnet_file_tn_master(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
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
                      offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_artnet_file_tn_master_name, tvb,
                      offset, 14, ENC_ASCII);
  offset += 14;

  proto_tree_add_checksum(tree, tvb, offset, hf_artnet_file_tn_master_checksum, -1, NULL, NULL, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
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
static unsigned
dissect_artnet_file_fn_master(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{
  return offset;
}

/* ArtFileFnReply */
static unsigned
dissect_artnet_file_fn_reply(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{
  return offset;
}

static int
dissect_artnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
  int           offset = 0;
  unsigned      size;
  uint16_t      opcode;
  const uint8_t *header;
  proto_tree   *ti, *hi, *si = NULL, *artnet_tree, *artnet_header_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ARTNET");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_artnet, tvb, offset, -1, ENC_NA);
  artnet_tree = proto_item_add_subtree(ti, ett_artnet);

  hi = proto_tree_add_item(artnet_tree, hf_artnet_header, tvb,
                             offset, ARTNET_HEADER_LENGTH, ENC_NA);
  artnet_header_tree = proto_item_add_subtree(hi, ett_artnet);

  proto_tree_add_item_ret_string(artnet_header_tree, hf_artnet_header_id,
                        tvb, offset, 8, ENC_ASCII|ENC_NA, pinfo->pool, &header);
  offset += 8;

  opcode = tvb_get_letohs(tvb, offset);

  col_add_str(pinfo->cinfo, COL_INFO,
    val_to_str_ext_const(opcode, &artnet_opcode_vals_ext, "Unknown"));


  proto_tree_add_uint(artnet_header_tree, hf_artnet_header_opcode, tvb,
                      offset, 2, opcode);

  proto_item_append_text(ti, ", Opcode: %s (0x%04x)", val_to_str_ext_const(opcode, &artnet_opcode_vals_ext, "Unknown"), opcode);

  offset += 2;

  if (opcode != ARTNET_OP_POLL_REPLY && opcode != ARTNET_OP_POLL_FP_REPLY) {

    proto_tree_add_item(artnet_header_tree, hf_artnet_header_protver, tvb,
                        offset, 2, ENC_BIG_ENDIAN);

    proto_item_set_len(artnet_header_tree, ARTNET_HEADER_LENGTH+2 );

    offset += 2;
  }

  switch (opcode) {

    case ARTNET_OP_POLL:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_poll,
                                tvb,
                                offset,
                                0,
                                ENC_NA);

      si = proto_item_add_subtree(hi, ett_artnet);

      size  = dissect_artnet_poll( tvb, offset, si, pinfo );
      size -= offset;

      proto_item_set_len(si, size);
      offset += size;

      break;

    case ARTNET_OP_POLL_REPLY:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_poll_reply,
                                tvb,
                                offset,
                                0,
                                ENC_NA);

      si = proto_item_add_subtree(hi, ett_artnet);

      size  = dissect_artnet_poll_reply( tvb, offset, si, pinfo);
      size -= offset;

      proto_item_set_len(si, size);
      offset += size;

      break;

    case ARTNET_OP_POLL_FP_REPLY:

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

      break;

    case ARTNET_OP_DIAG_DATA:

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

      break;

    case ARTNET_OP_COMMAND:

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

      break;

    case ARTNET_OP_DATA_REQUEST:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_data_request,
                                tvb,
                                offset,
                                0,
                                ENC_NA );
      si = proto_item_add_subtree(hi, ett_artnet );

      size  = dissect_artnet_data_request( tvb, offset, si );
      size -= offset;

      proto_item_set_len(si, size );
      offset += size;

      break;

    case ARTNET_OP_DATA_REPLY:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_data_reply,
                                tvb,
                                offset,
                                0,
                                ENC_NA );
      si = proto_item_add_subtree(hi, ett_artnet );

      size  = dissect_artnet_data_reply( tvb, offset, si );
      size -= offset;

      proto_item_set_len(si, size );
      offset += size;

      break;

    case ARTNET_OP_OUTPUT:
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
      break;


    case ARTNET_OP_SYNC:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_sync,
                                tvb,
                                offset,
                                0,
                                ENC_NA);

      si = proto_item_add_subtree(hi, ett_artnet);

      size  = dissect_artnet_sync( tvb, offset, si );
      size -= offset;

      proto_item_set_len(si, size);
      offset += size;

      break;


      case ARTNET_OP_ADDRESS:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_address,
                                tvb,
                                offset,
                                0,
                                ENC_NA);

      si = proto_item_add_subtree(hi, ett_artnet);

      size  = dissect_artnet_address( tvb, offset, si, pinfo );
      size -= offset;

      proto_item_set_len(si, size);
      offset += size;

      break;

    case ARTNET_OP_INPUT:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_input,
                                tvb,
                                offset,
                                0,
                                ENC_NA);

      si = proto_item_add_subtree(hi, ett_artnet);

      size  = dissect_artnet_input( tvb, offset, si, pinfo );
      size -= offset;

      proto_item_set_len(si, size);
      offset += size;

      break;

    case ARTNET_OP_TOD_REQUEST:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_tod_request,
                                tvb,
                                offset,
                                0,
                                ENC_NA);

      si = proto_item_add_subtree(hi, ett_artnet);

      size  = dissect_artnet_tod_request( tvb, offset, si, pinfo );
      size -= offset;

      proto_item_set_len(si, size);
      offset += size;

      break;

    case ARTNET_OP_TOD_DATA:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_tod_data,
                                tvb,
                                offset,
                                0,
                                ENC_NA);

      si = proto_item_add_subtree(hi, ett_artnet );

      size  = dissect_artnet_tod_data( tvb, offset, si, pinfo );
      size -= offset;

      proto_item_set_len(si, size );
      offset += size;

      break;

    case ARTNET_OP_TOD_CONTROL:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_tod_control,
                                tvb,
                                offset,
                                0,
                                ENC_NA );
      si = proto_item_add_subtree(hi, ett_artnet );

      size  = dissect_artnet_tod_control( tvb, offset, si, pinfo );
      size -= offset;

      proto_item_set_len(si, size );
      offset += size;

      break;

    case ARTNET_OP_RDM:
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
      break;

    case ARTNET_OP_RDM_SUB:

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

      break;

    case ARTNET_OP_MEDIA:

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

      break;

    case ARTNET_OP_MEDIA_PATCH:

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

      break;

    case ARTNET_OP_MEDIA_CONTROL:

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

      break;

    case ARTNET_OP_MEDIA_CONTRL_REPLY:

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

      break;

    case ARTNET_OP_TIME_CODE:

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

      break;

    case ARTNET_OP_TIME_SYNC:

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

      break;

    case ARTNET_OP_NZS:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_nzs,
                                tvb,
                                offset,
                                0,
                                ENC_NA);
      si = proto_item_add_subtree(hi, ett_artnet);

      size  = dissect_artnet_nzs( tvb, offset, si, pinfo, tree);
      size -= offset;

      proto_item_set_len( si, size );
      offset += size;

      break;

    case ARTNET_OP_TRIGGER:

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

      break;

    case ARTNET_OP_DIRECTORY:

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

      break;

    case ARTNET_OP_DIRECTORY_REPLY:

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

      break;


    case ARTNET_OP_VIDEO_SETUP:

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

      break;

    case ARTNET_OP_VIDEO_PALETTE:

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

      break;

    case ARTNET_OP_VIDEO_DATA:

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

      break;

    case ARTNET_OP_MAC_MASTER:

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

      break;

    case ARTNET_OP_MAC_SLAVE:

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

      break;

    case ARTNET_OP_FIRMWARE_MASTER:

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

      break;

    case ARTNET_OP_FIRMWARE_REPLY:

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

      break;

    case ARTNET_OP_FILE_TN_MASTER:

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

      break;

    case ARTNET_OP_FILE_FN_MASTER:

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

      break;

    case ARTNET_OP_FILE_FN_REPLY:

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

      break;

    case ARTNET_OP_IP_PROG:

      hi = proto_tree_add_item(artnet_tree,
                                hf_artnet_ip_prog,
                                tvb,
                                offset,
                                0,
                                ENC_NA);
      si = proto_item_add_subtree(hi, ett_artnet );

      size  = dissect_artnet_ip_prog( tvb,offset, si);
      size -= offset;

      proto_item_set_len(si, size );
      offset += size;

      break;

    case ARTNET_OP_IP_PROG_REPLY:

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

      break;


    default:
      if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(artnet_tree, hf_artnet_data, tvb, offset, -1, ENC_NA);
      }
      return tvb_captured_length(tvb);
  }

  if (tvb_reported_length_remaining(tvb, offset) > 0) {
    proto_tree_add_item(artnet_tree, hf_artnet_excess_bytes, tvb,
      offset, -1, ENC_NA);
  }
  return tvb_captured_length(tvb);
}

/* Heuristic dissector */
static bool
dissect_artnet_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  uint64_t    qword;

  /* check if we atleast have the 8 byte header */
  if (tvb_captured_length(tvb) < 8)
    return false;

  /* Check the 8 byte header "Art-Net\0" = 0x4172742d4e657400*/
  qword = tvb_get_ntoh64(tvb,0);
  if(qword != UINT64_C (0x4172742d4e657400))
    return false;

  /* if the header matches, dissect it */
  dissect_artnet(tvb, pinfo, tree, data);

  return true;
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

    { &hf_artnet_data,
      { "Data",
        "artnet.data",
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

    /* Header */

    { &hf_artnet_header,
      { "Descriptor Header",
        "artnet.header",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net Descriptor Header", HFILL }},

    { &hf_artnet_header_id,
      { "ID",
        "artnet.header.id",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "ArtNET ID", HFILL }},

    { &hf_artnet_header_opcode,
      { "OpCode",
        "artnet.header.opcode",
        FT_UINT16, BASE_HEX | BASE_EXT_STRING, &artnet_opcode_vals_ext, 0x0,
        "Art-Net message type", HFILL }},

    { &hf_artnet_header_protver,
      { "ProtVer",
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

    { &hf_artnet_poll_talktome_reply_change,
      { "Send me ArtPollReply on change",
        "artnet.poll.talktome_reply_change",
        FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
        NULL, HFILL }},

    { &hf_artnet_poll_talktome_diag,
      { "Send diagnostics messages",
        "artnet.poll.talktome_diag",
        FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
        NULL, HFILL }},

    { &hf_artnet_poll_talktome_diag_unicast,
      { "Send diagnostics unicast",
        "artnet.poll.talktome_diag_unicast",
        FT_UINT8, BASE_HEX, VALS(artnet_talktome_diag_unicast_vals), 0x08,
        NULL, HFILL }},

    { &hf_artnet_poll_talktome_vlc,
      { "VLC transmission",
        "artnet.poll.talktome_vlc",
        FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled), 0x10,
        NULL, HFILL }},

    { &hf_artnet_poll_talktome_targeted,
      { "Targeted mode",
        "artnet.poll.talktome_targeted",
        FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20,
        NULL, HFILL }},

    { &hf_artnet_poll_diag_priority,
      { "Priority",
        "artnet.poll.diag_priority",
        FT_UINT8, BASE_DEC, VALS(artnet_talktome_diag_priority_vals), 0x0,
        "Minimum diagnostics message priority", HFILL }},

    { &hf_artnet_poll_target_port_top,
      { "Target Port Top",
        "artnet.poll.target_port_top",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Top of the port range", HFILL }},

    { &hf_artnet_poll_target_port_bottom,
      { "Target Port Bottom",
        "artnet.poll.target_port_bottom",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Bottom of the port range", HFILL }},

    { &hf_artnet_poll_esta_man,
      { "ESTA Code",
        "artnet.poll.esta_man",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_esta_man_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_oem,
      { "OEM",
        "artnet.poll.oem",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_oem_code_vals_ext, 0x0,
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

    { &hf_artnet_poll_reply_netswitch,
      { "NetSwitch",
        "artnet.poll_reply.netswitch",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Bits 14-8 of port address", HFILL }},

    { &hf_artnet_poll_reply_subswitch,
      { "SubSwitch",
        "artnet.poll_reply.subswitch",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Bits 7-4 of port address", HFILL }},

    { &hf_artnet_poll_reply_oem,
      { "OEM",
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

    { &hf_artnet_poll_reply_status_ubea_present,
      { "UBEA Present",
        "artnet.poll_reply.ubea_present",
        FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x01,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status_rdm_supported,
      { "RDM Supported",
        "artnet.poll_reply.rdm_supported",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status_rom_booted,
      { "ROM Booted",
        "artnet.poll_reply.rom_booted",
        FT_UINT8, BASE_HEX, VALS(artnet_rom_booted_vals), 0x04,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status_port_prog,
      { "Port Address Programming Authority",
        "artnet.poll_reply.port_prog",
        FT_UINT8, BASE_HEX, VALS(artnet_port_prog_auth_vals), 0x30,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status_indicator,
      { "Indicator State",
        "artnet.poll_reply.indicator",
        FT_UINT8, BASE_HEX, VALS(artnet_indicator_state_vals), 0xC0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_esta_man,
      { "ESTA Code",
        "artnet.poll_reply.esta_man",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_esta_man_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_short_name,
      { "Short Name",
        "artnet.poll_reply.short_name",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_long_name,
      { "Long Name",
        "artnet.poll_reply.long_name",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_node_report,
      { "Node Report",
        "artnet.poll_reply.node_report",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
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
        FT_UINT8, BASE_HEX, VALS(artnet_port_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_port_types_2,
      { "Type of Port 2",
        "artnet.poll_reply.port_types_2",
        FT_UINT8, BASE_HEX, VALS(artnet_port_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_port_types_3,
      { "Type of Port 3",
        "artnet.poll_reply.port_types_3",
        FT_UINT8, BASE_HEX, VALS(artnet_port_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_port_types_4,
      { "Type of Port 4",
        "artnet.poll_reply.port_types_4",
        FT_UINT8, BASE_HEX, VALS(artnet_port_type_vals), 0x0,
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

    { &hf_artnet_poll_reply_good_input_recv_error,
      { "Receive errors detected",
        "artnet.poll_reply.good_input_recv_error",
        FT_UINT8, BASE_HEX, NULL, 0x04,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_input_disabled,
      { "Input is disabled",
        "artnet.poll_reply.good_input_disabled",
        FT_UINT8, BASE_HEX, NULL, 0x08,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_input_dmx_text,
      { "DMX text packets supported",
        "artnet.poll_reply.good_input_dmx_text",
        FT_UINT8, BASE_HEX, NULL, 0x10,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_input_dmx_sip,
      { "DMX SIPs supported",
        "artnet.poll_reply.good_input_dmx_sip",
        FT_UINT8, BASE_HEX, NULL, 0x20,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_input_dmx_test,
      { "DMX test packets supported",
        "artnet.poll_reply.good_input_dmx_test",
        FT_UINT8, BASE_HEX, NULL, 0x40,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_input_data,
      { "Data received",
        "artnet.poll_reply.good_input_data",
        FT_UINT8, BASE_HEX, NULL, 0x80,
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

    { &hf_artnet_poll_reply_good_output_b,
      { "Output Status (B)",
        "artnet.poll_reply.good_output_b",
        FT_NONE, BASE_NONE, NULL, 0,
        "Port output status (B)", HFILL }},

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
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_b_1,
      { "Output status (B) of Port 1",
        "artnet.poll_reply.good_output_b_1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_b_2,
      { "Output status (B) of Port 2",
        "artnet.poll_reply.good_output_b_2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_b_3,
      { "Output status (B) of Port 3",
        "artnet.poll_reply.good_output_b_3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_b_4,
      { "Output status (B) of Port 4",
        "artnet.poll_reply.good_output_b_4",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_tx_proto,
      { "Transmit protocol",
        "artnet.poll_reply.good_output_tx_proto",
        FT_UINT8, BASE_HEX, VALS(vals_artnet_poll_reply_tx_proto), 0x01,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_merge_ltp,
      { "Merge mode is LTP",
        "artnet.poll_reply.good_output_merge_ltp",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_short,
      { "DMX output short circuit",
        "artnet.poll_reply.good_output_short",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_merge_artnet,
      { "Merging Art-Net data",
        "artnet.poll_reply.good_output_merge_artnet",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_dmx_text,
      { "DMX text packets supported",
        "artnet.poll_reply.good_output_dmx_text",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_dmx_sip,
      { "DMX SIPs supported",
        "artnet.poll_reply.good_output_dmx_sip",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_dmx_test,
      { "DMX test packets supported",
        "artnet.poll_reply.good_output_dmx_test",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_data,
      { "Data transmitted",
        "artnet.poll_reply.good_output_data",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_style,
      { "Output Style",
        "artnet.poll_reply.good_output_style",
        FT_UINT8, BASE_HEX, VALS(vals_artnet_poll_reply_output_style), 0x40,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_good_output_rdm,
      { "RDM",
        "artnet.poll_reply.good_output_rdm",
        FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
        NULL, HFILL }},

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

    { &hf_artnet_poll_reply_swin_1_universe,
      { "Universe of input port 1",
        "artnet.poll_reply.swin_1_universe",
        FT_UINT16, BASE_DEC,NULL, 0x0,
        NULL,HFILL }},
    { &hf_artnet_poll_reply_swin_2_universe,
      { "Universe of input port 2",
        "artnet.poll_reply.swin_2_universe",
        FT_UINT16, BASE_DEC,NULL, 0x0,
        NULL,HFILL }},
    { &hf_artnet_poll_reply_swin_3_universe,
      { "Universe of input port 3",
        "artnet.poll_reply.swin_3_universe",
        FT_UINT16, BASE_DEC,NULL, 0x0,
        NULL,HFILL }},
    { &hf_artnet_poll_reply_swin_4_universe,
      { "Universe of input port 4",
        "artnet.poll_reply.swin_4_universe",
        FT_UINT16, BASE_DEC,NULL, 0x0,
        NULL,HFILL }},

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

    { &hf_artnet_poll_reply_swout_1_universe,
      { "Universe of output port 1",
        "artnet.poll_reply.swout_1_universe",
        FT_UINT16, BASE_DEC,NULL, 0x0,
        NULL,HFILL }},
    { &hf_artnet_poll_reply_swout_2_universe,
      { "Universe of output port 2",
        "artnet.poll_reply.swout_2_universe",
        FT_UINT16, BASE_DEC,NULL, 0x0,
        NULL,HFILL }},
    { &hf_artnet_poll_reply_swout_3_universe,
      { "Universe of output port 3",
        "artnet.poll_reply.swout_3_universe",
        FT_UINT16, BASE_DEC,NULL, 0x0,
        NULL,HFILL }},
    { &hf_artnet_poll_reply_swout_4_universe,
      { "Universe of output port 4",
        "artnet.poll_reply.swout_4_universe",
        FT_UINT16, BASE_DEC,NULL, 0x0,
        NULL,HFILL }},

    { &hf_artnet_poll_reply_sacnprio,
      { "sACN Priority",
        "artnet.poll_reply.sacnprio",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swmacro,
      { "SwMacro",
        "artnet.poll_reply.swmacro",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Macro key inputs", HFILL }},

    { &hf_artnet_poll_reply_swmacro_1,
      { "Macro 1",
        "artnet.poll_reply.swmacro_1",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x01,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swmacro_2,
      { "Macro 2",
        "artnet.poll_reply.swmacro_2",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x02,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swmacro_3,
      { "Macro 3",
        "artnet.poll_reply.swmacro_3",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x04,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swmacro_4,
      { "Macro 4",
        "artnet.poll_reply.swmacro_4",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x08,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swmacro_5,
      { "Macro 5",
        "artnet.poll_reply.swmacro_5",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x10,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swmacro_6,
      { "Macro 6",
        "artnet.poll_reply.swmacro_6",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x20,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swmacro_7,
      { "Macro 7",
        "artnet.poll_reply.swmacro_7",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x40,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swmacro_8,
      { "Macro 8",
        "artnet.poll_reply.swmacro_8",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x80,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swremote,
      { "SwRemote",
        "artnet.poll_reply.swremote",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Remote trigger", HFILL }},

    { &hf_artnet_poll_reply_swremote_1,
      { "Remote 1",
        "artnet.poll_reply.swremote_1",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x01,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swremote_2,
      { "Remote 2",
        "artnet.poll_reply.swremote_2",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x02,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swremote_3,
      { "Remote 3",
        "artnet.poll_reply.swremote_3",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x04,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swremote_4,
      { "Remote 4",
        "artnet.poll_reply.swremote_4",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x08,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swremote_5,
      { "Remote 5",
        "artnet.poll_reply.swremote_5",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x10,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swremote_6,
      { "Remote 6",
        "artnet.poll_reply.swremote_6",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x20,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swremote_7,
      { "Remote 7",
        "artnet.poll_reply.swremote_7",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x40,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_swremote_8,
      { "Remote 8",
        "artnet.poll_reply.swremote_8",
        FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x80,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_style,
      { "Style",
        "artnet.poll_reply.style",
        FT_UINT8, BASE_HEX, VALS(vals_artnet_poll_reply_style), 0x0,
        "Equipment style", HFILL }},

    { &hf_artnet_poll_reply_mac,
      { "MAC",
        "artnet.poll_reply.mac",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_bind_ip_address,
      { "Bind IP Address",
        "artnet.poll_reply.bind_ip_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "IP address of root device", HFILL }},

    { &hf_artnet_poll_reply_bind_index,
      { "Bind Index",
        "artnet.poll_reply.bind_index",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status2,
      { "Status2",
        "artnet.poll_reply.status2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status2_web_supported,
      { "Web configuration supported",
        "artnet.poll_reply.websupport",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status2_dhcp_used,
      { "DHCP configuration used",
        "artnet.poll_reply.dhcpused",
        FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x02,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status2_dhcp_supported,
      { "DHCP configuration supported",
        "artnet.poll_reply.dhcpsupport",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status2_bigaddr_supported,
      { "Port-Address size",
        "artnet.poll_reply.addrsupport",
        FT_UINT8, BASE_HEX, VALS(artnet_poll_reply_status2_bigaddr_supported_vals), 0x08,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status2_sacn_supported,
      { "sACN supported",
        "artnet.poll_reply.sacnsupport",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        "Switch between Art-Net and sACN (E1.31)", HFILL }},

    { &hf_artnet_poll_reply_status2_squawking,
      { "Squawking",
        "artnet.poll_reply.squawking",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status2_output_switching_supported,
      { "Switch output style",
        "artnet.poll_reply.switch_output_style",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        "Switch output style using ArtCommand", HFILL }},

    { &hf_artnet_poll_reply_status2_control_rdm_supported,
      { "Control RDM",
        "artnet.poll_reply.control_rdm",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
        "Control RDM using ArtCommand", HFILL }},

    { &hf_artnet_poll_reply_status3,
      { "Status3",
        "artnet.poll_reply.status3",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status3_switching_port_supported,
      { "Input/Output switching",
        "artnet.poll_reply.switch_ports",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
        "Switch ports between input/output", HFILL }},

    { &hf_artnet_poll_reply_status3_llrp_supported,
      { "LLRP",
        "artnet.poll_reply.llrp",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status3_failover_supported,
      { "Fail-over",
        "artnet.poll_reply.failover",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_status3_failsafe_state,
      { "Failsafe state",
        "artnet.poll_reply.failsafe_state",
        FT_UINT8, BASE_HEX, VALS(vals_artnet_poll_reply_status3_failsafe_state), 0xC0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_default_responder_uid,
      { "Default Responder UID",
        "artnet.poll_reply.default_responder_uid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "RDMnet & LLRP Default Responder UID", HFILL }},

    { &hf_artnet_poll_reply_node_report_status_code,
      { "Node Report Status Code",
        "artnet.poll_reply.node_report_status_code",
        FT_UINT16, BASE_HEX, VALS(vals_artnet_poll_reply_node_report_status_code), 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_node_report_response_counter,
      { "Node Report Response Counter",
        "artnet.poll_reply.node_report_response_counter",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_node_report_status_string,
      { "Node Report Status String",
        "artnet.poll_reply.node_report_status_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_user,
      { "User specific data",
        "artnet.poll_reply.user",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_poll_reply_refreshrate,
      { "Refresh rate",
        "artnet.poll_reply.refreshrate",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_hz, 0,
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


    /* ArtSync */

    { &hf_artnet_sync,
      { "ArtSync packet",
        "artnet.sync",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtSync packet", HFILL }},

    { &hf_artnet_sync_aux,
      { "Aux",
        "artnet.sync.aux",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},


    /* ArtNzs */

    { &hf_artnet_nzs,
      { "ArtNZS packet",
        "artnet.nzs",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtNZS packet", HFILL }},

    { &hf_artnet_nzs_sequence,
      { "Sequence",
        "artnet.nzs.sequence",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_start_code,
      { "Start Code",
        "artnet.nzs.start_code",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_subuni,
      { "Sub Universe",
        "artnet.nzs.subuni",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_net,
      { "Net",
        "artnet.nzs.net",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_length,
      { "Length",
        "artnet.nzs.length",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_man_id,
      { "ESTA Code",
        "artnet.nzs.vlc_esta_man_id",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_esta_man_vals_ext, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_sub_code,
      { "VLC Sub Code",
        "artnet.nzs.vlc_sub_code",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_flags,
      { "VLC Flags",
        "artnet.nzs.vlc_flags",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_flags_beacon,
      { "Beacon",
        "artnet.nzs.vlc_beacon",
        FT_UINT8, BASE_HEX, VALS(vals_artnet_nzs_vlc_beacon), 0x20,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_flags_reply,
      { "Reply",
        "artnet.nzs.vlc_reply",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_flags_ieee,
      { "IEEE",
        "artnet.nzs.vlc_ieee",
        FT_UINT8, BASE_HEX, VALS(vals_artnet_nzs_vlc_ieee), 0x80,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_transaction,
      { "VLC Transaction",
        "artnet.nzs.vlc_transaction",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_slot_addr,
      { "VLC Slot Address",
        "artnet.nzs.vlc_slot_addr",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_payload_size,
      { "VLC Payload Size",
        "artnet.nzs.vlc_payload_size",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_payload_checksum,
      { "VLC Payload Checksum",
        "artnet.nzs.vlc_payload_checksum",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_mod_depth,
      { "VLC Modulation Depth",
        "artnet.nzs.vlc_mod_depth",
        FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_mod_freq,
      { "VLC Modulation Frequency",
        "artnet.nzs.vlc_mod_freq",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_hz, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_mod_type,
      { "VLC Modulation Type",
        "artnet.nzs.vlc_mod_type",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_lang_code,
      { "VLC Payload Language Code",
        "artnet.nzs.vlc_lang_code",
        FT_UINT16, BASE_HEX, VALS(vals_artnet_nzs_vlc_lang_code), 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_beacon_repeat,
      { "VLC Beacon Repeat Frequency",
        "artnet.nzs.vlc_beacon_freq",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_hz, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_payload,
      { "VLC Payload",
        "artnet.nzs.vlc_payload",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_payload_beacon_url,
      { "VLC Payload (Beacon URL)",
        "artnet.nzs.vlc_payload_beacon_url",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_payload_beacon_text,
      { "VLC Payload (Beacon Text)",
        "artnet.nzs.vlc_payload_beacon_text",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_nzs_vlc_payload_beacon_location_id,
      { "VLC Payload (Beacon Location ID)",
        "artnet.nzs.vlc_payload_beacon_location_id",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},

    /* ArtAddress */

    { &hf_artnet_address,
      { "ArtAddress packet",
        "artnet.address",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtAddress packet", HFILL }},

    { &hf_artnet_address_netswitch_special,
      { "NetSwitch",
      "artnet.address.netswitch_special",
      FT_UINT8, BASE_HEX, VALS(artnet_address_switch_vals), 0,
      NULL, HFILL }},

    { &hf_artnet_address_netswitch_net,
      { "Net",
      "artnet.address.netswitch_net",
      FT_UINT8, BASE_DEC, NULL, 0x7F,
      NULL, HFILL }},

    { &hf_artnet_address_netswitch_write,
      { "Write Net",
      "artnet.address.netswitch_write",
      FT_BOOLEAN, 8, NULL, 0x80,
      NULL, HFILL }},

    { &hf_artnet_address_bind_index,
      { "Bind Index",
        "artnet.address.bind_index",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_short_name,
      { "Short Name",
        "artnet.address.short_name",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_address_long_name,
      { "Long Name",
        "artnet.address.long_name",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
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

    { &hf_artnet_address_subswitch_special,
      { "NetSwitch",
      "artnet.address.subswitch_special",
      FT_UINT8, BASE_HEX, VALS(artnet_address_switch_vals), 0,
      NULL, HFILL }},

    { &hf_artnet_address_subswitch_sub,
      { "Sub-Net",
      "artnet.address.subswitch_sub",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      NULL, HFILL }},

    { &hf_artnet_address_subswitch_write,
      { "Write Sub-Net",
      "artnet.address.subswitch_write",
      FT_BOOLEAN, 8, NULL, 0x80,
      NULL, HFILL }},

    { &hf_artnet_address_sacnprio,
      { "sACN Priority",
        "artnet.address.sacnprio",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
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

    { &hf_artnet_input_bind_index,
      { "Bind Index",
        "artnet.input.bind_index",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

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

    { &hf_artnet_input_input_disabled,
      { "Disabled",
      "artnet.input.disabled",
      FT_BOOLEAN, 8, NULL, 0xff,
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

    { &hf_artnet_tod_request_net,
      { "Net",
        "artnet.tod_request.net",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

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

    { &hf_artnet_tod_data_rdm_ver,
      { "RDM Version",
        "artnet.tod_data.rdm_ver",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_data_port,
      { "Port",
        "artnet.tod_data.port",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_data_bind_index,
      { "Bind Index",
        "artnet.tod_data.bind_index",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_data_net,
      { "Net",
        "artnet.tod_data.net",
        FT_UINT8, BASE_HEX, NULL, 0x0,
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

    { &hf_artnet_tod_control_net,
      { "Net",
        "artnet.tod_control.net",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Top 7 bits of the port address", HFILL }},

    { &hf_artnet_tod_control_command,
      { "Command",
        "artnet.tod_control.command",
        FT_UINT8, BASE_HEX, VALS(artnet_tod_control_command_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_tod_control_address,
      { "Address",
        "artnet.tod_control.address",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Lower byte of the port address", HFILL }},

    { &hf_artnet_tod_control_universe,
        { "Universe",
        "artnet.tod_control.universe",
        FT_UINT16, BASE_DEC, NULL, 0x0,
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
        FT_UINT16, BASE_HEX | BASE_EXT_STRING, &rdm_param_id_vals_ext, 0x0,
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
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_prog_sm,
      { "Program Subnet Mask",
        "artnet.ip_prog.command_prog_sm",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_prog_ip,
      { "Program IP",
        "artnet.ip_prog.command_prog_ip",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_reset,
      { "Reset Parameters",
        "artnet.ip_prog.command_reset",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_gw,
      { "Program Default Gateway",
        "artnet.ip_prog.command_prog_gw",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_unused,
      { "Unused",
        "artnet.ip_prog.command_unused",
        FT_UINT8, BASE_HEX, NULL, 0x20,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_dhcp_enable,
      { "Enable DHCP",
        "artnet.ip_prog.command_dhcp_enable",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_command_prog_enable,
      { "Enable Programming",
        "artnet.ip_prog.command_prog_enable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_ip,
      { "IP Address",
        "artnet.ip_prog.ip",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_sm,
      { "Subnet Mask",
        "artnet.ip_prog.sm",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "IP Subnet mask", HFILL }},

    { &hf_artnet_ip_prog_port,
      { "Port",
        "artnet.ip_prog.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_gw,
      { "Default Gateway",
        "artnet.ip_prog.gw",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},


    /* ArtIpProgReply */

    { &hf_artnet_ip_prog_reply,
      { "ArtIpProgReply packet",
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

    { &hf_artnet_ip_prog_reply_gw,
      { "Default Gateway",
        "artnet.ip_prog_reply.gw",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_reply_status,
      { "Status",
        "artnet.ip_prog_reply.status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_reply_status_unused,
      { "Unused",
        "artnet.ip_prog_reply.unused",
        FT_UINT8, BASE_HEX, NULL, 0xbf,
        NULL, HFILL }},

    { &hf_artnet_ip_prog_reply_status_dhcp_enable,
      { "DHCP Enabled",
        "artnet.ip_prog_reply.status_dhcp_enable",
        FT_BOOLEAN, 8, NULL, 0x40,
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
      { "Priority",
        "artnet.diag_data.priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_diag_data_port,
      { "Logical port",
        "artnet.diag_data.port",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_diag_data_length,
      { "Length",
        "artnet.diag_data.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_diag_data_data,
      { "Data",
        "artnet.diag_data.data",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtCommand */

    { &hf_artnet_command,
      { "ArtCommand packet",
        "artnet.command",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtCommand packet", HFILL }},

    { &hf_artnet_command_esta_man,
      { "ESTA Code",
        "artnet.command.esta_man",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_esta_man_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_artnet_command_length,
      { "Length",
        "artnet.command.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_command_data,
      { "Data",
        "artnet.command_data.data",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtDataRequest */

    { &hf_artnet_data_request,
      { "ArtDataRequest packet",
        "artnet.data_request",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtDataRequest packet", HFILL }},

    { &hf_artnet_data_request_esta_man,
      { "ESTA Code",
        "artnet.data_request.esta_man",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_esta_man_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_artnet_data_request_oem,
      { "OEM",
        "artnet.data_request.oem",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_oem_code_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_artnet_data_request_request,
      { "Request",
        "artnet.data_request.request",
        FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(artnet_data_request_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_data_request_spare,
      { "Spare",
        "artnet.data_request.spare",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ArtDataReply */

    { &hf_artnet_data_reply,
      { "ArtDataReply packet",
        "artnet.data_reply",
        FT_NONE, BASE_NONE, NULL, 0,
        "Art-Net ArtDataReply packet", HFILL }},

    { &hf_artnet_data_reply_esta_man,
      { "ESTA Code",
        "artnet.data_reply.esta_man",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_esta_man_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_artnet_data_reply_oem,
      { "OEM",
        "artnet.data_reply.oem",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_oem_code_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_artnet_data_reply_request,
      { "Request",
        "artnet.data_reply.request",
        FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(artnet_data_request_vals), 0x0,
        NULL, HFILL }},

    { &hf_artnet_data_reply_payload_length,
      { "Payload length",
        "artnet.data_reply.payload_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_artnet_data_reply_payload,
      { "Payload",
        "artnet.data_reply.payload",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

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

    { &hf_artnet_time_code_frames,
      { "Frames",
        "artnet.time_code.frames",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_time_code_seconds,
      { "Seconds",
        "artnet.time_code.seconds",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_time_code_minutes,
      { "Minutes",
        "artnet.time_code.minutes",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_time_code_hours,
      { "Hours",
        "artnet.time_code.hours",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_artnet_time_code_type,
      { "Type",
        "artnet.time_code.type",
        FT_UINT8, BASE_DEC, VALS(artnet_time_code_vals), 0,
        NULL, HFILL }},

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

    { &hf_artnet_trigger_oem,
      { "OEM",
        "artnet.trigger.oem",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &artnet_oem_code_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_artnet_trigger_key,
      { "Key",
        "artnet.trigger.key",
        FT_UINT8, BASE_HEX_DEC, 0, 0x0,
        NULL, HFILL }},

    { &hf_artnet_trigger_key_unspecific,
      { "Key (unspecific)",
        "artnet.trigger.key_unspecific",
        FT_UINT8, BASE_HEX, VALS(artnet_trigger_key_vals), 0x0,
        "Key (not specific to manufacturer)", HFILL }},

    { &hf_artnet_trigger_subkey,
      { "SubKey",
        "artnet.trigger.subkey",
        FT_UINT8, BASE_HEX_DEC, 0, 0x0,
        NULL, HFILL }},

    { &hf_artnet_trigger_data,
      { "Data",
        "artnet.trigger.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

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
      { "Length",
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
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
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

  static ei_register_info ei[] = {
    { &ei_artnet_poll_reply_bind_ip_without_index,
      { "artnet.poll_reply.bind_ip_without_index", PI_MALFORMED, PI_WARN,
          "Bind IP address set without bind index", EXPFILL }
    },
    { &ei_artnet_poll_reply_bind_index_without_ip,
      { "artnet.poll_reply.bind_index_without_ip", PI_MALFORMED, PI_WARN,
          "Bind index set without bind IP address", EXPFILL }
    },
    { &ei_artnet_poll_reply_node_report_invalid_format,
      { "artnet.poll_reply.node_report_format_invalid", PI_MALFORMED, PI_WARN,
          "Node report has invalid format.", EXPFILL }
    }
  };

  static int *ett[] = {
    &ett_artnet,
    &ett_artnet_poll_talktome,
    &ett_artnet_poll_reply_status,
    &ett_artnet_poll_reply_good_input_1,
    &ett_artnet_poll_reply_good_input_2,
    &ett_artnet_poll_reply_good_input_3,
    &ett_artnet_poll_reply_good_input_4,
    &ett_artnet_poll_reply_good_output_1,
    &ett_artnet_poll_reply_good_output_2,
    &ett_artnet_poll_reply_good_output_3,
    &ett_artnet_poll_reply_good_output_4,
    &ett_artnet_poll_reply_good_output_b_1,
    &ett_artnet_poll_reply_good_output_b_2,
    &ett_artnet_poll_reply_good_output_b_3,
    &ett_artnet_poll_reply_good_output_b_4,
    &ett_artnet_poll_reply_swmacro,
    &ett_artnet_poll_reply_swremote,
    &ett_artnet_poll_reply_status2,
    &ett_artnet_poll_reply_status3,
    &ett_artnet_ip_prog_command,
    &ett_artnet_ip_prog_reply_status,
    &ett_artnet_address_netswitch,
    &ett_artnet_address_subswitch,
    &ett_artnet_input_input_1,
    &ett_artnet_input_input_2,
    &ett_artnet_input_input_3,
    &ett_artnet_input_input_4,
    &ett_artnet_nzs_vlc_flags
  };

  proto_artnet = proto_register_protocol("Art-Net", "ARTNET", "artnet");
  proto_register_field_array(proto_artnet, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_artnet = expert_register_protocol(proto_artnet);
  expert_register_field_array(expert_artnet, ei, array_length(ei));

  artnet_handle  = register_dissector("artnet", dissect_artnet, proto_artnet);
}

void
proto_reg_handoff_artnet(void) {
  dissector_add_for_decode_as_with_preference("udp.port", artnet_handle);
  rdm_handle      = find_dissector_add_dependency("rdm", proto_artnet);
  dmx_chan_handle = find_dissector_add_dependency("dmx-chan", proto_artnet);

  heur_dissector_add("udp", dissect_artnet_heur, "ARTNET over UDP", "artnet_udp", proto_artnet, HEURISTIC_ENABLE);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
