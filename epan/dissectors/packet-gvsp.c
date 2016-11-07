/* packet-gvsp.c
 * Routines for AIA GigE Vision (TM) Streaming Protocol dissection
 * Copyright 2012, AIA <www.visiononline.org> All rights reserved
 *
 * GigE Vision (TM): GigE Vision a standard developed under the sponsorship of the AIA for
 * the benefit of the machine vision industry. GVSP stands for GigE Vision (TM) Streaming
 * Protocol.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>

void proto_register_gvsp(void);
void proto_reg_handoff_gvsp(void);

#define GVSP_MIN_PACKET_SIZE         8
#define GVSP_V2_MIN_PACKET_SIZE     20

/*
  Payload types
 */

#define GVSP_PAYLOAD_IMAGE               ( 0x0001 )
#define GVSP_PAYLOAD_RAWDATA             ( 0x0002 )
#define GVSP_PAYLOAD_FILE                ( 0x0003 )
#define GVSP_PAYLOAD_CHUNKDATA           ( 0x0004 )
#define GVSP_PAYLOAD_EXTENDEDCHUNKDATA   ( 0x0005 ) /* Deprecated */
#define GVSP_PAYLOAD_JPEG                ( 0x0006 )
#define GVSP_PAYLOAD_JPEG2000            ( 0x0007 )
#define GVSP_PAYLOAD_H264                ( 0x0008 )
#define GVSP_PAYLOAD_MULTIZONEIMAGE      ( 0x0009 )
#define GVSP_PAYLOAD_DEVICEPSECIFICSTART ( 0x8000 )


/*
   GVSP packet types
 */

#define GVSP_PACKET_LEADER            ( 1 )
#define GVSP_PACKET_TRAILER           ( 2 )
#define GVSP_PACKET_PAYLOAD           ( 3 )
#define GVSP_PACKET_ALLIN             ( 4 )
#define GVSP_PACKET_PAYLOAD_H264      ( 5 )
#define GVSP_PACKET_PAYLOAD_MULTIZONE ( 6 )


/*
   GVSP statuses
 */

#define GEV_STATUS_SUCCESS                             (0x0000)
#define GEV_STATUS_PACKET_RESEND                       (0x0100)
#define GEV_STATUS_NOT_IMPLEMENTED                     (0x8001)
#define GEV_STATUS_INVALID_PARAMETER                   (0x8002)
#define GEV_STATUS_INVALID_ADDRESS                     (0x8003)
#define GEV_STATUS_WRITE_PROTECT                       (0x8004)
#define GEV_STATUS_BAD_ALIGNMENT                       (0x8005)
#define GEV_STATUS_ACCESS_DENIED                       (0x8006)
#define GEV_STATUS_BUSY                                (0x8007)
#define GEV_STATUS_LOCAL_PROBLEM                       (0x8008) /* deprecated */
#define GEV_STATUS_MSG_MISMATCH                        (0x8009) /* deprecated */
#define GEV_STATUS_INVALID_PROTOCOL                    (0x800A) /* deprecated */
#define GEV_STATUS_NO_MSG                              (0x800B) /* deprecated */
#define GEV_STATUS_PACKET_UNAVAILABLE                  (0x800C)
#define GEV_STATUS_DATA_OVERRUN                        (0x800D)
#define GEV_STATUS_INVALID_HEADER                      (0x800E)
#define GEV_STATUS_WRONG_CONFIG                        (0x800F) /* deprecated */
#define GEV_STATUS_PACKET_NOT_YET_AVAILABLE            (0x8010)
#define GEV_STATUS_PACKET_AND_PREV_REMOVED_FROM_MEMORY (0x8011)
#define GEV_STATUS_PACKET_REMOVED_FROM_MEMORY          (0x8012)
#define GEV_STATUS_ERROR                               (0x8FFF)


/*
   Pixel type color
 */

#define GVSP_PIX_MONO             (0x01000000)
#define GVSP_PIX_COLOR            (0x02000000)
#define GVSP_PIX_CUSTOM           (0x80000000)

/*
   Pixel types
 */
#define GVSP_PIX_MONO1P 0x01010037
#define GVSP_PIX_MONO2P 0x01020038
#define GVSP_PIX_MONO4P 0x01040039
#define GVSP_PIX_MONO8 0x01080001
#define GVSP_PIX_MONO8S 0x01080002
#define GVSP_PIX_MONO10 0x01100003
#define GVSP_PIX_MONO10P 0x010A0046
#define GVSP_PIX_MONO12 0x01100005
#define GVSP_PIX_MONO12P 0x010C0047
#define GVSP_PIX_MONO14 0x01100025
#define GVSP_PIX_MONO16 0x01100007
#define GVSP_PIX_BAYERBG8 0x0108000B
#define GVSP_PIX_BAYERBG10 0x0110000F
#define GVSP_PIX_BAYERBG10P 0x010A0052
#define GVSP_PIX_BAYERBG12 0x01100013
#define GVSP_PIX_BAYERBG12P 0x010C0053
#define GVSP_PIX_BAYERBG16 0x01100031
#define GVSP_PIX_BAYERGB8 0x0108000A
#define GVSP_PIX_BAYERGB10 0x0110000E
#define GVSP_PIX_BAYERGB10P 0x010A0054
#define GVSP_PIX_BAYERGB12 0x01100012
#define GVSP_PIX_BAYERGB12P 0x010C0055
#define GVSP_PIX_BAYERGB16 0x01100030
#define GVSP_PIX_BAYERGR8 0x01080008
#define GVSP_PIX_BAYERGR10 0x0110000C
#define GVSP_PIX_BAYERGR10P 0x010A0056
#define GVSP_PIX_BAYERGR12 0x01100010
#define GVSP_PIX_BAYERGR12P 0x010C0057
#define GVSP_PIX_BAYERGR16 0x0110002E
#define GVSP_PIX_BAYERRG8 0x01080009
#define GVSP_PIX_BAYERRG10 0x0110000D
#define GVSP_PIX_BAYERRG10P 0x010A0058
#define GVSP_PIX_BAYERRG12 0x01100011
#define GVSP_PIX_BAYERRG12P 0x010C0059
#define GVSP_PIX_BAYERRG16 0x0110002F
#define GVSP_PIX_RGBA8 0x02200016
#define GVSP_PIX_RGBA10 0x0240005F
#define GVSP_PIX_RGBA10P 0x02280060
#define GVSP_PIX_RGBA12 0x02400061
#define GVSP_PIX_RGBA12P 0x02300062
#define GVSP_PIX_RGBA14 0x02400063
#define GVSP_PIX_RGBA16 0x02400064
#define GVSP_PIX_RGB8 0x02180014
#define GVSP_PIX_RGB8_PLANAR 0x02180021
#define GVSP_PIX_RGB10 0x02300018
#define GVSP_PIX_RGB10_PLANAR 0x02300022
#define GVSP_PIX_RGB10P 0x021E005C
#define GVSP_PIX_RGB10P32 0x0220001D
#define GVSP_PIX_RGB12 0x0230001A
#define GVSP_PIX_RGB12_PLANAR 0x02300023
#define GVSP_PIX_RGB12P 0x0224005D
#define GVSP_PIX_RGB14 0x0230005E
#define GVSP_PIX_RGB16 0x02300033
#define GVSP_PIX_RGB16_PLANAR 0x02300024
#define GVSP_PIX_RGB565P 0x02100035
#define GVSP_PIX_BGRA8 0x02200017
#define GVSP_PIX_BGRA10 0x0240004C
#define GVSP_PIX_BGRA10P 0x0228004D
#define GVSP_PIX_BGRA12 0x0240004E
#define GVSP_PIX_BGRA12P 0x0230004F
#define GVSP_PIX_BGRA14 0x02400050
#define GVSP_PIX_BGRA16 0x02400051
#define GVSP_PIX_BGR8 0x02180015
#define GVSP_PIX_BGR10 0x02300019
#define GVSP_PIX_BGR10P 0x021E0048
#define GVSP_PIX_BGR12 0x0230001B
#define GVSP_PIX_BGR12P 0x02240049
#define GVSP_PIX_BGR14 0x0230004A
#define GVSP_PIX_BGR16 0x0230004B
#define GVSP_PIX_BGR565P 0x02100036
#define GVSP_PIX_R8 0x010800C9
#define GVSP_PIX_R10 0x010A00CA
#define GVSP_PIX_R12 0x010C00CB
#define GVSP_PIX_R16 0x011000CC
#define GVSP_PIX_G8 0x010800CD
#define GVSP_PIX_G10 0x010A00CE
#define GVSP_PIX_G12 0x010C00CF
#define GVSP_PIX_G16 0x011000D0
#define GVSP_PIX_B8 0x010800D1
#define GVSP_PIX_B10 0x010A00D2
#define GVSP_PIX_B12 0x010C00D3
#define GVSP_PIX_B16 0x011000D4
#define GVSP_PIX_COORD3D_ABC8 0x021800B2
#define GVSP_PIX_COORD3D_ABC8_PLANAR 0x021800B3
#define GVSP_PIX_COORD3D_ABC10P 0x021E00DB
#define GVSP_PIX_COORD3D_ABC10P_PLANAR 0x021E00DC
#define GVSP_PIX_COORD3D_ABC12P 0x022400DE
#define GVSP_PIX_COORD3D_ABC12P_PLANAR 0x022400DF
#define GVSP_PIX_COORD3D_ABC16 0x023000B9
#define GVSP_PIX_COORD3D_ABC16_PLANAR 0x023000BA
#define GVSP_PIX_COORD3D_ABC32F 0x026000C0
#define GVSP_PIX_COORD3D_ABC32F_PLANAR 0x026000C1
#define GVSP_PIX_COORD3D_AC8 0x021000B4
#define GVSP_PIX_COORD3D_AC8_PLANAR 0x021000B5
#define GVSP_PIX_COORD3D_AC10P 0x021400F0
#define GVSP_PIX_COORD3D_AC10P_PLANAR 0x021400F1
#define GVSP_PIX_COORD3D_AC12P 0x021800F2
#define GVSP_PIX_COORD3D_AC12P_PLANAR 0x021800F3
#define GVSP_PIX_COORD3D_AC16 0x022000BB
#define GVSP_PIX_COORD3D_AC16_PLANAR 0x022000BC
#define GVSP_PIX_COORD3D_AC32F 0x024000C2
#define GVSP_PIX_COORD3D_AC32F_PLANAR 0x024000C3
#define GVSP_PIX_COORD3D_A8 0x010800AF
#define GVSP_PIX_COORD3D_A10P 0x010A00D5
#define GVSP_PIX_COORD3D_A12P 0x010C00D8
#define GVSP_PIX_COORD3D_A16 0x011000B6
#define GVSP_PIX_COORD3D_A32F 0x012000BD
#define GVSP_PIX_COORD3D_B8 0x010800B0
#define GVSP_PIX_COORD3D_B10P 0x010A00D6
#define GVSP_PIX_COORD3D_B12P 0x010C00D9
#define GVSP_PIX_COORD3D_B16 0x011000B7
#define GVSP_PIX_COORD3D_B32F 0x012000BE
#define GVSP_PIX_COORD3D_C8 0x010800B1
#define GVSP_PIX_COORD3D_C10P 0x010A00D7
#define GVSP_PIX_COORD3D_C12P 0x010C00DA
#define GVSP_PIX_COORD3D_C16 0x011000B8
#define GVSP_PIX_COORD3D_C32F 0x012000BF
#define GVSP_PIX_CONFIDENCE1 0x010800C4
#define GVSP_PIX_CONFIDENCE1P 0x010100C5
#define GVSP_PIX_CONFIDENCE8 0x010800C6
#define GVSP_PIX_CONFIDENCE16 0x011000C7
#define GVSP_PIX_CONFIDENCE32F 0x012000C8
#define GVSP_PIX_BICOLORBGRG8 0x021000A6
#define GVSP_PIX_BICOLORBGRG10 0x022000A9
#define GVSP_PIX_BICOLORBGRG10P 0x021400AA
#define GVSP_PIX_BICOLORBGRG12 0x022000AD
#define GVSP_PIX_BICOLORBGRG12P 0x021800AE
#define GVSP_PIX_BICOLORRGBG8 0x021000A5
#define GVSP_PIX_BICOLORRGBG10 0x022000A7
#define GVSP_PIX_BICOLORRGBG10P 0x021400A8
#define GVSP_PIX_BICOLORRGBG12 0x022000AB
#define GVSP_PIX_BICOLORRGBG12P 0x021800AC
#define GVSP_PIX_SCF1WBWG8 0x01080067
#define GVSP_PIX_SCF1WBWG10 0x01100068
#define GVSP_PIX_SCF1WBWG10P 0x010A0069
#define GVSP_PIX_SCF1WBWG12 0x0110006A
#define GVSP_PIX_SCF1WBWG12P 0x010C006B
#define GVSP_PIX_SCF1WBWG14 0x0110006C
#define GVSP_PIX_SCF1WBWG16 0x0110006D
#define GVSP_PIX_SCF1WGWB8 0x0108006E
#define GVSP_PIX_SCF1WGWB10 0x0110006F
#define GVSP_PIX_SCF1WGWB10P 0x010A0070
#define GVSP_PIX_SCF1WGWB12 0x01100071
#define GVSP_PIX_SCF1WGWB12P 0x010C0072
#define GVSP_PIX_SCF1WGWB14 0x01100073
#define GVSP_PIX_SCF1WGWB16 0x01100074
#define GVSP_PIX_SCF1WGWR8 0x01080075
#define GVSP_PIX_SCF1WGWR10 0x01100076
#define GVSP_PIX_SCF1WGWR10P 0x010A0077
#define GVSP_PIX_SCF1WGWR12 0x01100078
#define GVSP_PIX_SCF1WGWR12P 0x010C0079
#define GVSP_PIX_SCF1WGWR14 0x0110007A
#define GVSP_PIX_SCF1WGWR16 0x0110007B
#define GVSP_PIX_SCF1WRWG8 0x0108007C
#define GVSP_PIX_SCF1WRWG10 0x0110007D
#define GVSP_PIX_SCF1WRWG10P 0x010A007E
#define GVSP_PIX_SCF1WRWG12 0x0110007F
#define GVSP_PIX_SCF1WRWG12P 0x010C0080
#define GVSP_PIX_SCF1WRWG14 0x01100081
#define GVSP_PIX_SCF1WRWG16 0x01100082
#define GVSP_PIX_YCBCR8 0x0218005B
#define GVSP_PIX_YCBCR8_CBYCR 0x0218003A
#define GVSP_PIX_YCBCR10_CBYCR 0x02300083
#define GVSP_PIX_YCBCR10P_CBYCR 0x021E0084
#define GVSP_PIX_YCBCR12_CBYCR 0x02300085
#define GVSP_PIX_YCBCR12P_CBYCR 0x02240086
#define GVSP_PIX_YCBCR411_8 0x020C005A
#define GVSP_PIX_YCBCR411_8_CBYYCRYY 0x020C003C
#define GVSP_PIX_YCBCR422_8 0x0210003B
#define GVSP_PIX_YCBCR422_8_CBYCRY 0x02100043
#define GVSP_PIX_YCBCR422_10 0x02200065
#define GVSP_PIX_YCBCR422_10_CBYCRY 0x02200099
#define GVSP_PIX_YCBCR422_10P 0x02140087
#define GVSP_PIX_YCBCR422_10P_CBYCRY 0x0214009A
#define GVSP_PIX_YCBCR422_12 0x02200066
#define GVSP_PIX_YCBCR422_12_CBYCRY 0x0220009B
#define GVSP_PIX_YCBCR422_12P 0x02180088
#define GVSP_PIX_YCBCR422_12P_CBYCRY 0x0218009C
#define GVSP_PIX_YCBCR601_8_CBYCR 0x0218003D
#define GVSP_PIX_YCBCR601_10_CBYCR 0x02300089
#define GVSP_PIX_YCBCR601_10P_CBYCR 0x021E008A
#define GVSP_PIX_YCBCR601_12_CBYCR 0x0230008B
#define GVSP_PIX_YCBCR601_12P_CBYCR 0x0224008C
#define GVSP_PIX_YCBCR601_411_8_CBYYCRYY 0x020C003F
#define GVSP_PIX_YCBCR601_422_8 0x0210003E
#define GVSP_PIX_YCBCR601_422_8_CBYCRY 0x02100044
#define GVSP_PIX_YCBCR601_422_10 0x0220008D
#define GVSP_PIX_YCBCR601_422_10_CBYCRY 0x0220009D
#define GVSP_PIX_YCBCR601_422_10P 0x0214008E
#define GVSP_PIX_YCBCR601_422_10P_CBYCRY 0x0214009E
#define GVSP_PIX_YCBCR601_422_12 0x0220008F
#define GVSP_PIX_YCBCR601_422_12_CBYCRY 0x0220009F
#define GVSP_PIX_YCBCR601_422_12P 0x02180090
#define GVSP_PIX_YCBCR601_422_12P_CBYCRY 0x021800A0
#define GVSP_PIX_YCBCR709_8_CBYCR 0x02180040
#define GVSP_PIX_YCBCR709_10_CBYCR 0x02300091
#define GVSP_PIX_YCBCR709_10P_CBYCR 0x021E0092
#define GVSP_PIX_YCBCR709_12_CBYCR 0x02300093
#define GVSP_PIX_YCBCR709_12P_CBYCR 0x02240094
#define GVSP_PIX_YCBCR709_411_8_CBYYCRYY 0x020C0042
#define GVSP_PIX_YCBCR709_422_8 0x02100041
#define GVSP_PIX_YCBCR709_422_8_CBYCRY 0x02100045
#define GVSP_PIX_YCBCR709_422_10 0x02200095
#define GVSP_PIX_YCBCR709_422_10_CBYCRY 0x022000A1
#define GVSP_PIX_YCBCR709_422_10P 0x02140096
#define GVSP_PIX_YCBCR709_422_10P_CBYCRY 0x021400A2
#define GVSP_PIX_YCBCR709_422_12 0x02200097
#define GVSP_PIX_YCBCR709_422_12_CBYCRY 0x022000A3
#define GVSP_PIX_YCBCR709_422_12P 0x02180098
#define GVSP_PIX_YCBCR709_422_12P_CBYCRY 0x021800A4
#define GVSP_PIX_YUV8_UYV 0x02180020
#define GVSP_PIX_YUV411_8_UYYVYY 0x020C001E
#define GVSP_PIX_YUV422_8 0x02100032
#define GVSP_PIX_YUV422_8_UYVY 0x0210001F
#define GVSP_PIX_MONO10PACKED 0x010C0004
#define GVSP_PIX_MONO12PACKED 0x010C0006
#define GVSP_PIX_BAYERBG10PACKED 0x010C0029
#define GVSP_PIX_BAYERBG12PACKED 0x010C002D
#define GVSP_PIX_BAYERGB10PACKED 0x010C0028
#define GVSP_PIX_BAYERGB12PACKED 0x010C002C
#define GVSP_PIX_BAYERGR10PACKED 0x010C0026
#define GVSP_PIX_BAYERGR12PACKED 0x010C002A
#define GVSP_PIX_BAYERRG10PACKED 0x010C0027
#define GVSP_PIX_BAYERRG12PACKED 0x010C002B
#define GVSP_PIX_RGB10V1PACKED 0x0220001C
#define GVSP_PIX_RGB12V1PACKED 0x02240034


/* Structure to hold GVSP packet information */
typedef struct _gvsp_packet_info
{
    gint    chunk;
    guint8  format;
    guint16 status;
    guint16 payloadtype;
    guint64 blockid;
    guint32 packetid;
    gint    enhanced;
    gint    flag_resendrangeerror;
    gint    flag_previousblockdropped;
    gint    flag_packetresend;
} gvsp_packet_info;


/*Define the gvsp proto */
static int proto_gvsp = -1;
/*static int global_gvsp_port = 20202;*/
static dissector_handle_t gvsp_handle;


/* Define the tree for gvsp */
static int ett_gvsp = -1;
static int ett_gvsp_flags = -1;
static int ett_gvsp_header = -1;
static int ett_gvsp_payload = -1;
static int ett_gvsp_trailer = -1;
static int ett_gvsp_pixelformat = -1;
static int ett_gvsp_fieldinfo = -1;
static int ett_gvsp_cs = -1;
static int ett_gvsp_sc_zone_direction = -1;
static int ett_gvsp_zoneinfo = -1;


static const value_string statusnames[] = {
    { GEV_STATUS_SUCCESS,                             "GEV_STATUS_SUCCESS" },
    { GEV_STATUS_PACKET_RESEND,                       "GEV_STATUS_PACKET_RESEND" },
    { GEV_STATUS_NOT_IMPLEMENTED,                     "GEV_STATUS_NOT_IMPLEMENTED" },
    { GEV_STATUS_INVALID_PARAMETER,                   "GEV_STATUS_INVALID_PARAMETER" },
    { GEV_STATUS_INVALID_ADDRESS,                     "GEV_STATUS_INVALID_ADDRESS" },
    { GEV_STATUS_WRITE_PROTECT,                       "GEV_STATUS_WRITE_PROTECT" },
    { GEV_STATUS_BAD_ALIGNMENT,                       "GEV_STATUS_BAD_ALIGNMENT" },
    { GEV_STATUS_ACCESS_DENIED,                       "GEV_STATUS_ACCESS_DENIED" },
    { GEV_STATUS_BUSY,                                "GEV_STATUS_BUSY" },
    { GEV_STATUS_LOCAL_PROBLEM,                       "GEV_STATUS_LOCAL_PROBLEM (deprecated)" },
    { GEV_STATUS_MSG_MISMATCH,                        "GEV_STATUS_MSG_MISMATCH (deprecated)" },
    { GEV_STATUS_INVALID_PROTOCOL,                    "GEV_STATUS_INVALID_PROTOCOL (deprecated)" },
    { GEV_STATUS_NO_MSG,                              "GEV_STATUS_NO_MSG (deprecated)" },
    { GEV_STATUS_PACKET_UNAVAILABLE,                  "GEV_STATUS_PACKET_UNAVAILABLE" },
    { GEV_STATUS_DATA_OVERRUN,                        "GEV_STATUS_DATA_OVERRUN" },
    { GEV_STATUS_INVALID_HEADER,                      "GEV_STATUS_INVALID_HEADER" },
    { GEV_STATUS_WRONG_CONFIG,                        "GEV_STATUS_WRONG_CONFIG (deprecated)" },
    { GEV_STATUS_PACKET_NOT_YET_AVAILABLE,            "GEV_STATUS_PACKET_NOT_YET_AVAILABLE" },
    { GEV_STATUS_PACKET_AND_PREV_REMOVED_FROM_MEMORY, "GEV_STATUS_PACKET_AND_PREV_REMOVED_FROM_MEMORY" },
    { GEV_STATUS_PACKET_REMOVED_FROM_MEMORY,          "GEV_STATUS_PACKET_REMOVED_FROM_MEMORY" },
    { GEV_STATUS_ERROR,                               "GEV_STATUS_ERROR" },
    { 0, NULL },
};

static value_string_ext statusnames_ext = VALUE_STRING_EXT_INIT(statusnames);

static const value_string formatnames[] = {
    { GVSP_PACKET_LEADER,                   "LEADER" },
    { GVSP_PACKET_TRAILER,                  "TRAILER" },
    { GVSP_PACKET_PAYLOAD,                  "PAYLOAD" },
    { GVSP_PACKET_ALLIN,                    "ALLIN" },
    { GVSP_PACKET_PAYLOAD_H264,             "H264" },
    { GVSP_PACKET_PAYLOAD_MULTIZONE,        "MULTIZONE" },
    { 0x80 | GVSP_PACKET_LEADER,            "LEADER (ext IDs)" },
    { 0x80 | GVSP_PACKET_TRAILER,           "TRAILER (ext IDs)" },
    { 0x80 | GVSP_PACKET_PAYLOAD,           "PAYLOAD (ext IDs)" },
    { 0x80 | GVSP_PACKET_ALLIN,             "ALLIN (ext IDs)" },
    { 0x80 | GVSP_PACKET_PAYLOAD_H264,      "H264 (ext IDs)" },
    { 0x80 | GVSP_PACKET_PAYLOAD_MULTIZONE, "MULTIZONE (ext IDs)" },
    { 0, NULL },
};

static const value_string payloadtypenames[] = {
    { GVSP_PAYLOAD_IMAGE,                      "IMAGE" },
    { GVSP_PAYLOAD_RAWDATA,                    "RAWDATA" },
    { GVSP_PAYLOAD_FILE,                       "FILE" },
    { GVSP_PAYLOAD_CHUNKDATA,                  "CHUNKDATA" },
    { GVSP_PAYLOAD_EXTENDEDCHUNKDATA,          "EXTENDEDCHUNKDATA (obsolete with v2.0)" },
    { GVSP_PAYLOAD_JPEG,                       "JPEG" },
    { GVSP_PAYLOAD_JPEG2000,                   "JPEG2000" },
    { GVSP_PAYLOAD_H264,                       "H264" },
    { GVSP_PAYLOAD_MULTIZONEIMAGE,             "MUTLIZONEIAMGE" },
    { 0x4000 | GVSP_PAYLOAD_IMAGE,             "IMAGE (v2.0 chunks)" },
    { 0x4000 | GVSP_PAYLOAD_RAWDATA,           "RAWDATA (v2.0 Chunks)" },
    { 0x4000 | GVSP_PAYLOAD_FILE,              "FILE (v2.0 Chunks)" },
    { 0x4000 | GVSP_PAYLOAD_CHUNKDATA,         "CHUNKDATA (v2.0 Chunks)" },
    { 0x4000 | GVSP_PAYLOAD_EXTENDEDCHUNKDATA, "EXTENDEDCHUNKDATA (v2.0 chunks?)" },
    { 0x4000 | GVSP_PAYLOAD_JPEG,              "JPEG (v2.0 Chunks)" },
    { 0x4000 | GVSP_PAYLOAD_JPEG2000,          "JPEG2000 (v2.0 Chunks)" },
    { 0x4000 | GVSP_PAYLOAD_H264,              "H264 (v2.0 Chunks)" },
    { 0x4000 | GVSP_PAYLOAD_MULTIZONEIMAGE,    "MULTIZONEIMAGE (v2.0 Chunks)" },
    { 0, NULL },
};

static value_string_ext payloadtypenames_ext = VALUE_STRING_EXT_INIT(payloadtypenames);

static const value_string pixeltypenames[] = {
    { GVSP_PIX_MONO1P, "Monochrome 1-bit packed" },
    { GVSP_PIX_CONFIDENCE1P, "Confidence 1-bit packed" },
    { GVSP_PIX_MONO2P, "Monochrome 2-bit packed" },
    { GVSP_PIX_MONO4P, "Monochrome 4-bit packed" },
    { GVSP_PIX_MONO8, "Monochrome 8-bit" },
    { GVSP_PIX_MONO8S, "Monochrome 8-bit signed" },
    { GVSP_PIX_BAYERGR8, "Bayer Green-Red 8-bit" },
    { GVSP_PIX_BAYERRG8, "Bayer Red-Green 8-bit" },
    { GVSP_PIX_BAYERGB8, "Bayer Green-Blue 8-bit" },
    { GVSP_PIX_BAYERBG8, "Bayer Blue-Green 8-bit" },
    { GVSP_PIX_SCF1WBWG8, "Sparse Color Filter #1 White-Blue-White-Green 8-bit" },
    { GVSP_PIX_SCF1WGWB8, "Sparse Color Filter #1 White-Green-White-Blue 8-bit" },
    { GVSP_PIX_SCF1WGWR8, "Sparse Color Filter #1 White-Green-White-Red 8-bit" },
    { GVSP_PIX_SCF1WRWG8, "Sparse Color Filter #1 White-Red-White-Green 8-bit" },
    { GVSP_PIX_COORD3D_A8, "3D coordinate A 8-bit" },
    { GVSP_PIX_COORD3D_B8, "3D coordinate B 8-bit" },
    { GVSP_PIX_COORD3D_C8, "3D coordinate C 8-bit" },
    { GVSP_PIX_CONFIDENCE1, "Confidence 1-bit unpacked" },
    { GVSP_PIX_CONFIDENCE8, "Confidence 8-bit" },
    { GVSP_PIX_R8, "Red 8-bit" },
    { GVSP_PIX_G8, "Green 8-bit" },
    { GVSP_PIX_B8, "Blue 8-bit" },
    { GVSP_PIX_MONO10P, "Monochrome 10-bit packed" },
    { GVSP_PIX_BAYERBG10P, "Bayer Blue-Green 10-bit packed" },
    { GVSP_PIX_BAYERGB10P, "Bayer Green-Blue 10-bit packed" },
    { GVSP_PIX_BAYERGR10P, "Bayer Green-Red 10-bit packed" },
    { GVSP_PIX_BAYERRG10P, "Bayer Red-Green 10-bit packed" },
    { GVSP_PIX_SCF1WBWG10P, "Sparse Color Filter #1 White-Blue-White-Green 10-bit packed" },
    { GVSP_PIX_SCF1WGWB10P, "Sparse Color Filter #1 White-Green-White-Blue 10-bit packed" },
    { GVSP_PIX_SCF1WGWR10P, "Sparse Color Filter #1 White-Green-White-Red 10-bit packed" },
    { GVSP_PIX_SCF1WRWG10P, "Sparse Color Filter #1 White-Red-White-Green 10-bit packed" },
    { GVSP_PIX_R10, "Red 10-bit" },
    { GVSP_PIX_G10, "Green 10-bit" },
    { GVSP_PIX_B10, "Blue 10-bit" },
    { GVSP_PIX_COORD3D_A10P, "3D coordinate A 10-bit packed" },
    { GVSP_PIX_COORD3D_B10P, "3D coordinate B 10-bit packed" },
    { GVSP_PIX_COORD3D_C10P, "3D coordinate C 10-bit packed" },
    { GVSP_PIX_MONO10PACKED, "GigE Vision specific format, Monochrome 10-bit packed" },
    { GVSP_PIX_MONO12PACKED, "GigE Vision specific format, Monochrome 12-bit packed" },
    { GVSP_PIX_BAYERGR10PACKED, "GigE Vision specific format, Bayer Green-Red 10-bit packed" },
    { GVSP_PIX_BAYERRG10PACKED, "GigE Vision specific format, Bayer Red-Green 10-bit packed" },
    { GVSP_PIX_BAYERGB10PACKED, "GigE Vision specific format, Bayer Green-Blue 10-bit packed" },
    { GVSP_PIX_BAYERBG10PACKED, "GigE Vision specific format, Bayer Blue-Green 10-bit packed" },
    { GVSP_PIX_BAYERGR12PACKED, "GigE Vision specific format, Bayer Green-Red 12-bit packed" },
    { GVSP_PIX_BAYERRG12PACKED, "GigE Vision specific format, Bayer Red-Green 12-bit packed" },
    { GVSP_PIX_BAYERGB12PACKED, "GigE Vision specific format, Bayer Green-Blue 12-bit packed" },
    { GVSP_PIX_BAYERBG12PACKED, "GigE Vision specific format, Bayer Blue-Green 12-bit packed" },
    { GVSP_PIX_MONO12P, "Monochrome 12-bit packed" },
    { GVSP_PIX_BAYERBG12P, "Bayer Blue-Green 12-bit packed" },
    { GVSP_PIX_BAYERGB12P, "Bayer Green-Blue 12-bit packed" },
    { GVSP_PIX_BAYERGR12P, "Bayer Green-Red 12-bit packed" },
    { GVSP_PIX_BAYERRG12P, "Bayer Red-Green 12-bit packed" },
    { GVSP_PIX_SCF1WBWG12P, "Sparse Color Filter #1 White-Blue-White-Green 12-bit packed" },
    { GVSP_PIX_SCF1WGWB12P, "Sparse Color Filter #1 White-Green-White-Blue 12-bit packed" },
    { GVSP_PIX_SCF1WGWR12P, "Sparse Color Filter #1 White-Green-White-Red 12-bit packed" },
    { GVSP_PIX_SCF1WRWG12P, "Sparse Color Filter #1 White-Red-White-Green 12-bit packed" },
    { GVSP_PIX_R12, "Red 12-bit" },
    { GVSP_PIX_G12, "Green 12-bit" },
    { GVSP_PIX_B12, "Blue 12-bit" },
    { GVSP_PIX_COORD3D_A12P, "3D coordinate A 12-bit packed" },
    { GVSP_PIX_COORD3D_B12P, "3D coordinate B 12-bit packed" },
    { GVSP_PIX_COORD3D_C12P, "3D coordinate C 12-bit packed" },
    { GVSP_PIX_MONO10, "Monochrome 10-bit unpacked" },
    { GVSP_PIX_MONO12, "Monochrome 12-bit unpacked" },
    { GVSP_PIX_MONO16, "Monochrome 16-bit" },
    { GVSP_PIX_BAYERGR10, "Bayer Green-Red 10-bit unpacked" },
    { GVSP_PIX_BAYERRG10, "Bayer Red-Green 10-bit unpacked" },
    { GVSP_PIX_BAYERGB10, "Bayer Green-Blue 10-bit unpacked" },
    { GVSP_PIX_BAYERBG10, "Bayer Blue-Green 10-bit unpacked" },
    { GVSP_PIX_BAYERGR12, "Bayer Green-Red 12-bit unpacked" },
    { GVSP_PIX_BAYERRG12, "Bayer Red-Green 12-bit unpacked" },
    { GVSP_PIX_BAYERGB12, "Bayer Green-Blue 12-bit unpacked" },
    { GVSP_PIX_BAYERBG12, "Bayer Blue-Green 12-bit unpacked" },
    { GVSP_PIX_MONO14, "Monochrome 14-bit unpacked" },
    { GVSP_PIX_BAYERGR16, "Bayer Green-Red 16-bit" },
    { GVSP_PIX_BAYERRG16, "Bayer Red-Green 16-bit" },
    { GVSP_PIX_BAYERGB16, "Bayer Green-Blue 16-bit" },
    { GVSP_PIX_BAYERBG16, "Bayer Blue-Green 16-bit" },
    { GVSP_PIX_SCF1WBWG10, "Sparse Color Filter #1 White-Blue-White-Green 10-bit unpacked" },
    { GVSP_PIX_SCF1WBWG12, "Sparse Color Filter #1 White-Blue-White-Green 12-bit unpacked" },
    { GVSP_PIX_SCF1WBWG14, "Sparse Color Filter #1 White-Blue-White-Green 14-bit unpacked" },
    { GVSP_PIX_SCF1WBWG16, "Sparse Color Filter #1 White-Blue-White-Green 16-bit unpacked" },
    { GVSP_PIX_SCF1WGWB10, "Sparse Color Filter #1 White-Green-White-Blue 10-bit unpacked" },
    { GVSP_PIX_SCF1WGWB12, "Sparse Color Filter #1 White-Green-White-Blue 12-bit unpacked" },
    { GVSP_PIX_SCF1WGWB14, "Sparse Color Filter #1 White-Green-White-Blue 14-bit unpacked" },
    { GVSP_PIX_SCF1WGWB16, "Sparse Color Filter #1 White-Green-White-Blue 16-bit" },
    { GVSP_PIX_SCF1WGWR10, "Sparse Color Filter #1 White-Green-White-Red 10-bit unpacked" },
    { GVSP_PIX_SCF1WGWR12, "Sparse Color Filter #1 White-Green-White-Red 12-bit unpacked" },
    { GVSP_PIX_SCF1WGWR14, "Sparse Color Filter #1 White-Green-White-Red 14-bit unpacked" },
    { GVSP_PIX_SCF1WGWR16, "Sparse Color Filter #1 White-Green-White-Red 16-bit" },
    { GVSP_PIX_SCF1WRWG10, "Sparse Color Filter #1 White-Red-White-Green 10-bit unpacked" },
    { GVSP_PIX_SCF1WRWG12, "Sparse Color Filter #1 White-Red-White-Green 12-bit unpacked" },
    { GVSP_PIX_SCF1WRWG14, "Sparse Color Filter #1 White-Red-White-Green 14-bit unpacked" },
    { GVSP_PIX_SCF1WRWG16, "Sparse Color Filter #1 White-Red-White-Green 16-bit" },
    { GVSP_PIX_COORD3D_A16, "3D coordinate A 16-bit" },
    { GVSP_PIX_COORD3D_B16, "3D coordinate B 16-bit" },
    { GVSP_PIX_COORD3D_C16, "3D coordinate C 16-bit" },
    { GVSP_PIX_CONFIDENCE16, "Confidence 16-bit" },
    { GVSP_PIX_R16, "Red 16-bit" },
    { GVSP_PIX_G16, "Green 16-bit" },
    { GVSP_PIX_B16, "Blue 16-bit" },
    { GVSP_PIX_COORD3D_A32F, "3D coordinate A 32-bit floating point" },
    { GVSP_PIX_COORD3D_B32F, "3D coordinate B 32-bit floating point" },
    { GVSP_PIX_COORD3D_C32F, "3D coordinate C 32-bit floating point" },
    { GVSP_PIX_CONFIDENCE32F, "Confidence 32-bit floating point" },
    { GVSP_PIX_YUV411_8_UYYVYY, "YUV 4:1:1 8-bit" },
    { GVSP_PIX_YCBCR411_8_CBYYCRYY, "YCbCr 4:1:1 8-bit" },
    { GVSP_PIX_YCBCR601_411_8_CBYYCRYY, "YCbCr 4:1:1 8-bit BT.601" },
    { GVSP_PIX_YCBCR709_411_8_CBYYCRYY, "YCbCr 4:1:1 8-bit BT.709" },
    { GVSP_PIX_YCBCR411_8, "YCbCr 4:1:1 8-bit" },
    { GVSP_PIX_YUV422_8_UYVY, "YUV 4:2:2 8-bit" },
    { GVSP_PIX_YUV422_8, "YUV 4:2:2 8-bit" },
    { GVSP_PIX_RGB565P, "Red-Green-Blue 5/6/5-bit packed" },
    { GVSP_PIX_BGR565P, "Blue-Green-Red 5/6/5-bit packed" },
    { GVSP_PIX_YCBCR422_8, "YCbCr 4:2:2 8-bit" },
    { GVSP_PIX_YCBCR601_422_8, "YCbCr 4:2:2 8-bit BT.601" },
    { GVSP_PIX_YCBCR709_422_8, "YCbCr 4:2:2 8-bit BT.709" },
    { GVSP_PIX_YCBCR422_8_CBYCRY, "YCbCr 4:2:2 8-bit" },
    { GVSP_PIX_YCBCR601_422_8_CBYCRY, "YCbCr 4:2:2 8-bit BT.601" },
    { GVSP_PIX_YCBCR709_422_8_CBYCRY, "YCbCr 4:2:2 8-bit BT.709" },
    { GVSP_PIX_BICOLORRGBG8, "Bi-color Red/Green - Blue/Green 8-bit" },
    { GVSP_PIX_BICOLORBGRG8, "Bi-color Blue/Green - Red/Green 8-bit" },
    { GVSP_PIX_COORD3D_AC8, "3D coordinate A-C 8-bit" },
    { GVSP_PIX_COORD3D_AC8_PLANAR, "3D coordinate A-C 8-bit planar" },
    { GVSP_PIX_YCBCR422_10P, "YCbCr 4:2:2 10-bit packed" },
    { GVSP_PIX_YCBCR601_422_10P, "YCbCr 4:2:2 10-bit packed BT.601" },
    { GVSP_PIX_YCBCR709_422_10P, "YCbCr 4:2:2 10-bit packed BT.709" },
    { GVSP_PIX_YCBCR422_10P_CBYCRY, "YCbCr 4:2:2 10-bit packed" },
    { GVSP_PIX_YCBCR601_422_10P_CBYCRY, "YCbCr 4:2:2 10-bit packed BT.601" },
    { GVSP_PIX_YCBCR709_422_10P_CBYCRY, "YCbCr 4:2:2 10-bit packed BT.709" },
    { GVSP_PIX_BICOLORRGBG10P, "Bi-color Red/Green - Blue/Green 10-bit packed" },
    { GVSP_PIX_BICOLORBGRG10P, "Bi-color Blue/Green - Red/Green 10-bit packed" },
    { GVSP_PIX_COORD3D_AC10P, "3D coordinate A-C 10-bit packed" },
    { GVSP_PIX_COORD3D_AC10P_PLANAR, "3D coordinate A-C 10-bit packed planar" },
    { GVSP_PIX_RGB8, "Red-Green-Blue 8-bit" },
    { GVSP_PIX_BGR8, "Blue-Green-Red 8-bit" },
    { GVSP_PIX_YUV8_UYV, "YUV 4:4:4 8-bit" },
    { GVSP_PIX_RGB8_PLANAR, "Red-Green-Blue 8-bit planar" },
    { GVSP_PIX_YCBCR8_CBYCR, "YCbCr 4:4:4 8-bit" },
    { GVSP_PIX_YCBCR601_8_CBYCR, "YCbCr 4:4:4 8-bit BT.601" },
    { GVSP_PIX_YCBCR709_8_CBYCR, "YCbCr 4:4:4 8-bit BT.709" },
    { GVSP_PIX_YCBCR8, "YCbCr 4:4:4 8-bit" },
    { GVSP_PIX_YCBCR422_12P, "YCbCr 4:2:2 12-bit packed" },
    { GVSP_PIX_YCBCR601_422_12P, "YCbCr 4:2:2 12-bit packed BT.601" },
    { GVSP_PIX_YCBCR709_422_12P, "YCbCr 4:2:2 12-bit packed BT.709" },
    { GVSP_PIX_YCBCR422_12P_CBYCRY, "YCbCr 4:2:2 12-bit packed" },
    { GVSP_PIX_YCBCR601_422_12P_CBYCRY, "YCbCr 4:2:2 12-bit packed BT.601" },
    { GVSP_PIX_YCBCR709_422_12P_CBYCRY, "YCbCr 4:2:2 12-bit packed BT.709" },
    { GVSP_PIX_BICOLORRGBG12P, "Bi-color Red/Green - Blue/Green 12-bit packed" },
    { GVSP_PIX_BICOLORBGRG12P, "Bi-color Blue/Green - Red/Green 12-bit packed" },
    { GVSP_PIX_COORD3D_ABC8, "3D coordinate A-B-C 8-bit" },
    { GVSP_PIX_COORD3D_ABC8_PLANAR, "3D coordinate A-B-C 8-bit planar" },
    { GVSP_PIX_COORD3D_AC12P, "3D coordinate A-C 12-bit packed" },
    { GVSP_PIX_COORD3D_AC12P_PLANAR, "3D coordinate A-C 12-bit packed planar" },
    { GVSP_PIX_BGR10P, "Blue-Green-Red 10-bit packed" },
    { GVSP_PIX_RGB10P, "Red-Green-Blue 10-bit packed" },
    { GVSP_PIX_YCBCR10P_CBYCR, "YCbCr 4:4:4 10-bit packed" },
    { GVSP_PIX_YCBCR601_10P_CBYCR, "YCbCr 4:4:4 10-bit packed BT.601" },
    { GVSP_PIX_YCBCR709_10P_CBYCR, "YCbCr 4:4:4 10-bit packed BT.709" },
    { GVSP_PIX_COORD3D_ABC10P, "3D coordinate A-B-C 10-bit packed" },
    { GVSP_PIX_COORD3D_ABC10P_PLANAR, "3D coordinate A-B-C 10-bit packed planar" },
    { GVSP_PIX_RGBA8, "Red-Green-Blue-alpha 8-bit" },
    { GVSP_PIX_BGRA8, "Blue-Green-Red-alpha 8-bit" },
    { GVSP_PIX_RGB10V1PACKED, "GigE Vision specific format, Red-Green-Blue 10-bit packed - variant 1" },
    { GVSP_PIX_RGB10P32, "Red-Green-Blue 10-bit packed into 32-bit" },
    { GVSP_PIX_YCBCR422_10, "YCbCr 4:2:2 10-bit unpacked" },
    { GVSP_PIX_YCBCR422_12, "YCbCr 4:2:2 12-bit unpacked" },
    { GVSP_PIX_YCBCR601_422_10, "YCbCr 4:2:2 10-bit unpacked BT.601" },
    { GVSP_PIX_YCBCR601_422_12, "YCbCr 4:2:2 12-bit unpacked BT.601" },
    { GVSP_PIX_YCBCR709_422_10, "YCbCr 4:2:2 10-bit unpacked BT.709" },
    { GVSP_PIX_YCBCR709_422_12, "YCbCr 4:2:2 12-bit unpacked BT.709" },
    { GVSP_PIX_YCBCR422_10_CBYCRY, "YCbCr 4:2:2 10-bit unpacked" },
    { GVSP_PIX_YCBCR422_12_CBYCRY, "YCbCr 4:2:2 12-bit unpacked" },
    { GVSP_PIX_YCBCR601_422_10_CBYCRY, "YCbCr 4:2:2 10-bit unpacked BT.601" },
    { GVSP_PIX_YCBCR601_422_12_CBYCRY, "YCbCr 4:2:2 12-bit unpacked BT.601" },
    { GVSP_PIX_YCBCR709_422_10_CBYCRY, "YCbCr 4:2:2 10-bit unpacked BT.709" },
    { GVSP_PIX_YCBCR709_422_12_CBYCRY, "YCbCr 4:2:2 12-bit unpacked BT.709" },
    { GVSP_PIX_BICOLORRGBG10, "Bi-color Red/Green - Blue/Green 10-bit unpacked" },
    { GVSP_PIX_BICOLORBGRG10, "Bi-color Blue/Green - Red/Green 10-bit unpacked" },
    { GVSP_PIX_BICOLORRGBG12, "Bi-color Red/Green - Blue/Green 12-bit unpacked" },
    { GVSP_PIX_BICOLORBGRG12, "Bi-color Blue/Green - Red/Green 12-bit unpacked" },
    { GVSP_PIX_COORD3D_AC16, "3D coordinate A-C 16-bit" },
    { GVSP_PIX_COORD3D_AC16_PLANAR, "3D coordinate A-C 16-bit planar" },
    { GVSP_PIX_RGB12V1PACKED, "GigE Vision specific format, Red-Green-Blue 12-bit packed - variant 1" },
    { GVSP_PIX_BGR12P, "Blue-Green-Red 12-bit packed" },
    { GVSP_PIX_RGB12P, "Red-Green-Blue 12-bit packed" },
    { GVSP_PIX_YCBCR12P_CBYCR, "YCbCr 4:4:4 12-bit packed" },
    { GVSP_PIX_YCBCR601_12P_CBYCR, "YCbCr 4:4:4 12-bit packed BT.601" },
    { GVSP_PIX_YCBCR709_12P_CBYCR, "YCbCr 4:4:4 12-bit packed BT.709" },
    { GVSP_PIX_COORD3D_ABC12P, "3D coordinate A-B-C 12-bit packed" },
    { GVSP_PIX_COORD3D_ABC12P_PLANAR, "3D coordinate A-B-C 12-bit packed planar" },
    { GVSP_PIX_BGRA10P, "Blue-Green-Red-alpha 10-bit packed" },
    { GVSP_PIX_RGBA10P, "Red-Green-Blue-alpha 10-bit packed" },
    { GVSP_PIX_RGB10, "Red-Green-Blue 10-bit unpacked" },
    { GVSP_PIX_BGR10, "Blue-Green-Red 10-bit unpacked" },
    { GVSP_PIX_RGB12, "Red-Green-Blue 12-bit unpacked" },
    { GVSP_PIX_BGR12, "Blue-Green-Red 12-bit unpacked" },
    { GVSP_PIX_RGB10_PLANAR, "Red-Green-Blue 10-bit unpacked planar" },
    { GVSP_PIX_RGB12_PLANAR, "Red-Green-Blue 12-bit unpacked planar" },
    { GVSP_PIX_RGB16_PLANAR, "Red-Green-Blue 16-bit planar" },
    { GVSP_PIX_RGB16, "Red-Green-Blue 16-bit" },
    { GVSP_PIX_BGR14, "Blue-Green-Red 14-bit unpacked" },
    { GVSP_PIX_BGR16, "Blue-Green-Red 16-bit" },
    { GVSP_PIX_BGRA12P, "Blue-Green-Red-alpha 12-bit packed" },
    { GVSP_PIX_RGB14, "Red-Green-Blue 14-bit unpacked" },
    { GVSP_PIX_RGBA12P, "Red-Green-Blue-alpha 12-bit packed" },
    { GVSP_PIX_YCBCR10_CBYCR, "YCbCr 4:4:4 10-bit unpacked" },
    { GVSP_PIX_YCBCR12_CBYCR, "YCbCr 4:4:4 12-bit unpacked" },
    { GVSP_PIX_YCBCR601_10_CBYCR, "YCbCr 4:4:4 10-bit unpacked BT.601" },
    { GVSP_PIX_YCBCR601_12_CBYCR, "YCbCr 4:4:4 12-bit unpacked BT.601" },
    { GVSP_PIX_YCBCR709_10_CBYCR, "YCbCr 4:4:4 10-bit unpacked BT.709" },
    { GVSP_PIX_YCBCR709_12_CBYCR, "YCbCr 4:4:4 12-bit unpacked BT.709" },
    { GVSP_PIX_COORD3D_ABC16, "3D coordinate A-B-C 16-bit" },
    { GVSP_PIX_COORD3D_ABC16_PLANAR, "3D coordinate A-B-C 16-bit planar" },
    { GVSP_PIX_BGRA10, "Blue-Green-Red-alpha 10-bit unpacked" },
    { GVSP_PIX_BGRA12, "Blue-Green-Red-alpha 12-bit unpacked" },
    { GVSP_PIX_BGRA14, "Blue-Green-Red-alpha 14-bit unpacked" },
    { GVSP_PIX_BGRA16, "Blue-Green-Red-alpha 16-bit" },
    { GVSP_PIX_RGBA10, "Red-Green-Blue-alpha 10-bit unpacked" },
    { GVSP_PIX_RGBA12, "Red-Green-Blue-alpha 12-bit unpacked" },
    { GVSP_PIX_RGBA14, "Red-Green-Blue-alpha 14-bit unpacked" },
    { GVSP_PIX_RGBA16, "Red-Green-Blue-alpha 16-bit" },
    { GVSP_PIX_COORD3D_AC32F, "3D coordinate A-C 32-bit floating point" },
    { GVSP_PIX_COORD3D_AC32F_PLANAR, "3D coordinate A-C 32-bit floating point planar" },
    { GVSP_PIX_COORD3D_ABC32F, "3D coordinate A-B-C 32-bit floating point" },
    { GVSP_PIX_COORD3D_ABC32F_PLANAR, "3D coordinate A-B-C 32-bit floating point planar" },
    { 0, NULL }
};

static value_string_ext pixeltypenames_ext = VALUE_STRING_EXT_INIT(pixeltypenames);

static const value_string colornames[] = {
    { GVSP_PIX_MONO >> 24,   "Mono" },
    { GVSP_PIX_COLOR >> 24,  "Color" },
    { GVSP_PIX_CUSTOM >> 24, "Custom" },
    { 0, NULL },
};

static const true_false_string directionnames = {
    "Receiver",
    "Transmitter"
};


static int hf_gvsp_status = -1;
static int hf_gvsp_blockid16 = -1;
static int hf_gvsp_flags = -1;
static int hf_gvsp_flagdevicespecific0 = -1;
static int hf_gvsp_flagdevicespecific1 = -1;
static int hf_gvsp_flagdevicespecific2 = -1;
static int hf_gvsp_flagdevicespecific3 = -1;
static int hf_gvsp_flagdevicespecific4 = -1;
static int hf_gvsp_flagdevicespecific5 = -1;
static int hf_gvsp_flagdevicespecific6 = -1;
static int hf_gvsp_flagdevicespecific7 = -1;
static int hf_gvsp_flagresendrangeerror = -1;
static int hf_gvsp_flagpreviousblockdropped = -1;
static int hf_gvsp_flagpacketresend = -1;
static int hf_gvsp_format = -1;
static int hf_gvsp_packetid24 = -1;
static int hf_gvsp_blockid64 = -1;
static int hf_gvsp_packetid32 = -1;
static int hf_gvsp_payloadtype = -1;
static int hf_gvsp_payloaddata = -1;
static int hf_gvsp_timestamp = -1;
static int hf_gvsp_pixelformat = -1;
static int hf_gvsp_sizex = -1;
static int hf_gvsp_sizey = -1;
static int hf_gvsp_offsetx = -1;
static int hf_gvsp_offsety = -1;
static int hf_gvsp_paddingx = -1;
static int hf_gvsp_paddingy = -1;
static int hf_gvsp_payloaddatasize = -1;
static int hf_gvsp_pixelcolor = -1;
static int hf_gvsp_pixeloccupy = -1;
static int hf_gvsp_pixelid = -1;
static int hf_gvsp_filename = -1;
static int hf_gvsp_payloadlength = -1;
static int hf_gvsp_fieldinfo = -1;
static int hf_gvsp_fieldid = -1;
static int hf_gvsp_fieldcount = -1;
static int hf_gvsp_genericflags = -1;
static int hf_gvsp_timestamptickfrequency = -1;
static int hf_gvsp_dataformat = -1;
static int hf_gvsp_packetizationmode = -1;
static int hf_gvsp_packetsize = -1;
static int hf_gvsp_profileidc = -1;
static int hf_gvsp_cs = -1;
static int hf_gvsp_cs0 = -1;
static int hf_gvsp_cs1 = -1;
static int hf_gvsp_cs2 = -1;
static int hf_gvsp_cs3 = -1;
static int hf_gvsp_levelidc = -1;
static int hf_gvsp_sropinterleavingdepth = -1;
static int hf_gvsp_sropmaxdondiff = -1;
static int hf_gvsp_sropdeintbufreq = -1;
static int hf_gvsp_sropinitbuftime = -1;
static int hf_gvsp_zoneinfo = -1;
static int hf_gvsp_zoneid = -1;
static int hf_gvsp_endofzone = -1;
static int hf_gvsp_addressoffsethigh = -1;
static int hf_gvsp_addressoffsetlow = -1;
static int hf_gvsp_sc_zone_direction = -1;
static int hf_gvsp_sc_zone0_direction = -1;
static int hf_gvsp_sc_zone1_direction = -1;
static int hf_gvsp_sc_zone2_direction = -1;
static int hf_gvsp_sc_zone3_direction = -1;
static int hf_gvsp_sc_zone4_direction = -1;
static int hf_gvsp_sc_zone5_direction = -1;
static int hf_gvsp_sc_zone6_direction = -1;
static int hf_gvsp_sc_zone7_direction = -1;
static int hf_gvsp_sc_zone8_direction = -1;
static int hf_gvsp_sc_zone9_direction = -1;
static int hf_gvsp_sc_zone10_direction = -1;
static int hf_gvsp_sc_zone11_direction = -1;
static int hf_gvsp_sc_zone12_direction = -1;
static int hf_gvsp_sc_zone13_direction = -1;
static int hf_gvsp_sc_zone14_direction = -1;
static int hf_gvsp_sc_zone15_direction = -1;
static int hf_gvsp_sc_zone16_direction = -1;
static int hf_gvsp_sc_zone17_direction = -1;
static int hf_gvsp_sc_zone18_direction = -1;
static int hf_gvsp_sc_zone19_direction = -1;
static int hf_gvsp_sc_zone20_direction = -1;
static int hf_gvsp_sc_zone21_direction = -1;
static int hf_gvsp_sc_zone22_direction = -1;
static int hf_gvsp_sc_zone23_direction = -1;
static int hf_gvsp_sc_zone24_direction = -1;
static int hf_gvsp_sc_zone25_direction = -1;
static int hf_gvsp_sc_zone26_direction = -1;
static int hf_gvsp_sc_zone27_direction = -1;
static int hf_gvsp_sc_zone28_direction = -1;
static int hf_gvsp_sc_zone29_direction = -1;
static int hf_gvsp_sc_zone30_direction = -1;
static int hf_gvsp_sc_zone31_direction = -1;
static int hf_gvsp_chunkdatapayloadlengthex = -1;
static int hf_gvsp_chunklayoutidex = -1;


static const int *pixelformat_fields[] = {
    &hf_gvsp_pixelcolor,
    &hf_gvsp_pixeloccupy,
    &hf_gvsp_pixelid,
    NULL
};

static const int *fieldinfo_fields[] = {
    &hf_gvsp_fieldid,
    &hf_gvsp_fieldcount,
    NULL
};

static const int *cs_fields[] = {
    &hf_gvsp_cs0,
    &hf_gvsp_cs1,
    &hf_gvsp_cs2,
    &hf_gvsp_cs3,
    NULL
};

static const int *sc_zone_direction_fields[] = {
    &hf_gvsp_sc_zone0_direction,
    &hf_gvsp_sc_zone1_direction,
    &hf_gvsp_sc_zone2_direction,
    &hf_gvsp_sc_zone3_direction,
    &hf_gvsp_sc_zone4_direction,
    &hf_gvsp_sc_zone5_direction,
    &hf_gvsp_sc_zone6_direction,
    &hf_gvsp_sc_zone7_direction,
    &hf_gvsp_sc_zone8_direction,
    &hf_gvsp_sc_zone9_direction,
    &hf_gvsp_sc_zone10_direction,
    &hf_gvsp_sc_zone11_direction,
    &hf_gvsp_sc_zone12_direction,
    &hf_gvsp_sc_zone13_direction,
    &hf_gvsp_sc_zone14_direction,
    &hf_gvsp_sc_zone15_direction,
    &hf_gvsp_sc_zone16_direction,
    &hf_gvsp_sc_zone17_direction,
    &hf_gvsp_sc_zone18_direction,
    &hf_gvsp_sc_zone19_direction,
    &hf_gvsp_sc_zone20_direction,
    &hf_gvsp_sc_zone21_direction,
    &hf_gvsp_sc_zone22_direction,
    &hf_gvsp_sc_zone23_direction,
    &hf_gvsp_sc_zone24_direction,
    &hf_gvsp_sc_zone25_direction,
    &hf_gvsp_sc_zone26_direction,
    &hf_gvsp_sc_zone27_direction,
    &hf_gvsp_sc_zone28_direction,
    &hf_gvsp_sc_zone29_direction,
    &hf_gvsp_sc_zone30_direction,
    &hf_gvsp_sc_zone31_direction,
    NULL
};

static const int *zoneinfo_fields[] = {
    &hf_gvsp_zoneid,
    &hf_gvsp_endofzone,
    NULL
};

static const int *flags_fields[] = {
    &hf_gvsp_flagdevicespecific0,
    &hf_gvsp_flagdevicespecific1,
    &hf_gvsp_flagdevicespecific2,
    &hf_gvsp_flagdevicespecific3,
    &hf_gvsp_flagdevicespecific4,
    &hf_gvsp_flagdevicespecific5,
    &hf_gvsp_flagdevicespecific6,
    &hf_gvsp_flagdevicespecific7,
    &hf_gvsp_flagresendrangeerror,
    &hf_gvsp_flagpreviousblockdropped,
    &hf_gvsp_flagpacketresend,
    NULL
};

/*
    \brief Dissects the image leader
 */

static gint dissect_image_leader(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Field info */
    proto_tree_add_bitmask(gvsp_tree, tvb, offset, hf_gvsp_fieldinfo,
                           ett_gvsp_fieldinfo, fieldinfo_fields, ENC_BIG_ENDIAN);

    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Timestamp */
    proto_tree_add_item(gvsp_tree, hf_gvsp_timestamp, tvb, offset + 4, 8, ENC_BIG_ENDIAN);

    /* Pixel format */
    proto_tree_add_bitmask(gvsp_tree, tvb, offset + 12, hf_gvsp_pixelformat, ett_gvsp_pixelformat,
                                  pixelformat_fields, ENC_BIG_ENDIAN);

    /* Size X */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sizex, tvb, offset + 16, 4, ENC_BIG_ENDIAN);

    /* Size Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sizey, tvb, offset + 20, 4, ENC_BIG_ENDIAN);

    /* Offset X */
    proto_tree_add_item(gvsp_tree, hf_gvsp_offsetx, tvb, offset + 24, 4, ENC_BIG_ENDIAN);

    /* Offset Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_offsety, tvb, offset + 28, 4, ENC_BIG_ENDIAN);

    /* Padding X */
    proto_tree_add_item(gvsp_tree, hf_gvsp_paddingx, tvb, offset + 32, 2, ENC_BIG_ENDIAN);

    /* Padding Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_paddingy, tvb, offset + 34, 2, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 36;
}


/*
    \brief Dissects the image trailer
 */

static gint dissect_image_trailer(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Size Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sizey, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 8;
}


/*
    \brief Dissects the raw data leader
 */

static gint dissect_raw_data_leader(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Timestamp */
    proto_tree_add_item(gvsp_tree, hf_gvsp_timestamp, tvb, offset + 4, 8, ENC_BIG_ENDIAN);

    /* Payload data size */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloaddatasize, tvb, offset + 12, 8, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 20;
}


/*
    \brief Dissects a file leader
 */

static gint dissect_file_leader(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    guint file_length = 0;

    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Timestamp */
    proto_tree_add_item(gvsp_tree, hf_gvsp_timestamp, tvb, offset + 4, 8, ENC_BIG_ENDIAN);

    /* Payload data size */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloaddatasize, tvb, offset + 12, 8, ENC_BIG_ENDIAN);

    /* Filename */
    file_length = tvb_strsize(tvb, offset + 20);
    proto_tree_add_item(gvsp_tree, hf_gvsp_filename, tvb, offset + 20, file_length, ENC_ASCII|ENC_NA);

    if (20 + file_length > G_MAXINT)
        return -1;

    /* Return dissected byte count (for all-in dissection) */
    return (gint)(20 + file_length);
}


/*
    \brief Dissects a chunk data leader
 */

static gint dissect_chunk_data_leader(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Timestamp */
    proto_tree_add_item(gvsp_tree, hf_gvsp_timestamp, tvb, offset + 4, 8, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 12;
}


/*
    \brief Dissects a chunk data trailer
 */

static gint dissect_chunk_data_trailer(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Payload data length */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadlength, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 8;
}


/*
    \brief Dissects extended chunk data leader
 */

static gint dissect_extended_chunk_data_leader(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Field info */
    proto_tree_add_bitmask(gvsp_tree, tvb, offset, hf_gvsp_fieldinfo,
                                  ett_gvsp_fieldinfo, fieldinfo_fields, ENC_BIG_ENDIAN);
    /* Generic flags */
    proto_tree_add_item(gvsp_tree, hf_gvsp_genericflags, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Timestamp */
    proto_tree_add_item(gvsp_tree, hf_gvsp_timestamp, tvb, offset + 4, 8, ENC_BIG_ENDIAN);

    /* Pixel format */
    proto_tree_add_bitmask(gvsp_tree, tvb, offset + 12, hf_gvsp_pixelformat, ett_gvsp_pixelformat,
                                  pixelformat_fields, ENC_BIG_ENDIAN);

    /* Size X */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sizex, tvb, offset + 16, 4, ENC_BIG_ENDIAN);

    /* Size Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sizey, tvb, offset + 20, 4, ENC_BIG_ENDIAN);

    /* Offset X */
    proto_tree_add_item(gvsp_tree, hf_gvsp_offsetx, tvb, offset + 24, 4, ENC_BIG_ENDIAN);

    /* Offset Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_offsety, tvb, offset + 28, 4, ENC_BIG_ENDIAN);

    /* Padding X */
    proto_tree_add_item(gvsp_tree, hf_gvsp_paddingx, tvb, offset + 32, 2, ENC_BIG_ENDIAN);

    /* Padding Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_paddingy, tvb, offset + 34, 2, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 36;
}


/*
    \brief Dissects extended chunk data trailer
 */

static gint dissect_extended_chunk_data_trailer(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Payload data length */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadlength, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

    /* Size Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sizey, tvb, offset + 8, 4, ENC_BIG_ENDIAN);

    /* Chunk layout ID */
    proto_tree_add_item(gvsp_tree, hf_gvsp_chunklayoutidex, tvb, offset + 12, 4, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 16;
}


/*
    \brief Dissects a JPEG leader
 */

static gint dissect_jpeg_leader(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Field info */
    proto_tree_add_bitmask(gvsp_tree, tvb, offset, hf_gvsp_fieldinfo,
                                  ett_gvsp_fieldinfo, fieldinfo_fields, ENC_BIG_ENDIAN);

    /* Generic flags */
    proto_tree_add_item(gvsp_tree, hf_gvsp_genericflags, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Timestamp */
    proto_tree_add_item(gvsp_tree, hf_gvsp_timestamp, tvb, offset + 4, 8, ENC_BIG_ENDIAN);

    /* Payload data size */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloaddatasize, tvb, offset + 12, 8, ENC_BIG_ENDIAN);

    /* Timestamp tick frequency */
    proto_tree_add_item(gvsp_tree, hf_gvsp_timestamptickfrequency, tvb, offset + 20, 8, ENC_BIG_ENDIAN);

    /* Data format */
    proto_tree_add_item(gvsp_tree, hf_gvsp_dataformat, tvb, offset + 28, 4, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 32;
}


/*
 \brief Dissects a H264 leader
 */

static gint dissect_h264_leader(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Field info */
    proto_tree_add_bitmask(gvsp_tree, tvb, offset, hf_gvsp_fieldinfo,
                                  ett_gvsp_fieldinfo, fieldinfo_fields, ENC_BIG_ENDIAN);

    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Payload data size */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloaddatasize, tvb, offset + 4, 8, ENC_BIG_ENDIAN);

    /* packetization_mode */
    proto_tree_add_item(gvsp_tree, hf_gvsp_packetizationmode, tvb, offset + 13, 1, ENC_BIG_ENDIAN);

    /* packet_size */
    proto_tree_add_item(gvsp_tree, hf_gvsp_packetsize, tvb, offset + 14, 2, ENC_BIG_ENDIAN);

    /* profile_idc */
    proto_tree_add_item(gvsp_tree, hf_gvsp_profileidc, tvb, offset + 17, 1, ENC_BIG_ENDIAN);

    /* cs0, 1, 2 ,3 */
    proto_tree_add_bitmask(gvsp_tree, tvb, offset + 18, hf_gvsp_cs, ett_gvsp_cs,
                           cs_fields, ENC_BIG_ENDIAN);

    /* level_idc */
    proto_tree_add_item(gvsp_tree, hf_gvsp_levelidc, tvb, offset + 19, 1, ENC_BIG_ENDIAN);

    /* srop_interleaving_depth */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sropinterleavingdepth, tvb, offset + 20, 2, ENC_BIG_ENDIAN);

    /* srop_max_don_diff */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sropmaxdondiff, tvb, offset + 22, 2, ENC_BIG_ENDIAN);

    /* srop_deint_buf_req */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sropdeintbufreq, tvb, offset + 24, 4, ENC_BIG_ENDIAN);

    /* srop_init_buf_time */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sropinitbuftime, tvb, offset + 28, 4, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 32;
}


/*
    \brief Dissects the multizone image leader
 */

static gint dissect_multizone_image_leader(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Field info */
    proto_tree_add_bitmask(gvsp_tree, tvb, offset, hf_gvsp_fieldinfo,
                                  ett_gvsp_fieldinfo, fieldinfo_fields, ENC_BIG_ENDIAN);
    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Timestamp */
    proto_tree_add_item(gvsp_tree, hf_gvsp_timestamp, tvb, offset + 4, 8, ENC_BIG_ENDIAN);

    /* Zone direction */
    proto_tree_add_bitmask(gvsp_tree, tvb, offset + 12, hf_gvsp_sc_zone_direction,
                           ett_gvsp_sc_zone_direction, sc_zone_direction_fields, ENC_BIG_ENDIAN);

    /* Pixel format */
    proto_tree_add_bitmask(gvsp_tree, tvb, offset + 16, hf_gvsp_pixelformat, ett_gvsp_pixelformat,
                                  pixelformat_fields, ENC_BIG_ENDIAN);

    /* Size X */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sizex, tvb, offset + 20, 4, ENC_BIG_ENDIAN);

    /* Size Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_sizey, tvb, offset + 24, 4, ENC_BIG_ENDIAN);

    /* Offset X */
    proto_tree_add_item(gvsp_tree, hf_gvsp_offsetx, tvb, offset + 28, 4, ENC_BIG_ENDIAN);

    /* Offset Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_offsety, tvb, offset + 32, 4, ENC_BIG_ENDIAN);

    /* Padding X */
    proto_tree_add_item(gvsp_tree, hf_gvsp_paddingx, tvb, offset + 36, 2, ENC_BIG_ENDIAN);

    /* Padding Y */
    proto_tree_add_item(gvsp_tree, hf_gvsp_paddingy, tvb, offset + 38, 2, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 40;
}


/*
    \brief Dissects a generic trailer (contains just the payload type)
 */

static gint dissect_generic_trailer(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Payload type */
    proto_tree_add_item(gvsp_tree, hf_gvsp_payloadtype, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 4;
}


/*
    \brief Dissects a generic trailer (contains just the payload type)
 */

static gint dissect_extra_chunk_info(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    /* Chunk data payload length */
    proto_tree_add_item(gvsp_tree, hf_gvsp_chunkdatapayloadlengthex, tvb, offset, 4, ENC_BIG_ENDIAN);

    /* Chunk layoud id */
    proto_tree_add_item(gvsp_tree, hf_gvsp_chunklayoutidex, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

    /* Return dissected byte count (for all-in dissection) */
    return 8;
}


/*
    \brief Check if a packet with given status has payload
 */
static gboolean status_with_payload(gvsp_packet_info *info){
    return info->status == GEV_STATUS_SUCCESS || ( info->enhanced && info->status == GEV_STATUS_PACKET_RESEND);
}

/*
    \brief Dissects a packet payload
 */

static void dissect_packet_payload(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, gvsp_packet_info *info)
{
    if (status_with_payload(info) && tvb_reported_length_remaining(tvb, offset))
    {
        proto_tree_add_item(gvsp_tree, hf_gvsp_payloaddata, tvb, offset, -1, ENC_NA);
    }
}


/*
    \brief Dissects a packet payload for H264
 */

static void dissect_packet_payload_h264(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, gvsp_packet_info *info)
{
    if (status_with_payload(info) && tvb_reported_length_remaining(tvb, offset))
    {
        /* Timestamp */
        proto_tree_add_item(gvsp_tree, hf_gvsp_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);

        /* Data */
        proto_tree_add_item(gvsp_tree, hf_gvsp_payloaddata, tvb, offset + 8, -1, ENC_NA);
    }
}


/*
    \brief Dissects a packet payload for multizone
 */

static void dissect_packet_payload_multizone(proto_tree *gvsp_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset, gvsp_packet_info *info)
{
    if (status_with_payload(info) && tvb_reported_length_remaining(tvb, offset))
    {
        /* Zone information */
        proto_tree_add_bitmask(gvsp_tree, tvb, offset + 1, hf_gvsp_zoneinfo,
                               ett_gvsp_zoneinfo, zoneinfo_fields, ENC_BIG_ENDIAN);

        /* Address offset high */
        proto_tree_add_item(gvsp_tree, hf_gvsp_addressoffsethigh, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

        /* Address offset low */
        proto_tree_add_item(gvsp_tree, hf_gvsp_addressoffsetlow, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

        /* Data */
        proto_tree_add_item(gvsp_tree, hf_gvsp_payloaddata, tvb, offset + 8, -1, ENC_NA);
    }
}


/*
    \brief Dissects an all in packet
 */

static void dissect_packet_all_in(proto_tree *gvsp_tree, tvbuff_t *tvb, gint offset, packet_info *pinfo, gvsp_packet_info *info)
{
    gint ret;

    switch (info->payloadtype)
    {
    case GVSP_PAYLOAD_IMAGE:
        offset += dissect_image_leader(gvsp_tree, tvb, pinfo, offset);
        offset += dissect_image_trailer(gvsp_tree, tvb, pinfo, offset);
        if (info->chunk != 0)
        {
            offset += dissect_extra_chunk_info(gvsp_tree, tvb, pinfo, offset);
        }
        dissect_packet_payload(gvsp_tree, tvb, pinfo, offset, info);
        break;

    case GVSP_PAYLOAD_RAWDATA:
        offset += dissect_raw_data_leader(gvsp_tree, tvb, pinfo, offset);
        offset += dissect_generic_trailer(gvsp_tree, tvb, pinfo, offset);
        if (info->chunk != 0)
        {
            offset += dissect_extra_chunk_info(gvsp_tree, tvb, pinfo, offset);
        }
        dissect_packet_payload(gvsp_tree, tvb, pinfo, offset, info);
        break;

    case GVSP_PAYLOAD_FILE:
        ret = dissect_file_leader(gvsp_tree, tvb, pinfo, offset);
        if (ret < 0)
            break;
        offset += ret;
        offset += dissect_generic_trailer(gvsp_tree, tvb, pinfo, offset);
        if (info->chunk != 0)
        {
            offset += dissect_extra_chunk_info(gvsp_tree, tvb, pinfo, offset);
        }
        dissect_packet_payload(gvsp_tree, tvb, pinfo, offset, info);
        break;

    case GVSP_PAYLOAD_CHUNKDATA:
        offset += dissect_chunk_data_leader(gvsp_tree, tvb, pinfo, offset);
        offset += dissect_chunk_data_trailer(gvsp_tree, tvb, pinfo, offset);
        if (info->chunk != 0)
        {
            offset += dissect_extra_chunk_info(gvsp_tree, tvb, pinfo, offset);
        }
        dissect_packet_payload(gvsp_tree, tvb, pinfo, offset, info);
        break;

    case GVSP_PAYLOAD_EXTENDEDCHUNKDATA:
        offset += dissect_extended_chunk_data_leader(gvsp_tree, tvb, pinfo, offset);
        offset += dissect_extended_chunk_data_trailer(gvsp_tree, tvb, pinfo, offset);
        if (info->chunk != 0)
        {
            offset += dissect_extra_chunk_info(gvsp_tree, tvb, pinfo, offset);
        }
        dissect_packet_payload(gvsp_tree, tvb, pinfo, offset, info);
        break;

    case GVSP_PAYLOAD_JPEG:
    case GVSP_PAYLOAD_JPEG2000:
        offset += dissect_jpeg_leader(gvsp_tree, tvb, pinfo, offset);
        offset += dissect_generic_trailer(gvsp_tree, tvb, pinfo, offset);
        if (info->chunk != 0)
        {
            offset += dissect_extra_chunk_info(gvsp_tree, tvb, pinfo, offset);
        }
        dissect_packet_payload(gvsp_tree, tvb, pinfo, offset, info);
        break;

    case GVSP_PAYLOAD_H264:
        offset += dissect_h264_leader(gvsp_tree, tvb, pinfo, offset);
        offset += dissect_generic_trailer(gvsp_tree, tvb, pinfo, offset);
        if (info->chunk != 0)
        {
            offset += dissect_extra_chunk_info(gvsp_tree, tvb, pinfo, offset);
        }
        dissect_packet_payload_h264(gvsp_tree, tvb, pinfo, offset, info);
        break;

    case GVSP_PAYLOAD_MULTIZONEIMAGE:
        offset += dissect_multizone_image_leader(gvsp_tree, tvb, pinfo, offset);
        offset += dissect_image_trailer(gvsp_tree, tvb, pinfo, offset);
        if (info->chunk != 0)
        {
            offset += dissect_extra_chunk_info(gvsp_tree, tvb, pinfo, offset);
        }
        dissect_packet_payload_multizone(gvsp_tree, tvb, pinfo, offset, info);
        break;
    }
}


/*
    \brief Dissects a leader packet
 */

static void dissect_packet_leader(proto_tree *gvsp_tree, tvbuff_t *tvb, gint offset, packet_info *pinfo, gvsp_packet_info *info)
{
    switch (info->payloadtype)
    {
    case GVSP_PAYLOAD_IMAGE:
        dissect_image_leader(gvsp_tree, tvb, pinfo, offset);
        break;

    case GVSP_PAYLOAD_RAWDATA:
        dissect_raw_data_leader(gvsp_tree, tvb, pinfo, offset);
        break;

    case GVSP_PAYLOAD_FILE:
        dissect_file_leader(gvsp_tree, tvb, pinfo, offset);
        break;

    case GVSP_PAYLOAD_CHUNKDATA:
        dissect_chunk_data_leader(gvsp_tree, tvb, pinfo, offset);
        break;

    case GVSP_PAYLOAD_EXTENDEDCHUNKDATA:
        dissect_extended_chunk_data_leader(gvsp_tree, tvb, pinfo, offset);
        break;

    case GVSP_PAYLOAD_JPEG:
    case GVSP_PAYLOAD_JPEG2000:
        dissect_jpeg_leader(gvsp_tree, tvb, pinfo, offset);
        break;

    case GVSP_PAYLOAD_H264:
        dissect_h264_leader(gvsp_tree, tvb, pinfo, offset);
        break;

    case GVSP_PAYLOAD_MULTIZONEIMAGE:
        dissect_multizone_image_leader(gvsp_tree, tvb, pinfo, offset);
        break;

    default:
        break;
    }
}


/*
    \brief Dissects a trailer packet
 */

static void dissect_packet_trailer(proto_tree *gvsp_tree, tvbuff_t *tvb, gint offset, packet_info *pinfo, gvsp_packet_info *info)
{
    switch (info->payloadtype)
    {
    case GVSP_PAYLOAD_IMAGE:
    case GVSP_PAYLOAD_MULTIZONEIMAGE:
        offset += dissect_image_trailer(gvsp_tree, tvb, pinfo, offset);
        break;

    case GVSP_PAYLOAD_CHUNKDATA:
        offset += dissect_chunk_data_trailer(gvsp_tree, tvb, pinfo, offset);
        break;

    case GVSP_PAYLOAD_EXTENDEDCHUNKDATA:
        offset += dissect_extended_chunk_data_trailer(gvsp_tree, tvb, pinfo, offset);
        break;

    case GVSP_PAYLOAD_RAWDATA:
    case GVSP_PAYLOAD_FILE:
    case GVSP_PAYLOAD_JPEG:
    case GVSP_PAYLOAD_JPEG2000:
    case GVSP_PAYLOAD_H264:
        offset += dissect_generic_trailer(gvsp_tree, tvb, pinfo, offset);
        break;

    default:
        break;
    }

    if (info->chunk != 0)
    {
        dissect_extra_chunk_info(gvsp_tree, tvb, pinfo, offset);
    }
}


/*
    \brief Point of entry of all GVSP dissection
 */

static int dissect_gvsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti = NULL;
    gint offset = 0;
    proto_tree *gvsp_tree = NULL;
    gvsp_packet_info info;

    if ((tvb_reported_length(tvb) <  GVSP_MIN_PACKET_SIZE) ||
        (tvb_captured_length(tvb) < 5))
    {
        return 0;
    }

    memset(&info, 0x00, sizeof(info));

    info.format = tvb_get_guint8(tvb, 4);

    if ((info.format & 0x80) && tvb_reported_length(tvb) < GVSP_V2_MIN_PACKET_SIZE)
    {
        return 0;
    }

    /* Set the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GVSP");

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Adds "Gigabit-Ethernet Streaming Protocol" heading to protocol tree */
    /* We will add fields to this using the gvsp_tree pointer */
    ti = proto_tree_add_item(tree, proto_gvsp, tvb, offset, -1, ENC_NA);
    gvsp_tree = proto_item_add_subtree(ti, ett_gvsp);

    /* Look for extended ID flag and then clear it */
    info.enhanced = info.format & 0x80;
    info.format &= 0x7F;

    /* Add packet format to info string */
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(info.format, formatnames, "Unknown Format (0x%x)"));

    /* Dissect status */
    info.status = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(gvsp_tree, hf_gvsp_status, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (info.enhanced == 0)
    {
        info.blockid = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(gvsp_tree, hf_gvsp_blockid16, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
    else
    {
        guint8 flags;
        flags = tvb_get_guint8(tvb, offset + 1);
        info.flag_resendrangeerror = flags & 0x04;
        info.flag_previousblockdropped = flags & 0x02;
        info.flag_packetresend = flags & 0x01;

        proto_tree_add_bitmask(gvsp_tree, tvb, offset, hf_gvsp_flags,
                               ett_gvsp_flags, flags_fields, ENC_BIG_ENDIAN);
    }

    offset += 2;

    proto_tree_add_item(gvsp_tree, hf_gvsp_format, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (info.enhanced == 0)
    {
        info.packetid = tvb_get_ntohl(tvb, offset - 1);
        info.packetid &= 0x00FFFFFF;
        proto_tree_add_item(gvsp_tree, hf_gvsp_packetid24, tvb, offset, 3, ENC_BIG_ENDIAN);
    }

    offset += 3;

    if (info.enhanced != 0)
    {
        info.blockid = tvb_get_ntoh64(tvb, offset);

        /* Dissect 64 bit block ID */
        proto_tree_add_item(gvsp_tree, hf_gvsp_blockid64, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        /* Dissect 32 bit packet ID */
        info.packetid = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(gvsp_tree, hf_gvsp_packetid32, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* At this point offset is pointing to end of packet */

    col_append_fstr(pinfo->cinfo, COL_INFO, "[Block ID: %" G_GINT64_MODIFIER "u Packet ID: %d] ", (guint64)info.blockid, info.packetid);

    if (info.flag_resendrangeerror != 0)
    {
        /* Add range error to info string */
        col_append_fstr(pinfo->cinfo, COL_INFO, "[RANGE_ERROR] ");
    }

    if (info.flag_previousblockdropped != 0)
    {
        /* Add block dropped to info string */
        col_append_fstr(pinfo->cinfo, COL_INFO, "[BLOCK_DROPPED] ");
    }

    if (info.flag_packetresend != 0)
    {
        /* Add packet resend to info string */
        col_append_fstr(pinfo->cinfo, COL_INFO, "[PACKET_RESEND] ");
    }

    /* Process packet types that are payload agnostic */
    switch (info.format)
    {
    case GVSP_PACKET_PAYLOAD:
        dissect_packet_payload(gvsp_tree, tvb, pinfo, offset, &info);
        return tvb_captured_length(tvb);

    case GVSP_PACKET_PAYLOAD_H264:
        dissect_packet_payload_h264(gvsp_tree, tvb, pinfo, offset, &info);
        return tvb_captured_length(tvb);

    case GVSP_PACKET_PAYLOAD_MULTIZONE:
        dissect_packet_payload_multizone(gvsp_tree, tvb, pinfo, offset, &info);
        return tvb_captured_length(tvb);

    default:
        break;
    }

    /* Get payload type, clear chunk bit */
    if (tvb_captured_length_remaining(tvb, offset) >= 2)
    {
        info.payloadtype = tvb_get_ntohs(tvb, offset + 2);
    }

    info.chunk = info.payloadtype & 0x4000;
    info.payloadtype &= 0x3FFF;


    /* Add payload type to information string */
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str_ext(info.payloadtype, &payloadtypenames_ext, "Unknown Payload Type (0x%x)"));

    /* Process packet types for specific payload types */
    switch (info.format)
    {
    case GVSP_PACKET_ALLIN:
        dissect_packet_all_in(gvsp_tree, tvb, offset, pinfo, &info);
        break;
    case GVSP_PACKET_LEADER:
        dissect_packet_leader(gvsp_tree, tvb, offset, pinfo, &info);
        break;
    case GVSP_PACKET_TRAILER:
        dissect_packet_trailer(gvsp_tree, tvb, offset, pinfo, &info);
        break;
    default:
        break;
    }
    return tvb_captured_length(tvb);
}

static gboolean dissect_gvsp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation = NULL;
    guint16 status_code = 0;
    guint8 format = 0;

    /* Verify packet size */
    if ((tvb_reported_length(tvb) <  GVSP_MIN_PACKET_SIZE) ||
        (tvb_captured_length(tvb) < 5))
    {
        return FALSE;
    }

    /* Larger packet size if Extended ID flag is set */
    format = tvb_get_guint8(tvb, 4);

    if ((format & 0x80) && tvb_reported_length(tvb) < GVSP_V2_MIN_PACKET_SIZE)
    {
        return FALSE;
    }

    /* Check for valid status codes */
    status_code = tvb_get_ntohs(tvb, 0);

    if (status_code == 0x0000 ||
        status_code == 0x0100 ||
        (status_code >= 0x8001 && status_code <= 0x8016) ||
        status_code == 0x8FFF)
    {
        format &= 0x7F;

        /* Check for valid format types */
        if (format >= 1 && format <= 6)
        {
            if(format == GVSP_PACKET_LEADER && tvb_captured_length_remaining(tvb, 8) >= 2)
            {
                guint32 payloadtype;
                payloadtype = tvb_get_ntohs(tvb, 8);
                payloadtype &= 0x3FFF;
                if (try_val_to_str_ext(payloadtype, &payloadtypenames_ext) == NULL ){
                    return FALSE;
                }
            }

            conversation = find_or_create_conversation(pinfo);
            conversation_set_dissector(conversation, gvsp_handle);
            dissect_gvsp(tvb, pinfo, tree, data);
            return TRUE;
        }
    }

    return FALSE;
}

/*
    \brief Registers the dissector. Invoked at program startup.
 */

void proto_register_gvsp(void)
{
    module_t *gvsp_module;

    static hf_register_info hfgvsp[] =
    {
        {& hf_gvsp_status,
        { "Status", "gvsp.status",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &statusnames_ext, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_blockid16,
        { "Block ID (16 bits)", "gvsp.blockid16",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_flags,
        { "Flags", "gvsp.flags",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_flagdevicespecific0,
        { "Flag Device Specific 0", "gvsp.flag.devicespecific0",
        FT_UINT16, BASE_HEX, NULL, 0x8000,
        NULL, HFILL
        }},

        {& hf_gvsp_flagdevicespecific1,
        { "Flag Device Specific 1", "gvsp.flag.devicespecific1",
        FT_UINT16, BASE_HEX, NULL, 0x4000,
        NULL, HFILL
        }},

        {& hf_gvsp_flagdevicespecific2,
        { "Flag Device Specific 2", "gvsp.flag.devicespecific2",
        FT_UINT16, BASE_HEX, NULL, 0x2000,
        NULL, HFILL
        }},

        {& hf_gvsp_flagdevicespecific3,
        { "Flag Device Specific 3", "gvsp.flag.devicespecific3",
        FT_UINT16, BASE_HEX, NULL, 0x1000,
        NULL, HFILL
        }},

        {& hf_gvsp_flagdevicespecific4,
        { "Flag Device Specific 4", "gvsp.flag.devicespecific4",
        FT_UINT16, BASE_HEX, NULL, 0x0800,
        NULL, HFILL
        }},

        {& hf_gvsp_flagdevicespecific5,
        { "Flag Device Specific 5", "gvsp.flag.devicespecific5",
        FT_UINT16, BASE_HEX, NULL, 0x0400,
        NULL, HFILL
        }},

        {& hf_gvsp_flagdevicespecific6,
        { "Flag Device Specific 6", "gvsp.flag.devicespecific6",
        FT_UINT16, BASE_HEX, NULL, 0x0200,
        NULL, HFILL
        }},

        {& hf_gvsp_flagdevicespecific7,
        { "Flag Device Specific 7", "gvsp.flag.devicespecific7",
        FT_UINT16, BASE_HEX, NULL, 0x0100,
        NULL, HFILL
        }},

        {& hf_gvsp_flagresendrangeerror,
        { "Flag Resend Range Error 7", "gvsp.flag.resendrangeerror",
        FT_UINT16, BASE_HEX, NULL, 0x0004,
        NULL, HFILL
        }},

        {& hf_gvsp_flagpreviousblockdropped,
        { "Flag Previous Block Dropped", "gvsp.flag.previousblockdropped",
        FT_UINT16, BASE_HEX, NULL, 0x0002,
        NULL, HFILL
        }},

        {& hf_gvsp_flagpacketresend,
        { "Flag Packet Resend", "gvsp.flag.packetresend",
        FT_UINT16, BASE_HEX, NULL, 0x0001,
        NULL, HFILL
        }},

        {& hf_gvsp_format,
        { "Format", "gvsp.format",
        FT_UINT8, BASE_HEX, VALS(formatnames), 0,
        NULL, HFILL
        }},

        {& hf_gvsp_packetid24,
        { "Packet ID (24 bits)", "gvsp.packetid24",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_blockid64,
        { "Block ID (64 bits v2.0)", "gvsp.blockid64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_packetid32,
        { "Packet ID (32 bits v2.0)", "gvsp.packetid32",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_payloadtype,
        { "Payload Type", "gvsp.payloadtype",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &payloadtypenames_ext, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_payloaddata,
        { "Payload Data", "gvsp.payloaddata",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_timestamp,
        { "Timestamp", "gvsp.timestamp",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_pixelformat,
        { "Pixel Format", "gvsp.pixel",
        FT_UINT32, BASE_HEX|BASE_EXT_STRING, &pixeltypenames_ext, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_sizex,
        { "Size X", "gvsp.sizex",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_sizey,
        { "Size Y", "gvsp.sizey",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_offsetx,
        { "Offset X", "gvsp.offsetx",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_offsety,
        { "Offset Y", "gvsp.offsety",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_paddingx,
        { "Padding X", "gvsp.paddingx",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_paddingy,
        { "Padding Y", "gvsp.paddingy",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_payloaddatasize,
        { "Payload Data Size", "gvsp.payloaddatasize",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_pixelcolor,
        { "Monochrome or Color", "gvsp.pixel.color",
        FT_UINT32, BASE_HEX, VALS(colornames), 0xFF000000,
        NULL, HFILL
        }},

        {& hf_gvsp_pixeloccupy,
        { "Occupy Bits", "gvsp.pixel.occupy",
        FT_UINT32, BASE_DEC, NULL, 0x00FF0000,
        NULL, HFILL
        }},

        {& hf_gvsp_pixelid,
        { "ID", "gvsp.pixel.id",
        FT_UINT32, BASE_HEX, NULL, 0x0000FFFF,
        NULL, HFILL
        }},

        {& hf_gvsp_filename,
        { "ID", "gvsp.filename",
        FT_STRINGZ, BASE_NONE, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_payloadlength,
        { "Payload Length", "gvsp.payloadlength",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_fieldinfo,
        { "Field Info", "gvsp.fieldinfo",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_fieldid,
        { "Field ID", "gvsp.fieldid",
        FT_UINT8, BASE_HEX, NULL, 0xF0,
        NULL, HFILL
        }},

        {& hf_gvsp_fieldcount,
        { "Field Count", "gvsp.fieldcount",
        FT_UINT8, BASE_HEX, NULL, 0x0F,
        NULL, HFILL
        }},

        {& hf_gvsp_genericflags,
        { "Generic Flag", "gvsp.genericflag",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_timestamptickfrequency ,
        { "Timestamp Tick Frequency", "gvsp.timestamptickfrequency",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_dataformat,
        { "Data Format", "gvsp.dataformat",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_packetizationmode,
        { "packetization_mode", "gvsp.packetizationmode",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_packetsize,
        { "packet_size", "gvsp.packetsize",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_profileidc,
        { "profile_idc", "gvsp.profileidc",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_cs,
        { "cs", "gvsp.cs",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_cs0,
        { "cs0", "gvsp.cs0",
        FT_UINT8, BASE_HEX, NULL, 0x80,
        NULL, HFILL
        }},

        {& hf_gvsp_cs1,
        { "cs1", "gvsp.cs1",
        FT_UINT8, BASE_HEX, NULL, 0x40,
        NULL, HFILL
        }},

        {& hf_gvsp_cs2,
        { "cs2", "gvsp.cs2",
        FT_UINT8, BASE_HEX, NULL, 0x20,
        NULL, HFILL
        }},

        {& hf_gvsp_cs3,
        { "cs3", "gvsp.cs3",
        FT_UINT8, BASE_HEX, NULL, 0x10,
        NULL, HFILL
        }},

        {& hf_gvsp_levelidc,
        { "level_idc", "gvsp.levelidc",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_sropinterleavingdepth,
        { "srop_interlaving_depth", "gvsp.sropinterleavingdepth",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_sropmaxdondiff,
        { "srop_max_don_diff", "gvsp.sropmaxdondiff",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_sropdeintbufreq,
        { "srop_deint_buf_req", "gvsp.sropdeintbufreq",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_sropinitbuftime,
        { "srop_init_buf_time", "gvsp.sropinitbuftime",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_zoneinfo,
        { "Zone Info", "gvsp.zoneinfo",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_zoneid,
        { "Zone ID", "gvsp.zoneid",
        FT_UINT8, BASE_HEX, NULL, 0x3E,
        NULL, HFILL
        }},

        {& hf_gvsp_endofzone,
        { "End of Zone", "gvsp.endofzone",
        FT_UINT8, BASE_HEX, NULL, 0x01,
        NULL, HFILL
        }},

        {& hf_gvsp_addressoffsethigh,
        { "Address Offset High", "gvsp.addressoffsethigh",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_addressoffsetlow,
        { "Address Offset Low", "gvsp.addressoffsetlow",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone_direction,
        { "Zone Directions Mask", "gvsp.zonedirection",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone0_direction,
        { "Zone 0 Direction", "gvsp.zone0direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x80000000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone1_direction,
        { "Zone 1 Direction", "gvsp.zone1direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x40000000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone2_direction,
        { "Zone 2 Direction", "gvsp.zone2direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x20000000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone3_direction,
        { "Zone 3 Direction", "gvsp.zone3direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x10000000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone4_direction,
        { "Zone 4 Direction", "gvsp.zone4direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x08000000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone5_direction,
        { "Zone 5 Direction", "gvsp.zone5direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x04000000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone6_direction,
        { "Zone 6 Direction", "gvsp.zone6direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x02000000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone7_direction,
        { "Zone 7 Direction", "gvsp.zone7direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x01000000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone8_direction,
        { "Zone 8 Direction", "gvsp.zone8direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00800000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone9_direction,
        { "Zone 9 Direction", "gvsp.zone9direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00400000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone10_direction,
        { "Zone 10 Direction", "gvsp.zone10direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00200000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone11_direction,
        { "Zone 11 Direction", "gvsp.zone1direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00100000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone12_direction,
        { "Zone 12 Direction", "gvsp.zone12direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00080000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone13_direction,
        { "Zone 13 Direction", "gvsp.zone13direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00040000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone14_direction,
        { "Zone 14 Direction", "gvsp.zone14direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00020000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone15_direction,
        { "Zone 15 Direction", "gvsp.zone15direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00010000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone16_direction,
        { "Zone 16 Direction", "gvsp.zone16direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00008000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone17_direction,
        { "Zone 17 Direction", "gvsp.zone17direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00004000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone18_direction,
        { "Zone 18 Direction", "gvsp.zone18direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00002000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone19_direction,
        { "Zone 19 Direction", "gvsp.zone19direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00001000,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone20_direction,
        { "Zone 20 Direction", "gvsp.zone20direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000800,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone21_direction,
        { "Zone 21 Direction", "gvsp.zone21direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000400,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone22_direction,
        { "Zone 22 Direction", "gvsp.zone22direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000200,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone23_direction,
        { "Zone 23 Direction", "gvsp.zone23direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000100,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone24_direction,
        { "Zone 24 Direction", "gvsp.zone24direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000080,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone25_direction,
        { "Zone 25 Direction", "gvsp.zone25direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000040,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone26_direction,
        { "Zone 26 Direction", "gvsp.zone26direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000020,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone27_direction,
        { "Zone 27 Direction", "gvsp.zone27direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000010,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone28_direction,
        { "Zone 28 Direction", "gvsp.zone28direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000008,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone29_direction,
        { "Zone 29 Direction", "gvsp.zone29direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000004,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone30_direction,
        { "Zone 30 Direction", "gvsp.zone30direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000002,
        NULL, HFILL
        }},

        {& hf_gvsp_sc_zone31_direction,
        { "Zone 31 Direction", "gvsp.zone31direction",
        FT_BOOLEAN, 32, TFS(&directionnames), 0x00000001,
        NULL, HFILL
        }},

        {& hf_gvsp_chunkdatapayloadlengthex,
        { "Chunk Data Payload Length", "gvsp.chunkdatapayloadlengthex",
        FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
        NULL, HFILL
        }},

        {& hf_gvsp_chunklayoutidex,
        { "Chunk Layout ID", "gvsp.chunklayoutidex",
        FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
        NULL, HFILL
        }},
    };

    static gint *ett[] = {
        &ett_gvsp,
        &ett_gvsp_flags,
        &ett_gvsp_header,
        &ett_gvsp_payload,
        &ett_gvsp_trailer,
        &ett_gvsp_pixelformat,
        &ett_gvsp_fieldinfo,
        &ett_gvsp_cs,
        &ett_gvsp_sc_zone_direction,
        &ett_gvsp_zoneinfo
    };

    proto_gvsp = proto_register_protocol("GigE Vision Streaming Protocol", "GVSP", "gvsp");

    gvsp_handle = register_dissector("gvsp", dissect_gvsp, proto_gvsp);

    proto_register_field_array(proto_gvsp, hfgvsp, array_length(hfgvsp));
    proto_register_subtree_array(ett, array_length(ett));

    gvsp_module = prefs_register_protocol(proto_gvsp, NULL);
    prefs_register_obsolete_preference(gvsp_module, "enable_heuristic");
}

void proto_reg_handoff_gvsp(void)
{
    dissector_add_for_decode_as_with_preference("udp.port", gvsp_handle);
    heur_dissector_add("udp", dissect_gvsp_heur, "GigE Vision over UDP", "gvsp_udp", proto_gvsp, HEURISTIC_DISABLE);
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
