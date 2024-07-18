/* packet-u3v.c
 * Routines for AIA USB3 Vision (TM) Protocol dissection
 * Copyright 2016, AIA (www.visiononline.org)
 *
 * USB3 Vision (TM): USB3 Vision a standard developed under the sponsorship of
 * the AIA for the benefit of the machine vision industry.
 * U3V stands for USB3 Vision (TM) Protocol.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>
#include "packet-usb.h"

/*
U3V descriptor constants
*/
#define DESCRIPTOR_TYPE_U3V_INTERFACE 0x24
#define DESCRIPTOR_SUBTYPE_U3V_DEVICE_INFO 0x01

/*
 Bootstrap registers addresses
 */
#define U3V_ABRM_GENCP_VERSION 0x00000000
#define U3V_ABRM_MANUFACTURER_NAME 0x00000004
#define U3V_ABRM_MODEL_NAME 0x00000044
#define U3V_ABRM_FAMILY_NAME 0x00000084
#define U3V_ABRM_DEVICE_VERSION 0x000000C4
#define U3V_ABRM_MANUFACTURER_INFO 0x00000104
#define U3V_ABRM_SERIAL_NUMBER 0x00000144
#define U3V_ABRM_USER_DEFINED_NAME 0x00000184
#define U3V_ABRM_DEVICE_CAPABILITY 0x000001C4
#define U3V_ABRM_MAXIMUM_DEVICE_RESPONSE_TIME 0x000001CC
#define U3V_ABRM_MANIFEST_TABLE_ADDRESS 0x000001D0
#define U3V_ABRM_SBRM_ADDRESS 0x000001D8
#define U3V_ABRM_DEVICE_CONFIGURATION 0x000001E0
#define U3V_ABRM_HEARTBEAT_TIMEOUT 0x000001E8
#define U3V_ABRM_MESSAGE_CHANNEL_CHANNEL_ID 0x000001EC
#define U3V_ABRM_TIMESTAMP 0x000001F0
#define U3V_ABRM_TIMESTAMP_LATCH 0x000001F8
#define U3V_ABRM_TIMESTAMP_INCREMENT 0x000001FC
#define U3V_ABRM_ACCESS_PRIVILEGE 0x00000204
#define U3V_ABRM_PROTOCOL_ENDIANNESS 0x00000208
#define U3V_ABRM_IMPLEMENTATION_ENDIANNESS 0x0000020C
#define U3V_SBRM_U3V_VERSION 0x00000000
#define U3V_SBRM_U3VCP_CAPABILITY_REGISTER 0x00000004
#define U3V_SBRM_U3VCP_CONFIGURATION_REGISTER 0x0000000C
#define U3V_SBRM_MAXIMUM_COMMAND_TRANSFER_LENGTH 0x00000014
#define U3V_SBRM_MAXIMUM_ACKNOWLEDGE_TRANSFER_LENGTH 0x00000018
#define U3V_SBRM_NUMBER_OF_STREAM_CHANNELS 0x0000001C
#define U3V_SBRM_SIRM_ADDRESS 0x00000020
#define U3V_SBRM_SIRM_LENGTH 0x00000028
#define U3V_SBRM_EIRM_ADDRESS 0x0000002C
#define U3V_SBRM_EIRM_LENGTH 0x00000034
#define U3V_SBRM_IIDC2_ADDRESS 0x00000038
#define U3V_SBRM_CURRENT_SPEED 0x00000040
#define U3V_SIRM_SI_INFO 0x00000000
#define U3V_SIRM_SI_CONTROL 0x00000004
#define U3V_SIRM_SI_REQUIRED_PAYLOAD_SIZE 0x00000008
#define U3V_SIRM_SI_REQUIRED_LEADER_SIZE 0x00000010
#define U3V_SIRM_SI_REQUIRED_TRAILER_SIZE 0x00000014
#define U3V_SIRM_SI_MAXIMUM_LEADER_SIZE 0x00000018
#define U3V_SIRM_SI_PAYLOAD_TRANSFER_SIZE 0x0000001C
#define U3V_SIRM_SI_PAYLOAD_TRANSFER_COUNT 0x00000020
#define U3V_SIRM_SI_PAYLOAD_FINAL_TRANSFER1_SIZE 0x00000024
#define U3V_SIRM_SI_PAYLOAD_FINAL_TRANSFER2_SIZE 0x00000028
#define U3V_SIRM_SI_MAXIMUM_TRAILER_SIZE 0x0000002C
#define U3V_EIRM_EI_CONTROL 0x00000000
#define U3V_EIRM_MAXIMUM_EVENT_TRANSFER_LENGTH 0x00000004
#define U3V_EIRM_EVENT_TEST_CONTROL 0x00000008

/*
 Command and acknowledge IDs
*/
#define U3V_READMEM_CMD 0x0800
#define U3V_READMEM_ACK 0x0801
#define U3V_WRITEMEM_CMD 0x0802
#define U3V_WRITEMEM_ACK 0x0803
#define U3V_PENDING_ACK 0x0805
#define U3V_EVENT_CMD 0x0C00
#define U3V_EVENT_ACK 0x0C01

/*
 Status codes
*/
#define U3V_STATUS_GENCP_SUCCESS               0x0000
#define U3V_STATUS_GENCP_NOT_IMPLEMENTED       0x8001
#define U3V_STATUS_GENCP_INVALID_PARAMETER     0x8002
#define U3V_STATUS_GENCP_INVALID_ADDRESS       0x8003
#define U3V_STATUS_GENCP_WRITE_PROTECT         0x8004
#define U3V_STATUS_GENCP_BAD_ALIGNMENT         0x8005
#define U3V_STATUS_GENCP_ACCESS_DENIED         0x8006
#define U3V_STATUS_GENCP_BUSY                  0x8007
/* 0x8008 - 0x800A have been used in GEV 1.x but are now deprecated. The GenCP specification did NOT recycle these values! */
#define U3V_STATUS_GENCP_MSG_TIMEOUT           0x800B
/* 0x800C - 0x800D are used in GEV only. The GenCP specification did NOT recycle these values! */
#define U3V_STATUS_GENCP_INVALID_HEADER        0x800E
#define U3V_STATUS_GENCP_WRONG_CONFIG          0x800F

#define U3V_STATUS_GENCP_ERROR                 0x8FFF

#define U3V_STATUS_RESEND_NOT_SUPPORTED        0xA001
#define U3V_STATUS_DSI_ENDPOINT_HALTED         0xA002
#define U3V_STATUS_SI_PAYLOAD_SIZE_NOT_ALIGNED 0xA003
#define U3V_STATUS_SI_REGISTERS_INCONSISTENT   0xA004
#define U3V_STATUS_DATA_DISCARDED              0xA100
#define U3V_STATUS_DATA_OVERRUN                0xA101

/*
 Prefix
*/
#define U3V_CONTROL_PREFIX 0x43563355
#define U3V_EVENT_PREFIX   0x45563355

#define U3V_STREAM_LEADER_PREFIX  0x4C563355
#define U3V_STREAM_TRAILER_PREFIX 0x54563355

/*
 Event IDs
*/
#define U3V_EVENT_TESTEVENT 0x4FFF

/*
 * Pixel Format IDs
*/
#define PFNC_U3V_MONO1P 0x01010037
#define PFNC_U3V_MONO2P 0x01020038
#define PFNC_U3V_MONO4P 0x01040039
#define PFNC_U3V_MONO8 0x01080001
#define PFNC_U3V_MONO8S 0x01080002
#define PFNC_U3V_MONO10 0x01100003
#define PFNC_U3V_MONO10P 0x010A0046
#define PFNC_U3V_MONO12 0x01100005
#define PFNC_U3V_MONO12P 0x010C0047
#define PFNC_U3V_MONO14 0x01100025
#define PFNC_U3V_MONO14P 0x010E0104
#define PFNC_U3V_MONO16 0x01100007
#define PFNC_U3V_MONO32 0x01200111
#define PFNC_U3V_BAYERBG4P 0x01040110
#define PFNC_U3V_BAYERBG8 0x0108000B
#define PFNC_U3V_BAYERBG10 0x0110000F
#define PFNC_U3V_BAYERBG10P 0x010A0052
#define PFNC_U3V_BAYERBG12 0x01100013
#define PFNC_U3V_BAYERBG12P 0x010C0053
#define PFNC_U3V_BAYERBG14 0x0110010C
#define PFNC_U3V_BAYERBG14P 0x010E0108
#define PFNC_U3V_BAYERBG16 0x01100031
#define PFNC_U3V_BAYERGB4P 0x0104010F
#define PFNC_U3V_BAYERGB8 0x0108000A
#define PFNC_U3V_BAYERGB10 0x0110000E
#define PFNC_U3V_BAYERGB10P 0x010A0054
#define PFNC_U3V_BAYERGB12 0x01100012
#define PFNC_U3V_BAYERGB12P 0x010C0055
#define PFNC_U3V_BAYERGB14 0x0110010B
#define PFNC_U3V_BAYERGB14P 0x010E0107
#define PFNC_U3V_BAYERGB16 0x01100030
#define PFNC_U3V_BAYERGR4P 0x0104010D
#define PFNC_U3V_BAYERGR8 0x01080008
#define PFNC_U3V_BAYERGR10 0x0110000C
#define PFNC_U3V_BAYERGR10P 0x010A0056
#define PFNC_U3V_BAYERGR12 0x01100010
#define PFNC_U3V_BAYERGR12P 0x010C0057
#define PFNC_U3V_BAYERGR14 0x01100109
#define PFNC_U3V_BAYERGR14P 0x010E0105
#define PFNC_U3V_BAYERGR16 0x0110002E
#define PFNC_U3V_BAYERRG4P 0x0104010E
#define PFNC_U3V_BAYERRG8 0x01080009
#define PFNC_U3V_BAYERRG10 0x0110000D
#define PFNC_U3V_BAYERRG10P 0x010A0058
#define PFNC_U3V_BAYERRG12 0x01100011
#define PFNC_U3V_BAYERRG12P 0x010C0059
#define PFNC_U3V_BAYERRG14 0x0110010A
#define PFNC_U3V_BAYERRG14P 0x010E0106
#define PFNC_U3V_BAYERRG16 0x0110002F
#define PFNC_U3V_RGBA8 0x02200016
#define PFNC_U3V_RGBA10 0x0240005F
#define PFNC_U3V_RGBA10P 0x02280060
#define PFNC_U3V_RGBA12 0x02400061
#define PFNC_U3V_RGBA12P 0x02300062
#define PFNC_U3V_RGBA14 0x02400063
#define PFNC_U3V_RGBA16 0x02400064
#define PFNC_U3V_RGB8 0x02180014
#define PFNC_U3V_RGB8_PLANAR 0x02180021
#define PFNC_U3V_RGB10 0x02300018
#define PFNC_U3V_RGB10_PLANAR 0x02300022
#define PFNC_U3V_RGB10P 0x021E005C
#define PFNC_U3V_RGB10P32 0x0220001D
#define PFNC_U3V_RGB12 0x0230001A
#define PFNC_U3V_RGB12_PLANAR 0x02300023
#define PFNC_U3V_RGB12P 0x0224005D
#define PFNC_U3V_RGB14 0x0230005E
#define PFNC_U3V_RGB16 0x02300033
#define PFNC_U3V_RGB16_PLANAR 0x02300024
#define PFNC_U3V_RGB565P 0x02100035
#define PFNC_U3V_BGRA8 0x02200017
#define PFNC_U3V_BGRA10 0x0240004C
#define PFNC_U3V_BGRA10P 0x0228004D
#define PFNC_U3V_BGRA12 0x0240004E
#define PFNC_U3V_BGRA12P 0x0230004F
#define PFNC_U3V_BGRA14 0x02400050
#define PFNC_U3V_BGRA16 0x02400051
#define PFNC_U3V_BGR8 0x02180015
#define PFNC_U3V_BGR10 0x02300019
#define PFNC_U3V_BGR10P 0x021E0048
#define PFNC_U3V_BGR12 0x0230001B
#define PFNC_U3V_BGR12P 0x02240049
#define PFNC_U3V_BGR14 0x0230004A
#define PFNC_U3V_BGR16 0x0230004B
#define PFNC_U3V_BGR565P 0x02100036
#define PFNC_U3V_R8 0x010800C9
#define PFNC_U3V_R10 0x01100120
#define PFNC_U3V_R10_DEPRECATED 0x010A00CA
#define PFNC_U3V_R12 0x01100121
#define PFNC_U3V_R12_DEPRECATED 0x010C00CB
#define PFNC_U3V_R16 0x011000CC
#define PFNC_U3V_G8 0x010800CD
#define PFNC_U3V_G10 0x01100122
#define PFNC_U3V_G10_DEPRECATED 0x010A00CE
#define PFNC_U3V_G12 0x01100123
#define PFNC_U3V_G12_DEPRECATED 0x010C00CF
#define PFNC_U3V_G16 0x011000D0
#define PFNC_U3V_B8 0x010800D1
#define PFNC_U3V_B10 0x01100124
#define PFNC_U3V_B10_DEPRECATED 0x010A00D2
#define PFNC_U3V_B12 0x01100125
#define PFNC_U3V_B12_DEPRECATED 0x010C00D3
#define PFNC_U3V_B16 0x011000D4
#define PFNC_U3V_COORD3D_ABC8 0x021800B2
#define PFNC_U3V_COORD3D_ABC8_PLANAR 0x021800B3
#define PFNC_U3V_COORD3D_ABC10P 0x021E00DB
#define PFNC_U3V_COORD3D_ABC10P_PLANAR 0x021E00DC
#define PFNC_U3V_COORD3D_ABC12P 0x022400DE
#define PFNC_U3V_COORD3D_ABC12P_PLANAR 0x022400DF
#define PFNC_U3V_COORD3D_ABC16 0x023000B9
#define PFNC_U3V_COORD3D_ABC16_PLANAR 0x023000BA
#define PFNC_U3V_COORD3D_ABC32F 0x026000C0
#define PFNC_U3V_COORD3D_ABC32F_PLANAR 0x026000C1
#define PFNC_U3V_COORD3D_AC8 0x021000B4
#define PFNC_U3V_COORD3D_AC8_PLANAR 0x021000B5
#define PFNC_U3V_COORD3D_AC10P 0x021400F0
#define PFNC_U3V_COORD3D_AC10P_PLANAR 0x021400F1
#define PFNC_U3V_COORD3D_AC12P 0x021800F2
#define PFNC_U3V_COORD3D_AC12P_PLANAR 0x021800F3
#define PFNC_U3V_COORD3D_AC16 0x022000BB
#define PFNC_U3V_COORD3D_AC16_PLANAR 0x022000BC
#define PFNC_U3V_COORD3D_AC32F 0x024000C2
#define PFNC_U3V_COORD3D_AC32F_PLANAR 0x024000C3
#define PFNC_U3V_COORD3D_A8 0x010800AF
#define PFNC_U3V_COORD3D_A10P 0x010A00D5
#define PFNC_U3V_COORD3D_A12P 0x010C00D8
#define PFNC_U3V_COORD3D_A16 0x011000B6
#define PFNC_U3V_COORD3D_A32F 0x012000BD
#define PFNC_U3V_COORD3D_B8 0x010800B0
#define PFNC_U3V_COORD3D_B10P 0x010A00D6
#define PFNC_U3V_COORD3D_B12P 0x010C00D9
#define PFNC_U3V_COORD3D_B16 0x011000B7
#define PFNC_U3V_COORD3D_B32F 0x012000BE
#define PFNC_U3V_COORD3D_C8 0x010800B1
#define PFNC_U3V_COORD3D_C10P 0x010A00D7
#define PFNC_U3V_COORD3D_C12P 0x010C00DA
#define PFNC_U3V_COORD3D_C16 0x011000B8
#define PFNC_U3V_COORD3D_C32F 0x012000BF
#define PFNC_U3V_CONFIDENCE1 0x010800C4
#define PFNC_U3V_CONFIDENCE1P 0x010100C5
#define PFNC_U3V_CONFIDENCE8 0x010800C6
#define PFNC_U3V_CONFIDENCE16 0x011000C7
#define PFNC_U3V_CONFIDENCE32F 0x012000C8
#define PFNC_U3V_BICOLORBGRG8 0x021000A6
#define PFNC_U3V_BICOLORBGRG10 0x022000A9
#define PFNC_U3V_BICOLORBGRG10P 0x021400AA
#define PFNC_U3V_BICOLORBGRG12 0x022000AD
#define PFNC_U3V_BICOLORBGRG12P 0x021800AE
#define PFNC_U3V_BICOLORRGBG8 0x021000A5
#define PFNC_U3V_BICOLORRGBG10 0x022000A7
#define PFNC_U3V_BICOLORRGBG10P 0x021400A8
#define PFNC_U3V_BICOLORRGBG12 0x022000AB
#define PFNC_U3V_BICOLORRGBG12P 0x021800AC
#define PFNC_U3V_DATA8 0x01080116
#define PFNC_U3V_DATA8S 0x01080117
#define PFNC_U3V_DATA16 0x01100118
#define PFNC_U3V_DATA16S 0x01100119
#define PFNC_U3V_DATA32 0x0120011A
#define PFNC_U3V_DATA32F 0x0120011C
#define PFNC_U3V_DATA32S 0x0120011B
#define PFNC_U3V_DATA64 0x0140011D
#define PFNC_U3V_DATA64F 0x0140011F
#define PFNC_U3V_DATA64S 0x0140011E
#define PFNC_U3V_SCF1WBWG8 0x01080067
#define PFNC_U3V_SCF1WBWG10 0x01100068
#define PFNC_U3V_SCF1WBWG10P 0x010A0069
#define PFNC_U3V_SCF1WBWG12 0x0110006A
#define PFNC_U3V_SCF1WBWG12P 0x010C006B
#define PFNC_U3V_SCF1WBWG14 0x0110006C
#define PFNC_U3V_SCF1WBWG16 0x0110006D
#define PFNC_U3V_SCF1WGWB8 0x0108006E
#define PFNC_U3V_SCF1WGWB10 0x0110006F
#define PFNC_U3V_SCF1WGWB10P 0x010A0070
#define PFNC_U3V_SCF1WGWB12 0x01100071
#define PFNC_U3V_SCF1WGWB12P 0x010C0072
#define PFNC_U3V_SCF1WGWB14 0x01100073
#define PFNC_U3V_SCF1WGWB16 0x01100074
#define PFNC_U3V_SCF1WGWR8 0x01080075
#define PFNC_U3V_SCF1WGWR10 0x01100076
#define PFNC_U3V_SCF1WGWR10P 0x010A0077
#define PFNC_U3V_SCF1WGWR12 0x01100078
#define PFNC_U3V_SCF1WGWR12P 0x010C0079
#define PFNC_U3V_SCF1WGWR14 0x0110007A
#define PFNC_U3V_SCF1WGWR16 0x0110007B
#define PFNC_U3V_SCF1WRWG8 0x0108007C
#define PFNC_U3V_SCF1WRWG10 0x0110007D
#define PFNC_U3V_SCF1WRWG10P 0x010A007E
#define PFNC_U3V_SCF1WRWG12 0x0110007F
#define PFNC_U3V_SCF1WRWG12P 0x010C0080
#define PFNC_U3V_SCF1WRWG14 0x01100081
#define PFNC_U3V_SCF1WRWG16 0x01100082
#define PFNC_U3V_YCBCR8 0x0218005B
#define PFNC_U3V_YCBCR8_CBYCR 0x0218003A
#define PFNC_U3V_YCBCR10_CBYCR 0x02300083
#define PFNC_U3V_YCBCR10P_CBYCR 0x021E0084
#define PFNC_U3V_YCBCR12_CBYCR 0x02300085
#define PFNC_U3V_YCBCR12P_CBYCR 0x02240086
#define PFNC_U3V_YCBCR411_8 0x020C005A
#define PFNC_U3V_YCBCR411_8_CBYYCRYY 0x020C003C
#define PFNC_U3V_YCBCR420_8_YY_CBCR_SEMIPLANAR 0x020C0112
#define PFNC_U3V_YCBCR420_8_YY_CRCB_SEMIPLANAR 0x020C0114
#define PFNC_U3V_YCBCR422_8 0x0210003B
#define PFNC_U3V_YCBCR422_8_CBYCRY 0x02100043
#define PFNC_U3V_YCBCR422_8_YY_CBCR_SEMIPLANAR 0x02100113
#define PFNC_U3V_YCBCR422_8_YY_CRCB_SEMIPLANAR 0x02100115
#define PFNC_U3V_YCBCR422_10 0x02200065
#define PFNC_U3V_YCBCR422_10_CBYCRY 0x02200099
#define PFNC_U3V_YCBCR422_10P 0x02140087
#define PFNC_U3V_YCBCR422_10P_CBYCRY 0x0214009A
#define PFNC_U3V_YCBCR422_12 0x02200066
#define PFNC_U3V_YCBCR422_12_CBYCRY 0x0220009B
#define PFNC_U3V_YCBCR422_12P 0x02180088
#define PFNC_U3V_YCBCR422_12P_CBYCRY 0x0218009C
#define PFNC_U3V_YCBCR601_8_CBYCR 0x0218003D
#define PFNC_U3V_YCBCR601_10_CBYCR 0x02300089
#define PFNC_U3V_YCBCR601_10P_CBYCR 0x021E008A
#define PFNC_U3V_YCBCR601_12_CBYCR 0x0230008B
#define PFNC_U3V_YCBCR601_12P_CBYCR 0x0224008C
#define PFNC_U3V_YCBCR601_411_8_CBYYCRYY 0x020C003F
#define PFNC_U3V_YCBCR601_422_8 0x0210003E
#define PFNC_U3V_YCBCR601_422_8_CBYCRY 0x02100044
#define PFNC_U3V_YCBCR601_422_10 0x0220008D
#define PFNC_U3V_YCBCR601_422_10_CBYCRY 0x0220009D
#define PFNC_U3V_YCBCR601_422_10P 0x0214008E
#define PFNC_U3V_YCBCR601_422_10P_CBYCRY 0x0214009E
#define PFNC_U3V_YCBCR601_422_12 0x0220008F
#define PFNC_U3V_YCBCR601_422_12_CBYCRY 0x0220009F
#define PFNC_U3V_YCBCR601_422_12P 0x02180090
#define PFNC_U3V_YCBCR601_422_12P_CBYCRY 0x021800A0
#define PFNC_U3V_YCBCR709_8_CBYCR 0x02180040
#define PFNC_U3V_YCBCR709_10_CBYCR 0x02300091
#define PFNC_U3V_YCBCR709_10P_CBYCR 0x021E0092
#define PFNC_U3V_YCBCR709_12_CBYCR 0x02300093
#define PFNC_U3V_YCBCR709_12P_CBYCR 0x02240094
#define PFNC_U3V_YCBCR709_411_8_CBYYCRYY 0x020C0042
#define PFNC_U3V_YCBCR709_422_8 0x02100041
#define PFNC_U3V_YCBCR709_422_8_CBYCRY 0x02100045
#define PFNC_U3V_YCBCR709_422_10 0x02200095
#define PFNC_U3V_YCBCR709_422_10_CBYCRY 0x022000A1
#define PFNC_U3V_YCBCR709_422_10P 0x02140096
#define PFNC_U3V_YCBCR709_422_10P_CBYCRY 0x021400A2
#define PFNC_U3V_YCBCR709_422_12 0x02200097
#define PFNC_U3V_YCBCR709_422_12_CBYCRY 0x022000A3
#define PFNC_U3V_YCBCR709_422_12P 0x02180098
#define PFNC_U3V_YCBCR709_422_12P_CBYCRY 0x021800A4
#define PFNC_U3V_YCBCR2020_8_CBYCR 0x021800F4
#define PFNC_U3V_YCBCR2020_10_CBYCR 0x023000F5
#define PFNC_U3V_YCBCR2020_10P_CBYCR 0x021E00F6
#define PFNC_U3V_YCBCR2020_12_CBYCR 0x023000F7
#define PFNC_U3V_YCBCR2020_12P_CBYCR 0x022400F8
#define PFNC_U3V_YCBCR2020_411_8_CBYYCRYY 0x020C00F9
#define PFNC_U3V_YCBCR2020_422_8 0x021000FA
#define PFNC_U3V_YCBCR2020_422_8_CBYCRY 0x021000FB
#define PFNC_U3V_YCBCR2020_422_10 0x022000FC
#define PFNC_U3V_YCBCR2020_422_10_CBYCRY 0x022000FD
#define PFNC_U3V_YCBCR2020_422_10P 0x021400FE
#define PFNC_U3V_YCBCR2020_422_10P_CBYCRY 0x021400FF
#define PFNC_U3V_YCBCR2020_422_12 0x02200100
#define PFNC_U3V_YCBCR2020_422_12_CBYCRY 0x02200101
#define PFNC_U3V_YCBCR2020_422_12P 0x02180102
#define PFNC_U3V_YCBCR2020_422_12P_CBYCRY 0x02180103
#define PFNC_U3V_YUV8_UYV 0x02180020
#define PFNC_U3V_YUV411_8_UYYVYY 0x020C001E
#define PFNC_U3V_YUV422_8 0x02100032
#define PFNC_U3V_YUV422_8_UYVY 0x0210001F
#define GVSP_MONO10PACKED 0x010C0004
#define GVSP_MONO12PACKED 0x010C0006
#define GVSP_BAYERBG10PACKED 0x010C0029
#define GVSP_BAYERBG12PACKED 0x010C002D
#define GVSP_BAYERGB10PACKED 0x010C0028
#define GVSP_BAYERGB12PACKED 0x010C002C
#define GVSP_BAYERGR10PACKED 0x010C0026
#define GVSP_BAYERGR12PACKED 0x010C002A
#define GVSP_BAYERRG10PACKED 0x010C0027
#define GVSP_BAYERRG12PACKED 0x010C002B
#define GVSP_RGB10V1PACKED 0x0220001C
#define GVSP_RGB12V1PACKED 0x02240034

/*
 Payload Types
*/
#define U3V_STREAM_PAYLOAD_IMAGE            0x0001
#define U3V_STREAM_PAYLOAD_IMAGE_EXT_CHUNK  0x4001
#define U3V_STREAM_PAYLOAD_CHUNK            0x4000

void proto_register_u3v(void);
void proto_reg_handoff_u3v(void);

/* Define the u3v protocol */
static int proto_u3v;

/* GenCP transaction tracking
 * the protocol only allows strict sequential
 * communication.
 *
 * we track the current cmd/ack/pend_ack information
 * in a struct that is created per GenCP communication
 *
 * in each request/response packet we add pointers
 * to this information, that allow navigation between packets
 * and dissection of addresses
 */
typedef struct _gencp_transaction_t {
    uint32_t cmd_frame;
    uint32_t ack_frame;
    nstime_t cmd_time;
    /* list of pending acknowledges */
    wmem_array_t *pend_ack_frame_list;
    /* current requested address */
    uint64_t address;
    /* current requested count read/write */
    uint32_t count;
} gencp_transaction_t;

typedef struct _u3v_conv_info_t {
    uint64_t abrm_addr;
    uint64_t sbrm_addr;
    uint64_t sirm_addr;
    uint64_t eirm_addr;
    uint64_t iidc2_addr;
    uint64_t manifest_addr;
    uint32_t ep_stream;
    gencp_transaction_t *trans_info;
} u3v_conv_info_t;

/*
 \brief IDs used for bootstrap dissection
*/
static int hf_u3v_gencp_prefix;
static int hf_u3v_flag;
static int hf_u3v_acknowledge_required_flag;
static int hf_u3v_command_id;
static int hf_u3v_length;
static int hf_u3v_request_id;
static int hf_u3v_status;
static int hf_u3v_address;
static int hf_u3v_count;
static int hf_u3v_eventcmd_id;
static int hf_u3v_eventcmd_error_id;
static int hf_u3v_eventcmd_device_specific_id;
static int hf_u3v_eventcmd_timestamp;
static int hf_u3v_eventcmd_data;
static int hf_u3v_time_to_completion;
static int hf_u3v_payloaddata;
static int hf_u3v_reserved;

static int hf_u3v_bootstrap_GenCP_Version;
static int hf_u3v_bootstrap_Manufacturer_Name;
static int hf_u3v_bootstrap_Model_Name;
static int hf_u3v_bootstrap_Family_Name;
static int hf_u3v_bootstrap_Device_Version;
static int hf_u3v_bootstrap_Manufacturer_Info;
static int hf_u3v_bootstrap_Serial_Number;
static int hf_u3v_bootstrap_User_Defined_Name;
static int hf_u3v_bootstrap_Device_Capability;
static int hf_u3v_bootstrap_Maximum_Device_Response_Time;
static int hf_u3v_bootstrap_Manifest_Table_Address;
static int hf_u3v_bootstrap_SBRM_Address;
static int hf_u3v_bootstrap_Device_Configuration;
static int hf_u3v_bootstrap_Heartbeat_Timeout;
static int hf_u3v_bootstrap_Message_Channel_channel_id;
static int hf_u3v_bootstrap_Timestamp;
static int hf_u3v_bootstrap_Timestamp_Latch;
static int hf_u3v_bootstrap_Timestamp_Increment;
static int hf_u3v_bootstrap_Access_Privilege;
static int hf_u3v_bootstrap_Protocol_Endianness;
static int hf_u3v_bootstrap_Implementation_Endianness;
static int hf_u3v_bootstrap_U3V_Version;
static int hf_u3v_bootstrap_U3VCP_Capability_Register;
static int hf_u3v_bootstrap_U3VCP_Configuration_Register;
static int hf_u3v_bootstrap_Maximum_Command_Transfer_Length;
static int hf_u3v_bootstrap_Maximum_Acknowledge_Transfer_Length;
static int hf_u3v_bootstrap_Number_of_Stream_Channels;
static int hf_u3v_bootstrap_SIRM_Address;
static int hf_u3v_bootstrap_SIRM_Length;
static int hf_u3v_bootstrap_EIRM_Address;
static int hf_u3v_bootstrap_EIRM_Length;
static int hf_u3v_bootstrap_IIDC2_Address;
static int hf_u3v_bootstrap_Current_Speed;
static int hf_u3v_bootstrap_SI_Info;
static int hf_u3v_bootstrap_SI_Control;
static int hf_u3v_bootstrap_SI_Required_Payload_Size;
static int hf_u3v_bootstrap_SI_Required_Leader_Size;
static int hf_u3v_bootstrap_SI_Required_Trailer_Size;
static int hf_u3v_bootstrap_SI_Maximum_Leader_Size;
static int hf_u3v_bootstrap_SI_Payload_Transfer_Size;
static int hf_u3v_bootstrap_SI_Payload_Transfer_Count;
static int hf_u3v_bootstrap_SI_Payload_Final_Transfer1_Size;
static int hf_u3v_bootstrap_SI_Payload_Final_Transfer2_Size;
static int hf_u3v_bootstrap_SI_Maximum_Trailer_Size;
static int hf_u3v_bootstrap_EI_Control;
static int hf_u3v_bootstrap_Maximum_Event_Transfer_Length;
static int hf_u3v_bootstrap_Event_Test_Control;
static int hf_u3v_custom_memory_addr;
static int hf_u3v_custom_memory_data;

static int hf_u3v_scd_readmem_cmd;
static int hf_u3v_scd_writemem_cmd;
static int hf_u3v_scd_event_cmd;
static int hf_u3v_scd_ack_readmem_ack;
static int hf_u3v_scd_writemem_ack;
static int hf_u3v_ccd_pending_ack;
static int hf_u3v_stream_leader;
static int hf_u3v_stream_trailer;
static int hf_u3v_stream_payload;
static int hf_u3v_ccd_cmd;
static int hf_u3v_ccd_ack;
static int hf_u3v_device_info_descriptor;

/* stream elements */
static int hf_u3v_stream_reserved;
static int hf_u3v_stream_leader_size;

static int hf_u3v_stream_prefix;
static int hf_u3v_stream_trailer_size;

static int hf_u3v_stream_block_id;
static int hf_u3v_stream_payload_type;
static int hf_u3v_stream_status;
static int hf_u3v_stream_valid_payload_size;

static int hf_u3v_stream_timestamp;
static int hf_u3v_stream_pixel_format;
static int hf_u3v_stream_size_x;
static int hf_u3v_stream_size_y;
static int hf_u3v_stream_offset_x;
static int hf_u3v_stream_offset_y;
static int hf_u3v_stream_padding_x;
static int hf_u3v_stream_chunk_layout_id;

static int hf_u3v_stream_data;

/* U3V device info descriptor */
static int hf_u3v_device_info_descriptor_bLength;
static int hf_u3v_device_info_descriptor_bDescriptorType;
static int hf_u3v_device_info_descriptor_bDescriptorSubtype;
static int hf_u3v_device_info_descriptor_bGenCPVersion;
static int hf_u3v_device_info_descriptor_bGenCPVersion_minor;
static int hf_u3v_device_info_descriptor_bGenCPVersion_major;
static int hf_u3v_device_info_descriptor_bU3VVersion;
static int hf_u3v_device_info_descriptor_bU3VVersion_minor;
static int hf_u3v_device_info_descriptor_bU3VVersion_major;
static int hf_u3v_device_info_descriptor_iDeviceGUID;
static int hf_u3v_device_info_descriptor_iVendorName;
static int hf_u3v_device_info_descriptor_iModelName;
static int hf_u3v_device_info_descriptor_iFamilyName;
static int hf_u3v_device_info_descriptor_iDeviceVersion;
static int hf_u3v_device_info_descriptor_iManufacturerInfo;
static int hf_u3v_device_info_descriptor_iSerialNumber;
static int hf_u3v_device_info_descriptor_iUserDefinedName;
static int hf_u3v_device_info_descriptor_bmSpeedSupport;
static int hf_u3v_device_info_descriptor_bmSpeedSupport_low_speed;
static int hf_u3v_device_info_descriptor_bmSpeedSupport_full_speed;
static int hf_u3v_device_info_descriptor_bmSpeedSupport_high_speed;
static int hf_u3v_device_info_descriptor_bmSpeedSupport_super_speed;
static int hf_u3v_device_info_descriptor_bmSpeedSupport_reserved;

/*Define the tree for u3v*/
static int ett_u3v;
static int ett_u3v_cmd;
static int ett_u3v_flags;
static int ett_u3v_ack;
static int ett_u3v_payload_cmd;
static int ett_u3v_payload_ack;
static int ett_u3v_payload_cmd_subtree;
static int ett_u3v_payload_ack_subtree;
static int ett_u3v_bootstrap_fields;
static int ett_u3v_stream_leader;
static int ett_u3v_stream_trailer;
static int ett_u3v_stream_payload;

static int ett_u3v_device_info_descriptor;
static int ett_u3v_device_info_descriptor_speed_support;
static int ett_u3v_device_info_descriptor_gencp_version;
static int ett_u3v_device_info_descriptor_u3v_version;

static dissector_handle_t u3v_handle;

static const value_string command_names[] =
{
    { U3V_READMEM_CMD, "READMEM_CMD" },
    { U3V_WRITEMEM_CMD, "WRITEMEM_CMD" },
    { U3V_EVENT_CMD, "EVENT_CMD" },
    { U3V_READMEM_ACK, "READMEM_ACK" },
    { U3V_WRITEMEM_ACK, "WRITEMEM_ACK" },
    { U3V_PENDING_ACK, "PENDING_ACK" },
    { U3V_EVENT_ACK, "EVENT_ACK" },
    { 0, NULL }
};

static const value_string event_id_names[] =
{
    { U3V_EVENT_TESTEVENT, "U3V_EVENT_TESTEVENT" },
    { 0, NULL }
};

static const value_string status_names[] =
{
    { U3V_STATUS_GENCP_SUCCESS, "U3V_STATUS_GENCP_SUCCESS" },
    { U3V_STATUS_GENCP_NOT_IMPLEMENTED, "U3V_STATUS_GENCP_NOT_IMPLEMENTED" },
    { U3V_STATUS_GENCP_INVALID_PARAMETER, "U3V_STATUS_GENCP_INVALID_PARAMETER" },
    { U3V_STATUS_GENCP_INVALID_ADDRESS, "U3V_STATUS_GENCP_INVALID_ADDRESS" },
    { U3V_STATUS_GENCP_WRITE_PROTECT, "U3V_STATUS_GENCP_WRITE_PROTECT" },
    { U3V_STATUS_GENCP_BAD_ALIGNMENT, "U3V_STATUS_GENCP_BAD_ALIGNMENT" },
    { U3V_STATUS_GENCP_ACCESS_DENIED, "U3V_STATUS_GENCP_ACCESS_DENIED" },
    { U3V_STATUS_GENCP_BUSY, "U3V_STATUS_GENCP_BUSY" },
    { U3V_STATUS_GENCP_WRONG_CONFIG, "U3V_STATUS_GENCP_WRONG_CONFIG" },
    { U3V_STATUS_RESEND_NOT_SUPPORTED, "U3V_STATUS_RESEND_NOT_SUPPORTED" },
    { U3V_STATUS_DSI_ENDPOINT_HALTED, "U3V_STATUS_DSI_ENDPOINT_HALTED" },
    { U3V_STATUS_SI_PAYLOAD_SIZE_NOT_ALIGNED, "U3V_STATUS_SI_PAYLOAD_SIZE_NOT_ALIGNED" },
    { U3V_STATUS_SI_REGISTERS_INCONSISTENT, "U3V_STATUS_SI_REGISTERS_INCONSISTENT" },
    { U3V_STATUS_DATA_DISCARDED, "U3V_STATUS_DATA_DISCARDED" },
    { U3V_STATUS_DATA_OVERRUN, "U3V_STATUS_DATA_OVERRUN" },
    { 0, NULL }
};

static const value_string status_names_short[] =
{
    { U3V_STATUS_GENCP_SUCCESS, "" },
    { U3V_STATUS_GENCP_NOT_IMPLEMENTED, "U3V_STATUS_GENCP_NOT_IMPLEMENTED" },
    { U3V_STATUS_GENCP_INVALID_PARAMETER, "U3V_STATUS_GENCP_INVALID_PARAMETER" },
    { U3V_STATUS_GENCP_INVALID_ADDRESS, "U3V_STATUS_GENCP_INVALID_ADDRESS" },
    { U3V_STATUS_GENCP_WRITE_PROTECT, "U3V_STATUS_GENCP_WRITE_PROTECT" },
    { U3V_STATUS_GENCP_BAD_ALIGNMENT, "U3V_STATUS_GENCP_BAD_ALIGNMENT" },
    { U3V_STATUS_GENCP_ACCESS_DENIED, "U3V_STATUS_GENCP_ACCESS_DENIED" },
    { U3V_STATUS_GENCP_BUSY, "U3V_STATUS_GENCP_BUSY" },
    { U3V_STATUS_GENCP_WRONG_CONFIG, "U3V_STATUS_GENCP_WRONG_CONFIG" },
    { U3V_STATUS_RESEND_NOT_SUPPORTED, "U3V_STATUS_RESEND_NOT_SUPPORTED" },
    { U3V_STATUS_DSI_ENDPOINT_HALTED, "U3V_STATUS_DSI_ENDPOINT_HALTED" },
    { U3V_STATUS_SI_PAYLOAD_SIZE_NOT_ALIGNED, "U3V_STATUS_SI_PAYLOAD_SIZE_NOT_ALIGNED" },
    { U3V_STATUS_SI_REGISTERS_INCONSISTENT, "U3V_STATUS_SI_REGISTERS_INCONSISTENT" },
    { U3V_STATUS_DATA_DISCARDED, "U3V_STATUS_DATA_DISCARDED" },
    { U3V_STATUS_DATA_OVERRUN, "U3V_STATUS_DATA_OVERRUN" },
    { 0, NULL }
};

/*
 \brief Register name to address mappings
 */
static const value_string bootstrap_register_names_abrm[] =
{
    { U3V_ABRM_GENCP_VERSION, "[GenCP_Version]" },
    { U3V_ABRM_MANUFACTURER_NAME, "[Manufacturer_Name]" },
    { U3V_ABRM_MODEL_NAME, "[Model_Name]" },
    { U3V_ABRM_FAMILY_NAME, "[Family_Name]" },
    { U3V_ABRM_DEVICE_VERSION, "[Device_Version]" },
    { U3V_ABRM_MANUFACTURER_INFO, "[Manufacturer_Info]" },
    { U3V_ABRM_SERIAL_NUMBER, "[Serial_Number]" },
    { U3V_ABRM_USER_DEFINED_NAME, "[User_Defined_Name]" },
    { U3V_ABRM_DEVICE_CAPABILITY, "[Device_Capability]" },
    { U3V_ABRM_MAXIMUM_DEVICE_RESPONSE_TIME, "[Maximum_Device_Response_Time]" },
    { U3V_ABRM_MANIFEST_TABLE_ADDRESS, "[Manifest_Table_Address]" },
    { U3V_ABRM_SBRM_ADDRESS, "[SBRM_Address]" },
    { U3V_ABRM_DEVICE_CONFIGURATION, "[Device_Configuration]" },
    { U3V_ABRM_HEARTBEAT_TIMEOUT, "[Heartbeat_Timeout]" },
    { U3V_ABRM_MESSAGE_CHANNEL_CHANNEL_ID, "[Message_Channel_channel_id]" },
    { U3V_ABRM_TIMESTAMP, "[Timestamp]" },
    { U3V_ABRM_TIMESTAMP_LATCH, "[Timestamp_Latch]" },
    { U3V_ABRM_TIMESTAMP_INCREMENT, "[Timestamp_Increment]" },
    { U3V_ABRM_ACCESS_PRIVILEGE, "[Access_Privilege]" },
    { U3V_ABRM_PROTOCOL_ENDIANNESS, "[Protocol_Endianness]" },
    { U3V_ABRM_IMPLEMENTATION_ENDIANNESS, "[Implementation_Endianness]" },
    { 0, NULL }
};

static const value_string bootstrap_register_names_sbrm[] =
{
    { U3V_SBRM_U3V_VERSION, "[U3V_Version]" },
    { U3V_SBRM_U3VCP_CAPABILITY_REGISTER, "[U3VCP_Capability_Register]" },
    { U3V_SBRM_U3VCP_CONFIGURATION_REGISTER, "[U3VCP_Configuration_Register]" },
    { U3V_SBRM_MAXIMUM_COMMAND_TRANSFER_LENGTH, "[Maximum_Command_Transfer_Length]" },
    { U3V_SBRM_MAXIMUM_ACKNOWLEDGE_TRANSFER_LENGTH, "[Maximum_Acknowledge_Transfer_Length]" },
    { U3V_SBRM_NUMBER_OF_STREAM_CHANNELS, "[Number_of_Stream_Channels]" },
    { U3V_SBRM_SIRM_ADDRESS, "[SIRM_Address]" },
    { U3V_SBRM_SIRM_LENGTH, "[SIRM_Length]" },
    { U3V_SBRM_EIRM_ADDRESS, "[EIRM_Address]" },
    { U3V_SBRM_EIRM_LENGTH, "[EIRM_Length]" },
    { U3V_SBRM_IIDC2_ADDRESS, "[IIDC2_Address]" },
    { U3V_SBRM_CURRENT_SPEED, "[Current_Speed]" },
    { 0, NULL }
};

static const value_string bootstrap_register_names_sirm[] =
{
    { U3V_SIRM_SI_INFO, "[SI_Info]" },
    { U3V_SIRM_SI_CONTROL, "[SI_Control]" },
    { U3V_SIRM_SI_REQUIRED_PAYLOAD_SIZE, "[SI_Required_Payload_Size]" },
    { U3V_SIRM_SI_REQUIRED_LEADER_SIZE, "[SI_Required_Leader_Size]" },
    { U3V_SIRM_SI_REQUIRED_TRAILER_SIZE, "[SI_Required_Trailer_Size]" },
    { U3V_SIRM_SI_MAXIMUM_LEADER_SIZE, "[SI_Maximum_Leader_Size]" },
    { U3V_SIRM_SI_PAYLOAD_TRANSFER_SIZE, "[SI_Payload_Transfer_Size]" },
    { U3V_SIRM_SI_PAYLOAD_TRANSFER_COUNT, "[SI_Payload_Transfer_Count]" },
    { U3V_SIRM_SI_PAYLOAD_FINAL_TRANSFER1_SIZE, "[SI_Payload_Final_Transfer1_Size]" },
    { U3V_SIRM_SI_PAYLOAD_FINAL_TRANSFER2_SIZE, "[SI_Payload_Final_Transfer2_Size]" },
    { U3V_SIRM_SI_MAXIMUM_TRAILER_SIZE, "[SI_Maximum_Trailer_Size]" },
    { 0, NULL }
};

static const value_string bootstrap_register_names_eirm[] =
{
    { U3V_EIRM_EI_CONTROL, "[EI_Control]" },
    { U3V_EIRM_MAXIMUM_EVENT_TRANSFER_LENGTH, "[Maximum_Event_Transfer_Length]" },
    { U3V_EIRM_EVENT_TEST_CONTROL, "[Event_Test_Control]" },
    { 0, NULL }
};

static const value_string pixel_format_names[] =
{
    { PFNC_U3V_MONO1P, "Mono1p (Monochrome 1-bit packed)" },
    { PFNC_U3V_CONFIDENCE1P, "Confidence1p (Confidence 1-bit packed)" },
    { PFNC_U3V_MONO2P, "Mono2p (Monochrome 2-bit packed)" },
    { PFNC_U3V_MONO4P, "Mono4p (Monochrome 4-bit packed)" },
    { PFNC_U3V_BAYERGR4P, "BayerGR4p (Bayer Green-Red 4-bit packed)" },
    { PFNC_U3V_BAYERRG4P, "BayerRG4p (Bayer Red-Green 4-bit packed)" },
    { PFNC_U3V_BAYERGB4P, "BayerGB4p (Bayer Green-Blue 4-bit packed)" },
    { PFNC_U3V_BAYERBG4P, "BayerBG4p (Bayer Blue-Green 4-bit packed)" },
    { PFNC_U3V_MONO8, "Mono8 (Monochrome 8-bit)" },
    { PFNC_U3V_MONO8S, "Mono8s (Monochrome 8-bit signed)" },
    { PFNC_U3V_BAYERGR8, "BayerGR8 (Bayer Green-Red 8-bit)" },
    { PFNC_U3V_BAYERRG8, "BayerRG8 (Bayer Red-Green 8-bit)" },
    { PFNC_U3V_BAYERGB8, "BayerGB8 (Bayer Green-Blue 8-bit)" },
    { PFNC_U3V_BAYERBG8, "BayerBG8 (Bayer Blue-Green 8-bit)" },
    { PFNC_U3V_SCF1WBWG8, "SCF1WBWG8 (Sparse Color Filter #1 White-Blue-White-Green 8-bit)" },
    { PFNC_U3V_SCF1WGWB8, "SCF1WGWB8 (Sparse Color Filter #1 White-Green-White-Blue 8-bit)" },
    { PFNC_U3V_SCF1WGWR8, "SCF1WGWR8 (Sparse Color Filter #1 White-Green-White-Red 8-bit)" },
    { PFNC_U3V_SCF1WRWG8, "SCF1WRWG8 (Sparse Color Filter #1 White-Red-White-Green 8-bit)" },
    { PFNC_U3V_COORD3D_A8, "Coord3D_A8 (3D coordinate A 8-bit)" },
    { PFNC_U3V_COORD3D_B8, "Coord3D_B8 (3D coordinate B 8-bit)" },
    { PFNC_U3V_COORD3D_C8, "Coord3D_C8 (3D coordinate C 8-bit)" },
    { PFNC_U3V_CONFIDENCE1, "Confidence1 (Confidence 1-bit unpacked)" },
    { PFNC_U3V_CONFIDENCE8, "Confidence8 (Confidence 8-bit)" },
    { PFNC_U3V_R8, "R8 (Red 8-bit)" },
    { PFNC_U3V_G8, "G8 (Green 8-bit)" },
    { PFNC_U3V_B8, "B8 (Blue 8-bit)" },
    { PFNC_U3V_DATA8, "Data8 (Data 8-bit)" },
    { PFNC_U3V_DATA8S, "Data8s (Data 8-bit signed)" },
    { PFNC_U3V_MONO10P, "Mono10p (Monochrome 10-bit packed)" },
    { PFNC_U3V_BAYERBG10P, "BayerBG10p (Bayer Blue-Green 10-bit packed)" },
    { PFNC_U3V_BAYERGB10P, "BayerGB10p (Bayer Green-Blue 10-bit packed)" },
    { PFNC_U3V_BAYERGR10P, "BayerGR10p (Bayer Green-Red 10-bit packed)" },
    { PFNC_U3V_BAYERRG10P, "BayerRG10p (Bayer Red-Green 10-bit packed)" },
    { PFNC_U3V_SCF1WBWG10P, "SCF1WBWG10p (Sparse Color Filter #1 White-Blue-White-Green 10-bit packed)" },
    { PFNC_U3V_SCF1WGWB10P, "SCF1WGWB10p (Sparse Color Filter #1 White-Green-White-Blue 10-bit packed)" },
    { PFNC_U3V_SCF1WGWR10P, "SCF1WGWR10p (Sparse Color Filter #1 White-Green-White-Red 10-bit packed)" },
    { PFNC_U3V_SCF1WRWG10P, "SCF1WRWG10p (Sparse Color Filter #1 White-Red-White-Green 10-bit packed)" },
    { PFNC_U3V_R10_DEPRECATED, "R10_Deprecated (Deprecated because size field is wrong)" },
    { PFNC_U3V_G10_DEPRECATED, "G10_Deprecated (Deprecated because size field is wrong)" },
    { PFNC_U3V_B10_DEPRECATED, "B10_Deprecated (Deprecated because size field is wrong)" },
    { PFNC_U3V_COORD3D_A10P, "Coord3D_A10p (3D coordinate A 10-bit packed)" },
    { PFNC_U3V_COORD3D_B10P, "Coord3D_B10p (3D coordinate B 10-bit packed)" },
    { PFNC_U3V_COORD3D_C10P, "Coord3D_C10p (3D coordinate C 10-bit packed)" },
    { GVSP_MONO10PACKED, "GVSP_Mono10Packed (GigE Vision specific format, Monochrome 10-bit packed)" },
    { GVSP_MONO12PACKED, "GVSP_Mono12Packed (GigE Vision specific format, Monochrome 12-bit packed)" },
    { GVSP_BAYERGR10PACKED, "GVSP_BayerGR10Packed (GigE Vision specific format, Bayer Green-Red 10-bit packed)" },
    { GVSP_BAYERRG10PACKED, "GVSP_BayerRG10Packed (GigE Vision specific format, Bayer Red-Green 10-bit packed)" },
    { GVSP_BAYERGB10PACKED, "GVSP_BayerGB10Packed (GigE Vision specific format, Bayer Green-Blue 10-bit packed)" },
    { GVSP_BAYERBG10PACKED, "GVSP_BayerBG10Packed (GigE Vision specific format, Bayer Blue-Green 10-bit packed)" },
    { GVSP_BAYERGR12PACKED, "GVSP_BayerGR12Packed (GigE Vision specific format, Bayer Green-Red 12-bit packed)" },
    { GVSP_BAYERRG12PACKED, "GVSP_BayerRG12Packed (GigE Vision specific format, Bayer Red-Green 12-bit packed)" },
    { GVSP_BAYERGB12PACKED, "GVSP_BayerGB12Packed (GigE Vision specific format, Bayer Green-Blue 12-bit packed)" },
    { GVSP_BAYERBG12PACKED, "GVSP_BayerBG12Packed (GigE Vision specific format, Bayer Blue-Green 12-bit packed)" },
    { PFNC_U3V_MONO12P, "Mono12p (Monochrome 12-bit packed)" },
    { PFNC_U3V_BAYERBG12P, "BayerBG12p (Bayer Blue-Green 12-bit packed)" },
    { PFNC_U3V_BAYERGB12P, "BayerGB12p (Bayer Green-Blue 12-bit packed)" },
    { PFNC_U3V_BAYERGR12P, "BayerGR12p (Bayer Green-Red 12-bit packed)" },
    { PFNC_U3V_BAYERRG12P, "BayerRG12p (Bayer Red-Green 12-bit packed)" },
    { PFNC_U3V_SCF1WBWG12P, "SCF1WBWG12p (Sparse Color Filter #1 White-Blue-White-Green 12-bit packed)" },
    { PFNC_U3V_SCF1WGWB12P, "SCF1WGWB12p (Sparse Color Filter #1 White-Green-White-Blue 12-bit packed)" },
    { PFNC_U3V_SCF1WGWR12P, "SCF1WGWR12p (Sparse Color Filter #1 White-Green-White-Red 12-bit packed)" },
    { PFNC_U3V_SCF1WRWG12P, "SCF1WRWG12p (Sparse Color Filter #1 White-Red-White-Green 12-bit packed)" },
    { PFNC_U3V_R12_DEPRECATED, "R12_Deprecated (Deprecated because size field is wrong)" },
    { PFNC_U3V_G12_DEPRECATED, "G12_Deprecated (Deprecated because size field is wrong)" },
    { PFNC_U3V_B12_DEPRECATED, "B12_Deprecated (Deprecated because size field is wrong)" },
    { PFNC_U3V_COORD3D_A12P, "Coord3D_A12p (3D coordinate A 12-bit packed)" },
    { PFNC_U3V_COORD3D_B12P, "Coord3D_B12p (3D coordinate B 12-bit packed)" },
    { PFNC_U3V_COORD3D_C12P, "Coord3D_C12p (3D coordinate C 12-bit packed)" },
    { PFNC_U3V_MONO14P, "Mono14p (Monochrome 14-bit packed)" },
    { PFNC_U3V_BAYERGR14P, "BayerGR14p (Bayer Green-Red 14-bit packed)" },
    { PFNC_U3V_BAYERRG14P, "BayerRG14p (Bayer Red-Green 14-bit packed)" },
    { PFNC_U3V_BAYERGB14P, "BayerGB14p (Bayer Green-Blue 14-bit packed)" },
    { PFNC_U3V_BAYERBG14P, "BayerBG14p (Bayer Blue-Green 14-bit packed)" },
    { PFNC_U3V_MONO10, "Mono10 (Monochrome 10-bit unpacked)" },
    { PFNC_U3V_MONO12, "Mono12 (Monochrome 12-bit unpacked)" },
    { PFNC_U3V_MONO16, "Mono16 (Monochrome 16-bit)" },
    { PFNC_U3V_BAYERGR10, "BayerGR10 (Bayer Green-Red 10-bit unpacked)" },
    { PFNC_U3V_BAYERRG10, "BayerRG10 (Bayer Red-Green 10-bit unpacked)" },
    { PFNC_U3V_BAYERGB10, "BayerGB10 (Bayer Green-Blue 10-bit unpacked)" },
    { PFNC_U3V_BAYERBG10, "BayerBG10 (Bayer Blue-Green 10-bit unpacked)" },
    { PFNC_U3V_BAYERGR12, "BayerGR12 (Bayer Green-Red 12-bit unpacked)" },
    { PFNC_U3V_BAYERRG12, "BayerRG12 (Bayer Red-Green 12-bit unpacked)" },
    { PFNC_U3V_BAYERGB12, "BayerGB12 (Bayer Green-Blue 12-bit unpacked)" },
    { PFNC_U3V_BAYERBG12, "BayerBG12 (Bayer Blue-Green 12-bit unpacked)" },
    { PFNC_U3V_MONO14, "Mono14 (Monochrome 14-bit unpacked)" },
    { PFNC_U3V_BAYERGR16, "BayerGR16 (Bayer Green-Red 16-bit)" },
    { PFNC_U3V_BAYERRG16, "BayerRG16 (Bayer Red-Green 16-bit)" },
    { PFNC_U3V_BAYERGB16, "BayerGB16 (Bayer Green-Blue 16-bit)" },
    { PFNC_U3V_BAYERBG16, "BayerBG16 (Bayer Blue-Green 16-bit)" },
    { PFNC_U3V_SCF1WBWG10, "SCF1WBWG10 (Sparse Color Filter #1 White-Blue-White-Green 10-bit unpacked)" },
    { PFNC_U3V_SCF1WBWG12, "SCF1WBWG12 (Sparse Color Filter #1 White-Blue-White-Green 12-bit unpacked)" },
    { PFNC_U3V_SCF1WBWG14, "SCF1WBWG14 (Sparse Color Filter #1 White-Blue-White-Green 14-bit unpacked)" },
    { PFNC_U3V_SCF1WBWG16, "SCF1WBWG16 (Sparse Color Filter #1 White-Blue-White-Green 16-bit unpacked)" },
    { PFNC_U3V_SCF1WGWB10, "SCF1WGWB10 (Sparse Color Filter #1 White-Green-White-Blue 10-bit unpacked)" },
    { PFNC_U3V_SCF1WGWB12, "SCF1WGWB12 (Sparse Color Filter #1 White-Green-White-Blue 12-bit unpacked)" },
    { PFNC_U3V_SCF1WGWB14, "SCF1WGWB14 (Sparse Color Filter #1 White-Green-White-Blue 14-bit unpacked)" },
    { PFNC_U3V_SCF1WGWB16, "SCF1WGWB16 (Sparse Color Filter #1 White-Green-White-Blue 16-bit)" },
    { PFNC_U3V_SCF1WGWR10, "SCF1WGWR10 (Sparse Color Filter #1 White-Green-White-Red 10-bit unpacked)" },
    { PFNC_U3V_SCF1WGWR12, "SCF1WGWR12 (Sparse Color Filter #1 White-Green-White-Red 12-bit unpacked)" },
    { PFNC_U3V_SCF1WGWR14, "SCF1WGWR14 (Sparse Color Filter #1 White-Green-White-Red 14-bit unpacked)" },
    { PFNC_U3V_SCF1WGWR16, "SCF1WGWR16 (Sparse Color Filter #1 White-Green-White-Red 16-bit)" },
    { PFNC_U3V_SCF1WRWG10, "SCF1WRWG10 (Sparse Color Filter #1 White-Red-White-Green 10-bit unpacked)" },
    { PFNC_U3V_SCF1WRWG12, "SCF1WRWG12 (Sparse Color Filter #1 White-Red-White-Green 12-bit unpacked)" },
    { PFNC_U3V_SCF1WRWG14, "SCF1WRWG14 (Sparse Color Filter #1 White-Red-White-Green 14-bit unpacked)" },
    { PFNC_U3V_SCF1WRWG16, "SCF1WRWG16 (Sparse Color Filter #1 White-Red-White-Green 16-bit)" },
    { PFNC_U3V_COORD3D_A16, "Coord3D_A16 (3D coordinate A 16-bit)" },
    { PFNC_U3V_COORD3D_B16, "Coord3D_B16 (3D coordinate B 16-bit)" },
    { PFNC_U3V_COORD3D_C16, "Coord3D_C16 (3D coordinate C 16-bit)" },
    { PFNC_U3V_CONFIDENCE16, "Confidence16 (Confidence 16-bit)" },
    { PFNC_U3V_R16, "R16 (Red 16-bit)" },
    { PFNC_U3V_G16, "G16 (Green 16-bit)" },
    { PFNC_U3V_B16, "B16 (Blue 16-bit)" },
    { PFNC_U3V_BAYERGR14, "BayerGR14 (Bayer Green-Red 14-bit)" },
    { PFNC_U3V_BAYERRG14, "BayerRG14 (Bayer Red-Green 14-bit)" },
    { PFNC_U3V_BAYERGB14, "BayerGB14 (Bayer Green-Blue 14-bit)" },
    { PFNC_U3V_BAYERBG14, "BayerBG14 (Bayer Blue-Green 14-bit)" },
    { PFNC_U3V_DATA16, "Data16 (Data 16-bit)" },
    { PFNC_U3V_DATA16S, "Data16s (Data 16-bit signed)" },
    { PFNC_U3V_R10, "R10 (Red 10-bit)" },
    { PFNC_U3V_R12, "R12 (Red 12-bit)" },
    { PFNC_U3V_G10, "G10 (Green 10-bit)" },
    { PFNC_U3V_G12, "G12 (Green 12-bit)" },
    { PFNC_U3V_B10, "B10 (Blue 10-bit)" },
    { PFNC_U3V_B12, "B12 (Blue 12-bit)" },
    { PFNC_U3V_COORD3D_A32F, "Coord3D_A32f (3D coordinate A 32-bit floating point)" },
    { PFNC_U3V_COORD3D_B32F, "Coord3D_B32f (3D coordinate B 32-bit floating point)" },
    { PFNC_U3V_COORD3D_C32F, "Coord3D_C32f (3D coordinate C 32-bit floating point)" },
    { PFNC_U3V_CONFIDENCE32F, "Confidence32f (Confidence 32-bit floating point)" },
    { PFNC_U3V_MONO32, "Mono32 (Monochrome 32-bit)" },
    { PFNC_U3V_DATA32, "Data32 (Data 32-bit)" },
    { PFNC_U3V_DATA32S, "Data32s (Data 32-bit signed)" },
    { PFNC_U3V_DATA32F, "Data32f (Data 32-bit floating point)" },
    { PFNC_U3V_DATA64, "Data64 (Data 64-bit)" },
    { PFNC_U3V_DATA64S, "Data64s (Data 64-bit signed)" },
    { PFNC_U3V_DATA64F, "Data64f (Data 64-bit floating point)" },
    { PFNC_U3V_YUV411_8_UYYVYY, "YUV411_8_UYYVYY (YUV 4:1:1 8-bit)" },
    { PFNC_U3V_YCBCR411_8_CBYYCRYY, "YCbCr411_8_CbYYCrYY (YCbCr 4:1:1 8-bit)" },
    { PFNC_U3V_YCBCR601_411_8_CBYYCRYY, "YCbCr601_411_8_CbYYCrYY (YCbCr 4:1:1 8-bit BT.601)" },
    { PFNC_U3V_YCBCR709_411_8_CBYYCRYY, "YCbCr709_411_8_CbYYCrYY (YCbCr 4:1:1 8-bit BT.709)" },
    { PFNC_U3V_YCBCR411_8, "YCbCr411_8 (YCbCr 4:1:1 8-bit)" },
    { PFNC_U3V_YCBCR2020_411_8_CBYYCRYY, "YCbCr2020_411_8_CbYYCrYY (YCbCr 4:1:1 8-bit BT.2020)" },
    { PFNC_U3V_YCBCR420_8_YY_CBCR_SEMIPLANAR, "YCbCr420_8_YY_CbCr_Semiplanar (YCbCr 4:2:0 8-bit YY/CbCr Semiplanar)" },
    { PFNC_U3V_YCBCR420_8_YY_CRCB_SEMIPLANAR, "YCbCr420_8_YY_CrCb_Semiplanar (YCbCr 4:2:0 8-bit YY/CrCb Semiplanar)" },
    { PFNC_U3V_YUV422_8_UYVY, "YUV422_8_UYVY (YUV 4:2:2 8-bit)" },
    { PFNC_U3V_YUV422_8, "YUV422_8 (YUV 4:2:2 8-bit)" },
    { PFNC_U3V_RGB565P, "RGB565p (Red-Green-Blue 5/6/5-bit packed)" },
    { PFNC_U3V_BGR565P, "BGR565p (Blue-Green-Red 5/6/5-bit packed)" },
    { PFNC_U3V_YCBCR422_8, "YCbCr422_8 (YCbCr 4:2:2 8-bit)" },
    { PFNC_U3V_YCBCR601_422_8, "YCbCr601_422_8 (YCbCr 4:2:2 8-bit BT.601)" },
    { PFNC_U3V_YCBCR709_422_8, "YCbCr709_422_8 (YCbCr 4:2:2 8-bit BT.709)" },
    { PFNC_U3V_YCBCR422_8_CBYCRY, "YCbCr422_8_CbYCrY (YCbCr 4:2:2 8-bit)" },
    { PFNC_U3V_YCBCR601_422_8_CBYCRY, "YCbCr601_422_8_CbYCrY (YCbCr 4:2:2 8-bit BT.601)" },
    { PFNC_U3V_YCBCR709_422_8_CBYCRY, "YCbCr709_422_8_CbYCrY (YCbCr 4:2:2 8-bit BT.709)" },
    { PFNC_U3V_BICOLORRGBG8, "BiColorRGBG8 (Bi-color Red/Green - Blue/Green 8-bit)" },
    { PFNC_U3V_BICOLORBGRG8, "BiColorBGRG8 (Bi-color Blue/Green - Red/Green 8-bit)" },
    { PFNC_U3V_COORD3D_AC8, "Coord3D_AC8 (3D coordinate A-C 8-bit)" },
    { PFNC_U3V_COORD3D_AC8_PLANAR, "Coord3D_AC8_Planar (3D coordinate A-C 8-bit planar)" },
    { PFNC_U3V_YCBCR2020_422_8, "YCbCr2020_422_8 (YCbCr 4:2:2 8-bit BT.2020)" },
    { PFNC_U3V_YCBCR2020_422_8_CBYCRY, "YCbCr2020_422_8_CbYCrY (YCbCr 4:2:2 8-bit BT.2020)" },
    { PFNC_U3V_YCBCR422_8_YY_CBCR_SEMIPLANAR, "YCbCr422_8_YY_CbCr_Semiplanar (YCbCr 4:2:2 8-bit YY/CbCr Semiplanar)" },
    { PFNC_U3V_YCBCR422_8_YY_CRCB_SEMIPLANAR, "YCbCr422_8_YY_CrCb_Semiplanar (YCbCr 4:2:2 8-bit YY/CrCb Semiplanar)" },
    { PFNC_U3V_YCBCR422_10P, "YCbCr422_10p (YCbCr 4:2:2 10-bit packed)" },
    { PFNC_U3V_YCBCR601_422_10P, "YCbCr601_422_10p (YCbCr 4:2:2 10-bit packed BT.601)" },
    { PFNC_U3V_YCBCR709_422_10P, "YCbCr709_422_10p (YCbCr 4:2:2 10-bit packed BT.709)" },
    { PFNC_U3V_YCBCR422_10P_CBYCRY, "YCbCr422_10p_CbYCrY (YCbCr 4:2:2 10-bit packed)" },
    { PFNC_U3V_YCBCR601_422_10P_CBYCRY, "YCbCr601_422_10p_CbYCrY (YCbCr 4:2:2 10-bit packed BT.601)" },
    { PFNC_U3V_YCBCR709_422_10P_CBYCRY, "YCbCr709_422_10p_CbYCrY (YCbCr 4:2:2 10-bit packed BT.709)" },
    { PFNC_U3V_BICOLORRGBG10P, "BiColorRGBG10p (Bi-color Red/Green - Blue/Green 10-bit packed)" },
    { PFNC_U3V_BICOLORBGRG10P, "BiColorBGRG10p (Bi-color Blue/Green - Red/Green 10-bit packed)" },
    { PFNC_U3V_COORD3D_AC10P, "Coord3D_AC10p (3D coordinate A-C 10-bit packed)" },
    { PFNC_U3V_COORD3D_AC10P_PLANAR, "Coord3D_AC10p_Planar (3D coordinate A-C 10-bit packed planar)" },
    { PFNC_U3V_YCBCR2020_422_10P, "YCbCr2020_422_10p (YCbCr 4:2:2 10-bit packed BT.2020)" },
    { PFNC_U3V_YCBCR2020_422_10P_CBYCRY, "YCbCr2020_422_10p_CbYCrY (YCbCr 4:2:2 10-bit packed BT.2020)" },
    { PFNC_U3V_RGB8, "RGB8 (Red-Green-Blue 8-bit)" },
    { PFNC_U3V_BGR8, "BGR8 (Blue-Green-Red 8-bit)" },
    { PFNC_U3V_YUV8_UYV, "YUV8_UYV (YUV 4:4:4 8-bit)" },
    { PFNC_U3V_RGB8_PLANAR, "RGB8_Planar (Red-Green-Blue 8-bit planar)" },
    { PFNC_U3V_YCBCR8_CBYCR, "YCbCr8_CbYCr (YCbCr 4:4:4 8-bit)" },
    { PFNC_U3V_YCBCR601_8_CBYCR, "YCbCr601_8_CbYCr (YCbCr 4:4:4 8-bit BT.601)" },
    { PFNC_U3V_YCBCR709_8_CBYCR, "YCbCr709_8_CbYCr (YCbCr 4:4:4 8-bit BT.709)" },
    { PFNC_U3V_YCBCR8, "YCbCr8 (YCbCr 4:4:4 8-bit)" },
    { PFNC_U3V_YCBCR422_12P, "YCbCr422_12p (YCbCr 4:2:2 12-bit packed)" },
    { PFNC_U3V_YCBCR601_422_12P, "YCbCr601_422_12p (YCbCr 4:2:2 12-bit packed BT.601)" },
    { PFNC_U3V_YCBCR709_422_12P, "YCbCr709_422_12p (YCbCr 4:2:2 12-bit packed BT.709)" },
    { PFNC_U3V_YCBCR422_12P_CBYCRY, "YCbCr422_12p_CbYCrY (YCbCr 4:2:2 12-bit packed)" },
    { PFNC_U3V_YCBCR601_422_12P_CBYCRY, "YCbCr601_422_12p_CbYCrY (YCbCr 4:2:2 12-bit packed BT.601)" },
    { PFNC_U3V_YCBCR709_422_12P_CBYCRY, "YCbCr709_422_12p_CbYCrY (YCbCr 4:2:2 12-bit packed BT.709)" },
    { PFNC_U3V_BICOLORRGBG12P, "BiColorRGBG12p (Bi-color Red/Green - Blue/Green 12-bit packed)" },
    { PFNC_U3V_BICOLORBGRG12P, "BiColorBGRG12p (Bi-color Blue/Green - Red/Green 12-bit packed)" },
    { PFNC_U3V_COORD3D_ABC8, "Coord3D_ABC8 (3D coordinate A-B-C 8-bit)" },
    { PFNC_U3V_COORD3D_ABC8_PLANAR, "Coord3D_ABC8_Planar (3D coordinate A-B-C 8-bit planar)" },
    { PFNC_U3V_COORD3D_AC12P, "Coord3D_AC12p (3D coordinate A-C 12-bit packed)" },
    { PFNC_U3V_COORD3D_AC12P_PLANAR, "Coord3D_AC12p_Planar (3D coordinate A-C 12-bit packed planar)" },
    { PFNC_U3V_YCBCR2020_8_CBYCR, "YCbCr2020_8_CbYCr (YCbCr 4:4:4 8-bit BT.2020)" },
    { PFNC_U3V_YCBCR2020_422_12P, "YCbCr2020_422_12p (YCbCr 4:2:2 12-bit packed BT.2020)" },
    { PFNC_U3V_YCBCR2020_422_12P_CBYCRY, "YCbCr2020_422_12p_CbYCrY (YCbCr 4:2:2 12-bit packed BT.2020)" },
    { PFNC_U3V_BGR10P, "BGR10p (Blue-Green-Red 10-bit packed)" },
    { PFNC_U3V_RGB10P, "RGB10p (Red-Green-Blue 10-bit packed)" },
    { PFNC_U3V_YCBCR10P_CBYCR, "YCbCr10p_CbYCr (YCbCr 4:4:4 10-bit packed)" },
    { PFNC_U3V_YCBCR601_10P_CBYCR, "YCbCr601_10p_CbYCr (YCbCr 4:4:4 10-bit packed BT.601)" },
    { PFNC_U3V_YCBCR709_10P_CBYCR, "YCbCr709_10p_CbYCr (YCbCr 4:4:4 10-bit packed BT.709)" },
    { PFNC_U3V_COORD3D_ABC10P, "Coord3D_ABC10p (3D coordinate A-B-C 10-bit packed)" },
    { PFNC_U3V_COORD3D_ABC10P_PLANAR, "Coord3D_ABC10p_Planar (3D coordinate A-B-C 10-bit packed planar)" },
    { PFNC_U3V_YCBCR2020_10P_CBYCR, "YCbCr2020_10p_CbYCr (YCbCr 4:4:4 10-bit packed BT.2020)" },
    { PFNC_U3V_RGBA8, "RGBa8 (Red-Green-Blue-alpha 8-bit)" },
    { PFNC_U3V_BGRA8, "BGRa8 (Blue-Green-Red-alpha 8-bit)" },
    { GVSP_RGB10V1PACKED, "GVSP_RGB10V1Packed (GigE Vision specific format, Red-Green-Blue 10-bit packed - variant 1)" },
    { PFNC_U3V_RGB10P32, "RGB10p32 (Red-Green-Blue 10-bit packed into 32-bit)" },
    { PFNC_U3V_YCBCR422_10, "YCbCr422_10 (YCbCr 4:2:2 10-bit unpacked)" },
    { PFNC_U3V_YCBCR422_12, "YCbCr422_12 (YCbCr 4:2:2 12-bit unpacked)" },
    { PFNC_U3V_YCBCR601_422_10, "YCbCr601_422_10 (YCbCr 4:2:2 10-bit unpacked BT.601)" },
    { PFNC_U3V_YCBCR601_422_12, "YCbCr601_422_12 (YCbCr 4:2:2 12-bit unpacked BT.601)" },
    { PFNC_U3V_YCBCR709_422_10, "YCbCr709_422_10 (YCbCr 4:2:2 10-bit unpacked BT.709)" },
    { PFNC_U3V_YCBCR709_422_12, "YCbCr709_422_12 (YCbCr 4:2:2 12-bit unpacked BT.709)" },
    { PFNC_U3V_YCBCR422_10_CBYCRY, "YCbCr422_10_CbYCrY (YCbCr 4:2:2 10-bit unpacked)" },
    { PFNC_U3V_YCBCR422_12_CBYCRY, "YCbCr422_12_CbYCrY (YCbCr 4:2:2 12-bit unpacked)" },
    { PFNC_U3V_YCBCR601_422_10_CBYCRY, "YCbCr601_422_10_CbYCrY (YCbCr 4:2:2 10-bit unpacked BT.601)" },
    { PFNC_U3V_YCBCR601_422_12_CBYCRY, "YCbCr601_422_12_CbYCrY (YCbCr 4:2:2 12-bit unpacked BT.601)" },
    { PFNC_U3V_YCBCR709_422_10_CBYCRY, "YCbCr709_422_10_CbYCrY (YCbCr 4:2:2 10-bit unpacked BT.709)" },
    { PFNC_U3V_YCBCR709_422_12_CBYCRY, "YCbCr709_422_12_CbYCrY (YCbCr 4:2:2 12-bit unpacked BT.709)" },
    { PFNC_U3V_BICOLORRGBG10, "BiColorRGBG10 (Bi-color Red/Green - Blue/Green 10-bit unpacked)" },
    { PFNC_U3V_BICOLORBGRG10, "BiColorBGRG10 (Bi-color Blue/Green - Red/Green 10-bit unpacked)" },
    { PFNC_U3V_BICOLORRGBG12, "BiColorRGBG12 (Bi-color Red/Green - Blue/Green 12-bit unpacked)" },
    { PFNC_U3V_BICOLORBGRG12, "BiColorBGRG12 (Bi-color Blue/Green - Red/Green 12-bit unpacked)" },
    { PFNC_U3V_COORD3D_AC16, "Coord3D_AC16 (3D coordinate A-C 16-bit)" },
    { PFNC_U3V_COORD3D_AC16_PLANAR, "Coord3D_AC16_Planar (3D coordinate A-C 16-bit planar)" },
    { PFNC_U3V_YCBCR2020_422_10, "YCbCr2020_422_10 (YCbCr 4:2:2 10-bit unpacked BT.2020)" },
    { PFNC_U3V_YCBCR2020_422_10_CBYCRY, "YCbCr2020_422_10_CbYCrY (YCbCr 4:2:2 10-bit unpacked BT.2020)" },
    { PFNC_U3V_YCBCR2020_422_12, "YCbCr2020_422_12 (YCbCr 4:2:2 12-bit unpacked BT.2020)" },
    { PFNC_U3V_YCBCR2020_422_12_CBYCRY, "YCbCr2020_422_12_CbYCrY (YCbCr 4:2:2 12-bit unpacked BT.2020)" },
    { GVSP_RGB12V1PACKED, "GVSP_RGB12V1Packed (GigE Vision specific format, Red-Green-Blue 12-bit packed - variant 1)" },
    { PFNC_U3V_BGR12P, "BGR12p (Blue-Green-Red 12-bit packed)" },
    { PFNC_U3V_RGB12P, "RGB12p (Red-Green-Blue 12-bit packed)" },
    { PFNC_U3V_YCBCR12P_CBYCR, "YCbCr12p_CbYCr (YCbCr 4:4:4 12-bit packed)" },
    { PFNC_U3V_YCBCR601_12P_CBYCR, "YCbCr601_12p_CbYCr (YCbCr 4:4:4 12-bit packed BT.601)" },
    { PFNC_U3V_YCBCR709_12P_CBYCR, "YCbCr709_12p_CbYCr (YCbCr 4:4:4 12-bit packed BT.709)" },
    { PFNC_U3V_COORD3D_ABC12P, "Coord3D_ABC12p (3D coordinate A-B-C 12-bit packed)" },
    { PFNC_U3V_COORD3D_ABC12P_PLANAR, "Coord3D_ABC12p_Planar (3D coordinate A-B-C 12-bit packed planar)" },
    { PFNC_U3V_YCBCR2020_12P_CBYCR, "YCbCr2020_12p_CbYCr (YCbCr 4:4:4 12-bit packed BT.2020)" },
    { PFNC_U3V_BGRA10P, "BGRa10p (Blue-Green-Red-alpha 10-bit packed)" },
    { PFNC_U3V_RGBA10P, "RGBa10p (Red-Green-Blue-alpha 10-bit packed)" },
    { PFNC_U3V_RGB10, "RGB10 (Red-Green-Blue 10-bit unpacked)" },
    { PFNC_U3V_BGR10, "BGR10 (Blue-Green-Red 10-bit unpacked)" },
    { PFNC_U3V_RGB12, "RGB12 (Red-Green-Blue 12-bit unpacked)" },
    { PFNC_U3V_BGR12, "BGR12 (Blue-Green-Red 12-bit unpacked)" },
    { PFNC_U3V_RGB10_PLANAR, "RGB10_Planar (Red-Green-Blue 10-bit unpacked planar)" },
    { PFNC_U3V_RGB12_PLANAR, "RGB12_Planar (Red-Green-Blue 12-bit unpacked planar)" },
    { PFNC_U3V_RGB16_PLANAR, "RGB16_Planar (Red-Green-Blue 16-bit planar)" },
    { PFNC_U3V_RGB16, "RGB16 (Red-Green-Blue 16-bit)" },
    { PFNC_U3V_BGR14, "BGR14 (Blue-Green-Red 14-bit unpacked)" },
    { PFNC_U3V_BGR16, "BGR16 (Blue-Green-Red 16-bit)" },
    { PFNC_U3V_BGRA12P, "BGRa12p (Blue-Green-Red-alpha 12-bit packed)" },
    { PFNC_U3V_RGB14, "RGB14 (Red-Green-Blue 14-bit unpacked)" },
    { PFNC_U3V_RGBA12P, "RGBa12p (Red-Green-Blue-alpha 12-bit packed)" },
    { PFNC_U3V_YCBCR10_CBYCR, "YCbCr10_CbYCr (YCbCr 4:4:4 10-bit unpacked)" },
    { PFNC_U3V_YCBCR12_CBYCR, "YCbCr12_CbYCr (YCbCr 4:4:4 12-bit unpacked)" },
    { PFNC_U3V_YCBCR601_10_CBYCR, "YCbCr601_10_CbYCr (YCbCr 4:4:4 10-bit unpacked BT.601)" },
    { PFNC_U3V_YCBCR601_12_CBYCR, "YCbCr601_12_CbYCr (YCbCr 4:4:4 12-bit unpacked BT.601)" },
    { PFNC_U3V_YCBCR709_10_CBYCR, "YCbCr709_10_CbYCr (YCbCr 4:4:4 10-bit unpacked BT.709)" },
    { PFNC_U3V_YCBCR709_12_CBYCR, "YCbCr709_12_CbYCr (YCbCr 4:4:4 12-bit unpacked BT.709)" },
    { PFNC_U3V_COORD3D_ABC16, "Coord3D_ABC16 (3D coordinate A-B-C 16-bit)" },
    { PFNC_U3V_COORD3D_ABC16_PLANAR, "Coord3D_ABC16_Planar (3D coordinate A-B-C 16-bit planar)" },
    { PFNC_U3V_YCBCR2020_10_CBYCR, "YCbCr2020_10_CbYCr (YCbCr 4:4:4 10-bit unpacked BT.2020)" },
    { PFNC_U3V_YCBCR2020_12_CBYCR, "YCbCr2020_12_CbYCr (YCbCr 4:4:4 12-bit unpacked BT.2020)" },
    { PFNC_U3V_BGRA10, "BGRa10 (Blue-Green-Red-alpha 10-bit unpacked)" },
    { PFNC_U3V_BGRA12, "BGRa12 (Blue-Green-Red-alpha 12-bit unpacked)" },
    { PFNC_U3V_BGRA14, "BGRa14 (Blue-Green-Red-alpha 14-bit unpacked)" },
    { PFNC_U3V_BGRA16, "BGRa16 (Blue-Green-Red-alpha 16-bit)" },
    { PFNC_U3V_RGBA10, "RGBa10 (Red-Green-Blue-alpha 10-bit unpacked)" },
    { PFNC_U3V_RGBA12, "RGBa12 (Red-Green-Blue-alpha 12-bit unpacked)" },
    { PFNC_U3V_RGBA14, "RGBa14 (Red-Green-Blue-alpha 14-bit unpacked)" },
    { PFNC_U3V_RGBA16, "RGBa16 (Red-Green-Blue-alpha 16-bit)" },
    { PFNC_U3V_COORD3D_AC32F, "Coord3D_AC32f (3D coordinate A-C 32-bit floating point)" },
    { PFNC_U3V_COORD3D_AC32F_PLANAR, "Coord3D_AC32f_Planar (3D coordinate A-C 32-bit floating point planar)" },
    { PFNC_U3V_COORD3D_ABC32F, "Coord3D_ABC32f (3D coordinate A-B-C 32-bit floating point)" },
    { PFNC_U3V_COORD3D_ABC32F_PLANAR, "Coord3D_ABC32f_Planar (3D coordinate A-B-C 32-bit floating point planar)" },
    { 0, NULL }
};

static value_string_ext pixel_format_names_ext = VALUE_STRING_EXT_INIT(pixel_format_names);

static const value_string payload_type_names[] =
{
    { U3V_STREAM_PAYLOAD_IMAGE, "Image" },
    { U3V_STREAM_PAYLOAD_IMAGE_EXT_CHUNK, "Image Extended Chunk" },
    { U3V_STREAM_PAYLOAD_CHUNK, "Chunk" },
    { 0, NULL }
};

static const value_string u3v_descriptor_subtypes[] =
{
    { DESCRIPTOR_SUBTYPE_U3V_DEVICE_INFO, "U3V DEVICE INFO" },
    { 0, NULL }
};

static int * const speed_support_fields[] = {
    &hf_u3v_device_info_descriptor_bmSpeedSupport_low_speed,
    &hf_u3v_device_info_descriptor_bmSpeedSupport_full_speed,
    &hf_u3v_device_info_descriptor_bmSpeedSupport_high_speed,
    &hf_u3v_device_info_descriptor_bmSpeedSupport_super_speed,
    &hf_u3v_device_info_descriptor_bmSpeedSupport_reserved,
    NULL
};


/*
 \brief Returns a register name based on its address
 */
static const char*
get_register_name_from_address(uint64_t addr, bool* is_custom_register, u3v_conv_info_t * u3v_conv_info)
{
    const char* address_string = NULL;
    uint32_t offset_address;

    if (is_custom_register != NULL) {
        *is_custom_register = false;
    }

    /* check if this is the access to one of the base address registers */
    if ( addr < 0x10000 ) {
        offset_address = (uint32_t)addr;
        address_string = try_val_to_str(offset_address, bootstrap_register_names_abrm);
    }
    if ( u3v_conv_info && u3v_conv_info->sbrm_addr != 0 && (addr >= u3v_conv_info->sbrm_addr)) {
        offset_address = (uint32_t)( addr - u3v_conv_info->sbrm_addr);
        address_string = try_val_to_str(offset_address, bootstrap_register_names_sbrm);
    }
    if ( u3v_conv_info && u3v_conv_info->sirm_addr != 0 && (addr >= u3v_conv_info->sirm_addr)) {
        offset_address = (uint32_t)( addr - u3v_conv_info->sirm_addr);
        address_string = try_val_to_str(offset_address, bootstrap_register_names_sirm);
    }
    if ( u3v_conv_info && u3v_conv_info->eirm_addr != 0 && (addr >= u3v_conv_info->eirm_addr)) {
        offset_address = (uint32_t)( addr - u3v_conv_info->eirm_addr);
        address_string = try_val_to_str(offset_address, bootstrap_register_names_eirm);
    }

    if (!address_string) {
        address_string = wmem_strdup_printf(wmem_packet_scope(), "[Addr:0x%016" PRIX64 "]", addr);
        if (is_custom_register != NULL) {
            *is_custom_register = true;
        }
    }

    return address_string;
}

/*
 \brief Returns true if a register (identified by its address) is a known bootstrap register
 */
static int
is_known_bootstrap_register(uint64_t addr, u3v_conv_info_t * u3v_conv_info)
{
    const char* address_string = NULL;
    uint32_t offset_address;
    /* check if this is the access to one of the base address registers */
    if ( addr < 0x10000 ) {
        offset_address = (uint32_t)addr;
        address_string = try_val_to_str(offset_address, bootstrap_register_names_abrm);
    }
    if ( u3v_conv_info->sbrm_addr != 0 &&  (addr >= u3v_conv_info->sbrm_addr)) {
        offset_address = (uint32_t)( addr - u3v_conv_info->sbrm_addr);
        address_string = try_val_to_str(offset_address, bootstrap_register_names_sbrm);
    }
    if ( u3v_conv_info->sirm_addr != 0 &&  (addr >= u3v_conv_info->sirm_addr)) {
        offset_address = (uint32_t)( addr - u3v_conv_info->sirm_addr);
        address_string = try_val_to_str(offset_address, bootstrap_register_names_sirm);
    }
    if ( u3v_conv_info->eirm_addr != 0 &&  (addr >= u3v_conv_info->eirm_addr)) {
        offset_address = (uint32_t)( addr - u3v_conv_info->eirm_addr);
        address_string = try_val_to_str(offset_address, bootstrap_register_names_eirm);
    }
    return address_string != NULL;
}

/*
 \brief Identify Base Address Pointer
*/
static void
dissect_u3v_register_bases(uint64_t addr, tvbuff_t *tvb, int offset, u3v_conv_info_t * u3v_conv_info)
{
    if ( addr < 0x10000 ) {
        switch (addr) {
        case U3V_ABRM_SBRM_ADDRESS:
            u3v_conv_info->sbrm_addr = tvb_get_letoh64(tvb, offset);
            break;
        case U3V_ABRM_MANIFEST_TABLE_ADDRESS:
            u3v_conv_info->manifest_addr = tvb_get_letoh64(tvb, offset);
            break;
        }
    }
    if ( u3v_conv_info->sbrm_addr != 0 && (addr >= u3v_conv_info->sbrm_addr)) {
        addr -= u3v_conv_info->sbrm_addr;
        switch(addr) {
        case U3V_SBRM_SIRM_ADDRESS:
            u3v_conv_info->sirm_addr = tvb_get_letoh64(tvb, offset);
            break;
        case U3V_SBRM_EIRM_ADDRESS:
            u3v_conv_info->eirm_addr = tvb_get_letoh64(tvb, offset);
            break;
        case U3V_SBRM_IIDC2_ADDRESS:
            u3v_conv_info->iidc2_addr = tvb_get_letoh64(tvb, offset);
            break;
        }
    }
}

/*
 \brief Attempt to dissect a bootstrap register
*/
static int
dissect_u3v_register(uint64_t addr, proto_tree *branch, tvbuff_t *tvb, int offset, int length, u3v_conv_info_t *u3v_conv_info)
{
    int isABRM = false, isSBRM = false, isSIRM = false,isEIRM = false;
    /* check if this is the access to one of the base address registers */
    if ( addr < 0x10000 ) {
        isABRM = true;
        switch (addr) {
        case U3V_ABRM_GENCP_VERSION:
            proto_tree_add_item(branch, hf_u3v_bootstrap_GenCP_Version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_MANUFACTURER_NAME:
            if ( length <= 64 ) {
                proto_tree_add_item(branch, hf_u3v_bootstrap_Manufacturer_Name, tvb, offset, length, ENC_ASCII);
            }
            break;
        case U3V_ABRM_MODEL_NAME:
            if ( length <= 64 ) {
                proto_tree_add_item(branch, hf_u3v_bootstrap_Model_Name, tvb, offset, length, ENC_ASCII);
            }
            break;
        case U3V_ABRM_FAMILY_NAME:
            if ( length <= 64 ) {
                proto_tree_add_item(branch, hf_u3v_bootstrap_Family_Name, tvb, offset, length, ENC_ASCII);
            }
            break;
        case U3V_ABRM_DEVICE_VERSION:
            if ( length <= 64 ) {
                proto_tree_add_item(branch, hf_u3v_bootstrap_Device_Version, tvb, offset, length, ENC_ASCII);
            }
            break;
        case U3V_ABRM_MANUFACTURER_INFO:
            if ( length <= 64 ) {
                proto_tree_add_item(branch, hf_u3v_bootstrap_Manufacturer_Info, tvb, offset, length, ENC_ASCII);
            }
            break;
        case U3V_ABRM_SERIAL_NUMBER:
            if ( length <= 64 ) {
                proto_tree_add_item(branch, hf_u3v_bootstrap_Serial_Number, tvb, offset, length, ENC_ASCII);
            }
            break;
        case U3V_ABRM_USER_DEFINED_NAME:
            if ( length <= 64 ) {
                proto_tree_add_item(branch, hf_u3v_bootstrap_User_Defined_Name, tvb, offset, length, ENC_ASCII);
            }
            break;
        case U3V_ABRM_DEVICE_CAPABILITY:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Device_Capability, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_MAXIMUM_DEVICE_RESPONSE_TIME:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Maximum_Device_Response_Time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_MANIFEST_TABLE_ADDRESS:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Manifest_Table_Address, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_SBRM_ADDRESS:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SBRM_Address, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_DEVICE_CONFIGURATION:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Device_Configuration, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_HEARTBEAT_TIMEOUT:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Heartbeat_Timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_MESSAGE_CHANNEL_CHANNEL_ID:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Message_Channel_channel_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_TIMESTAMP:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_TIMESTAMP_LATCH:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Timestamp_Latch, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_TIMESTAMP_INCREMENT:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Timestamp_Increment, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_ACCESS_PRIVILEGE:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Access_Privilege, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_PROTOCOL_ENDIANNESS:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Protocol_Endianness, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_ABRM_IMPLEMENTATION_ENDIANNESS:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Implementation_Endianness, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        default:
            isABRM = false;
            break;
        }
    }
    if ( u3v_conv_info->sbrm_addr != 0 && (addr >= u3v_conv_info->sbrm_addr)) {
        uint64_t map_offset = addr - u3v_conv_info->sbrm_addr;
        isSBRM = true;
        switch(map_offset) {
        case U3V_SBRM_U3V_VERSION:
            proto_tree_add_item(branch, hf_u3v_bootstrap_U3V_Version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_U3VCP_CAPABILITY_REGISTER:
            proto_tree_add_item(branch, hf_u3v_bootstrap_U3VCP_Capability_Register, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_U3VCP_CONFIGURATION_REGISTER:
            proto_tree_add_item(branch, hf_u3v_bootstrap_U3VCP_Configuration_Register, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_MAXIMUM_COMMAND_TRANSFER_LENGTH:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Maximum_Command_Transfer_Length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_MAXIMUM_ACKNOWLEDGE_TRANSFER_LENGTH:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Maximum_Acknowledge_Transfer_Length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_NUMBER_OF_STREAM_CHANNELS:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Number_of_Stream_Channels, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_SIRM_ADDRESS:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SIRM_Address, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_SIRM_LENGTH:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SIRM_Length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_EIRM_ADDRESS:
            proto_tree_add_item(branch, hf_u3v_bootstrap_EIRM_Address, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_EIRM_LENGTH:
            proto_tree_add_item(branch, hf_u3v_bootstrap_EIRM_Length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_IIDC2_ADDRESS:
            proto_tree_add_item(branch, hf_u3v_bootstrap_IIDC2_Address, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SBRM_CURRENT_SPEED:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Current_Speed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        default:
            isSBRM = false;
            break;
        }
    }
    if ( u3v_conv_info->sirm_addr != 0 && (addr >= u3v_conv_info->sirm_addr)) {
        uint64_t map_offset = addr - u3v_conv_info->sirm_addr;
        isSIRM = true;
        switch(map_offset) {
        case U3V_SIRM_SI_INFO:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SIRM_SI_CONTROL:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Control, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SIRM_SI_REQUIRED_PAYLOAD_SIZE:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Required_Payload_Size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SIRM_SI_REQUIRED_LEADER_SIZE:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Required_Leader_Size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SIRM_SI_REQUIRED_TRAILER_SIZE:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Required_Trailer_Size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SIRM_SI_MAXIMUM_LEADER_SIZE:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Maximum_Leader_Size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SIRM_SI_PAYLOAD_TRANSFER_SIZE:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Payload_Transfer_Size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SIRM_SI_PAYLOAD_TRANSFER_COUNT:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Payload_Transfer_Count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SIRM_SI_PAYLOAD_FINAL_TRANSFER1_SIZE:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Payload_Final_Transfer1_Size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SIRM_SI_PAYLOAD_FINAL_TRANSFER2_SIZE:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Payload_Final_Transfer2_Size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_SIRM_SI_MAXIMUM_TRAILER_SIZE:
            proto_tree_add_item(branch, hf_u3v_bootstrap_SI_Maximum_Trailer_Size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        default:
            isSIRM = false;
            break;
        }
    }
    if ( u3v_conv_info->eirm_addr != 0 && (addr >= u3v_conv_info->eirm_addr)) {
        uint64_t map_offset = addr -u3v_conv_info->eirm_addr;
        isEIRM=true;
        switch(map_offset) {
        case U3V_EIRM_EI_CONTROL:
            proto_tree_add_item(branch, hf_u3v_bootstrap_EI_Control, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_EIRM_MAXIMUM_EVENT_TRANSFER_LENGTH:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Maximum_Event_Transfer_Length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case U3V_EIRM_EVENT_TEST_CONTROL:
            proto_tree_add_item(branch, hf_u3v_bootstrap_Event_Test_Control, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        default:
            isEIRM = false;
            break;
        }
    }
    if(isABRM || isSBRM || isSIRM || isEIRM ) {
        return 1;
    }
    return 0;
}

/*
 \brief DISSECT: Read memory command
*/
static void
dissect_u3v_read_mem_cmd(proto_tree *u3v_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, u3v_conv_info_t *u3v_conv_info, gencp_transaction_t * gencp_trans)
{
    uint64_t addr = 0;
    const char* address_string = NULL;
    bool is_custom_register = false;
    uint16_t count = 0;
    int offset = startoffset;
    proto_item *item = NULL;

    addr = tvb_get_letoh64(tvb, offset);
    gencp_trans->address = addr;

    address_string = get_register_name_from_address(addr, &is_custom_register, u3v_conv_info);
    count = tvb_get_letohs(tvb, offset + 10);   /* Number of bytes to read from memory */

    gencp_trans->count = count;
    if ( 0xffffffff00000000 & addr ) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (0x%016" PRIX64 " (%d) bytes) %s", addr, count, address_string);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (0x%08X (%d) bytes)", (uint32_t)addr, count);
    }


    item = proto_tree_add_item(u3v_telegram_tree, hf_u3v_scd_readmem_cmd, tvb, offset, length, ENC_NA);
    u3v_telegram_tree = proto_item_add_subtree(item, ett_u3v_payload_cmd);

    /* address */
    if (is_known_bootstrap_register(addr, u3v_conv_info)) {
        item = proto_tree_add_uint64(u3v_telegram_tree, hf_u3v_address, tvb, offset, 8, addr);
        proto_item_append_text(item, " %s", address_string);
    } else {
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_custom_memory_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    }
    offset += 8;

    /* reserved field */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    /* count */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

/*
 \brief DISSECT: Write memory command
*/
static void
dissect_u3v_write_mem_cmd(proto_tree *u3v_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, u3v_conv_info_t *u3v_conv_info, gencp_transaction_t *gencp_trans)
{
    const char* address_string = NULL;
    bool is_custom_register = false;
    uint64_t addr = 0;
    unsigned byte_count = 0;
    proto_item *item = NULL;
    unsigned offset = startoffset + 8;

    addr = tvb_get_letoh64(tvb, startoffset);
    byte_count = length - 8;
    address_string = get_register_name_from_address(addr, &is_custom_register, u3v_conv_info);

    gencp_trans->address = addr;
    gencp_trans->count = byte_count;

    /* fill in Info column in Wireshark GUI */
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s: %d bytes", address_string, byte_count);


    /* Subtree initialization for Payload Data: WRITEMEM_CMD */
    item = proto_tree_add_item(u3v_telegram_tree, hf_u3v_scd_writemem_cmd, tvb, startoffset, length, ENC_NA);
    u3v_telegram_tree = proto_item_add_subtree(item, ett_u3v_payload_cmd);

    if (is_known_bootstrap_register(addr, u3v_conv_info)) {
        item = proto_tree_add_uint64(u3v_telegram_tree, hf_u3v_address, tvb, startoffset, 8, addr);
        proto_item_append_text(item, " %s", address_string);
        dissect_u3v_register(addr, u3v_telegram_tree, tvb, offset, byte_count, u3v_conv_info);
    } else {
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_custom_memory_addr, tvb, startoffset, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_custom_memory_data, tvb, startoffset + 8, byte_count, ENC_NA);
    }

}

/*
 *  \brief DISSECT: Event command
 */
static void
dissect_u3v_event_cmd(proto_tree *u3v_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length)
{
    int32_t eventid;
    int offset = startoffset;
    proto_item *item = NULL;

    /* Get event ID */
    eventid = tvb_get_letohs(tvb, offset + 2);

    /* fill in Info column in Wireshark GUI */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[ID: 0x%04X]", eventid);


    item = proto_tree_add_item(u3v_telegram_tree, hf_u3v_scd_event_cmd, tvb, offset, length, ENC_NA);
    u3v_telegram_tree = proto_item_add_subtree(item, ett_u3v_payload_cmd);

    offset += 2;

    /* Use range to determine type of event */
    if ((eventid >= 0x0000) && (eventid <= 0x8000)) {
        /* Standard ID */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_eventcmd_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    } else if ((eventid >= 0x8001) && (eventid <= 0x8FFF)) {
        /* Error */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_eventcmd_error_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    } else if ((eventid >= 0x9000) && (eventid <= 0xFFFF)) {
        /* Device specific */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_eventcmd_device_specific_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    offset += 2;

    /* Timestamp (64 bit) associated with event */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_eventcmd_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Data */
    if (length > offset ) {
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_eventcmd_data, tvb, offset, length - 12, ENC_NA);
    }
}

/*
 \brief DISSECT: Read memory acknowledge
*/
static void
dissect_u3v_read_mem_ack(proto_tree *u3v_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, u3v_conv_info_t *u3v_conv_info, gencp_transaction_t * gencp_trans)
{
    uint64_t addr = 0;
    const char *address_string = NULL;
    bool is_custom_register = false;
    bool have_address = (0 != gencp_trans->cmd_frame);
    proto_item *item = NULL;
    unsigned offset = startoffset;
    unsigned byte_count = (length);

    addr = gencp_trans->address;
    dissect_u3v_register_bases(addr, tvb, startoffset, u3v_conv_info);
    if (have_address) {
        address_string = get_register_name_from_address(addr, &is_custom_register, u3v_conv_info);
        /* Fill in Wireshark GUI Info column */
        col_append_str(pinfo->cinfo, COL_INFO, address_string);
    }


    /* Subtree initialization for Payload Data: READMEM_ACK */
    item = proto_tree_add_item(u3v_telegram_tree, hf_u3v_scd_ack_readmem_ack, tvb, startoffset, length, ENC_NA);
    u3v_telegram_tree = proto_item_add_subtree(item, ett_u3v_payload_cmd);

    /* Bootstrap register known address */
    if (have_address) {
        item = proto_tree_add_uint64(u3v_telegram_tree, hf_u3v_address, tvb, 0,0 , addr);
        proto_item_set_generated(item);

        if (is_known_bootstrap_register(addr, u3v_conv_info)) {
            dissect_u3v_register(addr, u3v_telegram_tree, tvb, offset, byte_count, u3v_conv_info);
        } else {
            proto_tree_add_item(u3v_telegram_tree, hf_u3v_custom_memory_data, tvb, startoffset, length, ENC_NA);
        }
    }
}

/*
 \brief DISSECT: Write memory acknowledge
*/
static void
dissect_u3v_write_mem_ack(proto_tree *u3v_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, u3v_conv_info_t *u3v_conv_info , gencp_transaction_t * gencp_trans)
{
    uint64_t addr = 0;
    int offset = startoffset;
    const char *address_string = NULL;
    bool is_custom_register = false;
    bool have_address = (0 != gencp_trans->cmd_frame);
    proto_item *item = NULL;

    addr = gencp_trans->address;
    if (have_address) {
        address_string = get_register_name_from_address(addr, &is_custom_register, u3v_conv_info);

        /* Fill in Wireshark GUI Info column */
        col_append_str(pinfo->cinfo, COL_INFO, address_string);
    }

    item = proto_tree_add_item(u3v_telegram_tree, hf_u3v_scd_writemem_ack, tvb, startoffset, length, ENC_NA);
    u3v_telegram_tree = proto_item_add_subtree(item, ett_u3v_payload_cmd);

    if (have_address) {
            item = proto_tree_add_uint64(u3v_telegram_tree, hf_u3v_address, tvb, 0,0 , addr);
            proto_item_set_generated(item);
        }
    /* Number of bytes successfully written to the device register map */
    if ( length == 4 ) {

        /* reserved field */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_reserved, tvb, offset, 2, ENC_NA);
        offset += 2;

        proto_tree_add_item(u3v_telegram_tree, hf_u3v_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
}

/*
 \brief DISSECT: Pending acknowledge
*/
static void
dissect_u3v_pending_ack(proto_tree *u3v_telegram_tree, tvbuff_t *tvb, packet_info *pinfo _U_, int startoffset, int length, u3v_conv_info_t *u3v_conv_info _U_, gencp_transaction_t *gencp_trans _U_)
{
    proto_item *item = NULL;
    unsigned offset = startoffset;

    /* Fill in Wireshark GUI Info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %d ms", tvb_get_letohs(tvb, startoffset+2));

    item = proto_tree_add_item(u3v_telegram_tree, hf_u3v_ccd_pending_ack, tvb, startoffset, length, ENC_NA);
    u3v_telegram_tree = proto_item_add_subtree(item, ett_u3v_payload_cmd);

    /* reserved field */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_item(u3v_telegram_tree, hf_u3v_time_to_completion, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

/*
 \brief DISSECT: Stream Leader
*/
static void
dissect_u3v_stream_leader(proto_tree *u3v_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, usb_conv_info_t *usb_conv_info _U_)
{
    uint32_t offset = 0;
    uint32_t payload_type = 0;
    uint64_t block_id = 0;
    proto_item *item = NULL;

    /* Subtree initialization for Stream Leader */
    item = proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_leader, tvb, 0, -1, ENC_NA);
    u3v_telegram_tree = proto_item_add_subtree(item, ett_u3v_stream_leader);

    /* Add the prefix code: */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_prefix, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* reserved field */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    /* leader size */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_leader_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* block id */
    block_id = tvb_get_letoh64(tvb, offset);
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_block_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* reserved field */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    /* payload type */
    payload_type = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_payload_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Add payload type to information string */
    col_append_fstr(pinfo->cinfo, COL_INFO, "Stream Leader  [ Block ID: %" PRIu64 " , Type %s]",
                    block_id,
                    val_to_str_const(payload_type, payload_type_names, "Unknown Payload Type"));

    if (payload_type == U3V_STREAM_PAYLOAD_IMAGE ||
        payload_type == U3V_STREAM_PAYLOAD_IMAGE_EXT_CHUNK ||
        payload_type == U3V_STREAM_PAYLOAD_CHUNK) {
        /* timestamp */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    if (payload_type == U3V_STREAM_PAYLOAD_IMAGE ||
        payload_type == U3V_STREAM_PAYLOAD_IMAGE_EXT_CHUNK ) {
        /* pixel format */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_pixel_format, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* size_x */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_size_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* size_y */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_size_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* offset_x */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_offset_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* offset_x */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_offset_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* padding_x */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_padding_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        /* offset += 2; */

        /* reserved field */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_reserved, tvb, offset, 2, ENC_NA);
        /* offset += 2; */
    }
}

/*
 \brief DISSECT: Stream Trailer
*/
static void
dissect_u3v_stream_trailer(proto_tree *u3v_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, usb_conv_info_t *usb_conv_info _U_)
{
    int offset = 0;
    uint64_t block_id;
    proto_item *item = NULL;

    /* Subtree initialization for Stream Trailer */
    item = proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_trailer, tvb, 0, -1, ENC_NA);
    u3v_telegram_tree = proto_item_add_subtree(item, ett_u3v_stream_trailer);

    /* Add the prefix code: */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_prefix, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* reserved field */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    /* trailer size */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_trailer_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* block id */
    block_id = tvb_get_letoh64(tvb, offset);
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_block_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* status*/
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_status, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* reserved field */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    /* block id */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_valid_payload_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* Add payload type to information string */
    col_append_fstr(pinfo->cinfo, COL_INFO, "Stream Trailer [ Block ID: %" PRIu64 "]", block_id);

    if (tvb_captured_length_remaining(tvb,offset) >=4 ) {
        /* size_y */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_size_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    if (tvb_captured_length_remaining(tvb,offset) >=4 ) {
        /* chunk layout id */
        proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_chunk_layout_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        /* offset += 4; */
    }
}

/*
 \brief DISSECT: Stream Payload
*/
static void
dissect_u3v_stream_payload(proto_tree *u3v_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item = NULL;

    /* Subtree initialization for Stream Payload */
    item = proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_payload, tvb, 0, -1, ENC_NA);
    u3v_telegram_tree = proto_item_add_subtree(item, ett_u3v_stream_payload);

    /* Data */
    proto_tree_add_item(u3v_telegram_tree, hf_u3v_stream_data, tvb, 0, -1, ENC_NA);

    /* Add payload type to information string */
    col_append_str(pinfo->cinfo, COL_INFO, "Stream Payload");
}

/*
  \brief Point of entry of all U3V packet dissection
*/
static int
dissect_u3v(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    int offset = 0;
    proto_tree *u3v_tree = NULL, *ccd_tree_flag, *u3v_telegram_tree = NULL, *ccd_tree = NULL;
    int data_length = 0;
    int req_id = 0;
    int command_id = -1;
    int status = 0;
    unsigned prefix = 0;
    proto_item *ti = NULL;
    proto_item *item = NULL;
    const char *command_string;
    usb_conv_info_t *usb_conv_info;
    int stream_detected = false;
    int control_detected = false;
    u3v_conv_info_t *u3v_conv_info = NULL;
    gencp_transaction_t *gencp_trans = NULL;

    usb_conv_info = (usb_conv_info_t *)data;

    /* decide if this packet belongs to U3V protocol */
    u3v_conv_info = (u3v_conv_info_t *)usb_conv_info->class_data;

    if (!u3v_conv_info) {
        u3v_conv_info = wmem_new0(wmem_file_scope(), u3v_conv_info_t);
        usb_conv_info->class_data = u3v_conv_info;
        usb_conv_info->class_data_type = USB_CONV_U3V;
    } else if (usb_conv_info->class_data_type != USB_CONV_U3V) {
        /* Don't dissect if another USB type is in the conversation */
        return 0;
    }

    prefix = tvb_get_letohl(tvb, 0);
    if ((tvb_reported_length(tvb) >= 4) && ( ( U3V_CONTROL_PREFIX == prefix ) || ( U3V_EVENT_PREFIX == prefix ) ) ) {
        control_detected = true;
    }

    if (((tvb_reported_length(tvb) >= 4) && (( U3V_STREAM_LEADER_PREFIX == prefix ) || ( U3V_STREAM_TRAILER_PREFIX == prefix )))
         || (usb_conv_info->endpoint == u3v_conv_info->ep_stream)) {
        stream_detected = true;
    }

    /* initialize interface class/subclass in case no descriptors have been dissected yet */
    if ( control_detected || stream_detected){
        if ( usb_conv_info->interfaceClass  == IF_CLASS_UNKNOWN &&
             usb_conv_info->interfaceSubclass  == IF_SUBCLASS_UNKNOWN){
            usb_conv_info->interfaceClass = IF_CLASS_MISCELLANEOUS;
            usb_conv_info->interfaceSubclass = IF_SUBCLASS_MISC_U3V;
        }
    }

    if ( control_detected ) {
        /* Set the protocol column */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "U3V");

        /* Clear out stuff in the info column */
        col_clear(pinfo->cinfo, COL_INFO);

        /* Adds "USB3Vision" heading to protocol tree */
        /* We will add fields to this using the u3v_tree pointer */
        ti = proto_tree_add_item(tree, proto_u3v, tvb, offset, -1, ENC_NA);
        u3v_tree = proto_item_add_subtree(ti, ett_u3v);

        prefix = tvb_get_letohl(tvb, offset);
        command_id = tvb_get_letohs(tvb, offset+6);

        /* decode CCD ( DCI/DCE command data layout) */
        if ((prefix == U3V_CONTROL_PREFIX || prefix == U3V_EVENT_PREFIX) && ((command_id % 2) == 0)) {
            command_string = val_to_str(command_id,command_names,"Unknown Command (0x%x)");
            item = proto_tree_add_item(u3v_tree, hf_u3v_ccd_cmd, tvb, offset, 8, ENC_NA);
            proto_item_append_text(item, ": %s", command_string);
            ccd_tree = proto_item_add_subtree(item, ett_u3v_cmd);

            /* Add the prefix code: */
            proto_tree_add_item(ccd_tree, hf_u3v_gencp_prefix, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            /* Add the flags */
            item = proto_tree_add_item(ccd_tree, hf_u3v_flag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            ccd_tree_flag  = proto_item_add_subtree(item, ett_u3v_flags);
            proto_tree_add_item(ccd_tree_flag, hf_u3v_acknowledge_required_flag, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, "> %s ", command_string);
        } else if (prefix == U3V_CONTROL_PREFIX && ((command_id % 2) == 1)) {
            command_string = val_to_str(command_id,command_names,"Unknown Acknowledge (0x%x)");
            item = proto_tree_add_item(u3v_tree, hf_u3v_ccd_ack, tvb, offset, 8, ENC_NA);
            proto_item_append_text(item, ": %s", command_string);
            ccd_tree = proto_item_add_subtree(item, ett_u3v_ack);

            /* Add the prefix code: */
            proto_tree_add_item(ccd_tree, hf_u3v_gencp_prefix, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            /* Add the status: */
            proto_tree_add_item(ccd_tree, hf_u3v_status, tvb, offset, 2,ENC_LITTLE_ENDIAN);
            status = tvb_get_letohs(tvb, offset);
            offset += 2;
            col_append_fstr(pinfo->cinfo, COL_INFO, "< %s %s",
                    command_string,
                    val_to_str(status, status_names_short, "Unknown status (0x%04X)"));
        } else {
            return 0;
        }

        /* Add the command id*/
        proto_tree_add_item(ccd_tree, hf_u3v_command_id, tvb, offset, 2,ENC_LITTLE_ENDIAN);
        offset += 2;

        /* Parse the second part of both the command and the acknowledge header:
        0          15 16         31
        -------- -------- -------- --------
        |     status      |   acknowledge   |
        -------- -------- -------- --------
        |     length      |      req_id     |
        -------- -------- -------- --------

        Add the data length
        Number of valid data bytes in this message, not including this header. This
        represents the number of bytes of payload appended after this header */

        proto_tree_add_item(ccd_tree, hf_u3v_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        data_length = tvb_get_letohs(tvb, offset);
        offset += 2;

        /* Add the request ID */
        proto_tree_add_item(ccd_tree, hf_u3v_request_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        req_id = tvb_get_letohs(tvb, offset);
        offset += 2;

        /* Add telegram subtree */
        u3v_telegram_tree = proto_item_add_subtree(u3v_tree, ett_u3v);

        if (!PINFO_FD_VISITED(pinfo)) {
              if ((command_id % 2) == 0) {
                    /* This is a command */
                    gencp_trans = wmem_new0(wmem_file_scope(), gencp_transaction_t);
                    gencp_trans->cmd_frame = pinfo->fd->num;
                    gencp_trans->ack_frame = 0;
                    gencp_trans->cmd_time = pinfo->abs_ts;
                    /* add reference to current packet */
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_u3v, req_id, gencp_trans);
                    /* add reference to current */
                    u3v_conv_info->trans_info = gencp_trans;
                } else {
                    gencp_trans = u3v_conv_info->trans_info;
                    if (gencp_trans) {
                        gencp_trans->ack_frame = pinfo->fd->num;
                        /* add reference to current packet */
                        p_add_proto_data(wmem_file_scope(), pinfo, proto_u3v, req_id, gencp_trans);
                    }
                }
         } else {
            gencp_trans = (gencp_transaction_t*)p_get_proto_data(wmem_file_scope(),pinfo, proto_u3v, req_id);
         }

        if (!gencp_trans) {
            /* create a "fake" gencp_trans structure */
            gencp_trans = wmem_new0(wmem_packet_scope(), gencp_transaction_t);
            gencp_trans->cmd_frame = 0;
            gencp_trans->ack_frame = 0;
            gencp_trans->cmd_time = pinfo->abs_ts;
        }

        /* dissect depending on command? */
        switch (command_id) {
        case U3V_READMEM_CMD:
            dissect_u3v_read_mem_cmd(u3v_telegram_tree, tvb, pinfo, offset, data_length,u3v_conv_info,gencp_trans);
            break;
        case U3V_WRITEMEM_CMD:
            dissect_u3v_write_mem_cmd(u3v_telegram_tree, tvb, pinfo, offset, data_length,u3v_conv_info,gencp_trans);
            break;
        case U3V_EVENT_CMD:
            dissect_u3v_event_cmd(u3v_telegram_tree, tvb, pinfo, offset, data_length);
            break;
        case U3V_READMEM_ACK:
            if ( U3V_STATUS_GENCP_SUCCESS == status ) {
                dissect_u3v_read_mem_ack(u3v_telegram_tree, tvb, pinfo, offset, data_length,u3v_conv_info,gencp_trans);
            }
            break;
        case U3V_WRITEMEM_ACK:
            dissect_u3v_write_mem_ack(u3v_telegram_tree, tvb, pinfo, offset, data_length, u3v_conv_info,gencp_trans);
            break;
        case U3V_PENDING_ACK:
            dissect_u3v_pending_ack(u3v_telegram_tree, tvb, pinfo, offset, data_length, u3v_conv_info,gencp_trans);
            break;
        default:
            proto_tree_add_item(u3v_telegram_tree, hf_u3v_payloaddata, tvb, offset, data_length, ENC_NA);
            break;
        }
        return data_length + 12;
    } else if ( stream_detected ) {
        /* this is streaming data */

        /* init this stream configuration */
        u3v_conv_info = (u3v_conv_info_t *)usb_conv_info->class_data;
        u3v_conv_info->ep_stream = usb_conv_info->endpoint;

        /* Set the protocol column */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "U3V");

        /* Clear out stuff in the info column */
        col_clear(pinfo->cinfo, COL_INFO);

        /* Adds "USB3Vision" heading to protocol tree */
        /* We will add fields to this using the u3v_tree pointer */
        ti = proto_tree_add_item(tree, proto_u3v, tvb, offset, -1, ENC_NA);
        u3v_tree = proto_item_add_subtree(ti, ett_u3v);

        if(tvb_captured_length(tvb) >=4) {
            prefix = tvb_get_letohl(tvb, offset);
            switch (prefix) {
            case U3V_STREAM_LEADER_PREFIX:
                dissect_u3v_stream_leader(u3v_tree, tvb, pinfo, usb_conv_info);
                break;
            case U3V_STREAM_TRAILER_PREFIX:
                dissect_u3v_stream_trailer(u3v_tree, tvb, pinfo, usb_conv_info);
                break;
            default:
                dissect_u3v_stream_payload(u3v_tree, tvb, pinfo, usb_conv_info);
                break;
            }
        }
        return tvb_captured_length(tvb);
    }
    return 0;
}


static bool
dissect_u3v_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    uint32_t prefix;
    usb_conv_info_t *usb_conv_info;

    /* all control and meta data packets of U3V contain at least the prefix */
    if (tvb_reported_length(tvb) < 4)
        return false;
    prefix = tvb_get_letohl(tvb, 0);

    /* check if stream endpoint has been already set up for this conversation */
    usb_conv_info = (usb_conv_info_t *)data;
    if (!usb_conv_info)
        return false;

    /* either right prefix or the endpoint of the interface descriptor
       set the correct class and subclass */
    if ((U3V_STREAM_LEADER_PREFIX  == prefix) || (U3V_STREAM_TRAILER_PREFIX == prefix) ||
        (U3V_CONTROL_PREFIX        == prefix) || (U3V_EVENT_PREFIX          == prefix) ||
        ((usb_conv_info->interfaceClass == IF_CLASS_MISCELLANEOUS &&
          usb_conv_info->interfaceSubclass == IF_SUBCLASS_MISC_U3V))) {
        dissect_u3v(tvb, pinfo, tree, data);
        return true;
    }

    return false;
}

static int
dissect_u3v_descriptors(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    uint8_t         type;
    int             offset = 0;
    proto_item *    ti;
    proto_tree *    sub_tree;
    uint32_t        version;


    /* The descriptor must at least have a length and type field. */
    if (tvb_reported_length(tvb) < 2) {
        return 0;
    }

    /* skip len */
    type = tvb_get_uint8(tvb, 1);

    /* Check for U3V device info descriptor. */
    if (type != DESCRIPTOR_TYPE_U3V_INTERFACE) {
        return 0;
    }

    ti = proto_tree_add_item(tree, hf_u3v_device_info_descriptor, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_u3v_device_info_descriptor);

    /* bLength */
    proto_tree_add_item(tree, hf_u3v_device_info_descriptor_bLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bDescriptorType */
    ti = proto_tree_add_item(tree, hf_u3v_device_info_descriptor_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(ti, " (U3V INTERFACE)");
    offset++;

    /* bDescriptorSubtype */
    proto_tree_add_item(tree, hf_u3v_device_info_descriptor_bDescriptorSubtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bGenCPVersion */
    if (!tvb_bytes_exist(tvb, offset, 4)) {
        /* Version not completely in buffer -> break dissection here. */
        return offset;
    }
    version = tvb_get_letohl(tvb, offset);
    ti = proto_tree_add_item(tree, hf_u3v_device_info_descriptor_bGenCPVersion, tvb, offset, 4, ENC_NA);
    proto_item_append_text(ti, ": %u.%u", version >> 16, version & 0xFFFF);
    sub_tree = proto_item_add_subtree(ti, ett_u3v_device_info_descriptor_gencp_version);
    proto_tree_add_item(sub_tree, hf_u3v_device_info_descriptor_bGenCPVersion_minor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(sub_tree, hf_u3v_device_info_descriptor_bGenCPVersion_major, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* bU3VVersion */
    if (!tvb_bytes_exist(tvb, offset, 4)) {
        /* Version not completely in buffer -> break dissection here. */
        return offset;
    }
    version = tvb_get_letohl(tvb, offset);
    ti = proto_tree_add_item(tree, hf_u3v_device_info_descriptor_bU3VVersion, tvb, offset, 4, ENC_NA);
    proto_item_append_text(ti, ": %u.%u", version >> 16, version & 0xFFFF);
    sub_tree = proto_item_add_subtree(ti, ett_u3v_device_info_descriptor_u3v_version);
    proto_tree_add_item(sub_tree, hf_u3v_device_info_descriptor_bU3VVersion_minor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(sub_tree, hf_u3v_device_info_descriptor_bU3VVersion_major, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* iDeviceGUID */
    proto_tree_add_item(tree, hf_u3v_device_info_descriptor_iDeviceGUID, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iVendorName */
    proto_tree_add_item(tree, hf_u3v_device_info_descriptor_iVendorName, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iModelName */
    proto_tree_add_item(tree, hf_u3v_device_info_descriptor_iModelName, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iFamilyName */
    proto_tree_add_item(tree, hf_u3v_device_info_descriptor_iFamilyName, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iDeviceVersion */
    proto_tree_add_item(tree, hf_u3v_device_info_descriptor_iDeviceVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iManufacturerInfo */
    proto_tree_add_item(tree, hf_u3v_device_info_descriptor_iManufacturerInfo, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iSerialNumber */
    proto_tree_add_item(tree, hf_u3v_device_info_descriptor_iSerialNumber, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iUserDefinedName */
    proto_tree_add_item(tree, hf_u3v_device_info_descriptor_iUserDefinedName, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bmSpeedSupport */
    proto_tree_add_bitmask(tree, tvb, offset, hf_u3v_device_info_descriptor_bmSpeedSupport,
                           ett_u3v_device_info_descriptor_speed_support, speed_support_fields, ENC_LITTLE_ENDIAN);

    offset++;

    return offset;
}

/*
 \brief Structures for register dissection
 */
static hf_register_info hf[] =
{
    /* Common U3V data */
    { &hf_u3v_gencp_prefix,
    { "Prefix", "u3v.gencp.prefix",
    FT_UINT32, BASE_HEX, NULL, 0x0,
    "U3V GenCP Prefix", HFILL
    } },

    { &hf_u3v_flag,
    { "Flags", "u3v.gencp.flags",
    FT_UINT16, BASE_HEX, NULL, 0x0,
    "U3V Flags", HFILL
    } },

    { &hf_u3v_acknowledge_required_flag,
    { "Acknowledge Required", "u3v.gencp.flag.acq_required",
    FT_BOOLEAN, 16, NULL, 0x4000,
    "U3V Acknowledge Required", HFILL
    } },

    { &hf_u3v_command_id,
    { "Command", "u3v.gencp.command_id",
    FT_UINT16, BASE_HEX, VALS( command_names ), 0x0,
    "U3V Command", HFILL
    } },

    { &hf_u3v_length,
    { "Payload Length", "u3v.gencp.payloadlength",
    FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
    "U3V Payload Length", HFILL
    } },

    { &hf_u3v_request_id,
    { "Request ID", "u3v.gencp.req_id",
    FT_UINT16, BASE_HEX, NULL, 0x0,
    "U3V Request ID", HFILL
    } },

    { &hf_u3v_payloaddata,
    { "Payload Data", "u3v.gencp.payloaddata",
    FT_BYTES, BASE_NONE, NULL, 0x0,
    "U3V Payload", HFILL
    } },

    { &hf_u3v_status,
    { "Status", "u3v.gencp.status",
    FT_UINT16, BASE_HEX, VALS( status_names ), 0x0,
    "U3V Status", HFILL
    } },

    /* Read memory */
    { &hf_u3v_address,
    { "Address", "u3v.gencp.address",
    FT_UINT64, BASE_HEX, NULL, 0x0,
    "U3V Address", HFILL } },

    { &hf_u3v_count,
    { "Count", "u3v.gencp.count",
    FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
    "U3V Count", HFILL
    } },

    /* Event */

    { &hf_u3v_eventcmd_id,
    { "ID", "u3v.cmd.event.id",
    FT_UINT16, BASE_HEX_DEC, VALS( event_id_names ), 0x0,
    "U3V Event ID", HFILL
    } },

    { &hf_u3v_eventcmd_error_id,
    { "Error ID", "u3v.cmd.event.errorid",
    FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
    "U3V Event Error ID", HFILL
    } },

    { &hf_u3v_eventcmd_device_specific_id,
    { "Device Specific ID", "u3v.cmd.event.devicespecificid",
    FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
    "U3V Event Device Specific ID", HFILL
    } },

    { &hf_u3v_eventcmd_timestamp,
    { "Timestamp", "u3v.cmd.event.timestamp",
    FT_UINT64, BASE_HEX_DEC, NULL, 0x0,
    "U3V Event Timestamp", HFILL
    } },

    { &hf_u3v_eventcmd_data,
    { "Data", "u3v.cmd.event.data",
    FT_BYTES, BASE_NONE, NULL, 0x0,
    "U3V Event Data", HFILL
    } },

    /* Pending acknowledge */
    { &hf_u3v_time_to_completion,
    { "Time to completion", "u3v.gencp.timetocompletion",
    FT_UINT16, BASE_DEC, NULL, 0x0,
    "U3V Time to completion [ms]", HFILL
    } },

    { &hf_u3v_reserved,
    { "Reserved", "u3v.reserved",
    FT_BYTES, BASE_NONE, NULL, 0,
    NULL, HFILL
    } },

    /* Custom */
    { &hf_u3v_custom_memory_addr,
    { "Custom Memory Address", "u3v.gencp.custom_addr",
    FT_UINT64, BASE_HEX, NULL, 0x0,
    "U3V Custom Memory Address", HFILL
    } },

    { &hf_u3v_custom_memory_data,
    { "Custom Memory Data", "u3v.gencp.custom_data",
    FT_BYTES, BASE_NONE, NULL, 0x0,
    "U3V Custom Memory Data", HFILL
    } },

    /* Bootstrap Defines */
    { &hf_u3v_bootstrap_GenCP_Version,
    { "GenCP Version", "u3v.bootstrap.GenCP_Version",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Complying GenCP Version", HFILL
    } },

    { &hf_u3v_bootstrap_Manufacturer_Name,
    { "Manufacturer Name", "u3v.bootstrap.Manufacturer_Name",
    FT_STRING, BASE_NONE, NULL, 0x0,
    "String containing the self-describing name of the manufacturer", HFILL
    } },

    { &hf_u3v_bootstrap_Model_Name,
    { "Model Name", "u3v.bootstrap.Model_Name",
    FT_STRING, BASE_NONE, NULL, 0x0,
    "String containing the self-describing name of the device model", HFILL
    } },

    { &hf_u3v_bootstrap_Family_Name,
    { "Family Name", "u3v.bootstrap.Family_Name",
    FT_STRING, BASE_NONE, NULL, 0x0,
    "String containing the name of the family of this device", HFILL
    } },

    { &hf_u3v_bootstrap_Device_Version,
    { "Device Version", "u3v.bootstrap.Device_Version",
    FT_STRING, BASE_NONE, NULL, 0x0,
    "String containing the version of this device", HFILL
    } },

    { &hf_u3v_bootstrap_Manufacturer_Info,
    { "Manufacturer Information", "u3v.bootstrap.Manufacturer_Info",
    FT_STRING, BASE_NONE, NULL, 0x0,
    "String containing additional manufacturer information", HFILL
    } },

    { &hf_u3v_bootstrap_Serial_Number,
    { "Serial Number", "u3v.bootstrap.Serial_Number",
    FT_STRING, BASE_NONE, NULL, 0x0,
    "String containing the serial number of the device", HFILL
    } },

    { &hf_u3v_bootstrap_User_Defined_Name,
    { "User Defined Name", "u3v.bootstrap.User_Defined_Name",
    FT_STRING, BASE_NONE, NULL, 0x0,
    "String containing the user defined name of the device", HFILL
    } },

    { &hf_u3v_bootstrap_Device_Capability,
    { "Device Capabilities", "u3v.bootstrap.Device_Capability",
    FT_UINT64, BASE_DEC, NULL, 0x0,
    "Bit field describing the device?s capabilities", HFILL
    } },

    { &hf_u3v_bootstrap_Maximum_Device_Response_Time,
    { "Device Maximum response time in ms", "u3v.bootstrap.Maximum_Device_Response_Time",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    NULL, HFILL
    } },

    { &hf_u3v_bootstrap_Manifest_Table_Address,
    { "Pointer to the Manifest Table", "u3v.bootstrap.Manifest_Table_Address",
    FT_UINT64, BASE_HEX, NULL, 0x0,
    NULL, HFILL
    } },

    { &hf_u3v_bootstrap_SBRM_Address,
    { "Pointer to the SBRM", "u3v.bootstrap.SBRM_Address",
    FT_UINT64, BASE_HEX, NULL, 0x0,
    "Pointer to the Technology Specific Bootstrap Register Map", HFILL
    } },

    { &hf_u3v_bootstrap_Device_Configuration,
    { "Device Configuration", "u3v.bootstrap.Device_Configuration",
    FT_UINT64, BASE_DEC, NULL, 0x0,
    "Bit field describing the device?s configuration", HFILL
    } },

    { &hf_u3v_bootstrap_Heartbeat_Timeout,
    { "Heartbeat Timeout in ms.", "u3v.bootstrap.Heartbeat_Timeout",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Heartbeat Timeout in ms. Not used for these specification.", HFILL
    } },

    { &hf_u3v_bootstrap_Message_Channel_channel_id,
    { "Message channel id", "u3v.bootstrap.Message_Channel_channel_id",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "channel_id use for the message channel", HFILL
    } },

    { &hf_u3v_bootstrap_Timestamp,
    { "Timestamp", "u3v.bootstrap.Timestamp",
    FT_UINT64, BASE_DEC, NULL, 0x0,
    "Current device time in ns", HFILL
    } },

    { &hf_u3v_bootstrap_Timestamp_Latch,
    { "Latch Timestamp", "u3v.bootstrap.Timestamp_Latch",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    NULL, HFILL
    } },

    { &hf_u3v_bootstrap_Timestamp_Increment,
    { "Timestamp Increment Value", "u3v.bootstrap.Timestamp_Increment",
    FT_UINT64, BASE_DEC, NULL, 0x0,
    NULL, HFILL
    } },

    { &hf_u3v_bootstrap_Access_Privilege,
    { "Access Privilege.", "u3v.bootstrap.Access_Privilege",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Access Privilege. Not used for these specification.", HFILL
    } },

    { &hf_u3v_bootstrap_Protocol_Endianness,
    { "Protocol Endianness", "u3v.bootstrap.Protocol_Endianness",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Endianness of protocol fields and bootstrap registers. Only little endian is supported by these specification.", HFILL
    } },

    { &hf_u3v_bootstrap_Implementation_Endianness,
    { "Device Endianness", "u3v.bootstrap.Implementation_Endianness",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Endianness of device implementation registers.  Only little endian is supported by these specification.", HFILL
    } },

    { &hf_u3v_bootstrap_U3V_Version,
    { "TL Version", "u3v.bootstrap.U3V_Version",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Version of the TL specification", HFILL
    } },

    { &hf_u3v_bootstrap_U3VCP_Capability_Register,
    { "Control channel capabilities", "u3v.bootstrap.U3VCP_Capability_Register",
    FT_UINT64, BASE_DEC, NULL, 0x0,
    "Indicates additional features on the control channel", HFILL
    } },

    { &hf_u3v_bootstrap_U3VCP_Configuration_Register,
    { "Control channel configuration", "u3v.bootstrap.U3VCP_Configuration_Register",
    FT_UINT64, BASE_DEC, NULL, 0x0,
    "Configures additional features on the control channel", HFILL
    } },

    { &hf_u3v_bootstrap_Maximum_Command_Transfer_Length,
    { "Maximum Command Transfer Length", "u3v.bootstrap.Maximum_Command_Transfer_Length",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Specifies the maximum supported command transfer length of the device", HFILL
    } },

    { &hf_u3v_bootstrap_Maximum_Acknowledge_Transfer_Length,
    { "Maximum Acknowledge Transfer Length", "u3v.bootstrap.Maximum_Acknowledge_Transfer_Length",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Specifies the maximum supported acknowledge transfer length of the device", HFILL
    } },

    { &hf_u3v_bootstrap_Number_of_Stream_Channels,
    { "Number of Stream Channels", "u3v.bootstrap.Number_of_Stream_Channels",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Number of Stream Channels and its corresponding Streaming Interface Register Maps (SIRM)", HFILL
    } },

    { &hf_u3v_bootstrap_SIRM_Address,
    { "Pointer to the first SIRM", "u3v.bootstrap.SIRM_Address",
    FT_UINT64, BASE_HEX, NULL, 0x0,
    "Pointer to the first Streaming Interface Register Map.", HFILL
    } },

    { &hf_u3v_bootstrap_SIRM_Length,
    { "Length of SIRM", "u3v.bootstrap.SIRM_Length",
    FT_UINT32, BASE_HEX, NULL, 0x0,
    "Specifies the length of each SIRM", HFILL
    } },

    { &hf_u3v_bootstrap_EIRM_Address,
    { "Pointer to the EIRM", "u3v.bootstrap.EIRM_Address",
    FT_UINT64, BASE_HEX, NULL, 0x0,
    "Pointer to the Event Interface Register Map.", HFILL
    } },

    { &hf_u3v_bootstrap_EIRM_Length,
    { "Length of EIRM", "u3v.bootstrap.EIRM_Length",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Specifies the length of the EIRM", HFILL
    } },

    { &hf_u3v_bootstrap_IIDC2_Address,
    { "Pointer to the IIDC2", "u3v.bootstrap.IIDC2_Address",
    FT_UINT64, BASE_HEX, NULL, 0x0,
    "Pointer to the IIDC2 register set.", HFILL
    } },

    { &hf_u3v_bootstrap_Current_Speed,
    { "LinkSpeed", "u3v.bootstrap.Current_Speed",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Specifies the current speed of the USB link.", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Info,
    { "Stream Info", "u3v.bootstrap.SI_Info",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Device reports information about stream interface", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Control,
    { "Stream Control", "u3v.bootstrap.SI_Control",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Stream interface Operation Control", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Required_Payload_Size,
    { "Stream Max Required Payload Size", "u3v.bootstrap.SI_Required_Payload_Size",
    FT_UINT64, BASE_DEC, NULL, 0x0,
    "Device reports maximum payload size with current settings", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Required_Leader_Size,
    { "Stream Max Required Leader Size", "u3v.bootstrap.SI_Required_Leader_Size",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Device reports maximum leader  size it will use", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Required_Trailer_Size,
    { "Stream Max Required Trailer Size", "u3v.bootstrap.SI_Required_Trailer_Size",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Device reports maximum trailer  size it will use", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Maximum_Leader_Size,
    { "Stream Max leader size", "u3v.bootstrap.SI_Maximum_Leader_Size",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Maximum leader size", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Payload_Transfer_Size,
    { "Stream transfer size", "u3v.bootstrap.SI_Payload_Transfer_Size",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Expected Size of a single Payload Transfer", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Payload_Transfer_Count,
    { "Stream transfer count", "u3v.bootstrap.SI_Payload_Transfer_Count",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Expected Number of Payload Transfers", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Payload_Final_Transfer1_Size,
    { "Stream final transfer 1 size", "u3v.bootstrap.SI_Payload_Final_Transfer1_Size",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Size of first final Payload transfer", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Payload_Final_Transfer2_Size,
    { "Stream final transfer 2 size", "u3v.bootstrap.SI_Payload_Final_Transfer2_Size",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Size of second final Payload transfer", HFILL
    } },

    { &hf_u3v_bootstrap_SI_Maximum_Trailer_Size,
    { "Stream Max trailer size", "u3v.bootstrap.SI_Maximum_Trailer_Size",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Maximum trailer size", HFILL
    } },

    { &hf_u3v_bootstrap_EI_Control,
    { "Event Interface Control", "u3v.bootstrap.EI_Control",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Event Interface Control Register", HFILL
    } },

    { &hf_u3v_bootstrap_Maximum_Event_Transfer_Length,
    { "Event max Transfer size", "u3v.bootstrap.Maximum_Event_Transfer_Length",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Specifies the maximum supported event command transfer length of the device.", HFILL
    } },

    { &hf_u3v_bootstrap_Event_Test_Control,
    { "Event test event control", "u3v.bootstrap.Event_Test_Control",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "Control the generation of test events.", HFILL
    } },

    { &hf_u3v_stream_prefix,
    { "Stream Prefix", "u3v.stream.prefix",
    FT_UINT32, BASE_HEX, NULL, 0,
    "U3V stream prefix", HFILL
    } },

    { &hf_u3v_stream_reserved,
    { "Reserved", "u3v.stream.reserved",
    FT_BYTES, BASE_NONE, NULL, 0,
    NULL, HFILL
    } },

    { &hf_u3v_stream_leader_size,
    { "Leader Size", "u3v.stream.leader_size",
    FT_UINT16, BASE_DEC, NULL, 0x0,
    "U3V stream leader size", HFILL
    } },

    { &hf_u3v_stream_trailer_size,
    { "Trailer Size", "u3v.stream.trailer_size",
    FT_UINT16, BASE_DEC, NULL, 0x0,
    "U3V stream trailer size", HFILL
    } },

    { &hf_u3v_stream_block_id,
    { "Block ID", "u3v.stream.block_id",
    FT_UINT64, BASE_DEC, NULL, 0x0,
    "U3V stream block id", HFILL
    } },

    { &hf_u3v_stream_payload_type,
    { "Payload Type", "u3v.stream.payload_type",
    FT_UINT16, BASE_HEX, VALS( payload_type_names ), 0x0,
    "U3V Payload Type", HFILL
    } },

    { &hf_u3v_stream_timestamp,
    { "Timestamp", "u3v.stream.timestamp",
    FT_UINT64, BASE_HEX_DEC, NULL, 0x0,
    "U3V Stream Timestamp", HFILL
    } },

    { &hf_u3v_stream_pixel_format,
    { "Pixel Format", "u3v.stream.pixel_format",
    FT_UINT32, BASE_HEX|BASE_EXT_STRING, VALS_EXT_PTR( &pixel_format_names_ext ), 0x0,
    "U3V Stream Pixel Format", HFILL
    } },

    { &hf_u3v_stream_size_x,
    { "Size X", "u3v.stream.sizex",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "U3V Stream Size X", HFILL
    } },

    { &hf_u3v_stream_size_y,
    { "Size Y", "u3v.stream.sizey",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "U3V Stream Size Y", HFILL
    } },

    { &hf_u3v_stream_offset_x,
    { "Offset X", "u3v.stream.offsetx",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "U3V Stream Offset X", HFILL
    } },

    { &hf_u3v_stream_offset_y,
    { "Offset Y", "u3v.stream.offsety",
    FT_UINT32, BASE_DEC, NULL, 0x0,
    "U3V Stream Offset Y", HFILL
    } },

    { &hf_u3v_stream_padding_x,
    { "Padding X", "u3v.stream.paddingx",
    FT_UINT16, BASE_DEC, NULL, 0x0,
    "U3V Stream Padding X", HFILL
    } },

    { &hf_u3v_stream_chunk_layout_id,
    { "Chunk Layout ID", "u3v.stream.chunk_layout_id",
    FT_UINT32, BASE_HEX, NULL, 0x0,
    "U3V Stream Chunk Layout ID", HFILL
    } },

    { &hf_u3v_stream_valid_payload_size,
    { "Valid Payload Size", "u3v.stream.valid_payload_size",
    FT_UINT64, BASE_HEX, NULL, 0x0,
    "U3V Stream Valid Payload Size", HFILL
    } },

    { &hf_u3v_stream_status,
    { "Status", "u3v.stream.status",
    FT_UINT16, BASE_HEX, VALS( status_names ), 0x0,
    "U3V Stream Status", HFILL
    } },

    { &hf_u3v_stream_data,
    { "Payload Data", "u3v.stream.data",
    FT_BYTES, BASE_NONE, NULL, 0x0,
    "U3V Stream Payload Data", HFILL
    } },

    /* U3V device info descriptor */
    { &hf_u3v_device_info_descriptor_bLength,
    { "bLength", "u3v.device_info.bLength",
    FT_UINT8, BASE_DEC, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bDescriptorType,
    { "bDescriptorType", "u3v.device_info.bDescriptorType",
    FT_UINT8, BASE_HEX, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bDescriptorSubtype,
    { "bDescriptorSubtype", "u3v.device_info.bDescriptorSubtype",
    FT_UINT8, BASE_HEX, VALS( u3v_descriptor_subtypes ), 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bGenCPVersion,
    { "bGenCPVersion", "u3v.device_info.bGenCPVersion",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bGenCPVersion_minor,
    { "Minor Version", "u3v.device_info.bGenCPVersion.minor",
    FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bGenCPVersion_major,
    { "Major Version", "u3v.device_info.bGenCPVersion.major",
    FT_UINT32, BASE_DEC, NULL, 0xFFFF0000,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bU3VVersion,
    { "bU3VVersion", "u3v.device_info.bU3VVersion",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bU3VVersion_minor,
    { "Minor Version", "u3v.device_info.bU3VVersion.minor",
    FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bU3VVersion_major,
    { "Major Version", "u3v.device_info.bU3VVersion.major",
    FT_UINT32, BASE_DEC, NULL, 0xFFFF0000,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_iDeviceGUID,
    { "iDeviceGUID", "u3v.device_info.iDeviceGUID",
    FT_UINT8, BASE_DEC, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_iVendorName,
    { "iVendorName", "u3v.device_info.iVendorName",
    FT_UINT8, BASE_DEC, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_iModelName,
    { "iModelName", "u3v.device_info.iModelName",
    FT_UINT8, BASE_DEC, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_iFamilyName,
    { "iFamilyName", "u3v.device_info.iFamilyName",
    FT_UINT8, BASE_DEC, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_iDeviceVersion,
    { "iDeviceVersion", "u3v.device_info.iDeviceVersion",
    FT_UINT8, BASE_DEC, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_iManufacturerInfo,
    { "iManufacturerInfo", "u3v.device_info.iManufacturerInfo",
    FT_UINT8, BASE_DEC, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_iSerialNumber,
    { "iSerialNumber", "u3v.device_info.iSerialNumber",
    FT_UINT8, BASE_DEC, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_iUserDefinedName,
    { "iUserDefinedName", "u3v.device_info.iUserDefinedName",
    FT_UINT8, BASE_DEC, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bmSpeedSupport,
    { "bmSpeedSupport", "u3v.device_info.bmSpeedSupport",
    FT_UINT8, BASE_HEX, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bmSpeedSupport_low_speed,
    { "Low-Speed", "u3v.device_info.bmSpeedSupport.lowSpeed",
    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bmSpeedSupport_full_speed,
    { "Full-Speed", "u3v.device_info.bmSpeedSupport.fullSpeed",
    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bmSpeedSupport_high_speed,
    { "High-Speed", "u3v.device_info.bmSpeedSupport.highSpeed",
    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bmSpeedSupport_super_speed,
    { "Super-Speed", "u3v.device_info.bmSpeedSupport.superSpeed",
    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor_bmSpeedSupport_reserved,
    { "Reserved", "u3v.device_info.bmSpeedSupport.reserved",
    FT_UINT8, BASE_HEX, NULL, 0xF0,
    NULL, HFILL } },

    { &hf_u3v_scd_readmem_cmd,
    { "SCD: READMEM_CMD", "u3v.scd_readmem_cmd",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_scd_writemem_cmd,
    { "SCD: WRITEMEM_CMD", "u3v.scd_writemem_cmd",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_scd_event_cmd,
    { "SCD: EVENT_CMD", "u3v.scd_event_cmd",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_scd_ack_readmem_ack,
    { "SCD: READMEM_ACK", "u3v.scd_ack_readmem_ack",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_scd_writemem_ack,
    { "SCD: WRITEMEM_ACK", "u3v.scd_writemem_ack",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_ccd_pending_ack,
    { "CCD: PENDING_ACK", "u3v.ccd_pending_ack",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_stream_leader,
    { "Stream: Leader", "u3v.stream_leader",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_stream_trailer,
    { "Stream: Trailer", "u3v.stream_trailer",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_stream_payload,
    { "Stream: Payload", "u3v.stream_payload",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_ccd_cmd,
    { "CCD", "u3v.ccd_cmd",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_ccd_ack,
    { "CCD", "u3v.ccd_ack",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } },

    { &hf_u3v_device_info_descriptor,
    { "U3V DEVICE INFO DESCRIPTOR", "u3v.device_info_descriptor",
    FT_NONE, BASE_NONE, NULL, 0x0,
    NULL, HFILL } }
};

void
proto_register_u3v(void)
{
    static int *ett[] = {
        &ett_u3v,
        &ett_u3v_cmd,
        &ett_u3v_flags,
        &ett_u3v_ack,
        &ett_u3v_payload_cmd,
        &ett_u3v_payload_ack,
        &ett_u3v_payload_ack_subtree,
        &ett_u3v_payload_cmd_subtree,
        &ett_u3v_bootstrap_fields,
        &ett_u3v_stream_leader,
        &ett_u3v_stream_trailer,
        &ett_u3v_stream_payload,
        &ett_u3v_device_info_descriptor,
        &ett_u3v_device_info_descriptor_speed_support,
        &ett_u3v_device_info_descriptor_gencp_version,
        &ett_u3v_device_info_descriptor_u3v_version,
    };

    proto_u3v = proto_register_protocol("USB 3 Vision", "U3V", "u3v");
    proto_register_field_array(proto_u3v, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    u3v_handle = register_dissector("u3v", dissect_u3v, proto_u3v);
}



void
proto_reg_handoff_u3v(void)
{
    dissector_handle_t u3v_descr_handle = NULL;

    dissector_add_uint("usb.bulk", IF_CLASS_MISCELLANEOUS, u3v_handle);
    heur_dissector_add("usb.bulk", dissect_u3v_heur, "USB3Vision Protocol", "u3v", proto_u3v,HEURISTIC_ENABLE);
    u3v_descr_handle = create_dissector_handle(dissect_u3v_descriptors, proto_u3v);
    dissector_add_uint("usb.descriptor", IF_CLASS_MISCELLANEOUS, u3v_descr_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
