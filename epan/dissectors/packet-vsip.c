/* packet-vsip.c
 * Routines for VSIP packet disassembly
 *
 * Copyright (c) 2010 by Verint Canada Systems Inc.
 *
 * Original Author: Charles Nepveu <charles.nepveu at verint.com>
 *         Generated using the TSN.1 compiler from protomatics.
 *
 * Updated to current API usage to create "manual" version of
 * dissector by Michael Mann
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

#include <epan/packet.h>

void proto_register_vsip(void);
void proto_reg_handoff_vsip(void);

static const value_string EVsipMessageType_vals[] =
{
   { 1, "VSIP Ping Request"},
   { 2, "VSIP Ping Response"},
   { 3, "VSIP Get Capabilities Request"},
   { 4, "VSIP Get Capabilities Response"},
   { 5, "VSIP Start Device Request"},
   { 6, "VSIP Stop Device Request"},
   { 7, "VSIP Set Configuration Request"},
   { 8, "VSIP Get Configuration Request"},
   { 9, "VSIP Get Configuration Response"},
   {10, "VSIP Send Command Request"},
   {11, "VSIP Event Notify"},
   {12, "VSIP Event Subscribe"},
   {13, "VSIP Error Response"},
   {19, "VSIP Content-Type Switch Request"},
   {20, "VSIP Content-Type Switch Response"},
   {21, "VSIP Start Device EX Request"},
   {22, "VSIP Stop Device EX Request"},
   {23, "VSIP Event Subscribe Extended"},
   {24, "VSIP Send Command EX Request"},
   {48, "VSIP Error Variable Arguments Response"},
   {0, NULL}
};

value_string_ext EVsipMessageType_vals_ext = VALUE_STRING_EXT_INIT(EVsipMessageType_vals);

const value_string EVsipVendorID_vals[] =
{
   {8192, "Unknown Vendor"},
   {8193, "Verint"},
   {8194, "DVTEL"},
   {8195, "GENETEC"},
   {8196, "RADIANT"},
   {8197, "SILENT WITNESS"},
   {8198, "EUROPLEX TECH"},
   {8199, "JVC"},
   {8200, "SAMSUNG"},
   {0, NULL}
};

const value_string EVsipEntityType_vals[] =
{
   { 0, "Device"},
   { 1, "Video decoder"},
   { 2, "Video encoder"},
   { 3, "Audio decoder"},
   { 4, "Audio encoder"},
   { 5, "Serial port"},
   { 6, "Input pin"},
   { 7, "Output pin"},
   {11, "Wireless connection"},
   {12, "Ethernet connection"},
   {13, "Motion detection"},
   {17, "Video sensor"},
   {18, "Content analyzer"},
   {20, "Content analyzer view"},
   {22, "Camera tampering detection"},
   {0, NULL}
};

const value_string EVsipContentType_vals[] =
{
   {0, "None"},
   {1, "Command and Control"},
   {2, "Stream -video, audio, serial-"},
   {3, "SSL Command and Control Client"},
   {4, "SSL Command and Control Server"},
   {5, "SSL Stream -video, audio, serial- Client"},
   {6, "SSL Stream -video, audio, serial- Server"},
   {0, NULL}
};

const value_string EVsipValueType_vals[] =
{
   {1, "Character - 8 bits"},
   {2, "Short - 16 bits"},
   {3, "Integer - 32 bits"},
   {4, "VSIP String - Variable"},
   {5, "Unsigned Integer - 32 bits"},
   {6, "GUID - 128 bits"},
   {7, "Float - 32 bits"},
   {8, "Binary - Variable"},
   {0, NULL}
};

const value_string EVsipConnectionType_vals[] =
{
   {  0, "VSIP_CONN_TYPE_NULL"},
   {  1, "VSIP_CONN_TYPE_UDP_UNICAST"},
   {  2, "VSIP_CONN_TYPE_UDP_MULTICAST"},
   {  3, "VSIP_CONN_TYPE_UDP"},
   {  7, "VSIP_CONN_TYPE_RTPSTANDARDH264_UDP"},
   { 11, "VSIP_CONN_TYPE_RTPSTANDARDH264_UDP_VOLATILE"},
   { 12, "VSIP_CONN_TYPE_TCP"},
   { 64, "VSIP_CONN_TYPE_RTP"},
   { 65, "VSIP_CONN_TYPE_RTPVERINT_UDP"},
   { 76, "VSIP_CONN_TYPE_RTPVERINT_TCP"},
   {129, "VSIP_CONN_TYPE_UDP_VOLATILE"},
   {140, "VSIP_CONN_TYPE_TCP_VOLATILE"},
   {192, "VSIP_CONN_TYPE_RTPVERINT_UDP_VOLATILE"},
   {204, "VSIP_CONN_TYPE_RTPVERINT_TCP_VOLATILE"},
   {0, NULL}
};

const value_string EVsipCommand_vals[] =
{
   { 1, "Send Key Frame"},
   { 2, "VSIP Proprietary Command"},
   { 3, "Set TCP Connection As Vital"},
   { 4, "Reset Wireless Passkey"},
   { 5, "Remove Multicast Stream"},
   { 7, "Clear Statistics"},
   { 8, "Clear Logs"},
   { 9, "Ping Remote Host"},
   {10, "VSIP_CA_COMMAND_ADD_VIEW"},
   {11, "VSIP_CA_COMMAND_DEL_VIEW"},
   {12, "VSIP_CA_COMMAND_FORCE_VIEW"},
   {13, "VSIP_CA_COMMAND_GET_VIEW_SNAPSHOT"},
   {14, "VSIP_CA_COMMAND_GET_LIVE_SNAPSHOT"},
   {15, "VSIP_CA_COMMAND_ADD_RULE"},
   {16, "VSIP_CA_COMMAND_DEL_RULE"},
   {17, "VSIP_CA_COMMAND_SET_RULE"},
   {18, "VSIP_CA_COMMAND_GET_RULES"},
   {19, "VSIP_CA_COMMAND_RESET_INT_PARAMS"},
   {32, "VSIP_CA_COMMAND_RESET_CA_CONFIG"},
   {33, "Install License"},
   {34, "Remove License"},
   {49, "Reset Out-Of-Position View"},
   {50, "Reset Out-Of-Position Params"},
   {51, "Reset Out-Of-Focus Params"},
   {64, "RTSP control over VSIP"},
   {0, NULL}
};

value_string_ext EVsipCommand_vals_ext = VALUE_STRING_EXT_INIT(EVsipCommand_vals);

const value_string EVsipConfigItem_vals[] =
{
   {   1, "CONFIG_NETWORK_PORT/CONFIG_NETWORK_RX_PORT"},
   {   2, "CONFIG_NETWORK_CONNECTION_TYPE"},
   {   3, "CONFIG_NETWORK_SUPPORTED_CONNECTION_TYPE"},
   {   4, "CONFIG_NETWORK_SSL_PASSKEY"},
   {   5, "CONFIG_NETWORK_MAC_ADDRESS"},
   {   6, "CONFIG_NETWORK_TX_PORT"},
   {   7, "CONFIG_NETWORK_RX_PORT2"},
   {   8, "CONFIG_NETWORK_RX_PORT3"},
   {   9, "CONFIG_NETWORK_RX_PORT4"},
   {  10, "CONFIG_NETWORK_TX_PORT2"},
   {  11, "CONFIG_NETWORK_TX_PORT3"},
   {  12, "CONFIG_NETWORK_TX_PORT4"},
   {  13, "CONFIG_NETWORK_DESTINATION_GUID"},
   {  14, "CONFIG_NETWORK_DESTINATION_GUID2"},
   {  15, "CONFIG_NETWORK_DESTINATION_GUID3"},
   {  16, "CONFIG_NETWORK_DESTINATION_GUID4"},
   { 257, "CONFIG_CONTENT_ANALYZER_TARGET_FRAME_RATE"},
   { 258, "CONFIG_CONTENT_ANALYZER_CURRENT_STREAMING_STATE"},
   { 259, "CONFIG_CONTENT_ANALYZER_INITIAL_STREAMING_STATE"},
   { 260, "CONFIG_CONTENT_ANALYZER_TARGET_IP_ADDRESS"},
   { 261, "CONFIG_CONTENT_ANALYZER_TARGET_VSIP_GUID"},
   { 262, "CONFIG_CONTENT_ANALYZER_SUPPORTED_TYPE"},
   { 263, "CONFIG_CONTENT_ANALYZER_JPEG_ENCODING_STATE"},
   { 264, "CONFIG_CONTENT_ANALYZER_JPEG_FRAME_RATE"},
   { 265, "CONFIG_CONTENT_ANALYZER_JPEG_QUALITY"},
   { 266, "CONFIG_CONTENT_ANALYZER_SOURCE_INPUT_NUMBER"},
   { 267, "CONFIG_CONTENT_ANALYZER_ACTUAL_TYPE"},
   { 268, "CONFIG_CONTENT_ANALYZER_VERSION"},
   { 269, "CONFIG_CONTENT_ANALYZER_FORENSICS_METADATA_ENABLED"},
   { 270, "CONFIG_CONTENT_ANALYZER_POSSIBLE_SENSORS"},
   { 271, "CONFIG_CONTENT_ANALYZER_CONNECTION_MODE"},
   { 272, "CONFIG_CONTENT_ANALYZER_INTERNAL_PARAMETERS"},
   { 273, "CONFIG_CONTENT_ANALYZER_STATUS"},
   { 274, "CONFIG_CONTENT_ANALYZER_CURRENT_VIEW_ID"},
   { 275, "CONFIG_CONTENT_ANALYZER_SUPPORTED_FEATURES"},
   { 276, "CONFIG_CONTENT_ANALYZER_CURRENT_SENSOR"},
   { 277, "CONFIG_CONTENT_ANALYZER_AVAILABLE_SENSORS"},
   { 278, "CONFIG_CONTENT_ANALYZER_AUTO_DISABLE_SCHEDULES"},
   { 513, "CONFIG_NETWORK_QOS_TYPE"},
   { 514, "CONFIG_NETWORK_QOS_VIDEO_PRIORITY"},
   { 515, "CONFIG_NETWORK_QOS_AUDIO_PRIORITY"},
   { 516, "CONFIG_NETWORK_QOS_CONTROL_PRIORITY"},
   { 517, "CONFIG_NETWORK_QOS_TOS_VIDEO_PRIORITY"},
   { 518, "CONFIG_NETWORK_QOS_TOS_AUDIO_PRIORITY"},
   { 519, "CONFIG_NETWORK_QOS_TOS_CONTROL_PRIORITY"},
   { 769, "CONFIG_SYSTEM_MONITOR_MAX_FATAL_ERR_COUNT"},
   {1025, "CONFIG_CONTENT_ANALYZER_VIEW_NAME"},
   {1026, "CONFIG_CONTENT_ANALYZER_VIEW_IS_DEFINED"},
   {1027, "CONFIG_CONTENT_ANALYZER_VIEW_SOURCE_INPUT_NUMBER"},
   {1028, "CONFIG_CONTENT_ANALYZER_VIEW_SUPPORTED_FEATURES"},
   {1281, "CONFIG_CAMALERT_PAINTOVER_MODE"},
   {1282, "CONFIG_CAMALERT_PAINTOVER_SENSITIVITY_OFFSET"},
   {1283, "CONFIG_CAMALERT_PAINTOVER_ALARM"},
   {1284, "CONFIG_CAMALERT_PAINTOVER_ALARM_RESET"},
   {1285, "CONFIG_CAMALERT_PAINTOVER_MEDIAN_THRES"},
   {1286, "CONFIG_CAMALERT_PAINTOVER_STDDEV_THRES"},
   {1287, "CONFIG_CAMALERT_PAINTOVER_MEDIAN"},
   {1288, "CONFIG_CAMALERT_PAINTOVER_STDDEV"},
   {1289, "CONFIG_CAMALERT_PAINTOVER_INPUT_NUMBER"},
   {1290, "CONFIG_CAMALERT_PAINTOVER_ALARM_STATE"},
   {1537, "CONFIG_CAMERA_TAMPERING_LIB_VERSION"},
   {1538, "CONFIG_CAMERA_TAMPERING_INPUT_NUM"},
   {1539, "CONFIG_CAMERA_TAMPERING_OOP_FRAME_RATE"},
   {1540, "CONFIG_CAMERA_TAMPERING_OOP_ENABLE"},
   {1541, "CONFIG_CAMERA_TAMPERING_OOP_SENSITIVITY_THRESHOLD"},
   {1542, "CONFIG_CAMERA_TAMPERING_OOP_PERST_LEVEL"},
   {1543, "CONFIG_CAMERA_TAMPERING_OOP_MASK"},
   {1544, "CONFIG_CAMERA_TAMPERING_OOP_MASK_ENABLE"},
   {1545, "CONFIG_CAMERA_TAMPERING_OOP_MASK_POLARITY"},
   {1546, "CONFIG_CAMERA_TAMPERING_OOP_ALARM_STATUS"},
   {1547, "CONFIG_CAMERA_TAMPERING_OOP_CURRENT_LEVEL"},
   {1548, "CONFIG_CAMERA_TAMPERING_OOF_ENABLE"},
   {1549, "CONFIG_CAMERA_TAMPERING_OOF_SENSITIVITY_THRESHOLD"},
   {1550, "CONFIG_CAMERA_TAMPERING_OOF_PERST_LEVEL"},
   {1551, "CONFIG_CAMERA_TAMPERING_OOF_MASK"},
   {1552, "CONFIG_CAMERA_TAMPERING_OOF_MASK_ENABLE"},
   {1553, "CONFIG_CAMERA_TAMPERING_OOF_MASK_POLARITY"},
   {1554, "CONFIG_CAMERA_TAMPERING_OOF_ALARM_STATUS"},
   {1555, "CONFIG_CAMERA_TAMPERING_OOF_CURRENT_LEVEL"},
   {1556, "CONFIG_CAMERA_TAMPERING_OOF_FRAME_RATE"},
   {1557, "CONFIG_CAMERA_TAMPERING_OOP_ILLUM_NORM"},
   {4097, "CONFIG_VIDEO_ATTRIBUTE_BRIGHTNESS"},
   {4098, "CONFIG_VIDEO_ATTRIBUTE_CONTRAST"},
   {4099, "CONFIG_VIDEO_ATTRIBUTE_GAIN_U"},
   {4100, "CONFIG_VIDEO_ATTRIBUTE_GAIN_V"},
   {4101, "CONFIG_VIDEO_ATTRIBUTE_HUE"},
   {4102, "CONFIG_VIDEO_ATTRIBUTE_MOTION_ENC"},
   {4103, "CONFIG_VIDEO_ATTRIBUTE_SATURATION"},
   {4104, "CONFIG_VIDEO_ATTRIBUTE_RECEIVER_MODE"},
   {4105, "CONFIG_VIDEO_ATTRIBUTE_INPUT_OPTION"},
   {4106, "CONFIG_VIDEO_ATTRIBUTE_H264_ENC"},
   {4113, "CONFIG_VIDEO_COMPRESSION_DATA_FORMAT"},
   {4114, "CONFIG_VIDEO_COMPRESSION_BLOCK_REFRESH"},
   {4115, "CONFIG_VIDEO_COMPRESSION_FRAME_RATE"},
   {4116, "CONFIG_VIDEO_COMPRESSION_OVERLAY_RATE"},
   {4117, "CONFIG_VIDEO_COMPRESSION_QUANTIZATION"},
   {4118, "CONFIG_VIDEO_COMPRESSION_BIT_RATE"},
   {4119, "CONFIG_VIDEO_COMPRESSION_INTRA_INTERVAL"},
   {4120, "CONFIG_VIDEO_COMPRESSION_QUANTIZATION_MIN"},
   {4121, "CONFIG_VIDEO_COMPRESSION_MODE"},
   {4122, "CONFIG_VIDEO_COMPRESSION_MODE_SUPPORTED"},
   {4123, "CONFIG_VIDEO_COMPRESSION_FRAME_RATE_CONTROL"},
   {4124, "CONFIG_VIDEO_COMPRESSION_TARGET_FILE_SIZE"},
   {4125, "CONFIG_VIDEO_COMPRESSION_VFS_QUALITY"},
   {4126, "CONFIG_VIDEO_ENHANCED_QUALITY_MODE"},
   {4127, "CONFIG_VIDEO_COMPRESSION_FRAME_SKIPRATE"},
   {4129, "CONFIG_VIDEO_INFO_ANALOG_FORMAT"},
   {4130, "CONFIG_VIDEO_INFO_SUPPORTED_DATA_FORMAT"},
   {4131, "CONFIG_VIDEO_INFO_SOURCE_INPUT"},
   {4132, "CONFIG_VIDEO_INFO_ENCODER_NUMBER"},
   {4133, "CONFIG_VIDEO_INFO_SINK_OUTPUT"},
   {4134, "CONFIG_VIDEO_INFO_DECODER_NUMBER"},
   {4135, "CONFIG_VIDEO_INFO_SECOND_CONNECTOR_STATE"},
   {4136, "CONFIG_VIDEO_INFO_INPUT_STATE"},
   {4137, "CONFIG_VIDEO_INFO_MAX_RESOLUTION"},
   {4138, "CONFIG_VIDEO_INFO_SUPPORTED_MAX_RESOLUTION"},
   {4139, "CONFIG_VIDEO_INFO_VIDEO_FORMAT_AUTODETECT"},
   {4145, "CONFIG_VIDEO_STREAMING_STATE_CURRENT"},
   {4146, "CONFIG_VIDEO_STREAMING_STATE_INITIAL"},
   {4147, "CONFIG_VIDEO_STREAMING_TARGET_IP_ADDRESS"},
   {4148, "CONFIG_VIDEO_STREAMING_TARGET_VSIP_GUID"},
   {4149, "CONFIG_VIDEO_STREAMING_TRANSPORT_PROTOCOL"},
   {4150, "CONFIG_VIDEO_STREAMING_RATE_CONTROL_MODE"},
   {4151, "CONFIG_VIDEO_STREAMING_INPUT_FILTER_MODE"},
   {4152, "CONFIG_VIDEO_STREAMING_ENCODER_MODE"},
   {4153, "CONFIG_VIDEO_STREAMING_MAX_BIT_RATE"},
   {4154, "CONFIG_VIDEO_STREAMING_DEFAULT_KEEP_ALIVE_ENABLE"},
   {4160, "CONFIG_VIDEO_STREAMING_DYN_FILT_ENABLE"},
   {4161, "CONFIG_VIDEO_DESTINATION_ADD"},
   {4162, "CONFIG_VIDEO_DESTINATION_REMOVE"},
   {4163, "CONFIG_VIDEO_STREAMING_RATE_CONTROL_MODE_SUPPORTED"},
   {4176, "CONFIG_VIDEO_ENERGY_VECTOR_FREQUENCY"},
   {4193, "CONFIG_VIDEO_WEB_MULTICAST_IP_ADDRESS"},
   {4194, "CONFIG_VIDEO_WEB_MULTICAST_IP_PORT"},
   {4208, "CONFIG_VIDEO_STREAMING_MAX_TX_SIZE"},
   {4209, "CONFIG_VIDEO_STREAMING_NOISE_GEN_MODE"},
   {4210, "CONFIG_VIDEO_STREAMING_NRF_MODE"},
   {4211, "CONFIG_VIDEO_STREAMING_INTERLACED_MODE"},
   {4212, "CONFIG_VIDEO_ROTATION_FILTER"},
   {4213, "CONFIG_VIDEO_STARVING_MODE"},
   {4214, "CONFIG_VIDEO_STARVING_DELAY"},
   {4215, "CONFIG_VIDEO_DEBLOCKING_FILTER"},
   {4216, "CONFIG_VIDEO_DEINTERLACING_MODE"},
   {4217, "CONFIG_VIDEO_DECODER_QUAD_DISCOVERY_MODE"},
   {4224, "CONFIG_VIDEO_ECODER_POWER"},
   {4224, "CONFIG_VIDEO_ENCODER_POWER"},
   {4225, "CONFIG_VIDEO_ENCODER_MAX_STREAMS"},
   {4226, "CONFIG_VIDEO_ENCODER_MOTD_SUPPORTED"},
   {4240, "CONFIG_VIDEO_COMPRESSION_H264_QUALITY"},
   {4241, "CONFIG_VIDEO_COMPRESSION_H264_ADV_PROFILE"},
   {4242, "CONFIG_VIDEO_COMPRESSION_H264_ADV_QUALITY"},
   {4243, "CONFIG_VIDEO_COMPRESSION_H264_ADV_QUARTER_PEL"},
   {4244, "CONFIG_VIDEO_COMPRESSION_H264_ADV_DEBLOCKING"},
   {4245, "CONFIG_VIDEO_COMPRESSION_H264_ADV_DEBLOCK_LEVEL"},
   {4246, "CONFIG_VIDEO_COMPRESSION_H264_ADV_CODING"},
   {4247, "CONFIG_VIDEO_COMPRESSION_H264_ADV_MOTION_VECTOR_RANGE"},
   {4248, "CONFIG_VIDEO_COMPRESSION_H264_MIN_QP"},
   {4249, "CONFIG_VIDEO_COMPRESSION_H264_MAX_QP"},
   {4250, "CONFIG_VIDEO_COMPRESSION_H264_RATE_CTRL"},
   {4272, "CONFIG_VIDEO_LOW_RESOLUTION_MODE"},
   {4273, "CONFIG_VIDEO_INPUT_STATE"},
   {4304, "CONFIG_VIDEO_OUTPUT_MODE"},
   {4305, "CONFIG_VIDEO_OUTPUT_MODE_SUPPORTED"},
   {4306, "CONFIG_VIDEO_OUTPUT_FORMAT"},
   {4307, "CONFIG_VIDEO_OUTPUT_FORMAT_SUPPORTED"},
   {4314, "CONFIG_VIDEO_RTSP_RESOURCE_PATH"},
   {4315, "CONFIG_VIDEO_RESOLUTION_RESOURCE_GROUP"},
   {8193, "CONFIG_AUDIO_ATTRIBUTE_PITCH"},
   {8194, "CONFIG_AUDIO_ATTRIBUTE_VOLUME"},
   {8208, "CONFIG_AUDIO_INPUT_TYPE"},
   {8209, "CONFIG_AUDIO_COMPRESSION_DATA_FORMAT"},
   {8210, "CONFIG_AUDIO_SAMPLING_RATE"},
   {8211, "CONFIG_AUDIO_COMPRESSION_CHANNEL"},
   {8212, "CONFIG_AUDIO_COMPRESSION_GAIN"},
   {8213, "CONFIG_AUDIO_COMPRESSION_SAMPLE_BITS"},
   {8214, "CONFIG_AUDIO_SAMPLING_RATE_SUPPORTED"},
   {8225, "CONFIG_AUDIO_INFO_SUPPORTED_DATA_FORMAT"},
   {8226, "CONFIG_AUDIO_INFO_INPUT_NUMBER"},
   {8227, "CONFIG_AUDIO_INFO_ENCODER_NUMBER"},
   {8228, "CONFIG_AUDIO_INFO_SUPPORTED_INPUT_TYPE"},
   {8240, "CONFIG_AUDIO_PLAYMODE"},
   {8241, "CONFIG_AUDIO_GAIN_IN_DB"},
   {8242, "CONFIG_AUDIO_GAIN_IN_DB_POSSIBLE_RANGE"},
   {8243, "CONFIG_AUDIO_BIAS_STATE"},
   {8244, "CONFIG_AUDIO_BIAS_IN_VOLT"},
   {8245, "CONFIG_AUDIO_BIAS_IN_VOLT_POSSIBLE_RANGE"},
   {8246, "CONFIG_AUDIO_GAIN_STATE"},
   {8257, "CONFIG_AUDIO_STREAMING_STATE_INITIAL"},
   {8258, "CONFIG_AUDIO_WEB_MULTICAST_IP_ADDRESS"},
   {8259, "CONFIG_AUDIO_WEB_MULTICAST_IP_PORT"},
   {8260, "CONFIG_AUDIO_STREAMING_TRANSPORT_PROTOCOL"},
   {8261, "CONFIG_AUDIO_DESTINATION_ADD"},
   {8262, "CONFIG_AUDIO_DESTINATION_REMOVE"},
   {8263, "CONFIG_AUDIO_AUDIO_MODE"},
   {8264, "CONFIG_AUDIO_STREAMING_DEFAULT_KEEP_ALIVE_ENABLE"},
   {8272, "CONFIG_AUDIO_STREAMING_TARGET_IP_ADDRESS"},
   {8273, "CONFIG_AUDIO_STREAMING_TARGET_VSIP_GUID"},
   {8410, "CONFIG_AUDIO_RTSP_RESOURCE_PATH"},
   {8411, "CONFIG_AUDIO_INPUT_RESOURCE_GROUP"},
   {12289, "CONFIG_SERIAL_PORT_BAUD_RATE"},
   {12290, "CONFIG_SERIAL_PORT_DATA_BITS"},
   {12291, "CONFIG_SERIAL_PORT_PARITY"},
   {12292, "CONFIG_SERIAL_PORT_STOP_BITS"},
   {12293, "CONFIG_SERIAL_PORT_READ_ONCE"},
   {12294, "CONFIG_SERIAL_PORT_WRITE_ONCE"},
   {12295, "CONFIG_SERIAL_PORT_READ_INTERCHAR_TIMEOUT"},
   {12296, "CONFIG_SERIAL_PORT_READ_TOTAL_TIMEOUT"},
   {12297, "CONFIG_SERIAL_PORT_LINE_DRIVER"},
   {12305, "CONFIG_SERIAL_HANDSHAKE"},
   {12306, "CONFIG_SERIAL_FLOW_SOFTWARE"},
   {12307, "CONFIG_SERIAL_FLOW_CTS"},
   {12308, "CONFIG_SERIAL_FLOW_DSR"},
   {12309, "CONFIG_SERIAL_CONTROL_RTS"},
   {12310, "CONFIG_SERIAL_CONTROL_DTR"},
   {12311, "CONFIG_SERIAL_CONTROL_SOFTWARE"},
   {12321, "CONFIG_SERIAL_STREAMING_STATE_INITIAL"},
   {12322, "CONFIG_SERIAL_STREAMING_TRANSPORT_PROTOCOL"},
   {12337, "CONFIG_SERIAL_RS422_485_OPERATING_MODE"},
   {12338, "CONFIG_SERIAL_STREAMING_TARGET_IP_ADDRESS"},
   {12339, "CONFIG_SERIAL_STREAMING_TARGET_IP_ADDRESS2"},
   {12340, "CONFIG_SERIAL_STREAMING_TARGET_IP_ADDRESS3"},
   {12341, "CONFIG_SERIAL_STREAMING_TARGET_IP_ADDRESS4"},
   {12342, "CONFIG_SERIAL_INFO_SUPPORTED_OPER_MODE"},
   {16385, "CONFIG_IO_PIN_STATE"},
   {20481, "CONFIG_SYSTEM_REBOOTREQUIRED"},
   {20482, "CONFIG_SYSTEM_DEVICE_NAME"},
   {20483, "CONFIG_SYSTEM_DEVICE_TYPE"},
   {20484, "CONFIG_SYSTEM_UTC_DATETIME"},
   {20485, "CONFIG_SYSTEM_GMT_OFFSET"},
   {20486, "CONFIG_SYSTEM_COUNTRY_CODE"},
   {20487, "CONFIG_SYSTEM_COUNTRY_CODE_CAP"},
   {20488, "CONFIG_SYSTEM_NTP_RTP_SYNCHRO_PAIR"},
   {20489, "CONFIG_SYSTEM_BOARD_TEMPERATURE"},
   {20490, "CONFIG_SYSTEM_TIMEZONE"},
   {20491, "CONFIG_SYSTEM_TIMEZONE_SUPPORTED_LIST"},
   {20497, "CONFIG_SYSTEM_FIRMWARE_VERSION"},
   {20498, "CONFIG_SYSTEM_UPTIME"},
   {20499, "CONFIG_SYSTEM_IP_FIRMWARE_UPDATE_SUPPORT"},
   {20500, "CONFIG_SYSTEM_FTP_FIRMWARE_UPDATE_SUPPORT"},
   {20501, "CONFIG_SYSTEM_XML_REPORT_GENERATION"},
   {20502, "CONFIG_SYSTEM_GLOBAL_SECURITY_PROFILE"},
   {20503, "CONFIG_SYSTEM_TELNET_SESSION"},
   {20504, "CONFIG_SYSTEM_IDENTIFY_STATUS"},
   {20505, "CONFIG_SYSTEM_AUDIO_HARDWARE"},
   {20512, "CONFIG_SYSTEM_FIRMWARE_METHOD_HTTP_SUPPORTED"},
   {20529, "CONFIG_SYSTEM_TIME_NTP_SERVER_USAGE"},
   {20530, "CONFIG_SYSTEM_TIME_NTP_SERVER_IP_ADDRESS"},
   {20531, "CONFIG_SYSTEM_TIME_NTP_SERVER_IP_PORT"},
   {20532, "CONFIG_SYSTEM_TIME_NTP_STATUS"},
   {20533, "CONFIG_SYSTEM_DST_ENABLED"},
   {20545, "CONFIG_SYSTEM_LOCAL_IP_ADDRESS"},
   {20546, "CONFIG_SYSTEM_LOCAL_IP_NETMASK"},
   {20547, "CONFIG_SYSTEM_GATEWAY"},
   {20548, "CONFIG_SYSTEM_DHCP_STATE"},
   {20549, "CONFIG_SYSTEM_HOST_NAME"},
   {20560, "CONFIG_SYSTEM_VOLATILE_CONNECTIONS"},
   {20561, "CONFIG_SYSTEM_MONITOR_SUPPORTED_FEATURES"},
   {20562, "CONFIG_SYSTEM_SET_ID"},
   {20563, "CONFIG_SYSTEM_HTTP_ACCESS_ENABLE"},
   {20564, "CONFIG_SYSTEM_HTTP_ACCESS_SECURED_ENABLE"},
   {20565, "CONFIG_SYSTEM_LED_STATE_ENABLE"},
   {20566, "CONFIG_SYSTEM_RESET_BUTTON_STATE"},
   {20576, "CONFIG_SYSTEM_LICENSING_SUPPORTED"},
   {20577, "CONFIG_SYSTEM_LICENSE"},
   {20578, "CONFIG_SYSTEM_LATEST_SUPPORTED_LICENSE_VERSION"},
   {20579, "CONFIG_SYSTEM_LAST_REMOVAL_CODE"},
   {20580, "CONFIG_SYSTEM_LICENSE_STATUS"},
   {20581, "CONFIG_SYSTEM_LICENSE_USAGE"},
   {20582, "CONFIG_SYSTEM_SERIAL_NUMBER"},
   {20583, "CONFIG_SYSTEM_SERIAL_NUMBER_STAMPER"},
   {20586, "CONFIG_SYSTEM_PERFORMANCE_OPTIONS_SUPP"},
   {20587, "CONFIG_SYSTEM_PERFORMANCE_OPTIONS"},
   {20592, "CONFIG_SYSTEM_SNMP_ENABLE"},
   {20593, "CONFIG_SYSTEM_SNMP_SYSTEM_CONTACT"},
   {20594, "CONFIG_SYSTEM_SNMP_SYSTEM_LOCATION"},
   {20595, "CONFIG_SYSTEM_SNMP_RO_COMMUNITY_NAME"},
   {20596, "CONFIG_SYSTEM_SNMP_RO_USER_NAME"},
   {20597, "CONFIG_SYSTEM_SNMP_RO_USER_AUTH_TYPE"},
   {20598, "CONFIG_SYSTEM_SNMP_RO_USER_AUTH_PASSWORD"},
   {20599, "CONFIG_SYSTEM_SNMP_RO_USER_PRIVACY_PROTOCOL"},
   {20600, "CONFIG_SYSTEM_SNMP_RO_USER_PRIVACY_PASSWORD"},
   {20601, "CONFIG_SYSTEM_SNMP_TRAP_PRIMARY_DEST_ADDRESS"},
   {20602, "CONFIG_SYSTEM_SNMP_TRAP_BACKUP_DEST_ADDRESS"},
   {20608, "CONFIG_SYSTEM_PROPERTY_RTSP_SUPPORT"},
   {24577, "CONFIG_IF_FILTER_ALLOW_MCAST_FWD"},
   {32769, "CONFIG_WLS_MAC_ASSOCIATIONS_LIST_CLIENT"},
   {32770, "CONFIG_WLS_MAC_ASSOCIATIONS_LIST_SLAVE"},
   {32771, "CONFIG_WLS_MODE"},
   {32772, "CONFIG_WLS_POSSIBLE_MODE"},
   {32773, "CONFIG_WLS_BAND"},
   {32774, "CONFIG_WLS_POSSIBLE_BAND"},
   {32775, "CONFIG_WLS_CHANNEL"},
   {32776, "CONFIG_WLS_POSSIBLE_CHANNEL"},
   {32777, "CONFIG_WLS_BIT_RATE"},
   {32778, "CONFIG_WLS_POSSIBLE_BIT_RATE"},
   {32779, "CONFIG_WLS_PASS_KEY"},
   {32780, "CONFIG_WLS_ENCRYPTION_TYPE"},
   {32781, "CONFIG_WLS_POSSIBLE_ENCRYPTION_TYPE"},
   {32782, "CONFIG_WLS_KEY_DISTRIBUTION"},
   {32783, "CONFIG_WLS_POSSIBLE_KEY_DISTRIBUTION"},
   {32784, "CONFIG_WLS_SSID"},
   {32785, "CONFIG_WLS_RSSI"},
   {32786, "CONFIG_WLS_ROLE"},
   {32787, "CONFIG_WLS_POSSIBLE_ROLE"},
   {32788, "CONFIG_WLS_FILTER_WLS_TO_WLS_MCAST"},
   {32789, "CONFIG_WLS_CURRENT_TX_BIT_RATE"},
   {32790, "CONFIG_WLS_CURRENT_SPCF_MASTER"},
   {32791, "CONFIG_WLS_DIST_RANGE"},
   {32792, "CONFIG_WLS_POSSIBLE_DIST_RANGE"},
   {32793, "CONFIG_WLS_CURRENT_RX_BIT_RATE"},
   {32794, "CONFIG_WLS_STARTING_ORDER"},
   {32795, "CONFIG_WLS_TRANSMIT_POWER_SCALE"},
   {32796, "CONFIG_WLS_OPERATING_MODE"},
   {32797, "CONFIG_WLS_ANTENNA_GAIN"},
   {32798, "CONFIG_WLS_SENSITIVITY_THRESHOLD"},
   {32799, "CONFIG_WLS_LINK_INFO"},
   {32800, "CONFIG_WLS_MIN_MARGIN"},
   {32801, "CONFIG_WLS_CHANNEL_BW"},
   {32802, "CONFIG_WLS_POSSIBLE_CHANNEL_BW"},
   {32803, "CONFIG_WLS_WPA_AUTH_TYPE"},
   {32804, "CONFIG_WLS_POSSIBLE_WPA_AUTH_TYPES"},
   {32805, "CONFIG_WLS_WPA_NEGOTIATION_TIMEOUT"},
   {32807, "CONFIG_WLS_WPA_PMK_LIFETIME"},
   {32808, "CONFIG_WLS_WPA_EAP_LOGIN"},
   {32809, "CONFIG_WLS_WPA_EAP_PASSWORD"},
   {32810, "CONFIG_WLS_WPA_CA_CERTIFICATE"},
   {32811, "CONFIG_WLS_WPA_UNIT_CERTIFICATE"},
   {32812, "CONFIG_WLS_WPA_UNIT_PRIVATE_KEY"},
   {32813, "CONFIG_WLS_WPA_PRIVATE_KEY_PASSPHRASE"},
   {32814, "CONFIG_WLS_ANTENNA_SELECTION"},
   {32815, "CONFIG_WLS_INTERCHANNEL_INTERFERENCE"},
   {32816, "CONFIG_WLS_SPCF_MAX_FRAME_PER_BURST"},
   {32817, "CONFIG_WLS_SPCF_MAX_POLLING_LATENCY"},
   {36865, "CONFIG_CAPABILITY_NAME"},
   {36866, "CONFIG_CAPABILITY_INSTANCE"},
   {36867, "CONFIG_CAPABILITY_EOD_STATS_SUPPORTED"},
   {36868, "CONFIG_CAPABILITY_LICENSABLE"},
   {36869, "CONFIG_CAPABILITY_LICENSING_STATUS"},
   {36870, "CONFIG_CAPABILITY_ENABLED"},
   {40961, "CONFIG_MOTD_UPPER_THRESHOLD"},
   {40962, "CONFIG_MOTD_LOWER_THRESHOLD"},
   {40963, "CONFIG_MOTD_NB_FRAMES"},
   {40964, "CONFIG_MOTD_VECT_LENGTH"},
   {40965, "CONFIG_MOTD_LEFT_TO_RIGHT"},
   {40966, "CONFIG_MOTD_RIGHT_TO_LEFT"},
   {40967, "CONFIG_MOTD_TOP_TO_BOTTOM"},
   {40968, "CONFIG_MOTD_BOTTOM_TO_TOP"},
   {40969, "CONFIG_MOTD_MASK_STRING"},
   {40970, "CONFIG_MOTD_MASK_ENABLED"},
   {40971, "CONFIG_MOTD_STATE"},
   {40972, "CONFIG_MOTD_INPUT_INDEX"},
   {40973, "CONFIG_MOTD_ALARM_STATE"},
   {45057, "CONFIG_PREA_MEMSPACE"},
   {45058, "CONFIG_PREA_STATE"},
   {45059, "CONFIG_PREA_RECORDING_STATE"},
   {45060, "CONFIG_PREA_INPUT_INDEX"},
   {49153, "CONFIG_PREPOST_CURRENT_STATE"},
   {49154, "CONFIG_PREPOST_INITIAL_STATE"},
   {49155, "CONFIG_PREPOST_OPERATIONAL_MODE"},
   {49156, "CONFIG_PREPOST_CR_IP"},
   {49157, "CONFIG_PREPOST_CR_PORT"},
   {49158, "CONFIG_PREPOST_CR_USERNAME"},
   {49159, "CONFIG_PREPOST_CR_PASSWORD"},
   {49160, "CONFIG_PREPOST_CR_CLIP_DIRECTORY"},
   {49161, "CONFIG_PREPOST_TRIGGER_IP"},
   {49162, "CONFIG_PREPOST_TRIGGER_PORT"},
   {49163, "CONFIG_PREPOST_TRIGGER_USERNAME"},
   {49164, "CONFIG_PREPOST_TRIGGER_PASSWORD"},
   {49165, "CONFIG_PREPOST_TRIGGER_CLIP_DIRECTORY"},
   {49166, "CONFIG_PREPOST_PRE_LENGTH"},
   {49167, "CONFIG_PREPOST_POST_LENGTH"},
   {49168, "CONFIG_PREPOST_FALLING_RISING"},
   {49169, "CONFIG_PREPOST_CR_CLIP_LENGTH"},
   {53249, "CONFIG_VSIP_PROTOCOL_PORT_NUMBER"},
   {53250, "CONFIG_VSIP_PROTOCOL_MULTICAST_IP_ADDRESS"},
   {53251, "CONFIG_VSIP_PROTOCOL_DISCOVERY_IP_ADDRESS"},
   {53252, "CONFIG_VSIP_TCP_HEARTBEAT_STATE"},
   {53253, "CONFIG_VSIP_EVENT_MONITOR_IP_ADDRESS"},
   {53254, "CONFIG_VSIP_EVENT_MONITOR_TCP_STATE"},
   {53255, "CONFIG_VSIP_EVENT_MAX_REPEAT_COUNT"},
   {57345, "CONFIG_OSD_DISPLAY_LOGO"},
   {57346, "CONFIG_OSD_TX_DEVICE_NAME"},
   {57347, "CONFIG_OSD_EVENT_DESCRIPTION"},
   {57348, "CONFIG_OSD_DISPLAY_CUSTOM_ITEM"},
   {57349, "CONFIG_OSD_FONT_HEIGHT"},
   {57350, "CONFIG_OSD_CUSTOM_MODE"},
   {57351, "CONFIG_OSD_SHOW_TRANSMITTER_NAME"},
   {57352, "CONFIG_OSD_DECODER_STARVE"},
   {57353, "CONFIG_OSD_DISPLAY_OPTION"},
   {57354, "CONFIG_OSD_DISPLAY_STARTUP_INFO"},
   {57355, "CONFIG_OSD_TRANSPARENCY"},
   {57356, "CONFIG_OSD_DISPLAY_CUSTOM_ITEM_SUPPORTED"},
   {57357, "CONFIG_OSD_DECODER_STARVE_SUPPORTED"},
   {61441, "CONFIG_VIDEO_SENSOR_SOURCE_TYPE"},
   {61442, "CONFIG_VIDEO_SENSOR_PRESET"},
   {61443, "CONFIG_VIDEO_SENSOR_WHITE_BALANCE_BIAS"},
   {61444, "CONFIG_VIDEO_SENSOR_BACKLIGHT_ENABLE"},
   {61445, "CONFIG_VIDEO_SENSOR_GAMMA_MODE"},
   {61446, "CONFIG_VIDEO_SENSOR_GAMMA_VALUE"},
   {61447, "CONFIG_VIDEO_SENSOR_LENS_TYPE"},
   {61448, "CONFIG_VIDEO_SENSOR_NORMAL_ZONE_MODE"},
   {61449, "CONFIG_VIDEO_SENSOR_BACKLIGHT_ZONE_MODE"},
   {61450, "CONFIG_VIDEO_SENSOR_WHITE_BALANCE_BIAS_MIN"},
   {61451, "CONFIG_VIDEO_SENSOR_WHITE_BALANCE_BIAS_MAX"},
   {61452, "CONFIG_VIDEO_SENSOR_WHITE_BALANCE_BIAS_STEP"},
   {61453, "CONFIG_VIDEO_SENSOR_GAMMA_MIN"},
   {61454, "CONFIG_VIDEO_SENSOR_GAMMA_MAX"},
   {61455, "CONFIG_VIDEO_SENSOR_GAMMA_STEP"},
   {61456, "CONFIG_VIDEO_SENSOR_NORMAL_ZONE_CUSTOM_STRING"},
   {61457, "CONFIG_VIDEO_SENSOR_BACKLIGHT_ZONE_CUSTOM_STRING"},
   {61458, "CONFIG_VIDEO_SENSOR_SAVE_USER_SETTINGS"},
   {61459, "CONFIG_VIDEO_SENSOR_VERSION"},
   {61460, "CONFIG_VIDEO_SENSOR_GAMMA_POSSIBLE_RANGE"},
   {61461, "CONFIG_VIDEO_SENSOR_WHITE_BIAS_POSSIBLE_RANGE"},
   {61462, "CONFIG_VIDEO_SENSOR_DAYNIGHT_CONTROL"},
   {61463, "CONFIG_VIDEO_SENSOR_DAYNIGHT_COLOR_MODE"},
   {61464, "CONFIG_VIDEO_SENSOR_DAYNIGHT_GAIN_LIMIT"},
   {61465, "CONFIG_VIDEO_SENSOR_DAYNIGHT_THRES_IN_GAIN"},
   {61466, "CONFIG_VIDEO_SENSOR_DAYNIGHT_THRES_OUT_GAIN"},
   {61467, "CONFIG_VIDEO_SENSOR_DAYNIGHT_GAIN_BOOST"},
   {61468, "CONFIG_VIDEO_SENSOR_DAYNIGHT_GAIN_LIMIT_MIN"},
   {61469, "CONFIG_VIDEO_SENSOR_DAYNIGHT_GAIN_LIMIT_MAX"},
   {61470, "CONFIG_VIDEO_SENSOR_DAYNIGHT_GAIN_LIMIT_STEP"},
   {61471, "CONFIG_VIDEO_SENSOR_DAYNIGHT_THRES_IN_MIN"},
   {61472, "CONFIG_VIDEO_SENSOR_DAYNIGHT_THRES_IN_MAX"},
   {61473, "CONFIG_VIDEO_SENSOR_DAYNIGHT_THRES_IN_STEP"},
   {61474, "CONFIG_VIDEO_SENSOR_DAYNIGHT_THRES_OUT_MIN"},
   {61475, "CONFIG_VIDEO_SENSOR_DAYNIGHT_THRES_OUT_MAX"},
   {61476, "CONFIG_VIDEO_SENSOR_DAYNIGHT_THRES_OUT_STEP"},
   {61477, "CONFIG_VIDEO_SENSOR_STATUS_DAYNIGHT"},
   {61478, "CONFIG_VIDEO_SENSOR_MODULE_TYPE"},
   {61479, "CONFIG_VIDEO_SENSOR_FIRMWARE_REVISION"},
   {61480, "CONFIG_VIDEO_SENSOR_DYNAMO_REVISION"},
   {61481, "CONFIG_VIDEO_SENSOR_DYNAMITE_REVISION"},
   {61483, "CONFIG_VIDEO_SENSOR_STATUS_ORIENTATION_ANGLE"},
   {61484, "CONFIG_VIDEO_SENSOR_DAYNIGHT_GAIN_LIMIT_POSSIBLE_RANGE"},
   {61485, "CONFIG_VIDEO_SENSOR_DAYNIGHT_THRES_IN_POSSIBLE_RANGE"},
   {61486, "CONFIG_VIDEO_SENSOR_DAYNIGHT_THRES_OUT_POSSIBLE_RANGE"},
   {61487, "CONFIG_VIDEO_SENSOR_LOAD_FACTORY_DEFAULT"},
   {61488, "CONFIG_VIDEO_SENSOR_NTSC_50HZ_ENVIRONMENT"},
   {61489, "CONFIG_VIDEO_SENSOR_MAX_SLOW_SHUTTER_SPEED_LIMIT"},
   {61490, "CONFIG_VIDEO_SENSOR_DAYNIGHT_METER_DELAY"},
   {61491, "CONFIG_VIDEO_SENSOR_DAYNIGHT_VALIDATE_DELAY"},
   {61504, "CONFIG_VIDEO_SENSOR_C215_PRESET_POS_SELECT"},
   {61505, "CONFIG_VIDEO_SENSOR_C215_WHITE_BAL_MODE"},
   {61506, "CONFIG_VIDEO_SENSOR_C215_AGC_MODE"},
   {61507, "CONFIG_VIDEO_SENSOR_C215_BACKLIGHT_COMP_MODE"},
   {61508, "CONFIG_VIDEO_SENSOR_C215_BW_MODE"},
   {61509, "CONFIG_VIDEO_SENSOR_C215_ZOOM_POSITION"},
   {61510, "CONFIG_VIDEO_SENSOR_C215_FOCUS_POSITION"},
   {61511, "CONFIG_VIDEO_SENSOR_C215_FOCUS_FAR"},
   {61512, "CONFIG_VIDEO_SENSOR_C215_FOCUS_NEAR"},
   {61513, "CONFIG_VIDEO_SENSOR_C215_FOCUS_STOP"},
   {61514, "CONFIG_VIDEO_SENSOR_C215_ZOOM_TELE"},
   {61515, "CONFIG_VIDEO_SENSOR_C215_ZOOM_WIDE"},
   {61516, "CONFIG_VIDEO_SENSOR_C215_ZOOM_STOP"},
   {61517, "CONFIG_VIDEO_SENSOR_C215_ALL_STOP"},
   {61518, "CONFIG_VIDEO_SENSOR_C215_ENTER_MEMORY"},
   {61519, "CONFIG_VIDEO_SENSOR_C215_SAVE_AS_POSITION"},
   {61520, "CONFIG_VIDEO_SENSOR_C215_EXTEND_POSITION_CLEAR"},
   {61521, "CONFIG_VIDEO_SENSOR_C215_ALL_CLEAR"},
   {61522, "CONFIG_VIDEO_SENSOR_C215_MANUAL_WHITE_BALANCE"},
   {61523, "CONFIG_VIDEO_SENSOR_C215_SHUTTER_SPEED"},
   {0, NULL}
};

value_string_ext EVsipConfigItem_vals_ext = VALUE_STRING_EXT_INIT(EVsipConfigItem_vals);

const value_string EVsipEventType_vals[] =
{
   { 1, "Input Pin State Change"},
   { 2, "Analog Video Input State Change"},
   { 3, "Motion Detection State Change"},
   { 4, "Device Temperature Critical"},
   { 5, "Device Temperature Above Normal"},
   { 8, "Video Decoder Packet Loss"},
   { 9, "Video Decoder State"},
   {10, "Fatal Message Logged"},
   {12, "Last Event Repeated"},
   {16, "Camera Tampering Detection"},
   {0, NULL}
};

const value_string EVsipErrorCode_vals[] =
{
   {   0, "VSIP_ERROR_CODE_SUCCESS"},
   {   1, "VSIP_ERROR_CODE_FAILURE"},
   {   3, "VSIP_ERROR_CODE_UNKNOWNCAPABILITY"},
   {4096, "VSIP_ERROR_CODE_ALREADY_EXISTS"},
   {4097, "VSIP_ERROR_CODE_DOESNT_EXIST"},
   {4098, "VSIP_ERROR_CODE_INVALID_ARGUMENTS"},
   {4099, "VSIP_ERROR_CODE_MAXIMUM_REACHED"},
   {4100, "VSIP_ERROR_CODE_ALREADY_REMOVED"},
   {4101, "VSIP_ERROR_CODE_WRONG_DEVICE"},
   {8192, "VSIP_ERROR_CODE_CA_STATUS_BAD_SIGNAL"},
   {8193, "VSIP_ERROR_CODE_CA_STATUS_SEARCHING"},
   {8194, "VSIP_ERROR_CODE_CA_STATUS_KNOWN_VIEW"},
   {8195, "VSIP_ERROR_CODE_CA_STATUS_UNKNOWN_VIEW"},
   {8197, "VSIP_ERROR_CODE_CA_DISABLED"},
   {8198, "VSIP_ERROR_CODE_CA_NOT_STARTED"},
   {8208, "VSIP_ERROR_CODE_VIEW_NAME_ALREADY_EXISTS"},
   {8209, "VSIP_ERROR_CODE_CANNOT_DELETE_LAST_VIEW"},
   {8210, "VSIP_ERROR_CODE_RULE_NOT_SUPPORTED"},
   {8224, "VSIP_ERROR_CODE_XML_INVALID_FORMAT"},
   {8226, "VSIP_ERROR_CODE_XML_MISSING_ELEMENT"},
   {8227, "VSIP_ERROR_CODE_XML_INVALID_VALUE"},
   {12288, "VSIP_ERROR_CODE_FEATURE_NOT_SUPPORTED"},
   {0, NULL}
};

value_string_ext EVsipErrorCode_vals_ext = VALUE_STRING_EXT_INIT(EVsipErrorCode_vals);


/* Global module variables. */
static int proto_vsip = -1;

static int hf_vsip_ValueTypeString_Size = -1;
static int hf_vsip_ValueTypeBinary_Size = -1;
static int hf_vsip_PingReq_ReplyAddress = -1;
static int hf_vsip_PingReq_ReplyPort = -1;
static int hf_vsip_PingReq_ConnType = -1;
static int hf_vsip_PingResp_SuppConnTypes_VOLATILE = -1;
static int hf_vsip_PingResp_SuppConnTypes_RTP = -1;
static int hf_vsip_PingResp_SuppConnTypes_SSL = -1;
static int hf_vsip_PingResp_SuppConnTypes_UDP_BROADCAST = -1;
static int hf_vsip_PingResp_SuppConnTypes_TCP_CLIENT = -1;
static int hf_vsip_PingResp_SuppConnTypes_TCP_SERVER = -1;
static int hf_vsip_PingResp_SuppConnTypes_UDP_MULTICAST = -1;
static int hf_vsip_PingResp_SuppConnTypes_UDP_UNICAST = -1;
static int hf_vsip_PingResp_DeviceIP = -1;
static int hf_vsip_PingResp_DevicePort = -1;
static int hf_vsip_PingResp_SuppConnTypes = -1;
static int hf_vsip_ContentTypeSwitchReq_DeviceGUID = -1;
static int hf_vsip_PingResp_DeviceGUID = -1;
static int hf_vsip_PingResp_VendorID = -1;
static int hf_vsip_PingResp_ProductType = -1;
static int hf_vsip_PingResp_Status = -1;
static int hf_vsip_PingResp_SubtypeLen = -1;
static int hf_vsip_PingResp_Subtype = -1;
static int hf_vsip_ContentTypeSwitchReq_ApplicationGUID = -1;
static int hf_vsip_ContentTypeSwitchReq_ContentType = -1;
static int hf_vsip_ContentTypeSwitchResp_DeviceGUID = -1;
static int hf_vsip_ContentTypeSwitchResp_SwitchResult = -1;
static int hf_vsip_GetCapabilitiesReq_DisabledCapabilities = -1;
static int hf_vsip_GetCapabilitiesResp_CapabilityArray_EntityType = -1;
static int hf_vsip_GetCapabilitiesResp_CapabilityArray_CapabilityGUID = -1;
static int hf_vsip_GetCapabilitiesResp_CapabilityArray_VendorID = -1;
static int hf_vsip_GetCapabilitiesResp_CapabilityArray_VersionNumber = -1;
static int hf_vsip_GetCapabilitiesResp_CapabilityCount = -1;
static int hf_vsip_StartDevice_CapabilityGUID = -1;
static int hf_vsip_StartDevice_TargetAddress = -1;
static int hf_vsip_StartDevice_TargetPort = -1;
static int hf_vsip_StartDevice_LocalPort = -1;
static int hf_vsip_StartDevice_ConnectionType = -1;
static int hf_vsip_StartDeviceEx_CapabilityGUID = -1;
static int hf_vsip_StartDeviceEx_TargetAddress = -1;
static int hf_vsip_StartDeviceEx_TargetPort = -1;
static int hf_vsip_StartDeviceEx_LocalPort = -1;
static int hf_vsip_StartDeviceEx_ConnectionType = -1;
static int hf_vsip_StartDeviceEx_TargetGUID = -1;
static int hf_vsip_StopDevice_CapabilityGUID = -1;
static int hf_vsip_StopDeviceEx_CapabilityGUID = -1;
static int hf_vsip_StopDeviceEx_TargetGUID = -1;
static int hf_vsip_SetConfigReq_ConfigItemArray_Value_ShortValue = -1;
static int hf_vsip_SetConfigReq_ConfigItemArray_ValueType = -1;
static int hf_vsip_SetConfigReq_ConfigItemArray_ConfigItemID = -1;
static int hf_vsip_SetConfigReq_ConfigItemArray_Value_IntValue = -1;
static int hf_vsip_SetConfigReq_ConfigItemArray_Value_StringValue = -1;
static int hf_vsip_SetConfigReq_ConfigItemArray_Value_UintValue = -1;
static int hf_vsip_SetConfigReq_ConfigItemArray_Value_GuidValue = -1;
static int hf_vsip_SetConfigReq_ConfigItemArray_Value_FloatValue = -1;
static int hf_vsip_SetConfigReq_ConfigItemArray_Value_BinaryValue = -1;
static int hf_vsip_SetConfigReq_CapabilityGUID = -1;
static int hf_vsip_SetConfigReq_ConfigItemCount = -1;
static int hf_vsip_GetConfigReq_ConfigItemArray_ConfigItemID = -1;
static int hf_vsip_GetConfigReq_CapabilityGUID = -1;
static int hf_vsip_GetConfigReq_ConfigItemCount = -1;
static int hf_vsip_GetConfigResp_ConfigItemArray_ConfigItemID = -1;
static int hf_vsip_GetConfigResp_ConfigItemArray_ValueType = -1;
static int hf_vsip_GetConfigResp_ConfigItemArray_Value_CharValue = -1;
static int hf_vsip_GetConfigResp_ConfigItemArray_Value_ShortValue = -1;
static int hf_vsip_GetConfigResp_ConfigItemArray_Value_IntValue = -1;
static int hf_vsip_GetConfigResp_ConfigItemArray_Value_StringValue = -1;
static int hf_vsip_GetConfigResp_ConfigItemArray_Value_UintValue = -1;
static int hf_vsip_GetConfigResp_ConfigItemArray_Value_GuidValue = -1;
static int hf_vsip_GetConfigResp_ConfigItemArray_Value_FloatValue = -1;
static int hf_vsip_GetConfigResp_ConfigItemArray_Value_BinaryValue = -1;
static int hf_vsip_SetConfigReq_ConfigItemArray_Value_CharValue = -1;
static int hf_vsip_GetConfigResp_CapabilityGUID = -1;
static int hf_vsip_GetConfigResp_ConfigItemCount = -1;
static int hf_vsip_SendCommand_CapabilityGUID = -1;
static int hf_vsip_SendCommand_CommandCode = -1;
static int hf_vsip_SendCommand_Arg1 = -1;
static int hf_vsip_SendCommand_Arg2 = -1;
static int hf_vsip_SendCommandEx_AddArgsArray_ValueType = -1;
static int hf_vsip_SendCommandEx_AddArgsArray_Value_CharValue = -1;
static int hf_vsip_SendCommandEx_AddArgsArray_Value_ShortValue = -1;
static int hf_vsip_SendCommandEx_AddArgsArray_Value_IntValue = -1;
static int hf_vsip_SendCommandEx_AddArgsArray_Value_StringValue = -1;
static int hf_vsip_SendCommandEx_AddArgsArray_Value_UintValue = -1;
static int hf_vsip_SendCommandEx_AddArgsArray_Value_GuidValue = -1;
static int hf_vsip_SendCommandEx_AddArgsArray_Value_FloatValue = -1;
static int hf_vsip_SendCommandEx_AddArgsArray_Value_BinaryValue = -1;
static int hf_vsip_SendCommandEx_CapabilityGUID = -1;
static int hf_vsip_SendCommandEx_CommandCode = -1;
static int hf_vsip_SendCommandEx_Arg1 = -1;
static int hf_vsip_SendCommandEx_Arg2 = -1;
static int hf_vsip_SendCommandEx_NumAddArgs = -1;
static int hf_vsip_EventNotify_CapabilityGUID = -1;
static int hf_vsip_EventNotify_EventType = -1;
static int hf_vsip_EventNotify_EventArgument = -1;
static int hf_vsip_EventSubscribeReq_ReceiverAddress = -1;
static int hf_vsip_EventSubscribeReq_ReceiverPort = -1;
static int hf_vsip_EventSubscribeReq_ConnectionType = -1;
static int hf_vsip_EventSubscribeExReq_ReceiverAddress = -1;
static int hf_vsip_EventSubscribeExReq_ReceiverPort = -1;
static int hf_vsip_EventSubscribeExReq_ConnectionType = -1;
static int hf_vsip_EventSubscribeExReq_DestinationGUID = -1;
static int hf_vsip_ErrorResponse_RequestMessageType = -1;
static int hf_vsip_ErrorResponse_StatusCode = -1;
static int hf_vsip_ErrorVAResponse_AddArgsArray_ValueType = -1;
static int hf_vsip_ErrorVAResponse_AddArgsArray_Value_CharValue = -1;
static int hf_vsip_ErrorVAResponse_AddArgsArray_Value_ShortValue = -1;
static int hf_vsip_ErrorVAResponse_AddArgsArray_Value_IntValue = -1;
static int hf_vsip_ErrorVAResponse_AddArgsArray_Value_StringValue = -1;
static int hf_vsip_ErrorVAResponse_AddArgsArray_Value_UintValue = -1;
static int hf_vsip_ErrorVAResponse_AddArgsArray_Value_GuidValue = -1;
static int hf_vsip_ErrorVAResponse_AddArgsArray_Value_FloatValue = -1;
static int hf_vsip_ErrorVAResponse_AddArgsArray_Value_BinaryValue = -1;
static int hf_vsip_ErrorVAResponse_NumAddArgs = -1;
static int hf_vsip_Version = -1;
static int hf_vsip_Type = -1;
static int hf_vsip_TransacId = -1;
static int hf_vsip_PacketSize = -1;

static int ett_vsipValueTypeString = -1;
static int ett_vsipValueTypeBinary = -1;
static int ett_vsipPingReq = -1;
static int ett_vsipPingResp_SuppConnTypes = -1;
static int ett_vsipPingResp = -1;
static int ett_vsipContentTypeSwitchReq = -1;
static int ett_vsipContentTypeSwitchResp = -1;
static int ett_vsipGetCapabilitiesReq = -1;
static int ett_vsipGetCapabilitiesResp_CapabilityArray = -1;
static int ett_vsipGetCapabilitiesResp = -1;
static int ett_vsipStartDevice = -1;
static int ett_vsipStartDeviceEx = -1;
static int ett_vsipStopDevice = -1;
static int ett_vsipStopDeviceEx = -1;
static int ett_vsipSetConfigReq_ConfigItemArray = -1;
static int ett_vsipSetConfigReq = -1;
static int ett_vsipGetConfigReq_ConfigItemArray = -1;
static int ett_vsipGetConfigReq = -1;
static int ett_vsipGetConfigResp_ConfigItemArray = -1;
static int ett_vsipGetConfigResp = -1;
static int ett_vsipSendCommand = -1;
static int ett_vsipSendCommandEx_AddArgsArray = -1;
static int ett_vsipSendCommandEx = -1;
static int ett_vsipEventNotify = -1;
static int ett_vsipEventSubscribeReq = -1;
static int ett_vsipEventSubscribeExReq = -1;
static int ett_vsipErrorResponse = -1;
static int ett_vsipErrorVAResponse_AddArgsArray = -1;
static int ett_vsipErrorVAResponse = -1;
static int ett_vsip = -1;


static guint32 vsip_ValueTypeString(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int hf_string)
{
   int soffset = offset;
   guint16 length;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_vsipValueTypeString, &ti, "ValueTypeString");

   length = tvb_get_ntohs(tvb, offset);
   proto_tree_add_item(tree, hf_vsip_ValueTypeString_Size, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   if (length > 0)
   {
       proto_tree_add_item(tree, hf_string, tvb, offset, length, ENC_ASCII|ENC_NA);
       offset += length;
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_ValueTypeBinary(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int hf_bin)
{
   int soffset = offset;
   guint32 length;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_vsipValueTypeBinary, &ti, "Binary");

   length = tvb_get_ntohl(tvb, offset);
   proto_tree_add_item(tree, hf_vsip_ValueTypeBinary_Size, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   if (length > 0)
   {
       proto_tree_add_item(tree, hf_bin, tvb, offset, length, ENC_NA);
       offset += length;
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_PingReq(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 7, ett_vsipPingReq, NULL, "PingReq");

   proto_tree_add_item(tree, hf_vsip_PingReq_ReplyAddress, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   proto_tree_add_item(tree, hf_vsip_PingReq_ReplyPort, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_PingReq_ConnType, tvb, offset, 1, ENC_BIG_ENDIAN);
   offset += 1;

   return offset - soffset;
}

static guint32 vsip_PingResp(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint16 len;
   proto_item *ti;
   const int  *supp_conn_types[] = {
        &hf_vsip_PingResp_SuppConnTypes_VOLATILE,
        &hf_vsip_PingResp_SuppConnTypes_RTP,
        &hf_vsip_PingResp_SuppConnTypes_SSL,
        &hf_vsip_PingResp_SuppConnTypes_UDP_BROADCAST,
        &hf_vsip_PingResp_SuppConnTypes_TCP_CLIENT,
        &hf_vsip_PingResp_SuppConnTypes_TCP_SERVER,
        &hf_vsip_PingResp_SuppConnTypes_UDP_MULTICAST,
        &hf_vsip_PingResp_SuppConnTypes_UDP_UNICAST,
        NULL
   };

   tree = proto_tree_add_subtree(tree, tvb, offset, 30, ett_vsipPingResp, &ti, "PingResp");

   proto_tree_add_item(tree, hf_vsip_PingResp_DeviceIP, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   proto_tree_add_item(tree, hf_vsip_PingResp_DevicePort, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_bitmask(tree, tvb, offset, hf_vsip_PingResp_SuppConnTypes, ett_vsipPingResp_SuppConnTypes, supp_conn_types, ENC_NA);
   offset += 1;

   proto_tree_add_item(tree, hf_vsip_PingResp_DeviceGUID, tvb, offset, 16, ENC_NA);
   offset += 16;

   proto_tree_add_item(tree, hf_vsip_PingResp_VendorID, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_PingResp_ProductType, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_PingResp_Status, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 1;

   len = tvb_get_ntohs(tvb, offset);
   proto_tree_add_uint(tree, hf_vsip_PingResp_SubtypeLen, tvb, offset, 2, len);
   offset += 2;

   if (len > 0)
   {
       proto_tree_add_item(tree, hf_vsip_PingResp_Subtype, tvb, offset, len, ENC_ASCII|ENC_NA);
       offset += len;
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_ContentTypeSwitchReq(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 33, ett_vsipContentTypeSwitchReq, NULL, "ContentTypeSwitchReq");
   proto_tree_add_item(tree, hf_vsip_ContentTypeSwitchReq_ApplicationGUID, tvb, offset, 16, ENC_NA);
   offset += 16;

   proto_tree_add_item(tree, hf_vsip_ContentTypeSwitchReq_ContentType, tvb, offset, 1, ENC_NA);
   offset++;

   proto_tree_add_item(tree, hf_vsip_ContentTypeSwitchReq_DeviceGUID, tvb, offset, 16, ENC_NA);
   offset += 16;

   return offset - soffset;
}

static guint32 vsip_ContentTypeSwitchResp(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 17, ett_vsipContentTypeSwitchResp, NULL, "ContentTypeSwitchResp");

   proto_tree_add_item(tree, hf_vsip_ContentTypeSwitchResp_DeviceGUID, tvb, offset, 16, ENC_NA);
   offset += 16;
   proto_tree_add_item(tree, hf_vsip_ContentTypeSwitchResp_SwitchResult, tvb, offset, 1, ENC_NA);

   return offset - soffset;
}

static guint32 vsip_GetCapabilitiesReq(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_vsipGetCapabilitiesReq, NULL, "GetCapabilitiesReq");

   proto_tree_add_item(tree, hf_vsip_GetCapabilitiesReq_DisabledCapabilities, tvb, offset, 1, ENC_NA);
   offset++;

   return offset - soffset;
}

static guint32 vsip_GetCapabilitiesResp_CapabilityArray(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 21, ett_vsipGetCapabilitiesResp_CapabilityArray, NULL, "CapabilityArray");

   proto_tree_add_item(tree, hf_vsip_GetCapabilitiesResp_CapabilityArray_EntityType, tvb, offset, 1, ENC_NA);
   offset++;

   proto_tree_add_item(tree, hf_vsip_GetCapabilitiesResp_CapabilityArray_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   proto_tree_add_item(tree, hf_vsip_GetCapabilitiesResp_CapabilityArray_VendorID, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_GetCapabilitiesResp_CapabilityArray_VersionNumber, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   return offset - soffset;
}

static guint32 vsip_GetCapabilitiesResp(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint16 count;
   guint32 i;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_vsipGetCapabilitiesResp, &ti, "GetCapabilitiesResp");

   count = tvb_get_ntohs(tvb, offset);
   proto_tree_add_uint(tree, hf_vsip_GetCapabilitiesResp_CapabilityCount, tvb, offset, 2, count);
   offset += 2;

   for(i = 0; i < count; ++i)
   {
       offset += vsip_GetCapabilitiesResp_CapabilityArray(tree, pinfo, tvb, offset);
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_StartDevice(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 25, ett_vsipStartDevice, NULL, "StartDevice");

   proto_tree_add_item(tree, hf_vsip_StartDevice_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   proto_tree_add_item(tree, hf_vsip_StartDevice_TargetAddress, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   proto_tree_add_item(tree, hf_vsip_StartDevice_TargetPort, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_StartDevice_LocalPort, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_StartDevice_ConnectionType, tvb, offset, 1, ENC_BIG_ENDIAN);
   offset += 1;

   return offset - soffset;
}


static guint32 vsip_StartDeviceEx(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 41, ett_vsipStartDeviceEx, NULL, "StartDeviceEx");

   proto_tree_add_item(tree, hf_vsip_StartDeviceEx_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   proto_tree_add_item(tree, hf_vsip_StartDeviceEx_TargetAddress, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   proto_tree_add_item(tree, hf_vsip_StartDeviceEx_TargetPort, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_StartDeviceEx_LocalPort, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_StartDeviceEx_ConnectionType, tvb, offset, 1, ENC_BIG_ENDIAN);
   offset++;

   proto_tree_add_item(tree, hf_vsip_StartDeviceEx_TargetGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   return offset - soffset;
}


static guint32 vsip_StopDevice(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_vsipStopDevice, NULL, "StopDevice");

   proto_tree_add_item(tree, hf_vsip_StopDevice_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   return offset - soffset;
}

static guint32 vsip_StopDeviceEx(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 32, ett_vsipStopDeviceEx, NULL, "StopDeviceEx");

   proto_tree_add_item(tree, hf_vsip_StopDeviceEx_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   proto_tree_add_item(tree, hf_vsip_StopDeviceEx_TargetGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   return offset - soffset;
}

static guint32 vsip_SetConfigReq_ConfigItemArray(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint8 type;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_vsipSetConfigReq_ConfigItemArray, &ti, "ConfigItemArray");

   proto_tree_add_item(tree, hf_vsip_SetConfigReq_ConfigItemArray_ConfigItemID, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   type = tvb_get_guint8(tvb, offset);
   proto_tree_add_item(tree, hf_vsip_SetConfigReq_ConfigItemArray_ValueType, tvb, offset, 1, ENC_BIG_ENDIAN);
   offset++;

   switch(type)
   {
    case 1:
       proto_tree_add_item(tree, hf_vsip_SetConfigReq_ConfigItemArray_Value_CharValue, tvb, offset, 1, ENC_NA);
       offset++;
       break;

    case 2:
       proto_tree_add_item(tree, hf_vsip_SetConfigReq_ConfigItemArray_Value_ShortValue, tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;
       break;

    case 3:
       proto_tree_add_item(tree, hf_vsip_SetConfigReq_ConfigItemArray_Value_IntValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 4:
       offset += vsip_ValueTypeString(tree, pinfo, tvb, offset, hf_vsip_SetConfigReq_ConfigItemArray_Value_StringValue);
       break;

    case 5:
       proto_tree_add_item(tree, hf_vsip_SetConfigReq_ConfigItemArray_Value_UintValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 6:
       proto_tree_add_item(tree, hf_vsip_SetConfigReq_ConfigItemArray_Value_GuidValue, tvb, offset, 16, ENC_BIG_ENDIAN);
       offset += 16;
       break;

    case 7:
       proto_tree_add_item(tree, hf_vsip_SetConfigReq_ConfigItemArray_Value_FloatValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 8:
       offset += vsip_ValueTypeBinary(tree, pinfo, tvb, offset, hf_vsip_SetConfigReq_ConfigItemArray_Value_BinaryValue);
       break;

    default:
      break;
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}


static guint32 vsip_SetConfigReq(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint16 count;
   guint32 i;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 18, ett_vsipSetConfigReq, &ti, "SetConfigReq");

   proto_tree_add_item(tree, hf_vsip_SetConfigReq_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   count = tvb_get_ntohs(tvb, offset);
   proto_tree_add_item(tree, hf_vsip_SetConfigReq_ConfigItemCount, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   for(i = 0; i < count; ++i)
   {
       offset += vsip_SetConfigReq_ConfigItemArray(tree, pinfo, tvb, offset);
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_GetConfigReq_ConfigItemArray(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_vsipGetConfigReq_ConfigItemArray, NULL, "ConfigItemArray");

   proto_tree_add_item(tree, hf_vsip_GetConfigReq_ConfigItemArray_ConfigItemID, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   return offset - soffset;
}

static guint32 vsip_GetConfigReq(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint16 count;
   guint32 i;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 18, ett_vsipGetConfigReq, &ti, "GetConfigReq");

   proto_tree_add_item(tree, hf_vsip_GetConfigReq_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   count = tvb_get_ntohs(tvb, offset);
   proto_tree_add_item(tree, hf_vsip_GetConfigReq_ConfigItemCount, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   for(i = 0; i < count; ++i)
   {
       offset += vsip_GetConfigReq_ConfigItemArray(tree, pinfo, tvb, offset);
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_GetConfigResp_ConfigItemArray(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint8 type;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_vsipGetConfigResp_ConfigItemArray, &ti, "ConfigItemArray");

   proto_tree_add_item(tree, hf_vsip_GetConfigResp_ConfigItemArray_ConfigItemID, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   type = tvb_get_guint8(tvb, offset);
   proto_tree_add_item(tree, hf_vsip_GetConfigResp_ConfigItemArray_ValueType, tvb, offset, 1, ENC_NA);
   offset++;

   switch(type)
   {
    case 1:
       proto_tree_add_item(tree, hf_vsip_GetConfigResp_ConfigItemArray_Value_CharValue, tvb, offset, 1, ENC_NA);
       offset++;
       break;

    case 2:
       proto_tree_add_item(tree, hf_vsip_GetConfigResp_ConfigItemArray_Value_ShortValue, tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;
       break;

    case 3:
       proto_tree_add_item(tree, hf_vsip_GetConfigResp_ConfigItemArray_Value_IntValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 4:
       offset += vsip_ValueTypeString(tree, pinfo, tvb, offset, hf_vsip_GetConfigResp_ConfigItemArray_Value_StringValue);
       break;

    case 5:
       proto_tree_add_item(tree, hf_vsip_GetConfigResp_ConfigItemArray_Value_UintValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 6:
       proto_tree_add_item(tree, hf_vsip_GetConfigResp_ConfigItemArray_Value_GuidValue, tvb, offset, 16, ENC_BIG_ENDIAN);
       offset += 16;
       break;

    case 7:
       proto_tree_add_item(tree, hf_vsip_GetConfigResp_ConfigItemArray_Value_FloatValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 8:
       offset += vsip_ValueTypeBinary(tree, pinfo, tvb, offset, hf_vsip_GetConfigResp_ConfigItemArray_Value_BinaryValue);
       break;

    default:
       break;
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_GetConfigResp(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint16 count;
   guint32 i;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 18, ett_vsipGetConfigResp, &ti, "GetConfigResp");

   proto_tree_add_item(tree, hf_vsip_GetConfigResp_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   count = tvb_get_ntohs(tvb, offset);
   proto_tree_add_uint(tree, hf_vsip_GetConfigResp_ConfigItemCount, tvb, offset, 2, count);
   offset += 2;

   for(i = 0; i < count; ++i)
   {
       offset += vsip_GetConfigResp_ConfigItemArray(tree, pinfo, tvb, offset);
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_SendCommand(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 25, ett_vsipSendCommand, &ti, "SendCommand");

   proto_tree_add_item(tree, hf_vsip_SendCommand_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   proto_tree_add_item(tree, hf_vsip_SendCommand_CommandCode, tvb, offset, 1, ENC_NA);
   offset++;

   proto_tree_add_item(tree, hf_vsip_SendCommand_Arg1, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   proto_tree_add_item(tree, hf_vsip_SendCommand_Arg2, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   return offset - soffset;
}

static guint32 vsip_SendCommandEx_AddArgsArray(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint8 type;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_vsipSendCommandEx_AddArgsArray, &ti, "AddArgsArray");

   type = tvb_get_guint8(tvb, offset);
   proto_tree_add_item(tree, hf_vsip_SendCommandEx_AddArgsArray_ValueType, tvb, offset, 1, ENC_NA);
   offset++;

   switch(type)
   {
    case 1:
       proto_tree_add_item(tree, hf_vsip_SendCommandEx_AddArgsArray_Value_CharValue, tvb, offset, 1, ENC_NA);
       offset++;
       break;

    case 2:
       proto_tree_add_item(tree, hf_vsip_SendCommandEx_AddArgsArray_Value_ShortValue, tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;
       break;

    case 3:
       proto_tree_add_item(tree, hf_vsip_SendCommandEx_AddArgsArray_Value_IntValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 4:
       offset += vsip_ValueTypeString(tree, pinfo, tvb, offset, hf_vsip_SendCommandEx_AddArgsArray_Value_StringValue);
       break;

    case 5:
       proto_tree_add_item(tree, hf_vsip_SendCommandEx_AddArgsArray_Value_UintValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 6:
       proto_tree_add_item(tree, hf_vsip_SendCommandEx_AddArgsArray_Value_GuidValue, tvb, offset, 16, ENC_BIG_ENDIAN);
       offset += 16;
       break;

    case 7:
       proto_tree_add_item(tree, hf_vsip_SendCommandEx_AddArgsArray_Value_FloatValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 8:
       offset += vsip_ValueTypeBinary(tree, pinfo, tvb, offset, hf_vsip_SendCommandEx_AddArgsArray_Value_BinaryValue);
       break;

    default:
      break;
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_SendCommandEx(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint16 count;
   guint32 i;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 27, ett_vsipSendCommandEx, &ti, "SendCommandEx");

   proto_tree_add_item(tree, hf_vsip_SendCommandEx_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   proto_tree_add_item(tree, hf_vsip_SendCommandEx_CommandCode, tvb, offset, 1, ENC_NA);
   offset++;

   proto_tree_add_item(tree, hf_vsip_SendCommandEx_Arg1, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   proto_tree_add_item(tree, hf_vsip_SendCommandEx_Arg2, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   count = tvb_get_ntohs(tvb, offset);
   proto_tree_add_uint(tree, hf_vsip_SendCommandEx_NumAddArgs, tvb, offset, 2, count);
   offset += 2;

   for(i = 0; i < count; ++i)
   {
       offset += vsip_SendCommandEx_AddArgsArray(tree, pinfo, tvb, offset);
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_EventNotify(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 22, ett_vsipEventNotify, NULL, "EventNotify");

   proto_tree_add_item(tree, hf_vsip_EventNotify_CapabilityGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   proto_tree_add_item(tree, hf_vsip_EventNotify_EventType, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_EventNotify_EventArgument, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   return offset - soffset;
}

static guint32 vsip_EventSubscribeReq(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 7, ett_vsipEventSubscribeReq, NULL, "EventSubscribeReq");

   proto_tree_add_item(tree, hf_vsip_EventSubscribeReq_ReceiverAddress, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   proto_tree_add_item(tree, hf_vsip_EventSubscribeReq_ReceiverPort, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_EventSubscribeReq_ConnectionType, tvb, offset, 1, ENC_BIG_ENDIAN);
   offset++;

   return offset - soffset;
}

static guint32 vsip_EventSubscribeExReq(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 23, ett_vsipEventSubscribeExReq, NULL, "EventSubscribeExReq");

   proto_tree_add_item(tree, hf_vsip_EventSubscribeExReq_ReceiverAddress, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   proto_tree_add_item(tree, hf_vsip_EventSubscribeExReq_ReceiverPort, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;

   proto_tree_add_item(tree, hf_vsip_EventSubscribeExReq_ConnectionType, tvb, offset, 1, ENC_BIG_ENDIAN);
   offset++;

   proto_tree_add_item(tree, hf_vsip_EventSubscribeExReq_DestinationGUID, tvb, offset, 16, ENC_BIG_ENDIAN);
   offset += 16;

   return offset - soffset;
}

static guint32 vsip_ErrorResponse(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
   int soffset = offset;

   tree = proto_tree_add_subtree(tree, tvb, offset, 5, ett_vsipErrorResponse, NULL, "ErrorResponse");

   proto_tree_add_item(tree, hf_vsip_ErrorResponse_RequestMessageType, tvb, offset, 1, ENC_NA);
   offset++;

   proto_tree_add_item(tree, hf_vsip_ErrorResponse_StatusCode, tvb, offset, 4, ENC_BIG_ENDIAN);
   offset += 4;

   return offset - soffset;
}

static guint32 vsip_ErrorVAResponse_AddArgsArray(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint8 type;
   proto_item* ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_vsipErrorVAResponse_AddArgsArray, &ti, "AddArgsArray");

   type = tvb_get_guint8(tvb, offset);
   proto_tree_add_item(tree, hf_vsip_ErrorVAResponse_AddArgsArray_ValueType, tvb, offset, 1, ENC_NA);
   offset++;

   switch(type)
   {
    case 1:
       proto_tree_add_item(tree, hf_vsip_ErrorVAResponse_AddArgsArray_Value_CharValue, tvb, offset, 1, ENC_NA);
       offset++;
       break;

    case 2:
       proto_tree_add_item(tree, hf_vsip_ErrorVAResponse_AddArgsArray_Value_ShortValue, tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;
       break;

    case 3:
       proto_tree_add_item(tree, hf_vsip_ErrorVAResponse_AddArgsArray_Value_IntValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 4:
       offset += vsip_ValueTypeString(tree, pinfo, tvb, offset, hf_vsip_ErrorVAResponse_AddArgsArray_Value_StringValue);
       break;

    case 5:
       proto_tree_add_item(tree, hf_vsip_ErrorVAResponse_AddArgsArray_Value_UintValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 6:
       proto_tree_add_item(tree, hf_vsip_ErrorVAResponse_AddArgsArray_Value_GuidValue, tvb, offset, 16, ENC_BIG_ENDIAN);
       offset += 16;
       break;

    case 7:
       proto_tree_add_item(tree, hf_vsip_ErrorVAResponse_AddArgsArray_Value_FloatValue, tvb, offset, 4, ENC_BIG_ENDIAN);
       offset += 4;
       break;

    case 8:
       offset += vsip_ValueTypeBinary(tree, pinfo, tvb, offset, hf_vsip_ErrorVAResponse_AddArgsArray_Value_BinaryValue);
       break;

    default:
      break;
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_ErrorVAResponse(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
   int soffset = offset;
   guint16 count;
   guint32 i;
   proto_item *ti;

   tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_vsipErrorVAResponse, &ti, "ErrorVAResponse");

   offset += vsip_ErrorResponse(tree, pinfo, tvb, offset);

   count = tvb_get_ntohs(tvb, offset);
   proto_tree_add_uint(tree, hf_vsip_ErrorVAResponse_NumAddArgs, tvb, offset, 2, count);
   offset += 2;

   for(i = 0; i < count; ++i)
   {
       offset += vsip_ErrorVAResponse_AddArgsArray(tree, pinfo, tvb, offset);
   }

   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}

static guint32 vsip_dissect_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree  *tree)
{
    int soffset = offset;
    guint16 version;
    guint8 type;
    proto_item *ti;

    version = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_vsip_Version, tvb, offset, 2, version);
    offset += 2;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_vsip_Type, tvb, offset, 1, type);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(type, &EVsipMessageType_vals_ext, "Unknown") );
    offset++;

    proto_tree_add_item(tree, hf_vsip_TransacId, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (version == 257)
    {
        proto_tree_add_item(tree, hf_vsip_PacketSize, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    else if(version == 256)
    {
        proto_tree_add_item(tree, hf_vsip_PacketSize, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    switch(type)
    {
       case 1:
         offset += vsip_PingReq(tree, pinfo, tvb, offset);
         break;

       case 2:
         offset += vsip_PingResp(tree, pinfo, tvb, offset);
         break;

       case 19:
         offset += vsip_ContentTypeSwitchReq(tree, pinfo, tvb, offset);
         break;

       case 20:
         offset += vsip_ContentTypeSwitchResp(tree, pinfo, tvb, offset);
         break;

       case 3:
         offset += vsip_GetCapabilitiesReq(tree, pinfo, tvb, offset);
         break;

       case 4:
         offset += vsip_GetCapabilitiesResp(tree, pinfo, tvb, offset);
         break;

       case 5:
         offset += vsip_StartDevice(tree, pinfo, tvb, offset);
         break;

       case 21:
         offset += vsip_StartDeviceEx(tree, pinfo, tvb, offset);
         break;

       case 6:
         offset += vsip_StopDevice(tree, pinfo, tvb, offset);
         break;

       case 22:
         offset += vsip_StopDeviceEx(tree, pinfo, tvb, offset);
         break;

       case 7:
         offset += vsip_SetConfigReq(tree, pinfo, tvb, offset);
         break;

       case 8:
         offset += vsip_GetConfigReq(tree, pinfo, tvb, offset);
         break;

       case 9:
         offset += vsip_GetConfigResp(tree, pinfo, tvb, offset);
         break;

       case 10:
         offset += vsip_SendCommand(tree, pinfo, tvb, offset);
         break;

       case 24:
         offset += vsip_SendCommandEx(tree, pinfo, tvb, offset);
         break;

       case 11:
         offset += vsip_EventNotify(tree, pinfo, tvb, offset);
         break;

       case 12:
         offset += vsip_EventSubscribeReq(tree, pinfo, tvb, offset);
         break;

       case 23:
         offset += vsip_EventSubscribeExReq(tree, pinfo, tvb, offset);
         break;

       case 13:
         offset += vsip_ErrorResponse(tree, pinfo, tvb, offset);
         break;

       case 48:
         offset += vsip_ErrorVAResponse(tree, pinfo, tvb, offset);
         break;

       default:
         break;
   }

   ti = proto_tree_get_parent(tree);
   proto_item_set_len(ti, offset - soffset);

   return offset - soffset;
}


static int dissect_vsip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    guint16    version;

    /* Make sure we have a supported version */
    version = tvb_get_ntohs(tvb, 0);
    if ((version != 0x0100) && (version != 0x0101))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VSIP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vsip, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_vsip);

    /* call the tsnc generated dissect function. */
    return vsip_dissect_pdu(tvb, 0, pinfo, tree);
}

static void
vsip_fmt_revision( gchar *result, guint32 revision )
{
   g_snprintf( result, ITEM_LABEL_LENGTH, "%d.%02d", (guint8)(( revision & 0xFF00 ) >> 8), (guint8)(revision & 0xFF) );
}

void proto_register_vsip(void)
{
    /* Setup protocol subtree array */
    static int *ett[] = {
       &ett_vsipValueTypeString,
       &ett_vsipValueTypeBinary,
       &ett_vsipPingReq,
       &ett_vsipPingResp_SuppConnTypes,
       &ett_vsipPingResp,
       &ett_vsipContentTypeSwitchReq,
       &ett_vsipContentTypeSwitchResp,
       &ett_vsipGetCapabilitiesReq,
       &ett_vsipGetCapabilitiesResp_CapabilityArray,
       &ett_vsipGetCapabilitiesResp,
       &ett_vsipStartDevice,
       &ett_vsipStartDeviceEx,
       &ett_vsipStopDevice,
       &ett_vsipStopDeviceEx,
       &ett_vsipSetConfigReq_ConfigItemArray,
       &ett_vsipSetConfigReq,
       &ett_vsipGetConfigReq_ConfigItemArray,
       &ett_vsipGetConfigReq,
       &ett_vsipGetConfigResp_ConfigItemArray,
       &ett_vsipGetConfigResp,
       &ett_vsipSendCommand,
       &ett_vsipSendCommandEx_AddArgsArray,
       &ett_vsipSendCommandEx,
       &ett_vsipEventNotify,
       &ett_vsipEventSubscribeReq,
       &ett_vsipEventSubscribeExReq,
       &ett_vsipErrorResponse,
       &ett_vsipErrorVAResponse_AddArgsArray,
       &ett_vsipErrorVAResponse,
       &ett_vsip
    };

    static hf_register_info hf[] = {
       { &hf_vsip_ValueTypeBinary_Size,
            { "Size", "vsip.ValueTypeBinary.Size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ValueTypeString_Size,
          { "Size", "vsip.ValueTypeString.Size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingReq_ReplyAddress,
          { "ReplyAddress", "vsip.PingReq.ReplyAddress", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingReq_ReplyPort,
          { "ReplyPort", "vsip.PingReq.ReplyPort", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingReq_ConnType,
          { "ConnType", "vsip.PingReq.ConnType", FT_UINT8, BASE_HEX,
             VALS(EVsipConnectionType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_PingResp_DeviceIP,
          { "DeviceIP", "vsip.PingResp.DeviceIP", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingResp_DevicePort,
          { "DevicePort", "vsip.PingResp.DevicePort", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingResp_DeviceGUID,
          { "DeviceGUID", "vsip.PingResp.DeviceGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingResp_VendorID,
          { "VendorID", "vsip.PingResp.VendorID", FT_UINT16, BASE_DEC,
             VALS(EVsipVendorID_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_PingResp_ProductType,
          { "ProductType", "vsip.PingResp.ProductType", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingResp_Status,
          { "Status", "vsip.PingResp.Status", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingResp_SubtypeLen,
          { "SubtypeLen", "vsip.PingResp.SubtypeLen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingResp_Subtype,
          { "Subtype", "vsip.PingResp.Subtype", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingResp_SuppConnTypes,
          { "SuppConnTypes", "vsip.PingResp.SuppConnTypes", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PingResp_SuppConnTypes_VOLATILE,
          { "VOLATILE", "vsip.PingResp_SuppConnTypes.VOLATILE", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80, NULL, HFILL } },
       { &hf_vsip_PingResp_SuppConnTypes_RTP,
          { "RTP", "vsip.PingResp_SuppConnTypes.RTP", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40, NULL, HFILL } },
       { &hf_vsip_PingResp_SuppConnTypes_SSL,
          { "SSL", "vsip.PingResp_SuppConnTypes.SSL", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL } },
       { &hf_vsip_PingResp_SuppConnTypes_UDP_BROADCAST,
          { "UDP_BROADCAST", "vsip.PingResp_SuppConnTypes.UDP_BROADCAST", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL } },
       { &hf_vsip_PingResp_SuppConnTypes_TCP_CLIENT,
          { "TCP_CLIENT", "vsip.PingResp_SuppConnTypes.TCP_CLIENT", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08, NULL, HFILL } },
       { &hf_vsip_PingResp_SuppConnTypes_TCP_SERVER,
          { "TCP_SERVER", "vsip.PingResp_SuppConnTypes.TCP_SERVER", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL } },
       { &hf_vsip_PingResp_SuppConnTypes_UDP_MULTICAST,
          { "UDP_MULTICAST", "vsip.PingResp_SuppConnTypes.UDP_MULTICAST", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL } },
       { &hf_vsip_PingResp_SuppConnTypes_UDP_UNICAST,
          { "UDP_UNICAST", "vsip.PingResp_SuppConnTypes.UDP_UNICAST", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL } },
       { &hf_vsip_ContentTypeSwitchReq_ApplicationGUID,
          { "ApplicationGUID", "vsip.ContentTypeSwitchReq.ApplicationGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ContentTypeSwitchReq_ContentType,
          { "ContentType", "vsip.ContentTypeSwitchReq.ContentType", FT_UINT8, BASE_DEC,
             VALS(EVsipContentType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_ContentTypeSwitchReq_DeviceGUID,
          { "DeviceGUID", "vsip.ContentTypeSwitchReq.DeviceGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ContentTypeSwitchResp_DeviceGUID,
          { "DeviceGUID", "vsip.ContentTypeSwitchResp.DeviceGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ContentTypeSwitchResp_SwitchResult,
          { "SwitchResult", "vsip.ContentTypeSwitchResp.SwitchResult", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetCapabilitiesReq_DisabledCapabilities,
          { "DisabledCapabilities", "vsip.GetCapabilitiesReq.DisabledCapabilities", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetCapabilitiesResp_CapabilityArray_EntityType,
          { "EntityType", "vsip.GetCapabilitiesResp_CapabilityArray.EntityType", FT_UINT8, BASE_DEC,
             VALS(EVsipEntityType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_GetCapabilitiesResp_CapabilityArray_CapabilityGUID,
          { "CapabilityGUID", "vsip.GetCapabilitiesResp_CapabilityArray.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetCapabilitiesResp_CapabilityArray_VendorID,
          { "VendorID", "vsip.GetCapabilitiesResp_CapabilityArray.VendorID", FT_UINT16, BASE_DEC,
             VALS(EVsipVendorID_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_GetCapabilitiesResp_CapabilityArray_VersionNumber,
          { "VersionNumber", "vsip.GetCapabilitiesResp_CapabilityArray.VersionNumber", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetCapabilitiesResp_CapabilityCount,
          { "CapabilityCount", "vsip.GetCapabilitiesResp.CapabilityCount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StartDevice_CapabilityGUID,
          { "CapabilityGUID", "vsip.StartDevice.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StartDevice_TargetAddress,
          { "TargetAddress", "vsip.StartDevice.TargetAddress", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StartDevice_TargetPort,
          { "TargetPort", "vsip.StartDevice.TargetPort", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StartDevice_LocalPort,
          { "LocalPort", "vsip.StartDevice.LocalPort", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StartDevice_ConnectionType,
          { "ConnectionType", "vsip.StartDevice.ConnectionType", FT_UINT8, BASE_DEC,
             VALS(EVsipConnectionType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_StartDeviceEx_CapabilityGUID,
          { "CapabilityGUID", "vsip.StartDeviceEx.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StartDeviceEx_TargetAddress,
          { "TargetAddress", "vsip.StartDeviceEx.TargetAddress", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StartDeviceEx_TargetPort,
          { "TargetPort", "vsip.StartDeviceEx.TargetPort", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StartDeviceEx_LocalPort,
          { "LocalPort", "vsip.StartDeviceEx.LocalPort", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StartDeviceEx_ConnectionType,
          { "ConnectionType", "vsip.StartDeviceEx.ConnectionType", FT_UINT8, BASE_DEC,
             VALS(EVsipConnectionType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_StartDeviceEx_TargetGUID,
          { "TargetGUID", "vsip.StartDeviceEx.TargetGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StopDevice_CapabilityGUID,
          { "CapabilityGUID", "vsip.StopDevice.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StopDeviceEx_CapabilityGUID,
          { "CapabilityGUID", "vsip.StopDeviceEx.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_StopDeviceEx_TargetGUID,
          { "TargetGUID", "vsip.StopDeviceEx.TargetGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemArray_ConfigItemID,
          { "ConfigItemID", "vsip.SetConfigReq_ConfigItemArray.ConfigItemID", FT_UINT16, BASE_DEC|BASE_EXT_STRING,
             &EVsipConfigItem_vals_ext, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemArray_ValueType,
          { "ValueType", "vsip.SetConfigReq_ConfigItemArray.ValueType", FT_UINT8, BASE_DEC,
             VALS(EVsipValueType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemArray_Value_CharValue,
          { "CharValue", "vsip.SetConfigReq_ConfigItemArray.CharValue",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemArray_Value_ShortValue,
          { "ShortValue", "vsip.SetConfigReq_ConfigItemArray.ShortValue",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemArray_Value_IntValue,
          { "IntValue", "vsip.SetConfigReq_ConfigItemArray.IntValue", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemArray_Value_StringValue,
          { "StringValue", "vsip.SetConfigReq_ConfigItemArray.StringValue", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemArray_Value_UintValue,
          { "UintValue", "vsip.SetConfigReq_ConfigItemArray.UintValue", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemArray_Value_GuidValue,
          { "GuidValue", "vsip.SetConfigReq_ConfigItemArray.GuidValue", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemArray_Value_FloatValue,
          { "FloatValue", "vsip.SetConfigReq_ConfigItemArray.FloatValue", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemArray_Value_BinaryValue,
          { "BinaryValue", "vsip.SetConfigReq_ConfigItemArray.BinaryValue", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_CapabilityGUID,
          { "CapabilityGUID", "vsip.SetConfigReq.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SetConfigReq_ConfigItemCount,
          { "ConfigItemCount", "vsip.SetConfigReq.ConfigItemCount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigReq_ConfigItemArray_ConfigItemID,
          { "ConfigItemID", "vsip.GetConfigReq_ConfigItemArray.ConfigItemID", FT_UINT16, BASE_DEC|BASE_EXT_STRING,
             &EVsipConfigItem_vals_ext, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigReq_CapabilityGUID,
          { "CapabilityGUID", "vsip.GetConfigReq.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigReq_ConfigItemCount,
          { "ConfigItemCount", "vsip.GetConfigReq.ConfigItemCount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemArray_ConfigItemID,
          { "ConfigItemID", "vsip.GetConfigResp_ConfigItemArray.ConfigItemID", FT_UINT16, BASE_DEC|BASE_EXT_STRING,
             &EVsipConfigItem_vals_ext, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemArray_ValueType,
          { "ValueType", "vsip.GetConfigResp_ConfigItemArray.ValueType", FT_UINT8, BASE_DEC,
             VALS(EVsipValueType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemArray_Value_CharValue,
          { "CharValue", "vsip.GetConfigResp_ConfigItemArray.CharValue", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemArray_Value_ShortValue,
          { "ShortValue", "vsip.GetConfigResp_ConfigItemArray.ShortValue", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemArray_Value_IntValue,
          { "IntValue", "vsip.GetConfigResp_ConfigItemArray.IntValue", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemArray_Value_StringValue,
          { "StringValue", "vsip.GetConfigResp_ConfigItemArray.StringValue", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemArray_Value_UintValue,
          { "UintValue", "vsip.GetConfigResp_ConfigItemArray.UintValue", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemArray_Value_GuidValue,
          { "GuidValue", "vsip.GetConfigResp_ConfigItemArray.GuidValue", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemArray_Value_FloatValue,
          { "FloatValue", "vsip.GetConfigResp_ConfigItemArray.FloatValue", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemArray_Value_BinaryValue,
          { "BinaryValue", "vsip.GetConfigResp_ConfigItemArray.BinaryValue", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_CapabilityGUID,
          { "CapabilityGUID", "vsip.GetConfigResp.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_GetConfigResp_ConfigItemCount,
          { "ConfigItemCount", "vsip.GetConfigResp.ConfigItemCount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommand_CapabilityGUID,
          { "CapabilityGUID", "vsip.SendCommand.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommand_CommandCode,
          { "CommandCode", "vsip.SendCommand.CommandCode", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
             &EVsipCommand_vals_ext, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommand_Arg1,
          { "Arg1", "vsip.SendCommand.Arg1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommand_Arg2,
          { "Arg2", "vsip.SendCommand.Arg2", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_AddArgsArray_ValueType,
          { "ValueType", "vsip.SendCommandEx_AddArgsArray.ValueType", FT_UINT8, BASE_DEC,
             VALS(EVsipValueType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_AddArgsArray_Value_CharValue,
          { "CharValue", "vsip.SendCommandEx_AddArgsArray.CharValue", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_AddArgsArray_Value_ShortValue,
          { "ShortValue", "vsip.SendCommandEx_AddArgsArray.ShortValue", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_AddArgsArray_Value_IntValue,
          { "IntValue", "vsip.SendCommandEx_AddArgsArray.IntValue", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_AddArgsArray_Value_StringValue,
          { "StringValue", "vsip.SendCommandEx_AddArgsArray.StringValue", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_AddArgsArray_Value_UintValue,
          { "UintValue", "vsip.SendCommandEx_AddArgsArray.UintValue", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_AddArgsArray_Value_GuidValue,
          { "GuidValue", "vsip.SendCommandEx_AddArgsArray.GuidValue", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_AddArgsArray_Value_FloatValue,
          { "FloatValue", "vsip.SendCommandEx_AddArgsArray.FloatValue", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_AddArgsArray_Value_BinaryValue,
          { "BinaryValue", "vsip.SendCommandEx_AddArgsArray.BinaryValue", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_CapabilityGUID,
          { "CapabilityGUID", "vsip.SendCommandEx.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_CommandCode,
          { "CommandCode", "vsip.SendCommandEx.CommandCode", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
             &EVsipCommand_vals_ext, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_Arg1,
          { "Arg1", "vsip.SendCommandEx.Arg1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_Arg2,
          { "Arg2", "vsip.SendCommandEx.Arg2", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_SendCommandEx_NumAddArgs,
          { "NumAddArgs", "vsip.SendCommandEx.NumAddArgs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_EventNotify_CapabilityGUID,
          { "CapabilityGUID", "vsip.EventNotify.CapabilityGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_EventNotify_EventType,
          { "EventType", "vsip.EventNotify.EventType", FT_UINT16, BASE_DEC,
             VALS(EVsipEventType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_EventNotify_EventArgument,
          { "EventArgument", "vsip.EventNotify.EventArgument", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_EventSubscribeReq_ReceiverAddress,
          { "ReceiverAddress", "vsip.EventSubscribeReq.ReceiverAddress", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_EventSubscribeReq_ReceiverPort,
          { "ReceiverPort", "vsip.EventSubscribeReq.ReceiverPort", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_EventSubscribeReq_ConnectionType,
          { "ConnectionType", "vsip.EventSubscribeReq.ConnectionType", FT_UINT8, BASE_DEC,
             VALS(EVsipConnectionType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_EventSubscribeExReq_ReceiverAddress,
          { "ReceiverAddress", "vsip.EventSubscribeExReq.ReceiverAddress", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_EventSubscribeExReq_ReceiverPort,
          { "ReceiverPort", "vsip.EventSubscribeExReq.ReceiverPort", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_EventSubscribeExReq_ConnectionType,
          { "ConnectionType", "vsip.EventSubscribeExReq.ConnectionType", FT_UINT8, BASE_DEC,
             VALS(EVsipConnectionType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_EventSubscribeExReq_DestinationGUID,
          { "DestinationGUID", "vsip.EventSubscribeExReq.DestinationGUID", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorResponse_RequestMessageType,
          { "RequestMessageType", "vsip.ErrorResponse.RequestMessageType", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
             &EVsipMessageType_vals_ext, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorResponse_StatusCode,
          { "StatusCode", "vsip.ErrorResponse.StatusCode", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
             &EVsipErrorCode_vals_ext, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorVAResponse_AddArgsArray_ValueType,
          { "ValueType", "vsip.ErrorVAResponse_AddArgsArray.ValueType", FT_UINT8, BASE_DEC,
             VALS(EVsipValueType_vals), 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorVAResponse_AddArgsArray_Value_CharValue,
          { "CharValue", "vsip.ErrorVAResponse_AddArgsArray.CharValue", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorVAResponse_AddArgsArray_Value_ShortValue,
          { "ShortValue", "vsip.ErrorVAResponse_AddArgsArray.ShortValue", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorVAResponse_AddArgsArray_Value_IntValue,
          { "IntValue", "vsip.ErrorVAResponse_AddArgsArray.IntValue", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorVAResponse_AddArgsArray_Value_StringValue,
          { "StringValue", "vsip.ErrorVAResponse_AddArgsArray.StringValue", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorVAResponse_AddArgsArray_Value_UintValue,
          { "UintValue", "vsip.ErrorVAResponse_AddArgsArray.UintValue", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorVAResponse_AddArgsArray_Value_GuidValue,
          { "GuidValue", "vsip.ErrorVAResponse_AddArgsArray.GuidValue", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorVAResponse_AddArgsArray_Value_FloatValue,
          { "FloatValue", "vsip.ErrorVAResponse_AddArgsArray.FloatValue", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorVAResponse_AddArgsArray_Value_BinaryValue,
          { "BinaryValue", "vsip.ErrorVAResponse_AddArgsArray.BinaryValue", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_ErrorVAResponse_NumAddArgs,
          { "NumAddArgs", "vsip.ErrorVAResponse.NumAddArgs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_Version,
          { "Version", "vsip.Version", FT_UINT16, BASE_CUSTOM,
             CF_FUNC(vsip_fmt_revision), 0x0, NULL, HFILL } },
       { &hf_vsip_Type,
          { "Type", "vsip.Type", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
             &EVsipMessageType_vals_ext, 0x0, NULL, HFILL } },
       { &hf_vsip_TransacId,
          { "TransacId", "vsip.TransacId", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_vsip_PacketSize,
          { "PacketSize", "vsip.PacketSize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    };

    proto_vsip = proto_register_protocol ( "Video Services over IP", "VSIP", "vsip");

    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_vsip, hf, array_length(hf));
}

void proto_reg_handoff_vsip(void)
{
    dissector_handle_t vsip_handle;

    vsip_handle = create_dissector_handle(dissect_vsip, proto_vsip);
    dissector_add_for_decode_as("udp.port", vsip_handle);
    dissector_add_for_decode_as("tcp.port", vsip_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
