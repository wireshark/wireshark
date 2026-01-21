/* packet-xcp.c
 * Universal Measurement and Calibration (XCP)
 * By <lars.voelker@technica-engineering.de>
 * Copyright 2023-2025 Dr. Lars Völker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
  * This is a dissector for the Universal Measurement and Calibration Protocol (XCP) by ASAM.
  *
  * Due to the nature of the XCP protocol, for each ECU a configuration entry needs to be set
  * as XCP does have different encoding per direction but does not state the direction.
  * For example and ECU with 192.0.2.85:5555/udp would require something like this:
  *   IPv4, 192.0.2.85, UDP, 5555, 1
  *
  * The protocol defines that it uses 239.255.0.0:5556 for multicast messages but port number
  * was not registered with IANA. So a user has to add this manually to UDP/TCP mappings:
  *   IPv4, 239.255.0.0, UDP, 5556, 0
  *
  * Not all messages and use cases are supported. For additional support, a bug should be created
  * with an attached trace file for that use case.
  *
  */

#include <config.h>

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/uat.h>
#include <epan/tfs.h>
#include <epan/expert.h>

#include "packet-udp.h"
#include "packet-tcp.h"
#include "packet-socketcan.h"

#define XCP_NAME                            "XCP"
#define XCP_FILTER_NAME                     "xcp"
#define XCP_LONG_NAME                       "Universal Measurement and Calibration Protocol (XCP)"

#define DATAFILE_XCP_MEMORY_ADDRESSES       "XCP_Addresses"
#define DATAFILE_XCP_ETH_MAPPING            "XCP_Mapping_UDP_TCP"
#define DATAFILE_XCP_CAN_MAPPING            "XCP_Mapping_CAN"

#define XCP_TYPE_UNKNOWN                    0
#define XCP_TYPE_CAN                        1
#define XCP_TYPE_ETHERNET                   2
#define XCP_TYPE_SXL                        3
#define XCP_TYPE_USB                        4
#define XCP_TYPE_FLEXRAY                    5

#define XCP_DIR_UNKNOWN                     0
#define XCP_DIR_M2S                         1
#define XCP_DIR_S2M                         2

#define XCP_ETH_HDR_LEN                     4

#define XCP_PID_RES                         0xFF
#define XCP_PID_ERR                         0xFE
#define XCP_PID_EV                          0xFD
#define XCP_PID_SERV                        0xFC

static const value_string pid_type_names_s2m[] = {
    {XCP_PID_RES,   "Positive Response"},
    {XCP_PID_ERR,   "Error"},
    {XCP_PID_EV,    "Event"},
    {XCP_PID_SERV,  "Service request"},
    {0, NULL}
};

#define XCP_CMD_CONNECT                     0xFF
#define XCP_CMD_DISCONNECT                  0xFE
#define XCP_CMD_GET_STATUS                  0xFD
#define XCP_CMD_SYNCH                       0xFC
#define XCP_CMD_GET_COMM_MODE_INFO          0xFB
#define XCP_CMD_GET_ID                      0xFA
#define XCP_CMD_SET_REQUEST                 0xF9
#define XCP_CMD_GET_SEED                    0xF8
#define XCP_CMD_UNLOCK                      0xF7
#define XCP_CMD_SET_MTA                     0xF6
#define XCP_CMD_UPLOAD                      0xF5
#define XCP_CMD_SHORT_UPLOAD                0xF4
#define XCP_CMD_BUILD_CHECKSUM              0xF3
#define XCP_CMD_TRANSPORT_LAYER_CMD         0xF2
#define XCP_CMD_USER_CMD                    0xF1

#define XCP_CMD_DOWNLOAD                    0xF0
#define XCP_CMD_DOWNLOAD_NEXT               0xEF
#define XCP_CMD_DOWNLOAD_MAX                0xEE
#define XCP_CMD_SHORT_DOWNLOAD              0xED
#define XCP_CMD_MODIFY_BITS                 0xEC

#define XCP_CMD_SET_CAL_PAGE                0xEB
#define XCP_CMD_GET_CAL_PAGE                0xEA
#define XCP_CMD_GET_PAG_PROCESSOR_INFO      0xE9
#define XCP_CMD_GET_SEGMENT_INFO            0xE8
#define XCP_CMD_GET_PAGE_INFO               0xE7
#define XCP_CMD_SET_SEGMENT_MODE            0xE6
#define XCP_CMD_GET_SEGMENT_MODE            0xE5
#define XCP_CMD_COPY_CAL_PAGE               0xE4

#define XCP_CMD_CLEAR_DAQ_LIST              0xE3
#define XCP_CMD_SET_DAQ_PTR                 0xE2
#define XCP_CMD_WRITE_DAQ                   0xE1
#define XCP_CMD_SET_DAQ_LIST_MODE           0xE0
#define XCP_CMD_GET_DAQ_LIST_MODE           0xDF
#define XCP_CMD_START_STOP_DAQ_LIST         0xDE
#define XCP_CMD_START_STOP_SYNCH            0xDD
#define XCP_CMD_GET_DAQ_CLOCK               0xDC
#define XCP_CMD_READ_DAQ                    0xDB
#define XCP_CMD_GET_DAQ_PROCESSOR_INFO      0xDA
#define XCP_CMD_GET_RESOLUTION_INFO         0xD9
#define XCP_CMD_GET_DAQ_LIST_INFO           0xD8
#define XCP_CMD_GET_DAQ_EVENT_INFO          0xD7
#define XCP_CMD_FREE_DAQ                    0xD6
#define XCP_CMD_ALLOC_DAQ                   0xD5
#define XCP_CMD_ALLOC_ODT                   0xD4
#define XCP_CMD_ALLOC_ODT_ENTRY             0xD3

#define XCP_CMD_PROGRAM_START               0xD2
#define XCP_CMD_PROGRAM_CLEAR               0xD1
#define XCP_CMD_PROGRAM                     0xD0
#define XCP_CMD_PROGRAM_RESET               0xCF
#define XCP_CMD_GET_PGM_PROCESSOR_INFO      0xCE
#define XCP_CMD_GET_SECTOR_INFO             0xCD
#define XCP_CMD_PROGRAM_PREPARE             0xCC
#define XCP_CMD_PROGRAM_FORMAT              0xCB
#define XCP_CMD_PROGRAM_NEXT                0xCA
#define XCP_CMD_PROGRAM_MAX                 0xC9
#define XCP_CMD_PROGRAM_VERIFY              0xC8

#define XCP_CMD_WRITE_DAQ_MULTIPLE          0xC7
#define XCP_CMD_TIME_CORRELATION_PROPERTIES 0xC6
#define XCP_CMD_DTO_CTR_PROPERTIES          0xC5

/* transport layer commands */
#define XCP_SUB_CMD_ETH_GET_SLAVE_ID        0xFF
#define XCP_SUB_CMD_ETH_GET_SLAVE_ID_EXT    0xFD
#define XCP_SUB_CMD_ETH_GET_SLAVE_IP_ADDR   0xFC
#define XCP_SUB_CMD_ETH_GET_DAQ_CLC_MCAST   0xFA

#define XCP_SUB_CMD_CAN_GET_SLAVE_ID        0xFF
#define XCP_SUB_CMD_CAN_GET_DAQ_ID          0xFE
#define XCP_SUB_CMD_CAN_SET_DAQ_ID          0xFD
#define XCP_SUB_CMD_CAN_GET_DAQ_CLC_MCAST   0xFA

/* two byte commands */
#define XCP_CMD_2BYTE_FIRST_BYTE            0xC0
#define XCP_CMD_2BYTE_GET_VERSION           0x00
#define XCP_CMD_2BYTE_SET_DAQ_PACKED_MODE   0x01
#define XCP_CMD_2BYTE_GET_DAQ_PACKED_MODE   0x02
#define XCP_CMD_2BYTE_XCP_SW_DEBUG          0xFC
#define XCP_CMD_2BYTE_XCP_POD_COMMANDS      0xFD

/* SW DEBUG over XCP commands */
#define XCP_CMD_SW_DBG_ATTACH               0x00
#define XCP_CMD_SW_DBG_GET_VENDOR_INFO      0x01
#define XCP_CMD_SW_DBG_GET_MODE_INFO        0x02
#define XCP_CMD_SW_DBG_GET_JTAG_ID          0x03
#define XCP_CMD_SW_DBG_HALT_AFTER_RESET     0x04
#define XCP_CMD_SW_DBG_GET_HWIO_INFO        0x05
#define XCP_CMD_SW_DBG_SET_HWIO_EVENT       0x06
#define XCP_CMD_SW_DBG_HWIO_CONTROL         0x07
#define XCP_CMD_SW_DBG_EXCL_TARGET_ACCESS   0x08
#define XCP_CMD_SW_DBG_SEQUENCE_MULTIPLE    0x09
#define XCP_CMD_SW_DBG_LLT                  0x0A
#define XCP_CMD_SW_DBG_READ_MODIFY_WRITE    0x0B
#define XCP_CMD_SW_DBG_WRITE                0x0C
#define XCP_CMD_SW_DBG_WRITE_NEXT           0x0D
#define XCP_CMD_SW_DBG_WRITE_CAN1           0x0E
#define XCP_CMD_SW_DBG_WRITE_CAN2           0x0F
#define XCP_CMD_SW_DBG_WRITE_CAN_NEXT       0x10
#define XCP_CMD_SW_DBG_READ                 0x11
#define XCP_CMD_SW_DBG_READ_CAN1            0x12
#define XCP_CMD_SW_DBG_READ_CAN2            0x13
#define XCP_CMD_SW_DBG_GET_TRI_DESC_TBL     0x14
#define XCP_CMD_SW_DBG_LLBT                 0x15

/* XCP POD commands */
#define XCP_CMD_POD_GET_INFO                0x0001
#define XCP_CMD_POD_SET_ACTIVE_CONFIG       0x0002
#define XCP_CMD_POD_MANAGE_TRANSFER         0x0003
#define XCP_CMD_POD_DOWNLOAD                0x0004
#define XCP_CMD_POD_UPLOAD                  0x0005
#define XCP_CMD_POD_GET_STATUS              0x0006


static const value_string cmd_code_names[] = {
    {XCP_CMD_CONNECT,                       "Set up Connection with Slave (Connect)"},
    {XCP_CMD_DISCONNECT,                    "Disconnect from Slave"},
    {XCP_CMD_GET_STATUS,                    "Get Current Session Status from Slave"},
    {XCP_CMD_SYNCH,                         "Synchronize Command Execution after Timeout"},
    {XCP_CMD_GET_COMM_MODE_INFO,            "Get Communication Mode Info"},
    {XCP_CMD_GET_ID,                        "Get Identification from Slave"},
    {XCP_CMD_SET_REQUEST,                   "Request to Save to Non-Volatile Memory"},
    {XCP_CMD_GET_SEED,                      "Get Seed for Unlocking a Protected Resource"},
    {XCP_CMD_UNLOCK,                        "Send Key for Unlocking a Protected Resource (Unlock)"},
    {XCP_CMD_SET_MTA,                       "Set Memory Transfer Address in Slave"},
    {XCP_CMD_UPLOAD,                        "Upload from Slave to Master"},
    {XCP_CMD_SHORT_UPLOAD,                  "Upload from Slave to Master (short version)"},
    {XCP_CMD_BUILD_CHECKSUM,                "Build Checksum over Memory Range"},
    {XCP_CMD_TRANSPORT_LAYER_CMD,           "Transport Layer Specific Command"},
    {XCP_CMD_USER_CMD,                      "User-defined Command"},

    {XCP_CMD_DOWNLOAD,                      "Download from Master to Slave"},
    {XCP_CMD_DOWNLOAD_NEXT,                 "Download from Master to Slave (Block Mode)"},
    {XCP_CMD_DOWNLOAD_MAX,                  "Download from Master to Slave (Fixed Size)"},
    {XCP_CMD_SHORT_DOWNLOAD,                "Download from Master to Slave (Short Version)"},
    {XCP_CMD_MODIFY_BITS,                   "Modify Bits"},

    {XCP_CMD_SET_CAL_PAGE,                  "Set Calibration Page"},
    {XCP_CMD_GET_CAL_PAGE,                  "Get Calibration Page"},
    {XCP_CMD_GET_PAG_PROCESSOR_INFO,        "Get General Information on PAG Processor"},
    {XCP_CMD_GET_SEGMENT_INFO,              "Get Specific Information for a SEGMENT"},
    {XCP_CMD_GET_PAGE_INFO,                 "Get Specific Information for a PAGE"},
    {XCP_CMD_SET_SEGMENT_MODE,              "Set Mode for a SEGMENT"},
    {XCP_CMD_GET_SEGMENT_MODE,              "Get Mode for a SEGMENT"},
    {XCP_CMD_COPY_CAL_PAGE,                 "Copy Page"},

    {XCP_CMD_CLEAR_DAQ_LIST,                "Clear DAQ List Configuration"},
    {XCP_CMD_SET_DAQ_PTR,                   "Set Pointer to ODT Entry"},
    {XCP_CMD_WRITE_DAQ,                     "Write Element in ODT Entry"},
    {XCP_CMD_SET_DAQ_LIST_MODE,             "Set Mode for DAQ List"},
    {XCP_CMD_GET_DAQ_LIST_MODE,             "Get Mode From DAQ List"},
    {XCP_CMD_START_STOP_DAQ_LIST,           "Start/Stop/Select DAQ List"},
    {XCP_CMD_START_STOP_SYNCH,              "Start/Stop DAQ Lists (Synch)"},
    {XCP_CMD_GET_DAQ_CLOCK,                 "Get DAQ Clock From Slave"},
    {XCP_CMD_READ_DAQ,                      "Read Element From ODT Entry"},
    {XCP_CMD_GET_DAQ_PROCESSOR_INFO,        "Get General Information on DAQ Processor"},
    {XCP_CMD_GET_RESOLUTION_INFO,           "Get General Information on DAQ Processing Resolution"},
    {XCP_CMD_GET_DAQ_LIST_INFO,             "Get Specific Information for a DAQ List"},
    {XCP_CMD_GET_DAQ_EVENT_INFO,            "Get Specific Information for an Event Channel"},
    {XCP_CMD_FREE_DAQ,                      "Clear Dynamic DAQ Configuration"},
    {XCP_CMD_ALLOC_DAQ,                     "Allocate DAQ Lists"},
    {XCP_CMD_ALLOC_ODT,                     "Allocate ODTs to a DAQ List"},
    {XCP_CMD_ALLOC_ODT_ENTRY,               "Allocate ODT Entries to an ODT"},

    {XCP_CMD_PROGRAM_START,                 "Indicate the Beginning of a Programming Sequence"},
    {XCP_CMD_PROGRAM_CLEAR,                 "Clear a Part of Non-volatile Memory"},
    {XCP_CMD_PROGRAM,                       "Program a Non-volatile Memory"},
    {XCP_CMD_PROGRAM_RESET,                 "Indicate the End of a Programming Sequence"},
    {XCP_CMD_GET_PGM_PROCESSOR_INFO,        "Get General Information on PGM Processor"},
    {XCP_CMD_GET_SECTOR_INFO,               "Get Specific Information for a SECTOR"},
    {XCP_CMD_PROGRAM_PREPARE,               "Prepare Non-volatile Memory Programming"},
    {XCP_CMD_PROGRAM_FORMAT,                "Set Data Format Before Programming"},
    {XCP_CMD_PROGRAM_NEXT,                  "Program a Non-volatile Memory Segment (Block Mode)"},
    {XCP_CMD_PROGRAM_MAX,                   "Program a Non-volatile Memory Segment (Fixed Size)"},
    {XCP_CMD_PROGRAM_VERIFY,                "Program Verify"},

    {XCP_CMD_WRITE_DAQ_MULTIPLE,            "Write Multiple Elements in ODT"},
    {XCP_CMD_TIME_CORRELATION_PROPERTIES,   "Time Correlation"},
    {XCP_CMD_DTO_CTR_PROPERTIES,            "DTO CTR Properties"},

    {XCP_CMD_2BYTE_FIRST_BYTE,              "2 Byte Command Prefix"},
    {0, NULL}
};

static const value_string cmd_code_names_2bytes[] = {
    {XCP_CMD_2BYTE_GET_VERSION,             "Get Version Information"},
    {XCP_CMD_2BYTE_SET_DAQ_PACKED_MODE,     "Set DAQ List Packet Mode"},
    {XCP_CMD_2BYTE_GET_DAQ_PACKED_MODE,     "Get DAQ List Packet Mode"},
    {XCP_CMD_2BYTE_XCP_SW_DEBUG,            "Software Debugging over XCP"},
    {XCP_CMD_2BYTE_XCP_POD_COMMANDS,        "XCP POD Commands"},
    {0, NULL}
};

static const value_string cmd_sw_dbg_names[] = {
    {XCP_CMD_SW_DBG_ATTACH,                 "Debugger Attach"},
    {XCP_CMD_SW_DBG_GET_VENDOR_INFO,        "Get Vendor Information"},
    {XCP_CMD_SW_DBG_GET_MODE_INFO,          "Get Debugging Properties"},
    {XCP_CMD_SW_DBG_GET_JTAG_ID,            "Get Target JTAG ID"},
    {XCP_CMD_SW_DBG_HALT_AFTER_RESET,       "Halt Target after Reset"},
    {XCP_CMD_SW_DBG_GET_HWIO_INFO,          "Get HW-IO Pin Information"},
    {XCP_CMD_SW_DBG_SET_HWIO_EVENT,         "HW-IO Event Control"},
    {XCP_CMD_SW_DBG_HWIO_CONTROL,           "HW-IO Pin State and Control"},
    {XCP_CMD_SW_DBG_EXCL_TARGET_ACCESS,     "Request Exclusive Target Interface Access"},
    {XCP_CMD_SW_DBG_SEQUENCE_MULTIPLE,      "Processing of Multiple JPL Debug Sequences"},
    {XCP_CMD_SW_DBG_LLT,                    "Low Level Telegram"},
    {XCP_CMD_SW_DBG_READ_MODIFY_WRITE,      "Read-Modify-Write"},
    {XCP_CMD_SW_DBG_WRITE,                  "Download from Master to Slave"},
    {XCP_CMD_SW_DBG_WRITE_NEXT,             "Download from Master to Slave (Block mode)"},
    {XCP_CMD_SW_DBG_WRITE_CAN1,             "Download from Master to Slave (CAN – Part 1)"},
    {XCP_CMD_SW_DBG_WRITE_CAN2,             "Download from Master to Slave (CAN – Part 2)"},
    {XCP_CMD_SW_DBG_WRITE_CAN_NEXT,         "Download from Master to Slave (CAN – Part 3)"},
    {XCP_CMD_SW_DBG_READ,                   "Upload from Slave to Master"},
    {XCP_CMD_SW_DBG_READ_CAN1,              "Upload from Slave to Master (CAN – Part 1)"},
    {XCP_CMD_SW_DBG_READ_CAN2,              "Upload from Slave to Master (CAN – Part 2)"},
    {XCP_CMD_SW_DBG_GET_TRI_DESC_TBL,       "Get TRI Parameter from Slave"},
    {XCP_CMD_SW_DBG_LLBT,                   "Low Level Byte Telegram"},
    {0, NULL}
};

static const value_string cmd_code_mnemonics[] = {
    {XCP_CMD_CONNECT,                       "CONNECT"},
    {XCP_CMD_DISCONNECT,                    "DISCONNECT"},
    {XCP_CMD_GET_STATUS,                    "GET_STATUS"},
    {XCP_CMD_SYNCH,                         "SYNCH"},
    {XCP_CMD_GET_COMM_MODE_INFO,            "GET_COMM_MODE_INFO"},
    {XCP_CMD_GET_ID,                        "GET_ID"},
    {XCP_CMD_SET_REQUEST,                   "SET_REQUEST"},
    {XCP_CMD_GET_SEED,                      "GET_SEED"},
    {XCP_CMD_UNLOCK,                        "UNLOCK"},
    {XCP_CMD_SET_MTA,                       "SET_MTA"},
    {XCP_CMD_UPLOAD,                        "UPLOAD"},
    {XCP_CMD_SHORT_UPLOAD,                  "SHORT_UPLOAD"},
    {XCP_CMD_BUILD_CHECKSUM,                "BUILD_CHECKSUM"},
    {XCP_CMD_TRANSPORT_LAYER_CMD,           "TRANSPORT_LAYER_CMD"},
    {XCP_CMD_USER_CMD,                      "USER_CMD"},

    {XCP_CMD_DOWNLOAD,                      "DOWNLOAD"},
    {XCP_CMD_DOWNLOAD_NEXT,                 "DOWNLOAD_NEXT"},
    {XCP_CMD_DOWNLOAD_MAX,                  "DOWNLOAD_MAX"},
    {XCP_CMD_SHORT_DOWNLOAD,                "SHORT_DOWNLOAD"},
    {XCP_CMD_MODIFY_BITS,                   "MODIFY_BITS"},

    {XCP_CMD_SET_CAL_PAGE,                  "SET_CAL_PAGE"},
    {XCP_CMD_GET_CAL_PAGE,                  "GET_CAL_PAGE"},
    {XCP_CMD_GET_PAG_PROCESSOR_INFO,        "GET_PAG_PROCESSOR_INFO"},
    {XCP_CMD_GET_SEGMENT_INFO,              "GET_SEGMENT_INFO"},
    {XCP_CMD_GET_PAGE_INFO,                 "GET_PAGE_INFO"},
    {XCP_CMD_SET_SEGMENT_MODE,              "SET_SEGMENT_MODE"},
    {XCP_CMD_GET_SEGMENT_MODE,              "GET_SEGMENT_MODE"},
    {XCP_CMD_COPY_CAL_PAGE,                 "COPY_CAL_PAGE"},

    {XCP_CMD_CLEAR_DAQ_LIST,                "CLEAR_DAQ_LIST"},
    {XCP_CMD_SET_DAQ_PTR,                   "SET_DAQ_PTR"},
    {XCP_CMD_WRITE_DAQ,                     "WRITE_DAQ"},
    {XCP_CMD_SET_DAQ_LIST_MODE,             "SET_DAQ_LIST_MODE"},
    {XCP_CMD_GET_DAQ_LIST_MODE,             "GET_DAQ_LIST_MODE"},
    {XCP_CMD_START_STOP_DAQ_LIST,           "START_STOP_DAQ_LIST"},
    {XCP_CMD_START_STOP_SYNCH,              "START_STOP_SYNCH"},
    {XCP_CMD_GET_DAQ_CLOCK,                 "GET_DAQ_CLOCK"},
    {XCP_CMD_READ_DAQ,                      "READ_DAQ"},
    {XCP_CMD_GET_DAQ_PROCESSOR_INFO,        "GET_DAQ_PROCESSOR_INFO"},
    {XCP_CMD_GET_RESOLUTION_INFO,           "GET_DAQ_RESOLUTION_INFO"},
    {XCP_CMD_GET_DAQ_LIST_INFO,             "GET_DAQ_LIST_INFO"},
    {XCP_CMD_GET_DAQ_EVENT_INFO,            "GET_DAQ_EVENT_INFO"},

    {XCP_CMD_FREE_DAQ,                      "FREE_DAQ"},
    {XCP_CMD_ALLOC_DAQ,                     "ALLOC_DAQ"},
    {XCP_CMD_ALLOC_ODT,                     "ALLOC_ODT"},
    {XCP_CMD_ALLOC_ODT_ENTRY,               "ALLOC_ODT_ENTRY"},

    {XCP_CMD_PROGRAM_START,                 "PROGRAM_START"},
    {XCP_CMD_PROGRAM_CLEAR,                 "PROGRAM_CLEAR"},
    {XCP_CMD_PROGRAM,                       "PROGRAM"},
    {XCP_CMD_PROGRAM_RESET,                 "PROGRAM_RESET"},
    {XCP_CMD_GET_PGM_PROCESSOR_INFO,        "GET_PGM_PROCESSOR_INFO"},
    {XCP_CMD_GET_SECTOR_INFO,               "GET_SECTOR_INFO"},
    {XCP_CMD_PROGRAM_PREPARE,               "PROGRAM_PREPARE"},
    {XCP_CMD_PROGRAM_FORMAT,                "PROGRAM_FORMAT"},
    {XCP_CMD_PROGRAM_NEXT,                  "PROGRAM_NEXT"},
    {XCP_CMD_PROGRAM_MAX,                   "PROGRAM_MAX"},
    {XCP_CMD_PROGRAM_VERIFY,                "PROGRAM_VERIFY"},

    {XCP_CMD_WRITE_DAQ_MULTIPLE,            "WRITE_DAQ_MULTIPLE"},
    {XCP_CMD_TIME_CORRELATION_PROPERTIES,   "TIME_CORRELATION_PROPERTIES"},
    {XCP_CMD_DTO_CTR_PROPERTIES,            "DTO_CTR_PROPERTIESs"},

    {XCP_CMD_2BYTE_FIRST_BYTE,              "PREFIX_2BYTE_COMMAND"},

    {0, NULL}
};

static const value_string cmd_code_mnemonics_2bytes[] = {
    {XCP_CMD_2BYTE_GET_VERSION,             "GET_VERSION"},
    {XCP_CMD_2BYTE_SET_DAQ_PACKED_MODE,     "SET_DAQ_PACKED_MODE"},
    {XCP_CMD_2BYTE_GET_DAQ_PACKED_MODE,     "GET_DAQ_PACKED_MODE"},
    {XCP_CMD_2BYTE_XCP_SW_DEBUG,            "SW_DBG_OVER_XCP"},
    {XCP_CMD_2BYTE_XCP_POD_COMMANDS,        "XCP_POD_COMMAND"},
    {0, NULL}
};

static const value_string sub_cmd_code_mnemonics_eth[] = {
    {XCP_SUB_CMD_ETH_GET_SLAVE_ID,          "GET_SLAVE_ID"},
    {XCP_SUB_CMD_ETH_GET_SLAVE_ID_EXT,      "GET_SLAVE_ID_EXTENDED"},
    {XCP_SUB_CMD_ETH_GET_SLAVE_IP_ADDR,     "GET_SLAVE_IP_ADDRESS"},
    {XCP_SUB_CMD_ETH_GET_DAQ_CLC_MCAST,     "GET_DAQ_CLOCK_MULTICAST"},
    {0, NULL}
};

static const value_string sub_cmd_code_mnemonics_can[] = {
    {XCP_SUB_CMD_CAN_GET_SLAVE_ID,          "GET_SLAVE_ID"},
    {XCP_SUB_CMD_CAN_GET_DAQ_ID,            "GET_DAQ_ID"},
    {XCP_SUB_CMD_CAN_SET_DAQ_ID,            "SET_DAQ_ID"},
    {XCP_SUB_CMD_CAN_GET_DAQ_CLC_MCAST,     "GET_DAQ_CLOCK_MULTICAST"},
    {0, NULL}
};

static const value_string cmd_sw_dbg_mnemonics[] = {
    {XCP_CMD_SW_DBG_ATTACH,                 "DBG_ATTACH"},
    {XCP_CMD_SW_DBG_GET_VENDOR_INFO,        "DBG_GET_VENDOR_INFO"},
    {XCP_CMD_SW_DBG_GET_MODE_INFO,          "DBG_GET_MODE_INFO"},
    {XCP_CMD_SW_DBG_GET_JTAG_ID,            "DBG_GET_JTAG_ID"},
    {XCP_CMD_SW_DBG_HALT_AFTER_RESET,       "DBG_HALT_AFTER_RESET"},
    {XCP_CMD_SW_DBG_GET_HWIO_INFO,          "DBG_GET_HWIO_INFO"},
    {XCP_CMD_SW_DBG_SET_HWIO_EVENT,         "DBG_SET_HWIO_EVENT"},
    {XCP_CMD_SW_DBG_HWIO_CONTROL,           "DBG_HWIO_CONTROL"},
    {XCP_CMD_SW_DBG_EXCL_TARGET_ACCESS,     "DBG_EXCLUSIVE_TARGET_ACCESS"},
    {XCP_CMD_SW_DBG_SEQUENCE_MULTIPLE,      "DBG_SEQUENCE_MULTIPLE"},
    {XCP_CMD_SW_DBG_LLT,                    "DBG_LLT"},
    {XCP_CMD_SW_DBG_READ_MODIFY_WRITE,      "DBG_READ_MODIFY_WRITE"},
    {XCP_CMD_SW_DBG_WRITE,                  "DBG_WRITE"},
    {XCP_CMD_SW_DBG_WRITE_NEXT,             "DBG_WRITE_NEXT"},
    {XCP_CMD_SW_DBG_WRITE_CAN1,             "DBG_WRITE_CAN1"},
    {XCP_CMD_SW_DBG_WRITE_CAN2,             "DBG_WRITE_CAN2"},
    {XCP_CMD_SW_DBG_WRITE_CAN_NEXT,         "DBG_WRITE_CAN_NEXT"},
    {XCP_CMD_SW_DBG_READ,                   "DBG_READ"},
    {XCP_CMD_SW_DBG_READ_CAN1,              "DBG_READ_CAN1"},
    {XCP_CMD_SW_DBG_READ_CAN2,              "DBG_READ_CAN2"},
    {XCP_CMD_SW_DBG_GET_TRI_DESC_TBL,       "DBG_GET_TRI_DESC_TBL"},
    {XCP_CMD_SW_DBG_LLBT,                   "DBG_LLBT"},
    {0, NULL}
};

static const value_string cmd_pod_mnemonics[] = {
    {XCP_CMD_POD_GET_INFO,                  "POD_GET_INFO"},
    {XCP_CMD_POD_SET_ACTIVE_CONFIG,         "POD_SET_ACTIVE_CONFIG"},
    {XCP_CMD_POD_MANAGE_TRANSFER,           "POD_MANAGE_TRANSFER"},
    {XCP_CMD_POD_DOWNLOAD,                  "POD_DOWNLOAD"},
    {XCP_CMD_POD_UPLOAD,                    "POD_UPLOAD"},
    {XCP_CMD_POD_GET_STATUS,                "POD_GET_STATUS"},
    {0, NULL}
};

static const value_string program_clear_mode_type[] = {
    {0, "Absolute Access Mode active"},
    {1, "Functional Access Mode active"},
    {0, NULL}
};

static const value_string daq_packed_mode_type[] = {
    {0, "Data not packed"},
    {1, "Element-grouped data packing"},
    {2, "Event-grouped data packing"},
    {0, NULL}
};

static const value_string daq_packed_timestamp_mode_type[] = {
    {0, "Single timestamp of last sample"},
    {1, "Single timestamp of first sample"},
    {2, "Event-grouped data packing"},
    {0, NULL}
};

static const value_string access_mode_type[] = {
    {1, "ECU access"},
    {2, "XCP access"},
    {0, NULL}
};

/* XCP_CMD_SET_DAQ_LIST_MODE */
#define SET_DAQ_LIST_MODE_PID_OFF           0x20
#define SET_DAQ_LIST_MODE_TSTAMP            0x10
#define SET_DAQ_LIST_MODE_DTO_CTR           0x08
#define SET_DAQ_LIST_MODE_DIR               0x02
#define SET_DAQ_LIST_MODE_ALT               0x01


/* XCP_CMD_START_STOP_DAQ_LIST */
static const value_string start_stop_daq_mode[] = {
    {0, "Stop"},
    {1, "Start"},
    {2, "Select"},
    {0, NULL}
};

static const true_false_string xcp_tfs_stim_daq = {
    "Stimulation (STIM)",
    "Data Acquisition (DAQ)"
};

/* XCP_CMD_START_STOP_SYNCH */
static const value_string start_stop_synch_mode[] = {
    {0, "Stop All"},
    {1, "Start Selected"},
    {2, "Stop Selected"},
    {3, "Prepare to Start Selected"},
    {0, NULL}
};

/* CMD: Connect */
static const value_string cmd_connect_mode[] = {
    {0,   "Normal"},
    {1,   "User-Defined"},
    {0, NULL}
};

static const true_false_string xcp_tfs_byte_order = {
    "Big Endian / Motorola",
    "Little Endian / Intel"
};

static const true_false_string xcp_tfs_protected = {
    "Protected with Seed & Key",
    "Not Protected with Seed & Key",
};

static const value_string comm_mode_address_granularity[] = {
    {0, "BYTE (1 byte)"},
    {1, "WORD (2 bytes)"},
    {2, "DWORD (4 bytes)"},
    {3, "reserved"},
    {0, NULL}
};

static const value_string get_id_req_id_type[] = {
    {0, "ASCII text"},
    {1, "ASAM-MC2 filename without path and extension"},
    {2, "ASAM-MC2 filename with path and extension"},
    {3, "URL where the ASAM-MC2 file can be found"},
    {4, "ASAM-MC2 file to upload"},
    {5, "ASAM-MC2 EPK"},
    {6, "ASAM-MC2 ECU"},
    {7, "ASAM POD SystemID"},
    {0, NULL}
};

static const value_string trigger_info_time_of_ts_sampl_type[] = {
    {0, "At Protocol Layer Command Processor"},
    {1, "Low Jitter, High Priority Interrupt"},
    {2, "Physical transmission to XCP master"},
    {3, "Physical reception of command"},
    {0, NULL}
};

static const value_string trigger_info_trigger_init_type[] = {
    {0, "Hardware trigger"},
    {1, "Event derived from XCP-independent time sync event"},
    {2, "GET_DAQ_CLOCK_MULTICAST"},
    {3, "GET_DAQ_CLOCK_MULTICAST via Time Sync Bridge"},
    {4, "State Change in Synt/Sync to Grandmaster Clock"},
    {5, "Leap second occurred on Grandmaster Clock"},
    {6, "Release of ECU reset"},
    {7, "Reserved"},
    {0, NULL}
};

static const value_string clock_format_type[] = {
    {0, "Not part of event payload"},
    {1, "DWORD"},
    {2, "DLONG/unsigned"},
    {3, "reserved"},
    {0, NULL}
};

static const true_false_string xcp_tfs_cluster_identifier = {
    "Present, when sent as response to TRIGGER_INITIATOR 2 or 3",
    "Not Present"
};

static const value_string daq_properties_overload_type[] = {
    {0, "No overload indication"},
    {1, "Overload indication in the MSB of PID"},
    {2, "Overload indication by Event Packet"},
    {3, "Not allowed"},
    {0, NULL}
};

static const true_false_string xcp_tfs_dynamic_static = {
    "Dynamic",
    "Static",
};

static const value_string daq_key_byte_id_field_type[] = {
    {0, "Absolute ODT number"},
    {1, "Relative ODT number, absolute DAQ list number (BYTE)"},
    {2, "Relative ODT number, absolute DAQ list number (WORD)"},
    {3, "Relative ODT number, absolute DAQ list number (WORD, aligned)"},
    {0, NULL}
};

static const value_string daq_key_byte_addr_ext_type[] = {
    {0, "Address extension can be different within one and the same ODT"},
    {1, "Address extension to be the same for all entries within one ODT"},
    {2, "Not allowed"},
    {3, "Address extension to be the same for all entries within one DAQ"},
    {0, NULL}
};

static const value_string optimization_type[] = {
    { 0, "OM_DEFAULT"},
    { 1, "OM_ODT_TYPE_16"},
    { 2, "OM_ODT_TYPE_32"},
    { 3, "OM_ODT_TYPE_64"},
    { 4, "OM_ODT_TYPE_ALIGNMENT"},
    { 5, "OM_MAX_ENTRY_SIZE"},

    { 9, "OM_ODT_TYPE_16 (strict)"},
    {10, "OM_ODT_TYPE_32 (strict)"},
    {11, "OM_ODT_TYPE_64 (strict)"},
    {0, NULL}
};

static const value_string daq_event_props_consistency[] = {
    {0, "Consistency on IDT level"},
    {1, "Consistency on DAQ level"},
    {2, "Consistency on Event Channel level"},
    {3, "No consistency available"},
    {0, NULL}
};

/* shared between XCP_CMD_GET_RESOLUTION_INFO and XCP_CMD_GET_DAQ_EVENT_INFO */
static const value_string xcp_time_unit[] = {
    {0, "1 ns"},
    {1, "10 ns"},
    {2, "100 ns"},
    {3, "1 µs"},
    {4, "10 µs"},
    {5, "100 µs"},
    {6, "1 ms"},
    {7, "10 ms"},
    {8, "100 ms"},
    {9, "1 s"},
    {10, "1 ps"},
    {11, "10 ps"},
    {12, "100 ps"},
    {0, NULL}
};

static const value_string transport_mode_eth_ip_version[] = {
    {0, "IPv4"},
    {0, NULL}
};

static const value_string get_seed_mode[] = {
    {0, "(first part of) seed"},
    {1, "remaining part of seed"},
    {0, NULL}
};

static const value_string checksum_types[] = {
    {0x01, "XCP_ADD_11"},
    {0x02, "XCP_ADD_12"},
    {0x03, "XCP_ADD_14"},
    {0x04, "XCP_ADD_22"},
    {0x05, "XCP_ADD_24"},
    {0x06, "XCP_ADD_44"},
    {0x07, "XCP_CRC_16"},
    {0x08, "XCP_CRC_16_CITT"},
    {0x09, "XCP_CRC_32"},
    {0xff, "XCP_USER_DEFINED"},
    {0, NULL}
};

static int proto_xcp;

static dissector_handle_t xcp_handle_udp;
static dissector_handle_t xcp_handle_tcp;
static dissector_handle_t xcp_handle_can;

/* Header fields */
static int hf_xcp_header_ethernet;
static int hf_xcp_length;
static int hf_xcp_counter;

static int hf_xcp_packet;
static int hf_xcp_pid_s2m;
static int hf_xcp_cmd_code;
static int hf_xcp_cmd_code_level1;

static int hf_xcp_reserved;
static int hf_xcp_unparsed;
static int hf_xcp_address;

static int hf_xcp_session_cfg_id;

static int hf_xcp_daq_list_number;
static int hf_xcp_odt_number;
static int hf_xcp_odt_entry_number;
static int hf_xcp_event_channel_number;

static int hf_xcp_logical_data_segment_number;
static int hf_xcp_logical_data_page_number;

static int hf_xcp_num_of_data_elements;
static int hf_xcp_address_extension;
static int hf_xcp_data_element_1byte;
static int hf_xcp_data_element_2bytes;
static int hf_xcp_data_element_4bytes;
static int hf_xcp_data_element_bytes;

/* XCP_CMD_CONNECT */
static int hf_xcp_conn_mode;
static int hf_xcp_conn_resource;
static int hf_xcp_conn_resource_dbg;
static int hf_xcp_conn_resource_pgm;
static int hf_xcp_conn_resource_stim;
static int hf_xcp_conn_resource_daq;
static int hf_xcp_conn_resource_cal_pag;

static int hf_xcp_conn_comm_mode_bsc;
static int hf_xcp_conn_comm_mode_bsc_optional;
static int hf_xcp_conn_comm_mode_bsc_sl_blk_mode;
static int hf_xcp_conn_comm_mode_bsc_addr_gran;
static int hf_xcp_conn_comm_mode_bsc_byte_order;

static int hf_xcp_conn_max_cto;
static int hf_xcp_conn_max_dto;
static int hf_xcp_conn_proto_layer_ver;
static int hf_xcp_conn_trans_layer_ver;

/* XCP_CMD_GET_STATUS */
static int hf_xcp_get_st_cur_ses;
static int hf_xcp_get_st_cur_ses_resume;
static int hf_xcp_get_st_cur_ses_daq_running;
static int hf_xcp_get_st_cur_ses_daq_cfg_lost;
static int hf_xcp_get_st_cur_ses_clear_daq_req;
static int hf_xcp_get_st_cur_ses_store_daq_req;
static int hf_xcp_get_st_cur_ses_calpag_cfg_lst;
static int hf_xcp_get_st_cur_ses_store_cal_req;

static int hf_xcp_get_st_cur_res_pro_st;
static int hf_xcp_get_st_cur_res_pro_st_dbg;
static int hf_xcp_get_st_cur_res_pro_st_pgm;
static int hf_xcp_get_st_cur_res_pro_st_stim;
static int hf_xcp_get_st_cur_res_pro_st_daq;
static int hf_xcp_get_st_cur_res_pro_st_calpag;

static int hf_xcp_get_st_cur_state_number;

/* XCP_CMD_GET_COMM_MODE_INFO */
static int hf_xcp_comm_mode_res1;
static int hf_xcp_comm_mode_opt;
static int hf_xcp_comm_mode_opt_interl;
static int hf_xcp_comm_mode_opt_mas_blck_mode;
static int hf_xcp_comm_mode_res2;
static int hf_xcp_comm_mode_max_bs;
static int hf_xcp_comm_mode_min_st;
static int hf_xcp_comm_mode_queue_size;
static int hf_xcp_comm_mode_driver_version;

/* XCP_CMD_GET_ID */
static int hf_xcp_get_id_req_id_type;

static int hf_xcp_get_id_mode;
static int hf_xcp_get_id_mode_compressed_encrypted;
static int hf_xcp_get_id_mode_transfer_mode;
static int hf_xcp_get_id_res;
static int hf_xcp_get_id_length;
static int hf_xcp_get_id_id_string;
static int hf_xcp_get_id_id_bytes;

/* XCP_CMD_SET_REQUEST */
static int hf_xcp_set_req_md;
static int hf_xcp_set_req_md_clr_daq_cfg_lost;
static int hf_xcp_set_req_md_clr_cal_pag_cfg_lost;
static int hf_xcp_set_req_md_clr_daq_req;
static int hf_xcp_set_req_md_str_daq_req_resume;
static int hf_xcp_set_req_md_str_daq_req_no_resume;
static int hf_xcp_set_req_md_str_cal_req;

/* GET_SEED */
static int hf_xcp_get_seed_mode;
static int hf_xcp_get_seed_resource;
static int hf_xcp_get_seed_dont_care;

static int hf_xcp_get_seed_length_of_seed;
static int hf_xcp_get_seed_seed;

/* UNLOCK */
static int hf_xcp_unlock_length_of_key;
static int hf_xcp_unlock_key;

/* DTO */
static int hf_xcp_data_element_name;

/* XCP_CMD_BUILD_CHECKSUM */
static int hf_xcp_build_chksum_res1;
static int hf_xcp_build_chksum_res2;
static int hf_xcp_build_chksum_block_size;

static int hf_xcp_build_chksum_type;
static int hf_xcp_build_chksum_res3;
static int hf_xcp_build_chksum;

/* XCP_CMD_TRANSPORT_LAYER */
static int hf_xcp_sub_command_eth;
static int hf_xcp_sub_command_eth_port;
static int hf_xcp_sub_command_eth_ipv4;
static int hf_xcp_sub_command_eth_reserved;
static int hf_xcp_sub_command_eth_ip_version;

static int hf_xcp_sub_command_can;

/* XCP_CMD_SET_CAL_PAGE */
static int hf_xcp_set_cal_page_mode;
static int hf_xcp_set_cal_page_mode_all;
static int hf_xcp_set_cal_page_mode_xcp;
static int hf_xcp_set_cal_page_mode_ecu;

/* XCP_CMD_GET_CAL_PAGE */
static int hf_xcp_access_mode;

/* XCP_CMD_COPY_CAL_PAGE */
static int hf_xcp_logical_data_segm_num_src;
static int hf_xcp_logical_data_page_num_src;
static int hf_xcp_logical_data_segm_num_dst;
static int hf_xcp_logical_data_page_num_dst;

/* XCP_CMD_WRITE_DAQ */
static int hf_xcp_bit_offset;
static int hf_xcp_size_of_daq_element;

/* XCP_CMD_SET_DAQ_LIST_MODE */
static int hf_xcp_set_daq_list_mode_mode;
static int hf_xcp_set_daq_list_mode_mode_pid_off;
static int hf_xcp_set_daq_list_mode_mode_timestamp;
static int hf_xcp_set_daq_list_mode_mode_dto_ctr;
static int hf_xcp_set_daq_list_mode_mode_dir;
static int hf_xcp_set_daq_list_mode_mode_alt;
static int hf_xcp_transmission_prescaler;
static int hf_xcp_daq_list_priority;


/* XCP_CMD_START_STOP_DAQ_LIST */
static int hf_xcp_start_stop_daq_mode;

static int hf_xcp_first_pid;


/* XCP_CMD_START_STOP_SYNCH */
static int hf_xcp_start_stop_synch_mode;

/* XCP_CMD_GET_DAQ_CLOCK */
static int hf_xcp_trigger_info;
static int hf_xcp_trigger_info_time_of_ts_sampl;
static int hf_xcp_trigger_info_trigger_init;
static int hf_xcp_payload_fmt;
static int hf_xcp_payload_fmt_cluster_ident;
static int hf_xcp_payload_fmt_fmt_ecu;
static int hf_xcp_payload_fmt_fmt_grandm;
static int hf_xcp_payload_fmt_xcp_slv;
static int hf_xcp_payload_timestamp_legacy;
/* TODO: add optional parameters */


/* XCP_CMD_GET_DAQ_PROCESSOR_INFO */
static int hf_xcp_daq_props;
static int hf_xcp_daq_props_overload;
static int hf_xcp_daq_props_pid_off_supported;
static int hf_xcp_daq_props_timestamp_supported;
static int hf_xcp_daq_props_bit_stim_supported;
static int hf_xcp_daq_props_resume_supported;
static int hf_xcp_daq_props_prescaler_supported;
static int hf_xcp_daq_props_config_type;

static int hf_xcp_max_daq;
static int hf_xcp_max_event_channel;
static int hf_xcp_min_daq;
static int hf_xcp_daq_key_byte;
static int hf_xcp_daq_key_byte_id_field;
static int hf_xcp_daq_key_byte_addr_ext;
static int hf_xcp_daq_key_byte_optimization;

/* XCP_CMD_GET_RESOLUTION_INFO */
static int hf_xcp_granularity_odt_entry_size_daq;
static int hf_xcp_max_odt_entry_size_daq;
static int hf_xcp_granularity_odt_entry_size_stim;
static int hf_xcp_max_odt_entry_size_stim;
static int hf_xcp_timestamp_mode;
static int hf_xcp_timestamp_mode_time_unit;
static int hf_xcp_timestamp_mode_timestamp_fixed;
static int hf_xcp_timestamp_mode_timestamp_size;
static int hf_xcp_timestamp_ticks;

/* XCP_CMD_GET_DAQ_LIST_INFO */
static int hf_xcp_daq_list_properties;
static int hf_xcp_daq_list_properties_packed;
static int hf_xcp_daq_list_properties_stim;
static int hf_xcp_daq_list_properties_daq;
static int hf_xcp_daq_list_properties_event_fixed;
static int hf_xcp_daq_list_properties_predefined;
static int hf_xcp_daq_list_max_odt;
static int hf_xcp_daq_list_max_odt_entries;
static int hf_xcp_daq_list_fixed_event;


/* XCP_CMD_GET_DAQ_EVENT_INFO */
static int hf_xcp_daq_event_properties;
static int hf_xcp_daq_event_properties_consistency;
static int hf_xcp_daq_event_properties_packed;
static int hf_xcp_daq_event_properties_stim;
static int hf_xcp_daq_event_properties_daq;

static int hf_xcp_max_daq_list;
static int hf_xcp_event_channel_name_length;
static int hf_xcp_event_channel_time_cycle;
static int hf_xcp_event_channel_time_unit;
static int hf_xcp_event_channel_priority;

/* XCP_CMD_ALLOC_DAQ */
static int hf_xcp_daq_count;

/* XCP_CMD_ALLOC_ODT */
static int hf_xcp_odt_count;

/* XCP_CMD_ALLOC_ODT_ENTRY */
static int hf_xcp_odt_entries_count;

/* PROGRAM_START */
static int hf_xcp_comm_mode_pgm;
static int hf_xcp_comm_mode_pgm_slave_block_mode;
static int hf_xcp_comm_mode_pgm_interleaved_mode;
static int hf_xcp_comm_mode_pgm_master_block_mode;
static int hf_xcp_max_cto_pgm;
static int hf_xcp_max_bs_pgm;
static int hf_xcp_min_st_pgm;
static int hf_xcp_queue_size_pgm;

/* 0xD1 PROGRAM_CLEAR */
static int hf_xcp_program_clear_mode;
static int hf_xcp_program_clear_range_abs;
static int hf_xcp_program_clear_range_fct;
static int hf_xcp_program_clear_range_fct_1;
static int hf_xcp_program_clear_range_fct_2;
static int hf_xcp_program_clear_range_fct_4;

/* 0xC0 0x0 GET_VERSION */
static int hf_xcp_version_proto_major;
static int hf_xcp_version_proto_minor;
static int hf_xcp_version_transp_layer_major;
static int hf_xcp_version_transp_layer_minor;

/* 0xC0 0x01SET_DAQ_PACKED_MODE */
static int hf_xcp_daq_packed_mode;
static int hf_xcp_packed_timestamp_mode;
static int hf_xcp_packed_timestamp_mode_flags;
static int hf_xcp_packed_sample_count;

/* 0xC0 0xFC SW DEBUG over XCP */
static int hf_xcp_debug_command;

/* 0xC0 0xFD XCP POD */
static int hf_xcp_pod_command;

static int ett_xcp;
static int ett_xcp_header;
static int ett_xcp_packet;
static int ett_xcp_resource_flags;
static int ett_xcp_comm_mode_basic_flags;
static int ett_xcp_current_session_status_flags;
static int ett_xcp_current_res_protec_status;
static int ett_xcp_comm_mode_optional;
static int ett_xcp_get_id_mode_parameter;
static int ett_xcp_set_request_mode;
static int ett_xcp_set_cal_page_mode;
static int ett_xcp_trigger_info;
static int ett_xcp_payload_format;
static int ett_xcp_daq_properties;
static int ett_xcp_daq_key_byte;
static int ett_xcp_timestamp_mode;
static int ett_xcp_daq_list_properties;
static int ett_xcp_comm_mode_pgm;
static int ett_xcp_daq_event_properties;
static int ett_xcp_set_daq_list_mode_mode;
static int ett_xcp_clear_program_range_fct;
static int ett_xcp_set_daq_packed_mode_timestamp_mode;
static int ett_xcp_element;

/* expert info items */
static expert_field ei_xcp_not_implemented;

void proto_register_xcp(void);
void proto_reg_handoff_xcp(void);

typedef struct _xcp_odt_entry {
    uint32_t                        ecu_id;
    uint32_t                        addr_ext;
    uint32_t                        address;
    char                           *name;

    uint32_t                        size;
} xcp_odt_entry_t;

typedef struct _xcp_odt {
    uint32_t                        odt_number;

    uint32_t                        pid;

    uint32_t                        number_of_odt_entries;
    wmem_array_t *                  current_odt_entries;
} xcp_odt_t;

typedef struct _xcp_daq {
    uint32_t                        daq_number;

    uint32_t                        number_of_odts;
    wmem_array_t *                  current_odts;
} xcp_daq_t;

#define XCP_MESSAGE_CMD_UNKNOWN 0xFFFFFFFF
typedef struct _xcp_message {
    bool                            m2s;
    uint32_t                        cmd;
    uint32_t                        cmd_lvl1;
    uint32_t                        transport_layer_sub_cmd;
    uint32_t                        cmd_sw_debug;
    uint32_t                        cmd_pod;
    uint32_t                        number_of_elements;
    struct _xcp_message             *peer_message;

    uint32_t                        current_daq_list_number;

    uint32_t                        number_of_daqs;
    wmem_array_t *                  current_daqs;
} xcp_message_t;

#define INIT_XCP_MESSAGE_T(X) \
    (X)->m2s = true; \
    (X)->cmd = XCP_MESSAGE_CMD_UNKNOWN; \
    (X)->cmd_lvl1 = XCP_MESSAGE_CMD_UNKNOWN; \
    (X)->transport_layer_sub_cmd = XCP_MESSAGE_CMD_UNKNOWN; \
    (X)->cmd_sw_debug = XCP_MESSAGE_CMD_UNKNOWN; \
    (X)->cmd_pod = XCP_MESSAGE_CMD_UNKNOWN; \
    (X)->number_of_elements = 0; \
    (X)->peer_message = NULL; \
    (X)->current_daq_list_number = 0xffffffff; \
    (X)->number_of_daqs = 0; \
    (X)->current_daqs = NULL;

typedef struct _xcp_stream {
    xcp_message_t                  *last_m2s;
    xcp_message_t                  *last_s2m;
    uint32_t                        addr_granularity;
    uint16_t                        ecu_id;
    unsigned int                    endianess;
    bool                            timestamp_extended;

    address                         s_addr;
    uint16_t                        s_port_number;

    uint32_t                        number_of_daqs;
    wmem_array_t *                  current_daqs;

    uint32_t                        current_daq;
    uint32_t                        current_odt;
    uint32_t                        current_odt_entry;

    wmem_map_t                     *pid_map;

} xcp_stream_t;

static uint32_t global_xcp_address_granularity_default = 0;

/* Cannot use wmem_file_scope() but since profile stays the same, this should be ok. */
#define INIT_XCP_STREAM_T(X) \
    (X)->last_m2s = NULL; \
    (X)->last_s2m = NULL; \
    (X)->addr_granularity = (global_xcp_address_granularity_default); \
    (X)->ecu_id = 0; \
    (X)->endianess = ENC_LITTLE_ENDIAN; \
    (X)->timestamp_extended = false; \
    clear_address(&((X)->s_addr)); \
    (X)->s_port_number = 0; \
    (X)->number_of_daqs = 0; \
    (X)->current_daqs = NULL; \
    (X)->current_daq = 0xFFFFFFFF; \
    (X)->current_odt = 0xFFFFFFFF; \
    (X)->current_odt_entry = 0xFFFFFFFF; \
    (X)->pid_map = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);


/*** Configuration ***/
/* Addresses */
typedef struct _xcp_memory_addresses_uat {
    uint32_t                        ecu_id;
    uint32_t                        addr_ext;
    uint32_t                        address;
    char                           *name;
} xcp_memory_addresses_uat_t;

static xcp_memory_addresses_uat_t  *xcp_memory_addresses;
static unsigned                     xcp_memory_addresses_num;
static GHashTable                  *data_xcp_memory_addresses;


/* Ethernet Mapping */
typedef struct _xcp_eth_mapping {
    address                         addr;
    uint8_t                         port_type;
    uint16_t                        port_number;
    uint16_t                        ecu_id;

    xcp_stream_t                   *stream;
} xcp_eth_mapping_t;

typedef struct _xcp_eth_mapping_uat {
    uint8_t                         protocol;
    char                           *ip_address;
    uint8_t                         port_type;
    uint32_t                        port_number;
    uint32_t                        ecu_id;
} xcp_eth_mapping_uat_t;

static xcp_eth_mapping_uat_t       *xcp_uat_eth_mappings;
static uint32_t                     xcp_uat_eth_mapping_num;
static uint32_t                     xcp_uat_eth_mapping_num_current = 0;
static xcp_eth_mapping_t           *xcp_eth_mappings_priv;
static GHashTable                  *data_xcp_eth_mappings = NULL;

#define XCP_PROTO_IPV4  1
#define XCP_PROTO_IPV6  2
#define XCP_PROTO_ANY   3

#define XCP_PORT_NONE   0
#define XCP_PORT_UDP    1
#define XCP_PORT_TCP    2

static const value_string xcp_proto_type_vals[] = {
  { XCP_PROTO_IPV4, "IPv4" },
  { XCP_PROTO_IPV6, "IPv6" },
  { XCP_PROTO_ANY, "ANY" },
  { 0x00, NULL }
};

static const value_string xcp_port_type_vals[] = {
  { XCP_PORT_UDP, "UDP" },
  { XCP_PORT_TCP, "TCP" },
  { 0x00, NULL }
};


/* CAN Mapping */
typedef struct _xcp_can_mapping {
    uint16_t                        bus_id;
    uint32_t                        can_id_m_to_s;
    uint32_t                        can_id_s_to_m;
    uint16_t                        ecu_id;

    xcp_stream_t                   *stream;
} xcp_can_mapping_t;

typedef struct _xcp_can_mapping_uat {
    uint32_t                        bus_id;
    uint32_t                        can_id_m_to_s;
    uint32_t                        can_id_s_to_m;
    uint32_t                        ecu_id;
} xcp_can_mapping_uat_t;

static xcp_can_mapping_uat_t       *xcp_uat_can_mappings;
static uint32_t                     xcp_uat_can_mapping_num;
static uint32_t                     xcp_uat_can_mapping_num_current = 0;
static xcp_can_mapping_t           *xcp_can_mappings_priv = NULL;
static GHashTable                  *data_xcp_can_mappings = NULL;


/* UAT: XCP Memory Addresses */
UAT_HEX_CB_DEF(xcp_memory_addresses,        ecu_id,     xcp_memory_addresses_uat_t)
UAT_HEX_CB_DEF(xcp_memory_addresses,        addr_ext,   xcp_memory_addresses_uat_t)
UAT_HEX_CB_DEF(xcp_memory_addresses,        address,    xcp_memory_addresses_uat_t)
UAT_CSTRING_CB_DEF(xcp_memory_addresses,    name,       xcp_memory_addresses_uat_t)

static uint64_t
xcp_memory_address_calc_key(uint16_t ecu_id, uint8_t addr_ext, uint32_t memory_address) {
    return ((uint64_t)ecu_id) << 40 | ((uint64_t)addr_ext) << 32 | (uint64_t)memory_address;
}

static char *
xcp_lookup_memory_address(uint16_t ecu_id, uint8_t addr_ext, uint32_t memory_address) {
    uint64_t key = xcp_memory_address_calc_key(ecu_id, addr_ext, memory_address);

    if (data_xcp_memory_addresses == NULL) {
        return NULL;
    }

    return (char *)g_hash_table_lookup(data_xcp_memory_addresses, &key);
}

static void *
copy_xcp_memory_addresses_cb(void *n, const void *o, size_t size _U_) {
    xcp_memory_addresses_uat_t        *new_rec = (xcp_memory_addresses_uat_t *)n;
    const xcp_memory_addresses_uat_t  *old_rec = (const xcp_memory_addresses_uat_t *)o;

    new_rec->ecu_id = old_rec->ecu_id;
    new_rec->addr_ext = old_rec->addr_ext;
    new_rec->address = old_rec->address;
    new_rec->name = g_strdup(old_rec->name);
    return new_rec;
}

static bool
update_xcp_memory_addresses_cb(void *r, char **err) {
    xcp_memory_addresses_uat_t *rec = (xcp_memory_addresses_uat_t *)r;

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    if ((rec->ecu_id) > 0xfffe) {
        *err = g_strdup_printf("We currently only support 16bit ECU-IDs (0x%x) up to 0xfffe", rec->ecu_id);
        return false;
    }

    return true;
}

static void
free_xcp_memory_addresses_cb(void *r) {
    xcp_memory_addresses_uat_t *rec = (xcp_memory_addresses_uat_t *)r;

    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static void
reset_xcp_memory_addresses_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_xcp_memory_addresses) {
        g_hash_table_destroy(data_xcp_memory_addresses);
        data_xcp_memory_addresses = NULL;
    }
}

static void
post_update_xcp_memory_addresses_cb(void) {
    reset_xcp_memory_addresses_cb();

    /* create new hash table */
    data_xcp_memory_addresses = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);

    for (unsigned i = 0; i < xcp_memory_addresses_num; i++) {
        uint64_t *key = g_new(uint64_t, 1);
        *key = xcp_memory_address_calc_key((uint16_t)xcp_memory_addresses[i].ecu_id, (uint8_t)xcp_memory_addresses[i].addr_ext, xcp_memory_addresses[i].address);
        g_hash_table_insert(data_xcp_memory_addresses, key, xcp_memory_addresses[i].name);
    }
}


/* UAT: Ethernet Mapping */
UAT_VS_DEF(xcp_uat_eth_mappings,            protocol,       xcp_eth_mapping_uat_t, uint8_t, XCP_PROTO_IPV4, "IPv4")
UAT_CSTRING_CB_DEF(xcp_uat_eth_mappings,    ip_address,     xcp_eth_mapping_uat_t)
UAT_VS_DEF(xcp_uat_eth_mappings,            port_type,      xcp_eth_mapping_uat_t, uint8_t, XCP_PORT_TCP, "TCP")
UAT_DEC_CB_DEF(xcp_uat_eth_mappings,        port_number,    xcp_eth_mapping_uat_t)
UAT_HEX_CB_DEF(xcp_uat_eth_mappings,        ecu_id,         xcp_eth_mapping_uat_t)

static uint64_t
xcp_eth_mapping_calc_key(const address *addr, const uint8_t xcp_port_type, const uint16_t port) {
    uint64_t hash = ((uint64_t)xcp_port_type) << 16 | (uint64_t)port;

    return add_address_to_hash64(hash, addr);
}

static void
register_xcp_eth(void) {
    uint32_t i;
    for (i = 0; i < xcp_uat_eth_mapping_num; i++) {
        uint16_t port_number = xcp_uat_eth_mappings[i].port_number;

        switch (xcp_uat_eth_mappings[i].port_type) {
        case XCP_PORT_UDP:
            if (xcp_handle_udp != NULL) {
                dissector_add_uint("udp.port", port_number, xcp_handle_udp);
            }
            break;
        case XCP_PORT_TCP:
            if (xcp_handle_tcp != NULL) {
                dissector_add_uint("tcp.port", port_number, xcp_handle_tcp);
            }
            break;
        }
    }
}

static void *
copy_xcp_eth_mapping_cb(void *n, const void *o, size_t size _U_) {
    xcp_eth_mapping_uat_t *new_rec = (xcp_eth_mapping_uat_t *)n;
    const xcp_eth_mapping_uat_t *old_rec = (const xcp_eth_mapping_uat_t *)o;

    new_rec->protocol = old_rec->protocol;
    new_rec->ip_address = g_strdup(old_rec->ip_address);
    new_rec->port_type = old_rec->port_type;
    new_rec->port_number = old_rec->port_number;
    new_rec->ecu_id = old_rec->ecu_id;

    return new_rec;
}

static bool
update_xcp_eth_mapping_cb(void *r, char **err) {
    xcp_eth_mapping_uat_t *rec = (xcp_eth_mapping_uat_t *)r;

    if ((rec->port_type) != XCP_PROTO_IPV4 && (rec->port_type) != XCP_PROTO_IPV6) {
        *err = g_strdup_printf("Invalid Proto Type (0x%d)", rec->protocol);
        return false;
    }

    /* TODO: check ip_address */

    if ((rec->port_type) != XCP_PORT_UDP && (rec->port_type) != XCP_PORT_TCP) {
        *err = g_strdup_printf("Invalid Port Type (0x%d)", rec->port_type);
        return false;
    }

    if ((rec->port_number) > 0xffff) {
        *err = g_strdup_printf("Invalid Port Number (0x%d)", rec->port_number);
        return false;
    }

    if ((rec->ecu_id) > 0xffff) {
        *err = g_strdup_printf("We currently only support 16bit ECU-IDs (0x%x) up to 0xffff", rec->ecu_id);
        return false;
    }

    return true;
}

static void
free_xcp_eth_mapping_cb(void *r) {
    xcp_eth_mapping_uat_t *rec = (xcp_eth_mapping_uat_t *)r;

    if (rec != NULL) {
        /* freeing result of g_strdup */
        g_free(rec->ip_address);
        rec->ip_address = NULL;
    }
}

static xcp_eth_mapping_t *
eth_mapping_uat_entry_to_eth_mapping_entry(uint32_t i) {
    xcp_eth_mapping_t *ret = &(xcp_eth_mappings_priv[i]);

    clear_address(&(ret->addr));

    switch (xcp_uat_eth_mappings[i].protocol) {
    case XCP_PROTO_IPV4: {
        ws_in4_addr tmp4;
        if (ws_inet_pton4(xcp_uat_eth_mappings[i].ip_address, &tmp4)) {
            alloc_address_wmem(wmem_epan_scope(), &(ret->addr), AT_IPv4, 4, &tmp4);
        }
    }
        break;
    case XCP_PROTO_IPV6: {
        ws_in6_addr tmp6;
        if (ws_inet_pton6(xcp_uat_eth_mappings[i].ip_address, &tmp6)) {
            alloc_address_wmem(wmem_epan_scope(), &(ret->addr), AT_IPv6, sizeof(ws_in6_addr), &tmp6);
        }
    }
        break;

    case XCP_PROTO_ANY:
        clear_address(&(ret->addr));
    }

    ret->port_type      = xcp_uat_eth_mappings[i].port_type;
    ret->port_number    = (uint16_t)xcp_uat_eth_mappings[i].port_number;
    ret->ecu_id         = (uint16_t)xcp_uat_eth_mappings[i].ecu_id;
    ret->stream         = NULL;

    return ret;
}

static void
reset_xcp_eth_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_xcp_eth_mappings) {
        g_hash_table_destroy(data_xcp_eth_mappings);
        data_xcp_eth_mappings = NULL;
    }
}

static void
post_update_xcp_eth_mapping_cb(void) {
    /* destroy the local xcp_uat_eth_mappings array */
    if (xcp_eth_mappings_priv != NULL) {
        for (uint32_t i = 0; i < xcp_uat_eth_mapping_num_current; i++) {
            if (xcp_eth_mappings_priv[i].stream != NULL) {
                wmem_free(wmem_epan_scope(), xcp_eth_mappings_priv[i].stream);
                xcp_eth_mappings_priv[i].stream = NULL;
            }
            free_address_wmem(wmem_epan_scope(), &(xcp_eth_mappings_priv[i].addr));
        }

        wmem_free(wmem_epan_scope(), xcp_eth_mappings_priv);
        xcp_eth_mappings_priv = NULL;
    }

    xcp_eth_mappings_priv = (xcp_eth_mapping_t *)wmem_alloc0_array(wmem_epan_scope(), xcp_eth_mapping_t, xcp_uat_eth_mapping_num);
    xcp_uat_eth_mapping_num_current = xcp_uat_eth_mapping_num;

    /* destroy old hash table, if it exists */
    reset_xcp_eth_mapping_cb();

    /* we don't need to free the data as long as we don't alloc it first */
    data_xcp_eth_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);

    for (uint32_t i = 0; i < xcp_uat_eth_mapping_num; i++) {
        xcp_eth_mapping_t* mapping = eth_mapping_uat_entry_to_eth_mapping_entry(i);

        uint64_t* hash = g_new(uint64_t, 1);
        *hash = xcp_eth_mapping_calc_key(&(mapping->addr), mapping->port_type, mapping->port_number);

        g_hash_table_insert(data_xcp_eth_mappings, hash, mapping);
    }

    /* we need to register the CAN-IDs */
    register_xcp_eth();
}

static xcp_eth_mapping_t *
get_eth_mapping(const address *addr, const uint8_t xcp_port_type, const uint16_t port) {
    if (data_xcp_eth_mappings == NULL) {
        return NULL;
    }

    uint64_t key = xcp_eth_mapping_calc_key(addr, xcp_port_type, port);
    xcp_eth_mapping_t *tmp = g_hash_table_lookup(data_xcp_eth_mappings, &key);
    return tmp;
}


/* UAT: CAN Mapping */
UAT_HEX_CB_DEF(xcp_uat_can_mappings,     bus_id,         xcp_can_mapping_uat_t)
UAT_HEX_CB_DEF(xcp_uat_can_mappings,     can_id_m_to_s,  xcp_can_mapping_uat_t)
UAT_HEX_CB_DEF(xcp_uat_can_mappings,     can_id_s_to_m,  xcp_can_mapping_uat_t)
UAT_HEX_CB_DEF(xcp_uat_can_mappings,     ecu_id,         xcp_can_mapping_uat_t)

static void
register_xcp_can(void) {
    if (xcp_handle_can == NULL) {
        return;
    }

    dissector_delete_all("can.id", xcp_handle_can);
    dissector_delete_all("can.extended_id", xcp_handle_can);

    /* CAN: loop over all frame IDs in HT */
    if (data_xcp_can_mappings != NULL) {
        GList *keys = g_hash_table_get_keys(data_xcp_can_mappings);

        GList *tmp;
        for (tmp = keys; tmp != NULL; tmp = tmp->next) {
            uint32_t id = (uint32_t)(*(uint64_t*)tmp->data);

            if ((id & CAN_EFF_FLAG) == CAN_EFF_FLAG) {
                dissector_add_uint("can.extended_id", id & CAN_EFF_MASK, xcp_handle_can);
            } else {
                dissector_add_uint("can.id", id & CAN_SFF_MASK, xcp_handle_can);
            }
        }

        g_list_free(keys);
    }
}

static void *
copy_xcp_can_mapping_cb(void *n, const void *o, size_t size _U_) {
    xcp_can_mapping_uat_t *new_rec = (xcp_can_mapping_uat_t *)n;
    const xcp_can_mapping_uat_t *old_rec = (const xcp_can_mapping_uat_t *)o;

    new_rec->bus_id         = old_rec->bus_id;
    new_rec->can_id_m_to_s  = old_rec->can_id_m_to_s;
    new_rec->can_id_s_to_m  = old_rec->can_id_s_to_m;
    new_rec->ecu_id         = old_rec->ecu_id;

    return new_rec;
}

static bool
update_xcp_can_mapping_cb(void *r, char **err) {
    xcp_can_mapping_uat_t *rec = (xcp_can_mapping_uat_t *)r;

    if ((rec->ecu_id) > 0xffff) {
        *err = g_strdup_printf("We currently only support 16bit ECU-IDs (0x%x) up to 0xffff", rec->ecu_id);
        return false;
    }

    if ((rec->can_id_m_to_s & (CAN_RTR_FLAG | CAN_ERR_FLAG)) != 0) {
        *err = g_strdup_printf("We currently do not support CAN IDs with RTR or Error Flag set (CAN_ID: 0x%x M->S)", rec->can_id_m_to_s);
        return false;
    }

    if ((rec->can_id_m_to_s & CAN_EFF_FLAG) == 0 && rec->can_id_m_to_s > CAN_SFF_MASK) {
        *err = g_strdup_printf("Standard CAN ID (EFF flag not set) cannot be bigger than 0x7ff (CAN_ID: 0x%x M->S)", rec->can_id_m_to_s);
        return false;
    }

    if ((rec->can_id_s_to_m & (CAN_RTR_FLAG | CAN_ERR_FLAG)) != 0) {
        *err = g_strdup_printf("We currently do not support CAN IDs with RTR or Error Flag set (CAN_ID: 0x%x S->M)", rec->can_id_s_to_m);
        return false;
    }

    if ((rec->can_id_s_to_m & CAN_EFF_FLAG) == 0 && rec->can_id_s_to_m > CAN_SFF_MASK) {
        *err = g_strdup_printf("Standard CAN ID (EFF flag not set) cannot be bigger than 0x7ff (CAN_ID: 0x%x S->M)", rec->can_id_s_to_m);
        return false;
    }

    return true;
}

static xcp_can_mapping_t *
can_mapping_uat_entry_to_can_mapping_entry(uint32_t i) {
    xcp_can_mapping_t *ret = &(xcp_can_mappings_priv[i]);

    ret->bus_id         = xcp_uat_can_mappings[i].bus_id;
    ret->can_id_m_to_s  = xcp_uat_can_mappings[i].can_id_m_to_s;
    ret->can_id_s_to_m  = xcp_uat_can_mappings[i].can_id_s_to_m;
    ret->ecu_id         = (uint16_t)xcp_uat_can_mappings[i].ecu_id;
    ret->stream         = NULL;

    return ret;
}

static void
reset_xcp_can_mapping_cb(void) {
    /* destroy hash table, if it exists */
    if (data_xcp_can_mappings) {
        g_hash_table_destroy(data_xcp_can_mappings);
        data_xcp_can_mappings = NULL;
    }
}

static void
post_update_xcp_can_mapping_cb(void) {
    uint32_t i;
    uint64_t *key;

    /* destroy the local xcp_uat_can_mappings array */
    if (xcp_can_mappings_priv != NULL) {
        for (i = 0; i < xcp_uat_can_mapping_num_current; i++) {
            if (xcp_can_mappings_priv[i].stream != NULL) {
                wmem_free(wmem_epan_scope(), xcp_can_mappings_priv[i].stream);
            }
        }

        wmem_free(wmem_epan_scope(), xcp_can_mappings_priv);
        xcp_can_mappings_priv = NULL;
    }

    xcp_can_mappings_priv = (xcp_can_mapping_t *)wmem_alloc0_array(wmem_epan_scope(), xcp_can_mapping_t, xcp_uat_can_mapping_num);
    xcp_uat_can_mapping_num_current = xcp_uat_can_mapping_num;

    /* destroy old hash table, if it exists */
    reset_xcp_can_mapping_cb();

    /* we don't need to free the data as long as we don't alloc it first */
    data_xcp_can_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);

    for (i = 0; i < xcp_uat_can_mapping_num; i++) {
        xcp_can_mapping_t* mapping = can_mapping_uat_entry_to_can_mapping_entry(i);

        /* M -> S */
        key = g_new(uint64_t, 1);
        *key = xcp_uat_can_mappings[i].can_id_m_to_s | (((uint64_t)xcp_uat_can_mappings[i].bus_id & 0xffff) << 32);
        g_hash_table_insert(data_xcp_can_mappings, key, mapping);

        /* S -> M */
        key = g_new(uint64_t, 1);
        *key = xcp_uat_can_mappings[i].can_id_s_to_m | (((uint64_t)xcp_uat_can_mappings[i].bus_id & 0xffff) << 32);
        g_hash_table_insert(data_xcp_can_mappings, key, mapping);
    }

    /* we need to register the CAN-IDs */
    register_xcp_can();
}

static xcp_can_mapping_t *
get_can_mapping(uint32_t id, uint16_t bus_id) {
    if (data_xcp_can_mappings == NULL) {
        return NULL;
    }

    /* key is Bus ID, EFF Flag, CAN-ID */
    uint64_t key = ((uint64_t)id & (CAN_EFF_MASK | CAN_EFF_FLAG)) | ((uint64_t)bus_id << 32);
    xcp_can_mapping_t *tmp = (xcp_can_mapping_t *)g_hash_table_lookup(data_xcp_can_mappings, &key);

    if (tmp == NULL) {
        /* try again without Bus ID set */
        key = id & (CAN_EFF_MASK | CAN_EFF_FLAG);
        tmp = (xcp_can_mapping_t *)g_hash_table_lookup(data_xcp_can_mappings, &key);
    }

    return tmp;
}

/*** State ***/

static xcp_daq_t *
get_daq_from_message(xcp_message_t *message, uint32_t i) {
    if (message == NULL || message->current_daqs == NULL || i >= message->number_of_daqs || i >= wmem_array_get_count(message->current_daqs)) {
        return NULL;
    }

    return (xcp_daq_t *)wmem_array_index(message->current_daqs, i);
}

static xcp_odt_t *
get_odt_from_message(xcp_message_t *message, uint32_t daq_number, uint32_t i) {
    xcp_daq_t *daq = get_daq_from_message(message, daq_number);

    if (daq == NULL || daq->current_odts == NULL || i >= daq->number_of_odts || i >= wmem_array_get_count(daq->current_odts)) {
        return NULL;
    }

    return (xcp_odt_t *)wmem_array_index(daq->current_odts, i);
}

static xcp_odt_entry_t *
get_odt_entry_from_message(xcp_message_t *message, uint32_t daq_number, uint32_t odt_number, uint32_t i) {
    xcp_odt_t *odt = get_odt_from_message(message, daq_number, odt_number);

    if (odt == NULL || odt->current_odt_entries == NULL || i >= odt->number_of_odt_entries || i >= wmem_array_get_count(odt->current_odt_entries)) {
        return NULL;
    }

    return (xcp_odt_entry_t *)wmem_array_index(odt->current_odt_entries, i);
}


/*** Dissector ***/
static int
dissect_transport_layer_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset_orig, int max_length _U_, bool m2s, uint32_t xcp_type, xcp_message_t *message, xcp_stream_t *stream _U_) {
    uint32_t    offset = offset_orig;
    uint32_t    subcmd;
    const char *tmp_name;

    if (m2s) {
        switch (xcp_type) {
        case XCP_TYPE_ETHERNET:
            /* All multi-byte parameters are ENC_LITTLE_ENDIAN */
            proto_tree_add_item_ret_uint(tree, hf_xcp_sub_command_eth, tvb, offset, 1, ENC_NA, &subcmd);
            message->transport_layer_sub_cmd = subcmd;
            offset += 1;

            tmp_name = try_val_to_str(subcmd, sub_cmd_code_mnemonics_eth);
            if (tmp_name != NULL) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", tmp_name);
            }

            switch (message->transport_layer_sub_cmd) {
            case XCP_SUB_CMD_ETH_GET_SLAVE_ID: {
                uint32_t ip_version = tvb_get_uint8(tvb, offset + 18);

                proto_tree_add_item(tree, hf_xcp_sub_command_eth_port, tvb, offset, 2, ENC_LITTLE_ENDIAN); // ENC_LITTLE_ENDIAN ok
                offset += 2;

                switch (ip_version) {
                case 0:
                    /* TODO: is this actually encoded in big-endian order? */
                    proto_tree_add_item(tree, hf_xcp_sub_command_eth_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;

                    /* TODO: we need to register the address and since the answer will be sent there... */
                    /* This is a bit unclear in the standard and requires example traces. */

                    proto_tree_add_item(tree, hf_xcp_sub_command_eth_reserved, tvb, offset, 12, ENC_NA);
                    offset += 12;

                    proto_tree_add_item(tree, hf_xcp_sub_command_eth_ip_version, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

            }
                break;
            //case XCP_SUB_CMD_ETH_GET_SLAVE_ID_EXT:
            //    /* TODO */
            //    break;
            //case XCP_SUB_CMD_ETH_GET_SLAVE_IP_ADDR:
            //    /* TODO */
            //    break;
            //case XCP_SUB_CMD_ETH_GET_DAQ_CLC_MCAST:
            //    /* TODO */
            //    break;
            }
            break;

        case XCP_TYPE_CAN:
            proto_tree_add_item_ret_uint(tree, hf_xcp_sub_command_can, tvb, offset, 1, ENC_NA, &subcmd);
            message->transport_layer_sub_cmd = subcmd;
            //offset += 1;

            //switch (message->transport_layer_sub_cmd) {
            //case XCP_SUB_CMD_CAN_GET_SLAVE_ID:
            //    /* TODO */
            //    break;
            //case XCP_SUB_CMD_CAN_GET_DAQ_ID:
            //    /* TODO */
            //    break;
            //case XCP_SUB_CMD_CAN_SET_DAQ_ID:
            //    /* TODO */
            //    break;
            //case XCP_SUB_CMD_CAN_GET_DAQ_CLC_MCAST:
            //    /* TODO */
            //    break;
            //}
            break;

        default:
            proto_tree_add_expert_remaining(tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
            col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
            break;
        }
    } else {
        if (message->peer_message != NULL) {
            switch (xcp_type) {
            case XCP_TYPE_ETHERNET:
                //switch (message->transport_layer_sub_cmd) {
                //case XCP_SUB_CMD_ETH_GET_SLAVE_ID:
                //    /* TODO */
                //    break;
                //case XCP_SUB_CMD_ETH_GET_SLAVE_ID_EXT:
                //    /* TODO */
                //    break;
                //case XCP_SUB_CMD_ETH_GET_SLAVE_IP_ADDR:
                //    /* TODO */
                //    break;
                //case XCP_SUB_CMD_ETH_GET_DAQ_CLC_MCAST:
                //    /* TODO */
                //    break;
                //}
                break;
            case XCP_TYPE_CAN:
                //switch (message->transport_layer_sub_cmd) {
                //case XCP_SUB_CMD_CAN_GET_SLAVE_ID:
                //    /* TODO */
                //    break;
                //case XCP_SUB_CMD_CAN_GET_DAQ_ID:
                //    /* TODO */
                //    break;
                //case XCP_SUB_CMD_CAN_SET_DAQ_ID:
                //    /* TODO */
                //    break;
                //case XCP_SUB_CMD_CAN_GET_DAQ_CLC_MCAST:
                //    /* TODO */
                //    break;
                //}
                break;

            default:
                proto_tree_add_expert_remaining(tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
                col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
                break;
            }
        }
    }

    return offset - offset_orig;
}

static int
dissect_sw_debug_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset_orig, int max_length _U_, bool m2s, uint32_t xcp_type _U_, xcp_message_t *message, xcp_stream_t *stream _U_) {
    uint32_t offset = offset_orig;

    if (m2s) {
        uint32_t cmd;
        proto_tree_add_item_ret_uint(tree, hf_xcp_debug_command, tvb, offset, 1, ENC_NA, &cmd);
        message->cmd_sw_debug = cmd;
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(pinfo->pool, cmd, cmd_sw_dbg_mnemonics, "Unknown Software Debug Command (0x%02x)"));
        offset += 1;

        /* TODO */
        proto_tree_add_expert_remaining(tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
        col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
        offset += tvb_captured_length_remaining(tvb, offset);

    } else {

        /* TODO */
        proto_tree_add_expert_remaining(tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
        col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    return offset - offset_orig;
}

static int
dissect_pod_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset_orig, int max_length _U_, bool m2s, uint32_t xcp_type _U_, xcp_message_t *message, xcp_stream_t *stream) {
    if (stream == NULL || message == NULL) {
        /* should never happen */
        ws_assert_not_reached();
        return 0;
    }

    uint32_t offset = offset_orig;

    if (m2s) {
        uint32_t cmd;
        proto_tree_add_item_ret_uint(tree, hf_xcp_pod_command, tvb, offset, 2, stream->endianess, &cmd);
        message->cmd_pod = cmd;
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(pinfo->pool, cmd, cmd_pod_mnemonics, "Unknown POD Command (0x%04x)"));
        offset += 1;

        switch (message->cmd_pod) {
        //case XCP_CMD_POD_GET_INFO:
        //    /* TODO */
        //    break;

        //case XCP_CMD_POD_SET_ACTIVE_CONFIG:
        //    /* TODO */
        //    break;

        //case XCP_CMD_POD_MANAGE_TRANSFER:
        //    /* TODO */
        //    break;

        //case XCP_CMD_POD_DOWNLOAD:
        //    /* TODO */
        //    break;

        //case XCP_CMD_POD_UPLOAD:
        //    /* TODO */
        //    break;

        case XCP_CMD_POD_GET_STATUS:
            /* No Parameters */
            break;

        default:
            proto_tree_add_expert_remaining(tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
            col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
            offset += tvb_captured_length_remaining(tvb, offset);
        }

    } else {
        switch (message->cmd_pod) {
        //case XCP_CMD_POD_GET_INFO:
        //    /* TODO */
        //    break;

        //case XCP_CMD_POD_SET_ACTIVE_CONFIG:
        //    /* TODO */
        //    break;

        //case XCP_CMD_POD_MANAGE_TRANSFER:
        //    /* TODO */
        //    break;

        case XCP_CMD_POD_DOWNLOAD:
            /* No Parameters */
            break;

        //case XCP_CMD_POD_UPLOAD:
        //    /* TODO */
        //    break;

        //case XCP_CMD_POD_GET_STATUS:
        //    /* TODO */
        //    break;

        default:
            proto_tree_add_expert_remaining(tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
            col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
            offset += tvb_captured_length_remaining(tvb, offset);
        }
    }

    return offset - offset_orig;
}

static int
dissect_xcp_m2s(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset_orig, int max_length, uint32_t xcp_type, xcp_message_t *message, xcp_stream_t *stream) {
    if (stream == NULL || message == NULL) {
        /* should never happen */
        ws_assert_not_reached();
        return 0;
    }

    uint32_t offset = offset_orig;
    proto_item *ti_root = NULL;
    proto_tree *xcp_tree = NULL;

    ti_root = proto_tree_add_item(tree, hf_xcp_packet, tvb, offset, max_length, ENC_NA);
    xcp_tree = proto_item_add_subtree(ti_root, ett_xcp_packet);

    uint32_t cmd;
    uint32_t cmd_lvl1 = XCP_MESSAGE_CMD_UNKNOWN;

    proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_cmd_code, tvb, offset, 1, ENC_NA, &cmd);
    offset += 1;

    if (cmd != XCP_CMD_2BYTE_FIRST_BYTE) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "XCP M->S: %s", val_to_str(pinfo->pool, cmd, cmd_code_mnemonics, "Unknown Command Code (0x%02x)"));
    } else {
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_cmd_code_level1, tvb, offset, 1, ENC_NA, &cmd_lvl1);
        offset += 1;

        if (cmd_lvl1 == XCP_CMD_2BYTE_XCP_POD_COMMANDS || cmd_lvl1 == XCP_CMD_2BYTE_XCP_SW_DEBUG) {
            col_set_str(pinfo->cinfo, COL_INFO, "XCP M->S:");
        } else {
            col_add_fstr(pinfo->cinfo, COL_INFO, "XCP M->S: %s", val_to_str(pinfo->pool, cmd_lvl1, cmd_code_mnemonics_2bytes, "Unknown Command Code (0xC0 0x%02x)"));
        }
    }

    /* setting up the meta data*/
    if (!(pinfo->fd->visited)) {
        stream->last_m2s = message;
        message->number_of_daqs = stream->number_of_daqs;
        message->current_daqs = stream->current_daqs;

        message->peer_message   = NULL;
        message->m2s            = true;
        message->cmd            = cmd;
        message->cmd_lvl1       = cmd_lvl1;
    }

    switch (cmd) {
    case XCP_CMD_CONNECT:
        proto_tree_add_item(xcp_tree, hf_xcp_conn_mode, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    case XCP_CMD_DISCONNECT:
        /* No Parameters */
        break;

    case XCP_CMD_GET_STATUS:
        /* No Parameters */
        break;

    case XCP_CMD_SYNCH:
        /* No Parameters */
        break;

    case XCP_CMD_GET_COMM_MODE_INFO:
        /* No Parameters */
        break;

    case XCP_CMD_GET_ID:
        proto_tree_add_item(xcp_tree, hf_xcp_get_id_req_id_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    case XCP_CMD_SET_REQUEST: {
        static int * const set_request_mode_flags[] = {
            &hf_xcp_set_req_md_clr_daq_cfg_lost,
            &hf_xcp_set_req_md_clr_cal_pag_cfg_lost,
            &hf_xcp_set_req_md_clr_daq_req,
            &hf_xcp_set_req_md_str_daq_req_resume,
            &hf_xcp_set_req_md_str_daq_req_no_resume,
            &hf_xcp_set_req_md_str_cal_req,
            NULL
        };

        proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_set_req_md, ett_xcp_set_request_mode, set_request_mode_flags, ENC_NA);
        offset += 1;

        proto_tree_add_item(xcp_tree, hf_xcp_session_cfg_id, tvb, offset, 2, stream->endianess);
        offset += 2;
    }
        break;

    case XCP_CMD_GET_SEED: {
        uint32_t seed_mode;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_get_seed_mode, tvb, offset, 1, ENC_NA, &seed_mode);
        offset += 1;

        if (seed_mode == 0) {
            proto_tree_add_item(xcp_tree, hf_xcp_get_seed_resource, tvb, offset, 1, ENC_NA);
        } else {
            proto_tree_add_item(xcp_tree, hf_xcp_get_seed_dont_care, tvb, offset, 1, ENC_NA);
        }
        offset += 1;
    }
        break;

    case XCP_CMD_UNLOCK: {
        proto_tree_add_item(xcp_tree, hf_xcp_unlock_length_of_key, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t key_length = max_length - (offset - offset_orig);
        proto_tree_add_item(xcp_tree, hf_xcp_unlock_key, tvb, offset, key_length, ENC_NA);
        offset += key_length;
    }
        break;

    case XCP_CMD_SET_MTA: {
        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t address_extension;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_address_extension, tvb, offset, 1, ENC_NA, &address_extension);
        offset += 1;

        uint32_t memory_address;
        proto_item *ti = proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_address, tvb, offset, 4, stream->endianess, &memory_address);
        offset += 4;

        char *name_string = xcp_lookup_memory_address(stream->ecu_id, (uint8_t)address_extension, memory_address);
        if (name_string != NULL) {
            proto_item_append_text(ti, " (%s)", name_string);
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x%04x %s", address_extension, memory_address, name_string);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x%04x", address_extension, memory_address);
        }
    }
        break;

    case XCP_CMD_UPLOAD:
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_num_of_data_elements, tvb, offset, 1, ENC_NA, &(message->number_of_elements));
        offset += 1;
        break;

    case XCP_CMD_SHORT_UPLOAD: {
        uint32_t number_of_elements;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_num_of_data_elements, tvb, offset, 1, ENC_NA, &number_of_elements);
        message->number_of_elements = number_of_elements;
        offset += 1;

        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t address_extension;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_address_extension, tvb, offset, 1, ENC_NA, &address_extension);
        offset += 1;

        uint32_t memory_address;
        proto_item *ti = proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_address, tvb, offset, 4, stream->endianess, &memory_address);
        offset += 4;

        char *name_string = xcp_lookup_memory_address(stream->ecu_id, (uint8_t)address_extension, memory_address);
        if (name_string != NULL) {
            proto_item_append_text(ti, " (%s)", name_string);
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x%04x [%d] %s", address_extension, memory_address, number_of_elements, name_string);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x%04x [%d]", address_extension, memory_address, number_of_elements);
        }

    }
        break;

    case XCP_CMD_BUILD_CHECKSUM: {
        proto_tree_add_item(xcp_tree, hf_xcp_build_chksum_res1, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(xcp_tree, hf_xcp_build_chksum_res2, tvb, offset, 2, stream->endianess);
        offset += 2;

        uint32_t block_size;
        proto_item *ti = proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_build_chksum_block_size, tvb, offset, 4, stream->endianess, &block_size);
        proto_item_append_text(ti, " (%d)", stream->addr_granularity * block_size);
        offset += 4;
    }
        break;

    case XCP_CMD_TRANSPORT_LAYER_CMD:
        offset += dissect_transport_layer_cmd(tvb, pinfo, xcp_tree, offset, max_length, true, xcp_type, message, stream);
        break;

    //case XCP_CMD_USER_CMD:
    //    /* TODO */
    //    break;


    case XCP_CMD_DOWNLOAD: {
        uint32_t number_of_elements;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_num_of_data_elements, tvb, offset, 1, ENC_NA, &number_of_elements);
        message->number_of_elements = number_of_elements;
        offset += 1;

        uint32_t i;
        uint32_t tmp;
        if (stream->addr_granularity == 1) {
            for (i = 0; i < number_of_elements; i++) {
                proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_1byte, tvb, offset, 1, ENC_NA, &tmp);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tmp);
                offset += 1;
            }
        } else if (stream->addr_granularity == 2) {
            for (i = 0; i < number_of_elements; i++) {
                proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_2bytes, tvb, offset, 2, stream->endianess, &tmp);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x", tmp);
                offset += 2;
            }
        } else if (stream->addr_granularity == 4) {
            proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
            offset += 2;

            for (i = 0; i < number_of_elements; i++) {
                proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_4bytes, tvb, offset, 4, stream->endianess, &tmp);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%08x", tmp);
                offset += 4;
            }
        }

    }
        break;

    //case XCP_CMD_DOWNLOAD_NEXT:
    //    /* TODO */
    //    break;

    //case XCP_CMD_DOWNLOAD_MAX:
    //    /* TODO */
    //    break;

    case XCP_CMD_SHORT_DOWNLOAD: {
        uint32_t number_of_elements;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_num_of_data_elements, tvb, offset, 1, ENC_NA, &number_of_elements);
        message->number_of_elements = number_of_elements;
        offset += 1;

        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t address_extension;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_address_extension, tvb, offset, 1, ENC_NA, &address_extension);
        offset += 1;

        uint32_t memory_address;
        proto_item *ti = proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_address, tvb, offset, 4, stream->endianess, &memory_address);
        offset += 4;

        char *name_string = xcp_lookup_memory_address(stream->ecu_id, (uint8_t)address_extension, memory_address);
        if (name_string != NULL) {
            proto_item_append_text(ti, " (%s)", name_string);
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x%04x [%d] %s", address_extension, memory_address, number_of_elements, name_string);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x%04x [%d]", address_extension, memory_address, number_of_elements);
        }

        uint32_t i;
        uint32_t tmp;

        if (stream->addr_granularity == 1) {
            for (i = 0; i < number_of_elements; i++) {
                proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_1byte, tvb, offset, 1, ENC_NA, &tmp);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tmp);
                offset += 1;
            }
        } else if (stream->addr_granularity == 2) {
            for (i = 0; i < number_of_elements; i++) {
                proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_2bytes, tvb, offset, 2, stream->endianess, &tmp);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x", tmp);
                offset += 2;
            }
        } else if (stream->addr_granularity == 4) {
            for (i = 0; i < number_of_elements; i++) {
                proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_4bytes, tvb, offset, 4, stream->endianess, &tmp);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%08x", tmp);
                offset += 4;
            }
        }

    }
        break;

    //case XCP_CMD_MODIFY_BITS:
    //    /* TODO */
    //    break;


    case XCP_CMD_SET_CAL_PAGE: {
        static int * const set_cal_page_mode[] = {
            &hf_xcp_set_cal_page_mode_all,
            &hf_xcp_set_cal_page_mode_xcp,
            &hf_xcp_set_cal_page_mode_ecu,
            NULL
        };

        proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_set_cal_page_mode, ett_xcp_set_cal_page_mode, set_cal_page_mode, ENC_NA);
        offset += 1;

        uint32_t segment_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_logical_data_segment_number, tvb, offset, 1, ENC_NA, &segment_number);
        offset += 1;

        uint32_t page_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_logical_data_page_number, tvb, offset, 1, ENC_NA, &page_number);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, ": SEGMENT:%d PAGE:%d", segment_number, page_number);
    }
        break;

    case XCP_CMD_GET_CAL_PAGE: {
        proto_tree_add_item(xcp_tree, hf_xcp_access_mode, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t segment_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_logical_data_segment_number, tvb, offset, 1, ENC_NA, &segment_number);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, ": SEGMENT:%d", segment_number);
    }
        break;

    case XCP_CMD_GET_PAG_PROCESSOR_INFO:
        /* No Parameters */
        break;

    //case XCP_CMD_GET_SEGMENT_INFO:
    //    /* TODO */
    //    break;

    //case XCP_CMD_GET_PAGE_INFO:
    //    /* TODO */
    //    break;

    //case XCP_CMD_SET_SEGMENT_MODE:
    //    /* TODO */
    //    break;

    //case XCP_CMD_GET_SEGMENT_MODE:
    //    /* TODO */
    //    break;

    case XCP_CMD_COPY_CAL_PAGE:
        proto_tree_add_item(xcp_tree, hf_xcp_logical_data_segm_num_src, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(xcp_tree, hf_xcp_logical_data_page_num_src, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(xcp_tree, hf_xcp_logical_data_segm_num_dst, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(xcp_tree, hf_xcp_logical_data_page_num_dst, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;


    case XCP_CMD_CLEAR_DAQ_LIST: {
        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t daq_list_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_daq_list_number, tvb, offset, 2, stream->endianess, &daq_list_number);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, ": DAQ_LIST:%d", daq_list_number);
    }
        break;

    case XCP_CMD_SET_DAQ_PTR: {
        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t daq_list_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_daq_list_number, tvb, offset, 2, stream->endianess, &daq_list_number);
        offset += 2;

        uint32_t odt_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_odt_number, tvb, offset, 1, ENC_NA, &odt_number);
        offset += 1;

        uint32_t odt_entry_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_odt_entry_number, tvb, offset, 1, ENC_NA, &odt_entry_number);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, ": DAQ_LIST:%d ODT:%d ODT_ENTRY:%d", daq_list_number, odt_number, odt_entry_number);

        stream->current_daq = daq_list_number;
        stream->current_odt = odt_number;
        stream->current_odt_entry = odt_entry_number;
    }
        break;

    case XCP_CMD_WRITE_DAQ: {
        uint32_t bit_offset;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_bit_offset, tvb, offset, 1, ENC_NA, &bit_offset);
        offset += 1;

        uint32_t size_of_daq_element;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_size_of_daq_element, tvb, offset, 1, ENC_NA, &size_of_daq_element);
        offset += 1;

        if (bit_offset == 0xff) {
            /* bit offset can be ignored */
            col_append_fstr(pinfo->cinfo, COL_INFO, ": SIZE_OF_DAQ_ELEMENT:%d", size_of_daq_element);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": BIT_OFFSET:%d SIZE_OF_DAQ_ELEMENT:%d", bit_offset, size_of_daq_element);
        }

        uint32_t address_extension;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_address_extension, tvb, offset, 1, ENC_NA, &address_extension);
        offset += 1;

        uint32_t memory_address;
        proto_item *ti = proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_address, tvb, offset, 4, stream->endianess, &memory_address);
        offset += 4;

        char *name_string = xcp_lookup_memory_address(stream->ecu_id, (uint8_t)address_extension, memory_address);
        if (name_string != NULL) {
            proto_item_append_text(ti, " (%s)", name_string);
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x%04x %s", address_extension, memory_address, name_string);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x%04x", address_extension, memory_address);
        }

        xcp_odt_entry_t *odt_entry = get_odt_entry_from_message(message, stream->current_daq, stream->current_odt, stream->current_odt_entry);
        if (odt_entry != NULL) {
            odt_entry->ecu_id = stream->ecu_id;
            odt_entry->addr_ext = address_extension;
            odt_entry->address = memory_address;
            odt_entry->name = name_string == false ? NULL : wmem_strdup(wmem_file_scope(), name_string);
            odt_entry->size = size_of_daq_element;
        }

        stream->current_odt_entry += 1;
    }
        break;

    case XCP_CMD_SET_DAQ_LIST_MODE: {
        static int * const set_daq_list_mode_mode_flags[] = {
            &hf_xcp_set_daq_list_mode_mode_pid_off,
            &hf_xcp_set_daq_list_mode_mode_timestamp,
            &hf_xcp_set_daq_list_mode_mode_dto_ctr,
            &hf_xcp_set_daq_list_mode_mode_dir,
            &hf_xcp_set_daq_list_mode_mode_alt,
            NULL
        };

        uint64_t mode;
        proto_tree_add_bitmask_ret_uint64(xcp_tree, tvb, offset, hf_xcp_set_daq_list_mode_mode, ett_xcp_set_daq_list_mode_mode, set_daq_list_mode_mode_flags, ENC_NA, &mode);
        offset += 1;

        uint32_t daq_list_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_daq_list_number, tvb, offset, 2, stream->endianess, &daq_list_number);
        offset += 2;

        uint32_t channel_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_event_channel_number, tvb, offset, 2, stream->endianess, &channel_number);
        offset += 2;

        uint32_t prescaler;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_transmission_prescaler, tvb, offset, 1, ENC_NA, &prescaler);
        offset += 1;

        uint32_t priority;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_daq_list_priority, tvb, offset, 1, ENC_NA, &priority);
        offset += 1;

        col_append_str(pinfo->cinfo, COL_INFO, ": ");
        if ((mode & SET_DAQ_LIST_MODE_PID_OFF) == SET_DAQ_LIST_MODE_PID_OFF) {
            col_append_str(pinfo->cinfo, COL_INFO, "PID:OFF ");
        } else {
            col_append_str(pinfo->cinfo, COL_INFO, "PID:ON ");
        }

        if ((mode & SET_DAQ_LIST_MODE_TSTAMP) == SET_DAQ_LIST_MODE_TSTAMP) {
            col_append_str(pinfo->cinfo, COL_INFO, "TSTAMP:ON ");
        } else {
            col_append_str(pinfo->cinfo, COL_INFO, "TSTAMP:OFF ");
        }

        if ((mode & SET_DAQ_LIST_MODE_DTO_CTR) == SET_DAQ_LIST_MODE_DTO_CTR) {
            col_append_str(pinfo->cinfo, COL_INFO, "DTO_CTR:ON ");
        } else {
            col_append_str(pinfo->cinfo, COL_INFO, "DTO_CTR:OFF ");
        }

        if ((mode & SET_DAQ_LIST_MODE_DIR) == SET_DAQ_LIST_MODE_DIR) {
            col_append_str(pinfo->cinfo, COL_INFO, "STIM ");
        } else {
            col_append_str(pinfo->cinfo, COL_INFO, "DAQ ");
        }

        if ((mode & SET_DAQ_LIST_MODE_ALT) == SET_DAQ_LIST_MODE_ALT) {
            col_append_str(pinfo->cinfo, COL_INFO, "ALT:ON ");
        } else {
            col_append_str(pinfo->cinfo, COL_INFO, "ALT:OFF ");
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, "DAQ_LIST:%d EVENT_CHANNEL:%d PRESCALER:%d PRIO:%d", daq_list_number, channel_number, prescaler, priority);

        /* TODO: This information affects the DTO format, so we need to store it for the connection. */
    }
        break;

    //case XCP_CMD_GET_DAQ_LIST_MODE:
    //    /* TODO */
    //    break;

    case XCP_CMD_START_STOP_DAQ_LIST: {
        uint32_t start_stop_mode;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_start_stop_daq_mode, tvb, offset, 1, ENC_NA, &start_stop_mode);
        offset += 1;

        uint32_t daq_list_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_daq_list_number, tvb, offset, 2, stream->endianess, &daq_list_number);
        offset += 2;

        const char *tmp = try_val_to_str(start_stop_mode, start_stop_daq_mode);
        if (tmp != NULL) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s DAQ_LIST:%d", tmp, daq_list_number);
        }

        message->current_daq_list_number = daq_list_number;
    }
    break;

    case XCP_CMD_START_STOP_SYNCH: {
        uint32_t start_stop_mode;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_start_stop_synch_mode, tvb, offset, 1, ENC_NA, &start_stop_mode);
        offset += 1;

        const char *tmp = try_val_to_str(start_stop_mode, start_stop_synch_mode);
        if (tmp != NULL) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", tmp);
        }

    }
        break;

    case XCP_CMD_GET_DAQ_CLOCK:
        /* No Parameters */
        break;

    case XCP_CMD_READ_DAQ:
        /* No Parameters */
        break;

    case XCP_CMD_GET_DAQ_PROCESSOR_INFO:
        /* No Parameters */
        break;

    case XCP_CMD_GET_RESOLUTION_INFO:
        /* No Parameters */
        break;

    case XCP_CMD_GET_DAQ_LIST_INFO: {
        uint32_t daq_list_number;

        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_daq_list_number, tvb, offset, 2, stream->endianess, &daq_list_number);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, ": DAQ_LIST:%d", daq_list_number);
    }
        break;

    case XCP_CMD_GET_DAQ_EVENT_INFO: {
        uint32_t channel_number;
        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_event_channel_number, tvb, offset, 2, stream->endianess, &channel_number);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, ": CHANNEL_NUMBER:%d", channel_number);
    }
        break;

    case XCP_CMD_FREE_DAQ:
        /* No Parameters */

        stream->number_of_daqs = 0;
        message->number_of_daqs = 0;
        break;

    case XCP_CMD_ALLOC_DAQ: {
        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t daq_count;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_daq_count, tvb, offset, 2, stream->endianess, &daq_count);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, ": DAQ_COUNT:%d", daq_count);

        stream->number_of_daqs = daq_count;
        message->number_of_daqs = daq_count;

        stream->current_daqs = wmem_array_new(wmem_file_scope(), sizeof(xcp_daq_t));
        message->current_daqs = stream->current_daqs;

        uint32_t i;
        for (i = 0; i < daq_count; i++) {
            xcp_daq_t tmp;
            tmp.daq_number = i;
            tmp.number_of_odts = 0;
            tmp.current_odts = NULL;
            wmem_array_append(message->current_daqs, &tmp, 1);
        }

    }
        break;

    case XCP_CMD_ALLOC_ODT: {
        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t daq_list_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_daq_list_number, tvb, offset, 2, stream->endianess, &daq_list_number);
        offset += 2;

        uint32_t odt_count;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_odt_count, tvb, offset, 1, ENC_NA, &odt_count);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, ": DAQ_LIST:%d ODT_COUNT:%d", daq_list_number, odt_count);

        xcp_daq_t *daq = get_daq_from_message(message, daq_list_number);
        if (daq != NULL) {
            if (odt_count > 0) {
                daq->number_of_odts = odt_count;
                daq->current_odts = wmem_array_new(wmem_file_scope(), sizeof(xcp_odt_t));

                uint32_t i;
                for (i = 0; i < odt_count; i++) {
                    xcp_odt_t tmp;
                    tmp.odt_number = i;
                    tmp.pid = 0xffffffff;
                    tmp.number_of_odt_entries = 0;
                    tmp.current_odt_entries = NULL;

                    wmem_array_append(daq->current_odts, &tmp, 1);
                }
            }
        }
    }
        break;

    case XCP_CMD_ALLOC_ODT_ENTRY: {
        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t daq_list_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_daq_list_number, tvb, offset, 2, stream->endianess, &daq_list_number);
        offset += 2;

        uint32_t odt_number;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_odt_number, tvb, offset, 1, ENC_NA, &odt_number);
        offset += 1;

        uint32_t odt_entries_count;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_odt_entries_count, tvb, offset, 1, ENC_NA, &odt_entries_count);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, ": DAQ_LIST:%d ODT:%d ODT_ENTRIES_COUNT:%d", daq_list_number, odt_number, odt_entries_count);

        xcp_odt_t *odt = get_odt_from_message(message, daq_list_number, odt_number);
        if (odt != NULL) {
            if (odt_entries_count > 0) {
                odt->number_of_odt_entries = odt_entries_count;
                odt->current_odt_entries = wmem_array_new(wmem_file_scope(), sizeof(xcp_odt_entry_t));

                uint32_t i;
                for (i = 0; i < odt_entries_count; i++) {
                    xcp_odt_entry_t odt_entry;
                    odt_entry.ecu_id = stream->ecu_id;
                    odt_entry.addr_ext = 0;
                    odt_entry.address = 0;
                    odt_entry.name = NULL;
                    wmem_array_append(odt->current_odt_entries, &odt_entry, 1);
                }
            }
        }
    }
        break;


    case XCP_CMD_PROGRAM_START:
        /* No Parameters */
        break;

    case XCP_CMD_PROGRAM_CLEAR: {
        static int * const program_clear_range_fct_flags[] = {
            &hf_xcp_program_clear_range_fct_4,
            &hf_xcp_program_clear_range_fct_2,
            &hf_xcp_program_clear_range_fct_1,
            NULL
        };

        uint32_t clear_mode;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_program_clear_mode, tvb, offset, 1, ENC_NA, &clear_mode);
        offset += 1;

        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t clear_range_abs;
        uint64_t clear_range_fct;
        switch (clear_mode) {
        case 0x00:
            proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_program_clear_range_abs, tvb, offset, 4, stream->endianess, &clear_range_abs);
            offset += 4;

            col_append_fstr(pinfo->cinfo, COL_INFO, ": Clear Absolute 0x%08x", clear_range_abs);
            break;
        case 0x01:
            proto_tree_add_bitmask_ret_uint64(xcp_tree, tvb, offset, hf_xcp_program_clear_range_fct, ett_xcp_set_daq_list_mode_mode, program_clear_range_fct_flags, stream->endianess, &clear_range_fct);
            offset += 4;

            col_append_str(pinfo->cinfo, COL_INFO, ": Clear Functional:");
            if ((clear_range_fct & 0x00000001) == 0x00000001) {
                col_append_str(pinfo->cinfo, COL_INFO, "  Calibration area(s)");
            }
            if ((clear_range_fct & 0x00000002) == 0x00000002) {
                col_append_str(pinfo->cinfo, COL_INFO, "  Code area(s)");
            }
            if ((clear_range_fct & 0x00000004) == 0x00000004) {
                col_append_str(pinfo->cinfo, COL_INFO, "  NVRAM area(s)");
            }
            break;
        }
    }
        break;

    case XCP_CMD_PROGRAM: {
        uint32_t number_of_elements;
        proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_num_of_data_elements, tvb, offset, 1, ENC_NA, &number_of_elements);
        message->number_of_elements = number_of_elements;
        offset += 1;

        uint32_t i;
        uint32_t tmp;
        if (stream->addr_granularity == 1) {
            for (i = 0; i < number_of_elements; i++) {
                proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_1byte, tvb, offset, 1, ENC_NA, &tmp);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tmp);
                offset += 1;
            }
        } else if (stream->addr_granularity == 2) {
            for (i = 0; i < number_of_elements; i++) {
                proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_2bytes, tvb, offset, 2, stream->endianess, &tmp);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x", tmp);
                offset += 2;
            }
        } else if (stream->addr_granularity == 4) {
            proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
            offset += 2;

            for (i = 0; i < number_of_elements; i++) {
                proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_4bytes, tvb, offset, 4, stream->endianess, &tmp);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%08x", tmp);
                offset += 4;
            }
        }
    }
        break;

    case XCP_CMD_PROGRAM_RESET:
        /* No Parameters */
        break;

    case XCP_CMD_GET_PGM_PROCESSOR_INFO:
        /* No Parameters */
        break;

    //case XCP_CMD_GET_SECTOR_INFO:
    //    /* TODO */
    //    break;

    //case XCP_CMD_PROGRAM_PREPARE:
    //    /* TODO */
    //    break;

    //case XCP_CMD_PROGRAM_FORMAT:
    //    /* TODO */
    //    break;

    //case XCP_CMD_PROGRAM_NEXT:
    //    /* TODO */
    //    break;

    //case XCP_CMD_PROGRAM_MAX:
    //    /* TODO */
    //    break;

    //case XCP_CMD_PROGRAM_VERIFY:
    //    /* TODO */
    //    break;

    //case XCP_CMD_WRITE_DAQ_MULTIPLE:
    //    /* TODO */
    //    break;

    //case XCP_CMD_TIME_CORRELATION_PROPERTIES:
    //    /* TODO */
    //    break;

    //case XCP_CMD_DTO_CTR_PROPERTIES:
    //    /* TODO */
    //    break;


    case XCP_CMD_2BYTE_FIRST_BYTE:
        switch (cmd_lvl1) {
        case XCP_CMD_2BYTE_GET_VERSION:
            /* No Parameters */
            break;

        case XCP_CMD_2BYTE_SET_DAQ_PACKED_MODE: {
            static int * const set_daq_packed_timestamp_mode[] = {
                &hf_xcp_packed_timestamp_mode_flags,
                NULL
            };

            uint32_t daq_list_number;
            proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_daq_list_number, tvb, offset, 2, stream->endianess, &daq_list_number);
            offset += 2;

            proto_tree_add_item(xcp_tree, hf_xcp_daq_packed_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_packed_timestamp_mode, ett_xcp_set_daq_packed_mode_timestamp_mode, set_daq_packed_timestamp_mode, ENC_NA);
            offset += 1;

            uint32_t sample_count;
            proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_packed_sample_count, tvb, offset, 2, stream->endianess, &sample_count);
            offset += 2;

            col_append_fstr(pinfo->cinfo, COL_INFO, ": DAQ_LIST:%d SAMPLE_COUNT:%d", daq_list_number, sample_count);
        }
            break;

        //case XCP_CMD_2BYTE_GET_DAQ_PACKED_MODE:
        //    /* TODO */
        //    break;

        case XCP_CMD_2BYTE_XCP_SW_DEBUG:
            offset += dissect_sw_debug_cmd(tvb, pinfo, xcp_tree, offset, tvb_captured_length_remaining(tvb, offset), true, xcp_type, message, stream);
            break;

        case XCP_CMD_2BYTE_XCP_POD_COMMANDS:
            offset += dissect_pod_cmd(tvb, pinfo, xcp_tree, offset, tvb_captured_length_remaining(tvb, offset), true, xcp_type, message, stream);
            break;

        default:
            proto_tree_add_expert_remaining(xcp_tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
            col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
        }
        break;

    default:
        proto_tree_add_expert_remaining(xcp_tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
        col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
    }

    int unparsed_length = tvb_captured_length_remaining(tvb, offset);
    if (unparsed_length > 0) {
        proto_tree_add_item(xcp_tree, hf_xcp_unparsed, tvb, offset, unparsed_length, ENC_NA);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    return offset - offset_orig;
}

static int
dissect_xcp_s2m(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset_orig, int max_length, uint32_t xcp_type, xcp_message_t *message, xcp_stream_t *stream) {
    if (stream == NULL || message == NULL) {
        /* should never happen */
        ws_assert_not_reached();
        return 0;
    }

    uint32_t offset = offset_orig;
    proto_item *ti_root = NULL;
    proto_tree *xcp_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "XCP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti_root = proto_tree_add_item(tree, hf_xcp_packet, tvb, offset, max_length, ENC_NA);
    xcp_tree = proto_item_add_subtree(ti_root, ett_xcp_packet);

    /* setting up the meta data*/
    if (!(pinfo->fd->visited)) {

        stream->last_s2m = message;

        if (stream->last_m2s != NULL) {
            message->peer_message = stream->last_m2s;
            stream->last_m2s->peer_message = message;
        }

        message->number_of_daqs = stream->number_of_daqs;
        message->current_daqs = stream->current_daqs;

        message->m2s = false;
    }

    uint32_t pid = 0;
    proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_pid_s2m, tvb, offset, 1, ENC_NA, &pid);
    offset += 1;

    if (pid == XCP_PID_RES) {

        if (message != NULL && message->peer_message != NULL && message->peer_message->cmd != XCP_MESSAGE_CMD_UNKNOWN) {
            message->cmd = message->peer_message->cmd;
            message->cmd_lvl1 = message->peer_message->cmd_lvl1;
            message->cmd_sw_debug = message->peer_message->cmd_sw_debug;
            message->cmd_pod = message->peer_message->cmd_pod;
            message->transport_layer_sub_cmd = message->peer_message->transport_layer_sub_cmd;

            if (message->cmd != XCP_CMD_2BYTE_FIRST_BYTE) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "XCP S->M: %s RES", val_to_str(pinfo->pool, message->cmd, cmd_code_mnemonics, "Unknown Command Code 0x%02x"));
            } else {
                switch (message->cmd_lvl1) {
                case XCP_CMD_2BYTE_XCP_SW_DEBUG:
                    col_append_fstr(pinfo->cinfo, COL_INFO, "XCP S->M: %s RES", val_to_str(pinfo->pool, message->cmd_sw_debug, cmd_sw_dbg_mnemonics, "Unknown Command Code 0xC0 0xFC 0x%02x"));
                    break;

                case XCP_CMD_2BYTE_XCP_POD_COMMANDS:
                    col_append_fstr(pinfo->cinfo, COL_INFO, "XCP S->M: %s RES", val_to_str(pinfo->pool, message->cmd_pod, cmd_pod_mnemonics, "Unknown Command Code 0xC0 0xFD 0x%04x"));
                    break;

                default:
                    col_append_fstr(pinfo->cinfo, COL_INFO, "XCP S->M: %s RES", val_to_str(pinfo->pool, message->cmd_lvl1, cmd_code_mnemonics_2bytes, "Unknown Command Code 0xC0 0x%02x"));
                    break;
                }
            }
        }

        switch (message->cmd) {
        case XCP_CMD_CONNECT: {
            static int * const resource_flags[] = {
                &hf_xcp_conn_resource_dbg,
                &hf_xcp_conn_resource_pgm,
                &hf_xcp_conn_resource_stim,
                &hf_xcp_conn_resource_daq,
                &hf_xcp_conn_resource_cal_pag,
                NULL
            };

            static int * const comm_mode_basic_flags[] = {
                &hf_xcp_conn_comm_mode_bsc_optional,
                &hf_xcp_conn_comm_mode_bsc_sl_blk_mode,
                &hf_xcp_conn_comm_mode_bsc_addr_gran,
                &hf_xcp_conn_comm_mode_bsc_byte_order,
                NULL
            };

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_conn_resource, ett_xcp_resource_flags, resource_flags, ENC_NA);
            offset += 1;

            if (!pinfo->fd->visited) {
                uint8_t address_granularity = (tvb_get_uint8(tvb, offset) & 0x06) >> 1;
                switch (address_granularity) {
                case 0:
                    stream->addr_granularity = 1;
                    break;
                case 1:
                    stream->addr_granularity = 2;
                    break;
                case 2:
                    stream->addr_granularity = 4;
                    break;
                default:
                    stream->addr_granularity = 0;
                    break;
                }
            }

            uint64_t comm_mode_basic;
            proto_tree_add_bitmask_ret_uint64(xcp_tree, tvb, offset, hf_xcp_conn_comm_mode_bsc, ett_xcp_comm_mode_basic_flags, comm_mode_basic_flags, ENC_NA, &comm_mode_basic);
            stream->endianess = ((comm_mode_basic & 0x01) == 0x01) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_conn_max_cto, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_conn_max_dto, tvb, offset, 2, stream->endianess);
            offset += 2;

            proto_tree_add_item(xcp_tree, hf_xcp_conn_proto_layer_ver, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_conn_trans_layer_ver, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
            break;

        case XCP_CMD_DISCONNECT:
            /* No Parameters */
            break;

        case XCP_CMD_GET_STATUS: {
            static int * const current_session_status_flags[] = {
                &hf_xcp_get_st_cur_ses_resume,
                &hf_xcp_get_st_cur_ses_daq_running,
                &hf_xcp_get_st_cur_ses_daq_cfg_lost,
                &hf_xcp_get_st_cur_ses_clear_daq_req,
                &hf_xcp_get_st_cur_ses_store_daq_req,
                &hf_xcp_get_st_cur_ses_calpag_cfg_lst,
                &hf_xcp_get_st_cur_ses_store_cal_req,
                NULL
            };

            static int * const current_protection_status_flags[] = {
                &hf_xcp_get_st_cur_res_pro_st_dbg,
                &hf_xcp_get_st_cur_res_pro_st_pgm,
                &hf_xcp_get_st_cur_res_pro_st_stim,
                &hf_xcp_get_st_cur_res_pro_st_daq,
                &hf_xcp_get_st_cur_res_pro_st_calpag,
                NULL
            };

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_get_st_cur_ses, ett_xcp_current_session_status_flags, current_session_status_flags, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_get_st_cur_res_pro_st, ett_xcp_current_res_protec_status, current_protection_status_flags, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_get_st_cur_state_number, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_session_cfg_id, tvb, offset, 2, stream->endianess);
            offset += 2;
        }
            break;

        case XCP_CMD_SYNCH:
            /* No Parameters */
            break;

        case XCP_CMD_GET_COMM_MODE_INFO: {
            static int * const comm_mode_optional_flags[] = {
                &hf_xcp_comm_mode_opt_interl,
                &hf_xcp_comm_mode_opt_mas_blck_mode,
                NULL
            };

            proto_tree_add_item(xcp_tree, hf_xcp_comm_mode_res1, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_comm_mode_opt, ett_xcp_comm_mode_optional, comm_mode_optional_flags, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_comm_mode_res2, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_comm_mode_max_bs, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_comm_mode_min_st, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_comm_mode_queue_size, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_comm_mode_driver_version, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
            break;

        case XCP_CMD_GET_ID: {
            static int * const get_id_mode_parameter[] = {
                &hf_xcp_get_id_mode_compressed_encrypted,
                &hf_xcp_get_id_mode_transfer_mode,
                NULL
            };

            uint64_t mode_bits;
            proto_tree_add_bitmask_ret_uint64(xcp_tree, tvb, offset, hf_xcp_get_id_mode, ett_xcp_get_id_mode_parameter, get_id_mode_parameter, ENC_NA, &mode_bits);
            bool mode_comp_enc = (mode_bits & 0x0000000000000002) == 0x0000000000000002;
            bool mode_transfer = (mode_bits & 0x0000000000000001) == 0x0000000000000001;
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_get_id_res, tvb, offset, 2, stream->endianess);
            offset += 2;

            uint32_t length;
            proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_get_id_length, tvb, offset, 4, stream->endianess, &length);
            offset += 4;

            if (mode_transfer) {
                if (!mode_comp_enc) {
                    proto_tree_add_item(xcp_tree, hf_xcp_get_id_id_string, tvb, offset, length, ENC_ASCII);
                    offset += length;
                } else {
                    proto_tree_add_item(xcp_tree, hf_xcp_get_id_id_bytes, tvb, offset, length, ENC_NA);
                    offset += length;
                }
            }
        }
            break;

        case XCP_CMD_SET_REQUEST:
            /* No Parameters */
            break;

        case XCP_CMD_GET_SEED: {
            proto_tree_add_item(xcp_tree, hf_xcp_get_seed_length_of_seed, tvb, offset, 1, ENC_NA);
            offset += 1;

            uint32_t seed_length = max_length - (offset - offset_orig);
            proto_tree_add_item(xcp_tree, hf_xcp_get_seed_seed, tvb, offset, seed_length, ENC_NA);
            offset += seed_length;
        }
            break;

        case XCP_CMD_UNLOCK: {
            static int * const current_protection_status_flags[] = {
                &hf_xcp_get_st_cur_res_pro_st_dbg,
                &hf_xcp_get_st_cur_res_pro_st_pgm,
                &hf_xcp_get_st_cur_res_pro_st_stim,
                &hf_xcp_get_st_cur_res_pro_st_daq,
                &hf_xcp_get_st_cur_res_pro_st_calpag,
                NULL
            };

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_get_st_cur_res_pro_st, ett_xcp_current_res_protec_status, current_protection_status_flags, ENC_NA);
            offset += 1;
        }
            break;

        case XCP_CMD_SET_MTA:
            /* No Parameters */
            break;

        case XCP_CMD_UPLOAD:
            /* fall through */
        case XCP_CMD_SHORT_UPLOAD: {
            uint32_t i;
            uint32_t tmp;

            if (message->peer_message == NULL) {
                /* this should never happen */
                ws_assert_not_reached();
                return offset - offset_orig;
            }

            if (stream->addr_granularity == 1) {
                for (i = 0; i < message->peer_message->number_of_elements; i++) {
                    proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_1byte, tvb, offset, 1, ENC_NA, &tmp);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tmp);
                    offset += 1;
                }
            } else if (stream->addr_granularity == 2) {
                proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
                offset += 1;
                for (i = 0; i < message->peer_message->number_of_elements; i++) {
                    proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_2bytes, tvb, offset, 2, stream->endianess, &tmp);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x", tmp);
                    offset += 2;
                }
            } else if (stream->addr_granularity == 4) {
                proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset + 1, 1, ENC_NA);
                proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset + 2, 1, ENC_NA);
                offset += 3;

                for (i = 0; i < message->peer_message->number_of_elements; i++) {
                    proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_data_element_4bytes, tvb, offset, 4, stream->endianess, &tmp);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%08x", tmp);
                    offset += 4;
                }
            }
        }
            break;

        case XCP_CMD_BUILD_CHECKSUM:
            proto_tree_add_item(xcp_tree, hf_xcp_build_chksum_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_build_chksum_res3, tvb, offset, 2, stream->endianess);
            offset += 2;

            proto_tree_add_item(xcp_tree, hf_xcp_build_chksum, tvb, offset, 4, stream->endianess);
            offset += 4;

            break;

        case XCP_CMD_TRANSPORT_LAYER_CMD:
            offset += dissect_transport_layer_cmd(tvb, pinfo, xcp_tree, offset, max_length, false, xcp_type, message, stream);
            break;

        //case XCP_CMD_USER_CMD:
        //    /* TODO */
        //    break;


        case XCP_CMD_DOWNLOAD:
            /* No Parameters */
            break;

        //case XCP_CMD_DOWNLOAD_NEXT:
        //    /* TODO */
        //    break;

        case XCP_CMD_DOWNLOAD_MAX:
            /* No Parameters */
            break;

        case XCP_CMD_SHORT_DOWNLOAD:
            /* No Parameters */
            break;

        case XCP_CMD_MODIFY_BITS:
            /* No Parameters */
            break;


        case XCP_CMD_SET_CAL_PAGE:
            /* No Parameters */
            break;

        case XCP_CMD_GET_CAL_PAGE: {
            proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;

            uint32_t page_number;
            proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_logical_data_page_number, tvb, offset, 1, ENC_NA, &page_number);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, ": PAGE:%d", page_number);
        }
            break;

        //case XCP_CMD_GET_PAG_PROCESSOR_INFO:
        //    /* TODO */
        //    break;

        case XCP_CMD_GET_SEGMENT_INFO:
            /* No Parameters */
            break;

        //case XCP_CMD_GET_PAGE_INFO:
        //    /* TODO */
        //    break;

        case XCP_CMD_SET_SEGMENT_MODE:
            /* No Parameters */
            break;

        //case XCP_CMD_GET_SEGMENT_MODE:
        //    /* TODO */
        //    break;

        case XCP_CMD_COPY_CAL_PAGE:
            /* No Parameters */
            break;


        case XCP_CMD_CLEAR_DAQ_LIST:
            /* No Parameters */
            break;

        case XCP_CMD_SET_DAQ_PTR:
            /* No Parameters */
            break;

        case XCP_CMD_WRITE_DAQ:
            /* No Parameters */
            break;

        case XCP_CMD_SET_DAQ_LIST_MODE:
            /* No Parameters */
            break;

            //case XCP_CMD_GET_DAQ_LIST_MODE:
            //    /* TODO */
            //    break;

        case XCP_CMD_START_STOP_DAQ_LIST: {
            uint32_t odt_pid;
            proto_tree_add_item_ret_uint(tree, hf_xcp_first_pid, tvb, offset, 1, ENC_NA, &odt_pid);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, ": PID:0x%02x", odt_pid);

            if (message != NULL && message->peer_message != NULL) {
                xcp_daq_t *daq = get_daq_from_message(message, message->peer_message->current_daq_list_number);

                if (daq != NULL && daq->current_odts != NULL && daq->number_of_odts <= wmem_array_get_count(daq->current_odts)) {
                    xcp_odt_t *odt;

                    uint32_t i;
                    for (i = 0; i < daq->number_of_odts; i++) {
                        odt = (xcp_odt_t *)wmem_array_index(daq->current_odts, i);
                        odt->pid = odt_pid + i;

                        wmem_map_insert(stream->pid_map, GUINT_TO_POINTER(odt_pid + i), (void *)odt);
                    }
                }
            }
        }
            break;

        case XCP_CMD_START_STOP_SYNCH:
            /* No Parameters */
            break;

        case XCP_CMD_GET_DAQ_CLOCK: {
            static int * const trigger_info[] = {
                &hf_xcp_trigger_info_time_of_ts_sampl,
                &hf_xcp_trigger_info_trigger_init,
                NULL
            };

            static int * const payload_format[] = {
                &hf_xcp_payload_fmt_cluster_ident,
                &hf_xcp_payload_fmt_fmt_ecu,
                &hf_xcp_payload_fmt_fmt_grandm,
                &hf_xcp_payload_fmt_xcp_slv,
                NULL
            };

            proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_trigger_info, ett_xcp_trigger_info, trigger_info, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_payload_fmt, ett_xcp_payload_format, payload_format, ENC_NA);
            offset += 1;

            /*
             * How to know format? After TIME_SYNCHRONIZATION_PROPERTIES with fmt > 1 was called,
             *
             * we switch to Extended Format! Except if MAX_CTO = 8.
             * Maybe the standard means TIME_CORRELATION_PROPERTIES???
             */
            if (stream->timestamp_extended) {
                proto_tree_add_expert_remaining(tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
                /* TODO */
            } else {
                proto_tree_add_item(xcp_tree, hf_xcp_payload_timestamp_legacy, tvb, offset, 4, stream->endianess);
                offset += 4;
            }
        }
            break;

        //case XCP_CMD_READ_DAQ:
        //    /* TODO */
        //    break;

        case XCP_CMD_GET_DAQ_PROCESSOR_INFO: {
            static int * const daq_properties_flags[] = {
                &hf_xcp_daq_props_overload,
                &hf_xcp_daq_props_pid_off_supported,
                &hf_xcp_daq_props_timestamp_supported,
                &hf_xcp_daq_props_bit_stim_supported,
                &hf_xcp_daq_props_resume_supported,
                &hf_xcp_daq_props_prescaler_supported,
                &hf_xcp_daq_props_config_type,
                NULL
            };

            static int * const daq_key_byte[] = {
                &hf_xcp_daq_key_byte_id_field,
                &hf_xcp_daq_key_byte_addr_ext,
                &hf_xcp_daq_key_byte_optimization,
                NULL
            };

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_daq_props, ett_xcp_daq_properties, daq_properties_flags, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_max_daq, tvb, offset, 2, stream->endianess);
            offset += 2;

            proto_tree_add_item(xcp_tree, hf_xcp_max_event_channel, tvb, offset, 2, stream->endianess);
            offset += 2;

            proto_tree_add_item(xcp_tree, hf_xcp_min_daq, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_daq_key_byte, ett_xcp_daq_key_byte, daq_key_byte, ENC_NA);
            offset += 1;
        }
            break;

        case XCP_CMD_GET_RESOLUTION_INFO: {
            static int * const timestamp_mode_flags[] = {
                &hf_xcp_timestamp_mode_time_unit,
                &hf_xcp_timestamp_mode_timestamp_fixed,
                &hf_xcp_timestamp_mode_timestamp_size,
                NULL
            };

            proto_tree_add_item(xcp_tree, hf_xcp_granularity_odt_entry_size_daq, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_max_odt_entry_size_daq, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_granularity_odt_entry_size_stim, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_max_odt_entry_size_stim, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_timestamp_mode, ett_xcp_timestamp_mode, timestamp_mode_flags, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_timestamp_ticks, tvb, offset, 2, stream->endianess);
            offset += 2;
        }
            break;

        case XCP_CMD_GET_DAQ_LIST_INFO: {
            static int * const daq_list_properties_flags[] = {
                &hf_xcp_daq_list_properties_packed,
                &hf_xcp_daq_list_properties_stim,
                &hf_xcp_daq_list_properties_daq,
                &hf_xcp_daq_list_properties_event_fixed,
                &hf_xcp_daq_list_properties_predefined,
                NULL
            };

            uint64_t flags;
            proto_tree_add_bitmask_ret_uint64(xcp_tree, tvb, offset, hf_xcp_daq_list_properties, ett_xcp_daq_list_properties, daq_list_properties_flags, ENC_NA, &flags);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_daq_list_max_odt, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_daq_list_max_odt_entries, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* The XCP standard is inconsistent about this! Parameter is always present but examples in the standard do not have it!? */
            if ((flags & 0x02) == 0x02) {
                proto_tree_add_item(xcp_tree, hf_xcp_daq_list_fixed_event, tvb, offset, 2, stream->endianess);
                offset += 2;
            }
        }
            break;

        case XCP_CMD_GET_DAQ_EVENT_INFO: {
            static int * const daq_event_properties_flags[] = {
                &hf_xcp_daq_event_properties_consistency,
                &hf_xcp_daq_event_properties_packed,
                &hf_xcp_daq_event_properties_stim,
                &hf_xcp_daq_event_properties_daq,
                NULL
            };

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_daq_event_properties, ett_xcp_daq_event_properties, daq_event_properties_flags, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_max_daq_list, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_event_channel_name_length, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_event_channel_time_cycle, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_event_channel_time_unit, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(xcp_tree, hf_xcp_event_channel_priority, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
            break;

        case XCP_CMD_FREE_DAQ:
            /* No Parameters */
            break;

        case XCP_CMD_ALLOC_DAQ:
            /* No Parameters */
            break;

        case XCP_CMD_ALLOC_ODT:
            /* No Parameters */
            break;

        case XCP_CMD_ALLOC_ODT_ENTRY:
            /* No Parameters */
            break;


        case XCP_CMD_PROGRAM_START: {
            static int * const comm_mode_pgm[] = {
                &hf_xcp_comm_mode_pgm_slave_block_mode,
                &hf_xcp_comm_mode_pgm_interleaved_mode,
                &hf_xcp_comm_mode_pgm_master_block_mode,
                NULL
            };

            proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(xcp_tree, tvb, offset, hf_xcp_comm_mode_pgm, ett_xcp_comm_mode_pgm, comm_mode_pgm, ENC_NA);
            offset += 1;

            uint32_t max_cto;
            proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_max_cto_pgm, tvb, offset, 1, ENC_NA, &max_cto);
            offset += 1;

            uint32_t max_bs;
            proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_max_bs_pgm, tvb, offset, 1, ENC_NA, &max_bs);
            offset += 1;

            uint32_t min_st;
            proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_min_st_pgm, tvb, offset, 1, ENC_NA, &min_st);
            offset += 1;

            uint32_t queue_size;
            proto_tree_add_item_ret_uint(xcp_tree, hf_xcp_queue_size_pgm, tvb, offset, 1, ENC_NA, &queue_size);
            offset += 1;

            col_append_fstr(pinfo->cinfo, COL_INFO, ": MAX_CTO:%d MAX_BS:%d MIN_ST:%d QUEUE_SIZE:%d", max_cto, max_bs, min_st, queue_size);
        }
            break;

        case XCP_CMD_PROGRAM_CLEAR:
            /* No Parameters */
            break;

        case XCP_CMD_PROGRAM:
            /* No Parameters */
            break;

        case XCP_CMD_PROGRAM_RESET:
            /* No Parameters */
            break;

        //case XCP_CMD_GET_PGM_PROCESSOR_INFO:
        //    /* TODO */
        //    break;

        //case XCP_CMD_GET_SECTOR_INFO:
        //    /* TODO */
        //    break;

        case XCP_CMD_PROGRAM_PREPARE:
            /* No Parameters */
            break;

        case XCP_CMD_PROGRAM_FORMAT:
            /* No Parameters */
            break;

        //case XCP_CMD_PROGRAM_NEXT:
        //    /* TODO */
        //    break;

        case XCP_CMD_PROGRAM_MAX:
            /* No Parameters */
            break;

        case XCP_CMD_PROGRAM_VERIFY:
            /* No Parameters */
            break;


        case XCP_CMD_WRITE_DAQ_MULTIPLE:
            /* No Parameters */
            break;

        //case XCP_CMD_TIME_CORRELATION_PROPERTIES:
        //    /* No Parameters ??? Examples says timestamps... */
        //    break;

        //case XCP_CMD_DTO_CTR_PROPERTIES:
        //    /* TODO */
        //    break;


        case XCP_CMD_2BYTE_FIRST_BYTE:
            switch (message->cmd_lvl1) {
                case XCP_CMD_2BYTE_GET_VERSION:
                    proto_tree_add_item(xcp_tree, hf_xcp_reserved, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(xcp_tree, hf_xcp_version_proto_major, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(xcp_tree, hf_xcp_version_proto_minor, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(xcp_tree, hf_xcp_version_transp_layer_major, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(xcp_tree, hf_xcp_version_transp_layer_minor, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    break;

                case XCP_CMD_2BYTE_SET_DAQ_PACKED_MODE: {
                    /* No parameter */
                }
                    break;

                //case XCP_CMD_2BYTE_GET_DAQ_PACKED_MODE:
                //    /* TODO */
                //    break;

            case XCP_CMD_2BYTE_XCP_SW_DEBUG:
                offset += dissect_sw_debug_cmd(tvb, pinfo, xcp_tree, offset, tvb_captured_length_remaining(tvb, offset), false, xcp_type, message, stream);
                break;

            case XCP_CMD_2BYTE_XCP_POD_COMMANDS:
                offset += dissect_pod_cmd(tvb, pinfo, xcp_tree, offset, tvb_captured_length_remaining(tvb, offset), false, xcp_type, message, stream);
                break;

            default:
                proto_tree_add_expert_remaining(xcp_tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
                col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
            }

            break;

        default:
            proto_tree_add_expert_remaining(xcp_tree, pinfo, &ei_xcp_not_implemented, tvb, offset);
            col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
        }
    } else if (stream->pid_map != NULL && wmem_map_contains(stream->pid_map, GUINT_TO_POINTER(pid))) {
        xcp_odt_t *odt = (xcp_odt_t *)wmem_map_lookup(stream->pid_map, GUINT_TO_POINTER(pid));

        if (odt != NULL && odt->current_odt_entries != NULL && odt->number_of_odt_entries <= wmem_array_get_count(odt->current_odt_entries)) {
            col_append_str(pinfo->cinfo, COL_INFO, "XCP S->M: DAQ:");

            // TODO: create header based on SEQ_DAQ_LIST_MODE!

            proto_item *ti;
            proto_tree *element_tree;

            uint32_t i;
            uint32_t j;
            uint32_t tmp;
            for (i = 0; i < odt->number_of_odt_entries; i++) {
                xcp_odt_entry_t *odt_entry = wmem_array_index(odt->current_odt_entries, i);

                if (odt_entry != NULL) {
                    if (odt_entry->name != NULL) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " %s:", odt_entry->name);
                    } else {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Param %d:", i);
                    }

                    int element_length = stream->addr_granularity * odt_entry->size;
                    ti = proto_tree_add_item(xcp_tree, hf_xcp_data_element_bytes, tvb, offset, element_length, ENC_NA);
                    element_tree = proto_item_add_subtree(ti, ett_xcp_element);
                    if (odt_entry->name != NULL) {
                        proto_tree_add_string(element_tree, hf_xcp_data_element_name, tvb, offset, element_length, odt_entry->name);
                    } else {
                        proto_tree_add_string(element_tree, hf_xcp_data_element_name, tvb, offset, element_length, wmem_strdup_printf(wmem_file_scope(), "Param %d", i));
                    }

                    switch (element_length) {
                    case 1:
                        proto_tree_add_item_ret_uint(element_tree, hf_xcp_data_element_1byte, tvb, offset, 1, ENC_NA, &tmp);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tmp);
                        offset += 1;
                        break;
                    case 2:
                        proto_tree_add_item_ret_uint(element_tree, hf_xcp_data_element_2bytes, tvb, offset, 2, stream->endianess, &tmp);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x", tmp);
                        offset += 2;
                        break;
                    case 4:
                        proto_tree_add_item_ret_uint(element_tree, hf_xcp_data_element_4bytes, tvb, offset, 4, stream->endianess, &tmp);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%08x", tmp);
                        offset += 4;
                        break;
                    default: {
                        for (j = 0; j < odt_entry->size; j++) {
                            switch (stream->addr_granularity) {
                            case 1:
                                proto_tree_add_item_ret_uint(element_tree, hf_xcp_data_element_1byte, tvb, offset, 1, ENC_NA, &tmp);
                                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tmp);
                                offset += 1;
                                break;
                            case 2:
                                proto_tree_add_item_ret_uint(element_tree, hf_xcp_data_element_2bytes, tvb, offset, 2, stream->endianess, &tmp);
                                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tmp);
                                offset += 2;
                                break;
                            case 4:
                                proto_tree_add_item_ret_uint(element_tree, hf_xcp_data_element_4bytes, tvb, offset, 4, stream->endianess, &tmp);
                                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tmp);
                                offset += 4;
                                break;
                            }
                        }
                    }
                        break;
                    }
                }
            }
        }
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "XCP S->M: PID: %s", val_to_str(pinfo->pool, pid, pid_type_names_s2m, "Unknown PID 0x%02x"));
    }

    int unparsed_length = tvb_captured_length_remaining(tvb, offset);
    if (unparsed_length > 0) {
        proto_tree_add_item(xcp_tree, hf_xcp_unparsed, tvb, offset, unparsed_length, ENC_NA);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    return offset - offset_orig;
}

static int
dissect_xcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, xcp_stream_t *stream, uint32_t xcp_type, uint32_t xcp_direction) {
    proto_item *ti = NULL;
    proto_item *ti_root = NULL;
    proto_tree *xcp_tree = NULL;

    uint32_t offset = 0;
    int max_length = -1;

    xcp_message_t *message_info;

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, XCP_NAME);

    message_info = (xcp_message_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_xcp, 0);
    if (!message_info) {
        message_info = wmem_new0(wmem_file_scope(), xcp_message_t);
        INIT_XCP_MESSAGE_T(message_info);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_xcp, 0, message_info);
    }

    ti_root = proto_tree_add_item(tree, proto_xcp, tvb, 0, -1, ENC_NA);
    xcp_tree = proto_item_add_subtree(ti_root, ett_xcp);

    if (!proto_field_is_referenced(tree, proto_xcp)) {
        xcp_tree = NULL;
    }

    switch (xcp_type) {
    case XCP_TYPE_ETHERNET: {
        /* Ethernet has an additional header that needs to be parsed first. */
        /* Multi-byte parameters in this header are always ENC_LITTLE_ENDIAN */
        proto_tree *xcp_header_tree = NULL;

        ti = proto_tree_add_item(xcp_tree, hf_xcp_header_ethernet, tvb, offset, 4, ENC_NA);
        xcp_header_tree = proto_item_add_subtree(ti, ett_xcp_header);

        uint32_t tmp = 0;
        proto_tree_add_item_ret_uint(xcp_header_tree, hf_xcp_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &tmp); // ENC_LITTLE_ENDIAN ok
        offset += 2;

        /* cast ok, since tmp can only have uint16 values */
        max_length = (int)tmp;

        proto_tree_add_item(xcp_header_tree, hf_xcp_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN); // ENC_LITTLE_ENDIAN ok
        offset += 2;

        break;
        }

    case XCP_TYPE_CAN:
        /* nothing to do */
        break;
    }

    /* The XCP packet do not say which direction they are going. If we cannot determine the direction, we show both. */
    uint32_t size_m2s = 0;
    uint32_t size_s2m = 0;

    if (xcp_direction == XCP_DIR_M2S || xcp_direction == XCP_DIR_UNKNOWN) {
        size_m2s = dissect_xcp_m2s(tvb, pinfo, xcp_tree, offset, max_length, xcp_type, message_info, stream);
    }

    if (xcp_direction == XCP_DIR_S2M || xcp_direction == XCP_DIR_UNKNOWN) {
        offset += dissect_xcp_s2m(tvb, pinfo, xcp_tree, offset, max_length, xcp_type, message_info, stream);
    }

    return offset + MAX(size_m2s, size_s2m);
}

static int
dissect_xcp_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    struct can_info *can_info = (struct can_info *)data;
    DISSECTOR_ASSERT(can_info);

    if (can_info->id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) {
        /* Error and RTR frames are not for us. */
        return 0;
    }

    xcp_can_mapping_t *can_mapping = get_can_mapping(can_info->id, can_info->bus_id);
    if (can_mapping == NULL) {
        return 0;
    }

    if (can_mapping->stream == NULL) {
        can_mapping->stream = wmem_alloc0(wmem_epan_scope(), sizeof(xcp_stream_t));

        INIT_XCP_STREAM_T(can_mapping->stream)
        can_mapping->stream->ecu_id = can_mapping->ecu_id;
    }

    uint32_t xcp_dir = XCP_DIR_UNKNOWN;
    if (can_info->id == can_mapping->can_id_m_to_s) {
        xcp_dir = XCP_DIR_M2S;
    } else if (can_info->id == can_mapping->can_id_s_to_m) {
        xcp_dir = XCP_DIR_S2M;
    }

    return dissect_xcp(tvb, pinfo, tree, can_mapping->stream, XCP_TYPE_CAN, xcp_dir);
}

static bool
dissect_xcp_can_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_xcp_can(tvb, pinfo, tree, data) != 0;
}

static uint32_t
xcp_ptype_to_port_type(packet_info *pinfo) {
    uint8_t xcp_port_type = XCP_PORT_NONE;

    switch (pinfo->ptype) {
    case PT_UDP:
        xcp_port_type = XCP_PORT_UDP;
        break;
    case PT_TCP:
        xcp_port_type = XCP_PORT_TCP;
        break;
    default:
        /* this should never happen */
        ws_assert_not_reached();
    }

    return xcp_port_type;
}

static uint32_t
xcp_stream_direction(packet_info *pinfo, xcp_stream_t *stream) {
    if (pinfo == NULL || stream == NULL) {
        return XCP_DIR_UNKNOWN;
    }

    if (pinfo->destport == stream->s_port_number && addresses_equal(&(pinfo->net_dst), &(stream->s_addr))) {
        return XCP_DIR_M2S;
    }

    if (pinfo->srcport == stream->s_port_number && addresses_equal(&(pinfo->net_src), &(stream->s_addr))) {
        return XCP_DIR_S2M;
    }

    return XCP_DIR_UNKNOWN;
}

static int
dissect_xcp_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    conversation_t *conv = find_conversation_pinfo(pinfo, 0);

    xcp_stream_t *stream = NULL;
    if (conv != NULL) {
        stream = (xcp_stream_t *)conversation_get_proto_data(conv, proto_xcp);

        if (stream != NULL) {
            return dissect_xcp(tvb, pinfo, tree, stream, XCP_TYPE_ETHERNET, xcp_stream_direction(pinfo, stream));
        }
    }

    /* we need to create the stream data first */

    uint8_t xcp_port_type = xcp_ptype_to_port_type(pinfo);
    if (xcp_port_type == XCP_PORT_NONE) {
        return 0;
    }

    uint32_t direction = XCP_DIR_UNKNOWN;

    xcp_eth_mapping_t *mapping = get_eth_mapping(&(pinfo->net_dst), xcp_port_type, pinfo->destport);
    if (mapping != NULL) {
        direction = XCP_DIR_M2S;
    } else {
        mapping = get_eth_mapping(&(pinfo->net_src), xcp_port_type, pinfo->srcport);
        if (mapping != NULL) {
            direction = XCP_DIR_S2M;
        }
    }

    if (mapping == NULL) {
        /* let us try the 'don't care' address */
        address any;
        clear_address(&any);

        mapping = get_eth_mapping(&any, xcp_port_type, pinfo->destport);
        if (mapping != NULL) {
            direction = XCP_DIR_M2S;
        } else {
            mapping = get_eth_mapping(&any, xcp_port_type, pinfo->srcport);
            if (mapping != NULL) {
                direction = XCP_DIR_S2M;
            }
        }
    }

    if (mapping == NULL) {
        return 0;
    }

    if (mapping->stream == NULL) {
        mapping->stream = wmem_alloc0(wmem_epan_scope(), sizeof(xcp_stream_t));
        INIT_XCP_STREAM_T(mapping->stream)
        mapping->stream->ecu_id = mapping->ecu_id;

        if (direction == XCP_DIR_M2S) {
            copy_address(&(mapping->stream->s_addr), &(pinfo->net_dst));
            mapping->stream->s_port_number = pinfo->destport;
        } else {
            copy_address(&(mapping->stream->s_addr), &(pinfo->net_src));
            mapping->stream->s_port_number = pinfo->srcport;
        }
    }

    return dissect_xcp(tvb, pinfo, tree, mapping->stream, XCP_TYPE_ETHERNET, direction);
}

static uint32_t
get_xcp_eth_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    /* Always ENC_LITTLE_ENDIAN */
    uint32_t ret = XCP_ETH_HDR_LEN + (uint32_t)tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN); // ENC_LITTLE_ENDIAN ok
    return ret;
}

static int
dissect_xcp_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return udp_dissect_pdus(tvb, pinfo, tree, XCP_ETH_HDR_LEN, NULL, get_xcp_eth_len, dissect_xcp_eth, data);
}

static int
dissect_xcp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
     tcp_dissect_pdus(tvb, pinfo, tree, true, XCP_ETH_HDR_LEN, get_xcp_eth_len, dissect_xcp_eth, data);
     return tvb_captured_length(tvb);
}

static void
check_config(void) {
    /* only 0, 1, 2, 4 allowed */
    if (global_xcp_address_granularity_default != 0 && global_xcp_address_granularity_default != 1 &&
        global_xcp_address_granularity_default != 2 && global_xcp_address_granularity_default != 4) {
        global_xcp_address_granularity_default = 0;
    }
}

void
proto_register_xcp(void) {
    module_t *xcp_module = NULL;
    expert_module_t* expert_module_xcp;

    /* UATs */
    uat_t *xcp_addresses_uat;
    uat_t *xcp_eth_mapping_uat;
    uat_t *xcp_can_mapping_uat;

    static hf_register_info hf[] = {
        { &hf_xcp_header_ethernet,                  { "XCP Header", "xcp.header_eth", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_length,                           { "Length", "xcp.header_eth.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_counter,                          { "Counter", "xcp.header_eth.counter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_xcp_packet,                           { "XCP Packet", "xcp.packet", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_pid_s2m,                          { "Packet Identifier (S2M)", "xcp.packet.pid_s2m", FT_UINT8, BASE_HEX, VALS(pid_type_names_s2m), 0x0, NULL, HFILL }},
        { &hf_xcp_cmd_code,                         { "Command Code", "xcp.packet.command_code", FT_UINT8, BASE_HEX, VALS(cmd_code_names), 0x0, NULL, HFILL }},
        { &hf_xcp_cmd_code_level1,                  { "Level 1 Command Code", "xcp.packet.command_code_level1", FT_UINT8, BASE_HEX, VALS(cmd_code_names_2bytes), 0x0, NULL, HFILL }},

        { &hf_xcp_reserved,                         { "Reserved", "xcp.packet.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_unparsed,                         { "Unparsed", "xcp.packet.unparsed", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_address,                          { "Address", "xcp.packet.address", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_xcp_session_cfg_id,                   { "Session Configuration ID", "xcp.packet.session_configuration_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_xcp_daq_list_number,                  { "DAQ List Number", "xcp.packet.daq_list_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_odt_number,                       { "ODT Number", "xcp.packet.odt_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_odt_entry_number,                 { "ODT Entry Number", "xcp.packet.odt_entry_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_event_channel_number,             { "Event Channel Number", "xcp.packet.event_channel_number", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_xcp_logical_data_segment_number,      { "Logical Data Segment Number", "xcp.packet.logical_data_segment_number", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_logical_data_page_number,         { "Logical Data Page Number", "xcp.packet.logical_data_page_number", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_xcp_num_of_data_elements,             { "Number of Data Elements", "xcp.packet.number_of_data_elements", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_address_extension,                { "Address Extension", "xcp.packet.address_extension", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_data_element_1byte,               { "Data Element (1 Byte)", "xcp.packet.data_element_1byte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_data_element_2bytes,              { "Data Element (2 Bytes)", "xcp.packet.data_element_2bytes", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_data_element_4bytes,              { "Data Element (4 Bytes)", "xcp.packet.data_element_4bytes", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_data_element_bytes,               { "Data Element", "xcp.packet.data_element", FT_BYTES, BASE_NONE | SEP_SPACE, NULL, 0x0, NULL, HFILL } },

        /* 0xFF XCP_CMD_CONNECT */
        { &hf_xcp_conn_mode,                        { "Mode", "xcp.packet.connect_mode", FT_UINT8, BASE_HEX, VALS(cmd_connect_mode), 0x0, NULL, HFILL }},
        { &hf_xcp_conn_resource,                    { "Resource", "xcp.packet.resource", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_conn_resource_dbg,                { "Software Debugging", "xcp.packet.resource.dbg", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x20, NULL, HFILL }},
        { &hf_xcp_conn_resource_pgm,                { "Programming", "xcp.packet.resource.pgm", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x10, NULL, HFILL }},
        { &hf_xcp_conn_resource_stim,               { "Stimulation", "xcp.packet.resource.stim", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x08, NULL, HFILL }},
        { &hf_xcp_conn_resource_daq,                { "DAQ lists", "xcp.packet.resource.daq", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x04, NULL, HFILL }},
        { &hf_xcp_conn_resource_cal_pag,            { "Calibration and Paging", "xcp.packet.resource.cal_pag", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x01, NULL, HFILL }},

        { &hf_xcp_conn_comm_mode_bsc,               { "Communication Mode Basic", "xcp.packet.comm_mode_basic", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_conn_comm_mode_bsc_optional,      { "Optional", "xcp.packet.comm_mode_basic.optional", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
        { &hf_xcp_conn_comm_mode_bsc_sl_blk_mode,   { "Slave Block Mode", "xcp.packet.comm_mode_basic.slave_block_mode", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x40, NULL, HFILL }},
        { &hf_xcp_conn_comm_mode_bsc_addr_gran,     { "Address Granularity", "xcp.packet.comm_mode_basic.address_granularity", FT_UINT8, BASE_HEX, VALS(comm_mode_address_granularity), 0x06, NULL, HFILL }},
        { &hf_xcp_conn_comm_mode_bsc_byte_order,    { "Byte Order", "xcp.packet.comm_mode_basic.byte_order", FT_BOOLEAN, 8, TFS(&xcp_tfs_byte_order), 0x01, NULL, HFILL }},

        { &hf_xcp_conn_max_cto,                     { "Max CTO", "xcp.packet.max_cto", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_conn_max_dto,                     { "Max DTO", "xcp.packet.max_dto", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_conn_proto_layer_ver,             { "Protocol Layer Version", "xcp.packet.proto_layer_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_conn_trans_layer_ver,             { "Transport Layer Version", "xcp.packet.transport_layer_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* 0xFD XCP_CMD_GET_STATUS */
        { &hf_xcp_get_st_cur_ses,                   { "Current Session Status", "xcp.packet.current_session_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_get_st_cur_ses_resume,            { "Resume Mode", "xcp.packet.current_session_status.resume", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
        { &hf_xcp_get_st_cur_ses_daq_running,       { "DAQ Running", "xcp.packet.current_session_status.daq_running", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
        { &hf_xcp_get_st_cur_ses_daq_cfg_lost,      { "Configuration of resource DAQ", "xcp.packet.current_session_status.daq_cfg_lost", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
        { &hf_xcp_get_st_cur_ses_clear_daq_req,     { "Request to clear DAQ configuration", "xcp.packet.current_session_status.clear_daq_req", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
        { &hf_xcp_get_st_cur_ses_store_daq_req,     { "Request to store DAQ list", "xcp.packet.current_session_status.store_daq_req", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
        { &hf_xcp_get_st_cur_ses_calpag_cfg_lst,    { "Configuration of resource CAL and PAG", "xcp.packet.current_session_status.cal_pag_cfg_lost", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
        { &hf_xcp_get_st_cur_ses_store_cal_req,     { "Request to store calibration data", "xcp.packet.current_session_status.store_cal_req", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

        { &hf_xcp_get_st_cur_res_pro_st,            { "Current Resource Protection Status", "xcp.packet.current_protection_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_get_st_cur_res_pro_st_dbg,        { "Software Debugging Commands", "xcp.packet.current_protection_status.dbg", FT_BOOLEAN, 8, TFS(&xcp_tfs_protected), 0x20, NULL, HFILL }},
        { &hf_xcp_get_st_cur_res_pro_st_pgm,        { "Programming Commands", "xcp.packet.current_protection_status.pgm", FT_BOOLEAN, 8, TFS(&xcp_tfs_protected), 0x10, NULL, HFILL }},
        { &hf_xcp_get_st_cur_res_pro_st_stim,       { "DAQ List Commands (STIM)", "xcp.packet.current_protection_status.stim", FT_BOOLEAN, 8, TFS(&xcp_tfs_protected), 0x08, NULL, HFILL }},
        { &hf_xcp_get_st_cur_res_pro_st_daq,        { "DAQ List Commands (DAQ)", "xcp.packet.current_protection_status.daq", FT_BOOLEAN, 8, TFS(&xcp_tfs_protected), 0x04, NULL, HFILL }},
        { &hf_xcp_get_st_cur_res_pro_st_calpag,     { "Calibration/Paging Commands", "xcp.packet.current_protection_status.cal_pag", FT_BOOLEAN, 8, TFS(&xcp_tfs_protected), 0x01, NULL, HFILL }},

        { &hf_xcp_get_st_cur_state_number,          { "State Number", "xcp.packet.current_state_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* 0xFB XCP_CMD_GET_COMM_MODE_INFO */
        { &hf_xcp_comm_mode_res1,                   { "Reserved", "xcp.packet.comm_mode_res1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_comm_mode_opt,                    { "Comm Mode Optional", "xcp.packet.comm_mode_opt", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_xcp_comm_mode_opt_interl,             { "Interleaved Mode", "xcp.packet.comm_mode_opt.interleaved", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x2, NULL, HFILL }},
        { &hf_xcp_comm_mode_opt_mas_blck_mode,      { "Master Block Mode", "xcp.packet.comm_mode_opt.master_block_mode", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x1, NULL, HFILL } },
        { &hf_xcp_comm_mode_res2,                   { "Reserved", "xcp.packet.comm_mode_res2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_comm_mode_max_bs,                 { "Max BS", "xcp.packet.max_bs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_comm_mode_min_st,                 { "Min ST", "xcp.packet.min_st", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_comm_mode_queue_size,             { "Queue Size", "xcp.packet.queue_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_comm_mode_driver_version,         { "XCP Driver Version Number", "xcp.packet.driver_version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* 0xFA XCP_CMD_GET_ID */
        { &hf_xcp_get_id_req_id_type,               { "Req ID Type", "xcp.packet.get_id_req_id_type", FT_UINT8, BASE_HEX, VALS(get_id_req_id_type), 0x0, NULL, HFILL } },

        { &hf_xcp_get_id_mode,                      { "Mode", "xcp.packet.get_id_mode", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_get_id_mode_compressed_encrypted, { "Compressed/Encrypted", "xcp.packet.get_id_mode.compressed_encrypted", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_xcp_get_id_mode_transfer_mode,        { "Transfer Mode", "xcp.packet.get_id_mode.transfer_mode", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_xcp_get_id_res,                       { "Reserved", "xcp.packet.get_id_res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_get_id_length,                    { "Length", "xcp.packet.get_id_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_get_id_id_string,                 { "Identification", "xcp.packet.get_id_id_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_get_id_id_bytes,                  { "Identification", "xcp.packet.get_id_id_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* 0xF9 XCP_CMD_SET_REQUEST */
        { &hf_xcp_set_req_md,                       { "Mode", "xcp.packet.set_request_mode", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_set_req_md_clr_daq_cfg_lost,      { "Clear DAQ Config Lost", "xcp.packet.set_request_mode.clear_daq_cfg_lost", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL } },
        { &hf_xcp_set_req_md_clr_cal_pag_cfg_lost,  { "Clear CAL/PAG Config Lost", "xcp.packet.set_request_mode.clear_cal_pag_cfg_lost", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
        { &hf_xcp_set_req_md_clr_daq_req,           { "Clear DAQ Request", "xcp.packet.set_request_mode.clear_daq_req", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
        { &hf_xcp_set_req_md_str_daq_req_resume,    { "Store DAQ Request Resume", "xcp.packet.set_request_mode.store_daq_req_resume", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_xcp_set_req_md_str_daq_req_no_resume, { "Store DAQ Request No Resume", "xcp.packet.set_request_mode.store_daq_req_no_resume", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_xcp_set_req_md_str_cal_req,           { "Store CAL Request", "xcp.packet.set_request_mode.store_cal_request", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },

        /* 0xF8 GET_SEED */
        { &hf_xcp_get_seed_mode,                    { "Mode", "xcp.packet.get_seed.mode", FT_UINT8, BASE_HEX, VALS(get_seed_mode), 0x0, NULL, HFILL } },
        { &hf_xcp_get_seed_resource,                { "Resource", "xcp.packet.get_seed.resource", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_get_seed_dont_care,               { "Don't Care", "xcp.packet.get_seed.dont_care", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_xcp_get_seed_length_of_seed,          { "Length of seed", "xcp.packet.get_seed.length_of_seed", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_get_seed_seed,                    { "Seed", "xcp.packet.get_seed.seed", FT_BYTES, BASE_NONE|SEP_SPACE, NULL, 0x0, NULL, HFILL } },

        /* 0xF7 UNLOCK */
        { &hf_xcp_unlock_length_of_key,             { "(remaining) Length of key in bytes", "xcp.packet.unlock.length_of_key", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_unlock_key,                       { "Key", "xcp.packet.unlock.key", FT_BYTES, BASE_NONE|SEP_SPACE, NULL, 0x0, NULL, HFILL } },

        /* DTO */
        { &hf_xcp_data_element_name,                { "Name", "xcp.packet.data_element.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* 0xF3 XCP_CMD_BUILD_CHECKSUM */
        { &hf_xcp_build_chksum_res1,                { "Reserved", "xcp.packet.build_checksum.reserved1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_build_chksum_res2,                { "Reserved", "xcp.packet.build_checksum.reserved2", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_build_chksum_block_size,          { "Block size [AG]", "xcp.packet.build_checksum.block_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_xcp_build_chksum_type,                { "Checksum type", "xcp.packet.build_checksum.checksum_type", FT_UINT8, BASE_HEX, VALS(checksum_types), 0x0, NULL, HFILL } },
        { &hf_xcp_build_chksum_res3,                { "Reserved", "xcp.packet.build_checksum.reserved3", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_build_chksum,                     { "Checksum", "xcp.packet.build_checksum.checksum", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* 0xF2 XCP_CMD_TRANSPORT_LAYER_CMD */
        { &hf_xcp_sub_command_eth,                  { "Sub Command Code", "xcp.packet.sub_command_eth", FT_UINT8, BASE_HEX, VALS(sub_cmd_code_mnemonics_eth), 0x0, NULL, HFILL } },
        { &hf_xcp_sub_command_eth_port,             { "Port", "xcp.packet.sub_command_eth.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_sub_command_eth_ipv4,             { "IP", "xcp.packet.sub_command_eth.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_sub_command_eth_reserved,         { "Reserved", "xcp.packet.sub_command_eth.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_sub_command_eth_ip_version,       { "IP Version", "xcp.packet.sub_command_eth.ip_version", FT_UINT8, BASE_HEX, VALS(transport_mode_eth_ip_version), 0x0, NULL, HFILL } },

        { &hf_xcp_sub_command_can,                  { "Sub Command Code", "xcp.packet.sub_command_eth", FT_UINT8, BASE_HEX, VALS(sub_cmd_code_mnemonics_can), 0x0, NULL, HFILL } },

        /* 0xEB XCP_CMD_SET_CAL_PAGE */
        { &hf_xcp_set_cal_page_mode,                { "Mode", "xcp.packet.set_cal_page_mode", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_set_cal_page_mode_all,            { "All", "xcp.packet.set_cal_page_mode.all", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL } },
        { &hf_xcp_set_cal_page_mode_xcp,            { "XCP", "xcp.packet.set_cal_page_mode.xcp", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_xcp_set_cal_page_mode_ecu,            { "ECU", "xcp.packet.set_cal_page_mode.ecu", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },

        /* 0xEA XCP_CMD_GET_CAL_PAGE */
        { &hf_xcp_access_mode,                      { "Access Mode", "xcp.packet.access_mode", FT_UINT8, BASE_HEX, VALS(access_mode_type), 0x0, NULL, HFILL } },

        /* 0xE4 XCP_CMD_COPY_CAL_PAGE */
        { &hf_xcp_logical_data_segm_num_src,        { "Local data segment number source", "xcp.packet.copy_cal_page.local_data_segm_num_src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_logical_data_page_num_src,        { "Local data page number source", "xcp.packet.copy_cal_page.local_data_page_num_src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_logical_data_segm_num_dst,        { "Local data segment number source", "xcp.packet.copy_cal_page.local_data_segm_num_dst", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_logical_data_page_num_dst,        { "Local data page number source", "xcp.packet.copy_cal_page.local_data_page_num_dst", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* 0xE1 XCP_CMD_WRITE_DAQ */
        { &hf_xcp_bit_offset,                       { "Bit Offset", "xcp.packet.bit_offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_size_of_daq_element,              { "Size of DAQ Element", "xcp.packet.size_of_daq_element", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* 0xE0 XCP_CMD_SET_DAQ_LIST_MODE */
        { &hf_xcp_set_daq_list_mode_mode,           { "Mode", "xcp.packet.set_daq_list_mode_mode", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_set_daq_list_mode_mode_pid_off,   { "PID off", "xcp.packet.get_id_mode.transfer_mode.pid_off", FT_BOOLEAN, 8, NULL, SET_DAQ_LIST_MODE_PID_OFF, NULL, HFILL } },
        { &hf_xcp_set_daq_list_mode_mode_timestamp, { "Timestamp", "xcp.packet.get_id_mode.transfer_mode.timestamp", FT_BOOLEAN, 8, NULL, SET_DAQ_LIST_MODE_TSTAMP, NULL, HFILL } },
        { &hf_xcp_set_daq_list_mode_mode_dto_ctr,   { "DTO CTR", "xcp.packet.get_id_mode.transfer_mode.dto_ctr", FT_BOOLEAN, 8, NULL, SET_DAQ_LIST_MODE_DTO_CTR, NULL, HFILL } },
        { &hf_xcp_set_daq_list_mode_mode_dir,       { "Direction", "xcp.packet.get_id_mode.transfer_mode.direction", FT_BOOLEAN, 8, TFS(&xcp_tfs_stim_daq), SET_DAQ_LIST_MODE_DIR, NULL, HFILL } },
        { &hf_xcp_set_daq_list_mode_mode_alt,       { "Alternating Display Mode", "xcp.packet.get_id_mode.transfer_mode.alternating", FT_BOOLEAN, 8, NULL, SET_DAQ_LIST_MODE_ALT, NULL, HFILL } },
        { &hf_xcp_transmission_prescaler,           { "Transmission Prescaler", "xcp.packet.transmission_prescaler", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_daq_list_priority,                { "DAQ List Priority", "xcp.packet.daq_list_priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* 0xDE XCP_CMD_START_STOP_DAQ_LIST */
        { &hf_xcp_start_stop_daq_mode,              { "Mode", "xcp.packet.start_stop_daq_mode", FT_UINT8, BASE_HEX, VALS(start_stop_daq_mode), 0x0, NULL, HFILL } },

        { &hf_xcp_first_pid,                        { "First PID", "xcp.packet.first_pid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* 0xDD XCP_CMD_START_STOP_SYNCH */
        { &hf_xcp_start_stop_synch_mode,            { "Mode", "xcp.packet.start_stop_synch_mode", FT_UINT8, BASE_HEX, VALS(start_stop_synch_mode), 0x0, NULL, HFILL } },

        /* 0xDC XCP_CMD_GET_DAQ_CLOCK */
        { &hf_xcp_trigger_info,                     { "Trigger Info", "xcp.packet.trigger_info", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_trigger_info_time_of_ts_sampl,    { "Time of Timestamp Sampling", "xcp.packet.trigger_info.time_of_timestamp_sample", FT_UINT8, BASE_DEC, VALS(trigger_info_time_of_ts_sampl_type), 0x18, NULL, HFILL } },
        { &hf_xcp_trigger_info_trigger_init,        { "Trigger Initiator", "xcp.packet.trigger_info.trigger_initiator", FT_UINT8, BASE_DEC, VALS(trigger_info_trigger_init_type), 0x07, NULL, HFILL } },
        { &hf_xcp_payload_fmt,                      { "Payload Format", "xcp.packet.payload_format", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_payload_fmt_cluster_ident,        { "Cluster Identifier", "xcp.packet.payload_fmt.cluster_ident_and_counter", FT_BOOLEAN, 8, TFS(&xcp_tfs_cluster_identifier), 0x40, NULL, HFILL } },
        { &hf_xcp_payload_fmt_fmt_ecu,              { "Format ECU Clock", "xcp.packet.payload_fmt.format_ecu_clock", FT_UINT8, BASE_DEC, VALS(clock_format_type), 0x30, NULL, HFILL } },
        { &hf_xcp_payload_fmt_fmt_grandm,           { "Format Grandmaster Clock", "xcp.packet.payload_fmt.format_grandmaster_clock", FT_UINT8, BASE_DEC, VALS(clock_format_type), 0x0c, NULL, HFILL } },
        { &hf_xcp_payload_fmt_xcp_slv,              { "Format XCP Slave Clock", "xcp.packet.payload_fmt.format_xcp_slave_clock", FT_UINT8, BASE_DEC, VALS(clock_format_type), 0x03, NULL, HFILL } },
        { &hf_xcp_payload_timestamp_legacy,         { "Timestamp (legacy)", "xcp.packet.payload_fmt.timestamp_legacy", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* 0xDA XCP_CMD_GET_DAQ_PROCESSOR_INFO */
        { &hf_xcp_daq_props,                        { "General properties of DAQ lists", "xcp.packet.daq_properties", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_daq_props_overload,               { "Overload", "xcp.packet.daq_properties_overload", FT_UINT8, BASE_HEX, VALS(daq_properties_overload_type), 0xC0, NULL, HFILL } },
        { &hf_xcp_daq_props_pid_off_supported,      { "PID off", "xcp.packet.daq_properties_pid_off_supported", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL } },
        { &hf_xcp_daq_props_timestamp_supported,    { "Timestamped mode", "xcp.packet.daq_properties_timestamp_supported", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL } },
        { &hf_xcp_daq_props_bit_stim_supported,     { "Bitwise data stimulation", "xcp.packet.daq_properties_bit_stim_supported", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08, NULL, HFILL } },
        { &hf_xcp_daq_props_resume_supported,       { "DAQ list resume mode", "xcp.packet.daq_properties_resume_supported", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL } },
        { &hf_xcp_daq_props_prescaler_supported,    { "Prescaler", "xcp.packet.daq_properties_prescaler_supported", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL } },
        { &hf_xcp_daq_props_config_type,            { "DAQ list configuration", "xcp.packet.daq_config_type", FT_BOOLEAN, 8, TFS(&xcp_tfs_dynamic_static), 0x01, NULL, HFILL } },

        { &hf_xcp_max_daq,                          { "Total number of available DAQ lists", "xcp.packet.max_daq", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_max_event_channel,                { "Total number of available event channels", "xcp.packet.max_event_channel", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_min_daq,                          { "Total number of predefined DAQ lists", "xcp.packet.min_daq", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_xcp_daq_key_byte,                     { "DAQ key byte", "xcp.packet.daq_key_byte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_daq_key_byte_id_field,            { "Identification Field", "xcp.packet.daq_key_byte_id_field", FT_UINT8, BASE_HEX, VALS(daq_key_byte_id_field_type), 0xC0, NULL, HFILL } },
        { &hf_xcp_daq_key_byte_addr_ext,            { "Address Extension", "xcp.packet.daq_key_byte_address_extension", FT_UINT8, BASE_HEX, VALS(daq_key_byte_addr_ext_type), 0x30, NULL, HFILL } },
        { &hf_xcp_daq_key_byte_optimization,        { "Optimization", "xcp.packet.daq_key_optimization", FT_UINT8, BASE_HEX, VALS(optimization_type), 0x0F, NULL, HFILL } },

        /* 0xD9 XCP_CMD_GET_RESOLUTION_INFO */
        { &hf_xcp_granularity_odt_entry_size_daq,   { "Granularity for size of ODT entry (DAQ direction)", "xcp.packet.granularity_odt_entry_size_daq", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_max_odt_entry_size_daq,           { "Maximum size of ODT entry (DAQ direction)", "xcp.packet.max_odt_entry_size_daq", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_granularity_odt_entry_size_stim,  { "Granularity for size of ODT entry (STIM direction)", "xcp.packet.granularity_odt_entry_size_stim", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_max_odt_entry_size_stim,          { "Maximum size of ODT entry (STIM direction)", "xcp.packet.max_odt_entry_size_stim", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_timestamp_mode,                   { "Timestamp unit and size", "xcp.packet.timestamp_mode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_timestamp_mode_time_unit,         { "Timestamp Unit", "xcp.packet.timestamp_mode_unit", FT_UINT8, BASE_HEX, VALS(xcp_time_unit), 0xf0, NULL, HFILL } },
        { &hf_xcp_timestamp_mode_timestamp_fixed,   { "Timestamp Fixed", "xcp.packet.timestamp_mode_timestamp_fixed", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
        { &hf_xcp_timestamp_mode_timestamp_size,    { "Timestamp Size", "xcp.packet.timestamp_size", FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
        { &hf_xcp_timestamp_ticks,                  { "Timestamp tickets per unit", "xcp.packet.timestamp_ticks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* 0xD8 XCP_CMD_GET_DAQ_LIST_INFO */
        { &hf_xcp_daq_list_properties,              { "DAQ List Properties", "xcp.packet.daq_list_properties", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_daq_list_properties_packed,       { "Packed", "xcp.packet.daq_list_properties_packed", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL } },
        { &hf_xcp_daq_list_properties_stim,         { "STIM", "xcp.packet.daq_list_properties_stim", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08, NULL, HFILL } },
        { &hf_xcp_daq_list_properties_daq,          { "DAQ", "xcp.packet.daq_list_properties_daq", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL } },
        { &hf_xcp_daq_list_properties_event_fixed,  { "Event Channel Fixed", "xcp.packet.daq_list_properties_event_fixed", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_xcp_daq_list_properties_predefined,   { "Predefined", "xcp.packet.daq_list_properties_predefined", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_xcp_daq_list_max_odt,                 { "Max ODT", "xcp.packet.max_odt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_daq_list_max_odt_entries,         { "Max ODT Entries", "xcp.packet.max_odt_entries", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_daq_list_fixed_event,             { "Fixed Event Channel", "xcp.packet.fixed_event", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* 0xD7 XCP_CMD_GET_DAQ_EVENT_INFO */
        { &hf_xcp_daq_event_properties,             { "DAQ Event Properties", "xcp.packet.daq_event_properties", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_daq_event_properties_consistency, { "Consistency", "xcp.packet.daq_event_properties_consistency", FT_UINT8, BASE_HEX, VALS(daq_event_props_consistency), 0xc0, NULL, HFILL } },
        { &hf_xcp_daq_event_properties_packed,      { "Packed", "xcp.packet.daq_event_properties_packed", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL } },
        { &hf_xcp_daq_event_properties_stim,        { "STIM", "xcp.packet.daq_event_properties_stim", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08, NULL, HFILL } },
        { &hf_xcp_daq_event_properties_daq,         { "DAQ", "xcp.packet.daq_event_properties_daq", FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL } },

        { &hf_xcp_max_daq_list,                     { "Maximum Number of DAQ Lists for this even channel", "xcp.packet.max_daq_list", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_event_channel_name_length,        { "Event Channel Name Length", "xcp.packet.event_channel_name_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_event_channel_time_cycle,         { "Event Channel Time Cycle", "xcp.packet.event_channel_time_cycle", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_event_channel_time_unit,          { "Event Channel Time Unit", "xcp.packet.event_channel_time_unit", FT_UINT8, BASE_DEC, VALS(xcp_time_unit), 0x0, NULL, HFILL } },
        { &hf_xcp_event_channel_priority,           { "Event Channel Priority", "xcp.packet.event_channel_priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* 0xD5 XCP_CMD_ALLOC_DAQ */
        { &hf_xcp_daq_count,                        { "DAQ Count", "xcp.packet.daq_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* 0xD4 XCP_CMD_ALLOC_ODT */
        { &hf_xcp_odt_count,                        { "ODT Counter", "xcp.packet.odt_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* 0xD3 XCP_CMD_ALLOC_ODT_ENTRY */
        { &hf_xcp_odt_entries_count,                { "ODT Entries Count", "xcp.packet.odt_entries_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* 0xD2 PROGRAM_START */
        { &hf_xcp_comm_mode_pgm,                    { "Comm Mode PGM", "xcp.packet.comm_mode_pgm", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_comm_mode_pgm_slave_block_mode,   { "Slave Block Mode", "xcp.packet.comm_mode_pgm.slave_block_mode", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x40, NULL, HFILL } },
        { &hf_xcp_comm_mode_pgm_interleaved_mode,   { "Interleaved Mode", "xcp.packet.comm_mode_pgm.interleaved", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x02, NULL, HFILL } },
        { &hf_xcp_comm_mode_pgm_master_block_mode,  { "Master Block Mode", "xcp.packet.comm_mode_pgm.master_block_mode", FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x01, NULL, HFILL } },
        { &hf_xcp_max_cto_pgm,                      { "Max DTO", "xcp.packet.max_dto_pgm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_max_bs_pgm,                       { "Max BS", "xcp.packet.max_bs_pgm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_min_st_pgm,                       { "Min ST", "xcp.packet.min_st_pgm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_queue_size_pgm,                   { "Queue Size", "xcp.packet.queue_size_pgm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* 0xD1 PROGRAM_CLEAR */
        { &hf_xcp_program_clear_mode,               { "Mode", "xcp.packet.program_clear_mode", FT_UINT8, BASE_HEX, VALS(program_clear_mode_type), 0x0, NULL, HFILL } },
        { &hf_xcp_program_clear_range_abs,          { "Clear Range", "xcp.packet.clear_range_abs", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_program_clear_range_fct,          { "Clear Range", "xcp.packet.clear_range_fct", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_program_clear_range_fct_1,        { "Clear All Calibration Data Area(s)", "xcp.packet.clear_range_fct.clear_all_calibration_data", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_xcp_program_clear_range_fct_2,        { "Clear All Code Area(s)", "xcp.packet.clear_range_fct.clear_all_code_areas", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_xcp_program_clear_range_fct_4,        { "Clear All NVRAM area(s)", "xcp.packet.clear_range_fct.clear_all_nvram_areas", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },


        /* 2BYTE COMMANDS */
        /* 0xC0 0x00 GET_VERSION */
        { &hf_xcp_version_proto_major,              { "Major version of protocol layer", "xcp.packet.version_proto_major", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_version_proto_minor,              { "Minor version of protocol layer", "xcp.packet.version_proto_minor", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_version_transp_layer_major,       { "Major version of active transport layer", "xcp.packet.version_transport_layer_major", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_version_transp_layer_minor,       { "Minor version of active transport layer", "xcp.packet.version_transport_layer_minor", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* 0xC0 0x01 SET_DAQ_PACKED_MODE */
        { &hf_xcp_daq_packed_mode,                  { "DAQ Packed Mode", "xcp.packet.daq_packed_mode", FT_UINT8, BASE_HEX, VALS(daq_packed_mode_type), 0x0, NULL, HFILL } },
        { &hf_xcp_packed_timestamp_mode,            { "Timestamp Mode", "xcp.packet.daq_packed_timestamp_mode", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_xcp_packed_timestamp_mode_flags,      { "Timestamp Modes", "xcp.packet.daq_packed_timestamp_modes", FT_UINT8, BASE_HEX, VALS(daq_packed_timestamp_mode_type), 0x03, NULL, HFILL } },
        { &hf_xcp_packed_sample_count,              { "Sample Count", "xcp.packet.daq_packet_sample_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },


        /* 0xC0 0xFC SW DEBUG over XCP */
        { &hf_xcp_debug_command,                    { "Command Code", "xcp.packet.sw_debug.command_code", FT_UINT8, BASE_HEX, VALS(cmd_sw_dbg_names), 0x0, NULL, HFILL } },

        /* 0xC0 0xFD XCP POD */
        { &hf_xcp_pod_command,                      { "POD Command", "xcp.packet.pod.command_code", FT_UINT16, BASE_HEX, VALS(cmd_pod_mnemonics), 0x0, NULL, HFILL } },
    };

    static int *ett[] = {
        &ett_xcp,
        &ett_xcp_header,
        &ett_xcp_packet,
        &ett_xcp_resource_flags,
        &ett_xcp_comm_mode_basic_flags,
        &ett_xcp_current_session_status_flags,
        &ett_xcp_current_res_protec_status,
        &ett_xcp_comm_mode_optional,
        &ett_xcp_get_id_mode_parameter,
        &ett_xcp_set_request_mode,
        &ett_xcp_set_cal_page_mode,
        &ett_xcp_trigger_info,
        &ett_xcp_payload_format,
        &ett_xcp_daq_properties,
        &ett_xcp_daq_key_byte,
        &ett_xcp_timestamp_mode,
        &ett_xcp_daq_list_properties,
        &ett_xcp_daq_event_properties,
        &ett_xcp_comm_mode_pgm,
        &ett_xcp_set_daq_list_mode_mode,
        &ett_xcp_clear_program_range_fct,
        &ett_xcp_set_daq_packed_mode_timestamp_mode,
        &ett_xcp_element,
    };

    static ei_register_info ei[] = {
        { &ei_xcp_not_implemented,{ "xcp.not_implemented", PI_UNDECODED, PI_WARN, "Not implemented yet. Please consider creating a ticket and attaching an example trace.", EXPFILL } },
    };

    proto_xcp = proto_register_protocol(XCP_LONG_NAME, XCP_NAME, XCP_FILTER_NAME);

    xcp_handle_udp = register_dissector("xcp_udp", dissect_xcp_udp, proto_xcp);
    xcp_handle_tcp = register_dissector("xcp_tcp", dissect_xcp_tcp, proto_xcp);

    proto_register_field_array(proto_xcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_xcp = expert_register_protocol(proto_xcp);
    expert_register_field_array(expert_module_xcp, ei, array_length(ei));

    xcp_module = prefs_register_protocol(proto_xcp, &check_config);

    prefs_register_uint_preference(xcp_module, "address_granularity_default", "Address Granularity Default Value (0, 1, 2, 4)",
                                   "The value for Address Granularity used, if not known.", 10, &global_xcp_address_granularity_default);

    /* UATs */
    static uat_field_t xcp_memory_addresses_fields[] = {
        UAT_FLD_HEX(xcp_memory_addresses,     ecu_id,   "ECU ID",               "ECU ID (16bit hex without leading 0x, 0x0000..0xfffe)"),
        UAT_FLD_HEX(xcp_memory_addresses,     addr_ext, "Address Extension",    "The memory address extension byte (8bit hex without leading 0x)"),
        UAT_FLD_HEX(xcp_memory_addresses,     address,  "Address",              "The memory address (32bit hex without leading 0x)"),
        UAT_FLD_CSTRING(xcp_memory_addresses, name,     "Name",                 "The name for the memory address"),
    UAT_END_FIELDS
    };

    xcp_addresses_uat = uat_new("Memory Addresses",
        sizeof(xcp_memory_addresses_uat_t),         /* record size           */
        DATAFILE_XCP_MEMORY_ADDRESSES,              /* filename              */
        true,                                       /* from profile          */
        (void **)&xcp_memory_addresses,             /* data_ptr              */
        &xcp_memory_addresses_num,                  /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_xcp_memory_addresses_cb,               /* copy callback         */
        update_xcp_memory_addresses_cb,             /* update callback       */
        free_xcp_memory_addresses_cb,               /* free callback         */
        post_update_xcp_memory_addresses_cb,        /* post update callback  */
        reset_xcp_memory_addresses_cb,              /* reset callback        */
        xcp_memory_addresses_fields                 /* UAT field definitions */
    );

    prefs_register_uat_preference(xcp_module, "addresses", "Memory Addresses",
        "A table to define names of memory addresses", xcp_addresses_uat);


    /* UAT for UDP/TCP communication */
    static uat_field_t xcp_eth_mapping_fields[] = {
        UAT_FLD_VS(xcp_uat_eth_mappings,        protocol,       "IPv4/IPv6",        xcp_proto_type_vals,    "IPv4 or IPv6 or ANY"),
        UAT_FLD_CSTRING(xcp_uat_eth_mappings,   ip_address,     "IP Address ECU",   "IP Address"),
        UAT_FLD_VS(xcp_uat_eth_mappings,        port_type,      "UDP/TCP",          xcp_port_type_vals,     "TCP or UDP"),
        UAT_FLD_DEC(xcp_uat_eth_mappings,       port_number,    "Port Number ECU",  "Port Number"),
        UAT_FLD_HEX(xcp_uat_eth_mappings,       ecu_id,         "ECU ID",           "ECU ID (16bit hex without leading 0x, 0x0000..0xfffe, 0xffff for multicast)"),
        UAT_END_FIELDS
    };

    xcp_eth_mapping_uat = uat_new("UDP/TCP",
        sizeof(xcp_eth_mapping_uat_t),              /* record size           */
        DATAFILE_XCP_ETH_MAPPING,                   /* filename              */
        true,                                       /* from profile          */
        (void **)&xcp_uat_eth_mappings,             /* data_ptr              */
        &xcp_uat_eth_mapping_num,                   /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_xcp_eth_mapping_cb,                    /* copy callback         */
        update_xcp_eth_mapping_cb,                  /* update callback       */
        free_xcp_eth_mapping_cb,                    /* free callback         */
        post_update_xcp_eth_mapping_cb,             /* post update callback  */
        reset_xcp_eth_mapping_cb,                   /* reset callback        */
        xcp_eth_mapping_fields                      /* UAT field definitions */
    );

    prefs_register_uat_preference(xcp_module, "eth_mappings", "UDP/TCP Mappings",
        "A table to map UDP and TCP packets to XCP", xcp_eth_mapping_uat);


    /* add UAT for CAN */
    static uat_field_t xcp_can_mapping_fields[] = {
        UAT_FLD_HEX(xcp_uat_can_mappings, bus_id,        "Bus ID",       "Bus ID on which frame was recorded with 0=any (16bit hex without leading 0x)"),
        UAT_FLD_HEX(xcp_uat_can_mappings, can_id_m_to_s, "CAN ID M->S",  "CAN ID M->S (32bit hex without leading 0x, highest bit 1 for extended, 0 for standard ID)"),
        UAT_FLD_HEX(xcp_uat_can_mappings, can_id_s_to_m, "CAN ID S->M",  "CAN ID S->M (32bit hex without leading 0x, highest bit 1 for extended, 0 for standard ID)"),
        UAT_FLD_HEX(xcp_uat_can_mappings, ecu_id,        "ECU ID",       "ECU ID (16bit hex without leading 0x, 0x0000..0xfffe, 0xffff to all)"),
        UAT_END_FIELDS
    };

    xcp_can_mapping_uat = uat_new("CAN",
        sizeof(xcp_can_mapping_uat_t),              /* record size           */
        DATAFILE_XCP_CAN_MAPPING,                   /* filename              */
        true,                                       /* from profile          */
        (void **)&xcp_uat_can_mappings,             /* data_ptr              */
        &xcp_uat_can_mapping_num,                   /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_xcp_can_mapping_cb,                    /* copy callback         */
        update_xcp_can_mapping_cb,                  /* update callback       */
        NULL,                                       /* free callback         */
        post_update_xcp_can_mapping_cb,             /* post update callback  */
        reset_xcp_can_mapping_cb,                   /* reset callback        */
        xcp_can_mapping_fields                      /* UAT field definitions */
    );

    prefs_register_uat_preference(xcp_module, "can_mappings", "CAN Mappings",
        "A table to map CAN payloads to XCP", xcp_can_mapping_uat);

}

void
proto_reg_handoff_xcp(void) {
    static bool initialized = false;

    if (!initialized) {
        xcp_handle_can = register_dissector("xcp_over_can", dissect_xcp_can, proto_xcp);
        dissector_add_for_decode_as("can.subdissector", xcp_handle_can);
        heur_dissector_add("can", dissect_xcp_can_heur, "XCP over CAN", "xcp_can_heur", proto_xcp, HEURISTIC_ENABLE);

        initialized = true;
    }
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
