/* packet-sbus.c
 * Routines for Ether-S-Bus dissection
 * Copyright 2010, Christian Durrer <christian.durrer@sensemail.ch>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/expert.h>

/* Attribute values*/
#define SBUS_REQUEST                   0x00
#define SBUS_RESPONSE                  0x01
#define SBUS_ACKNAK                    0x02

/*SBus command codes*/
#define SBUS_RD_COUNTER                0x00
#define SBUS_RD_DISPLAY_REGISTER       0x01
#define SBUS_RD_FLAG                   0x02
#define SBUS_RD_INPUT                  0x03
#define SBUS_RD_RTC                    0x04
#define SBUS_RD_OUTPUT                 0x05
#define SBUS_RD_REGISTER               0x06
#define SBUS_RD_TIMER                  0x07
#define SBUS_WR_COUNTER                0x0A
#define SBUS_WR_FLAG                   0x0B
#define SBUS_WR_RTC                    0x0C
#define SBUS_WR_OUTPUT                 0x0D
#define SBUS_WR_REGISTER               0x0E
#define SBUS_WR_TIMER                  0x0F
#define SBUS_RDWR_MULTI_MEDIAS         0x13
#define SBUS_RD_PCD_STATUS_CPU0        0x14
#define SBUS_RD_PCD_STATUS_CPU1        0x15
#define SBUS_RD_PCD_STATUS_CPU2        0x16
#define SBUS_RD_PCD_STATUS_CPU3        0x17
#define SBUS_RD_PCD_STATUS_CPU4        0x18
#define SBUS_RD_PCD_STATUS_CPU5        0x19
#define SBUS_RD_PCD_STATUS_CPU6        0x1A
#define SBUS_RD_PCD_STATUS_OWN         0x1B
#define SBUS_RD_SBUS_STN_NBR           0x1D
#define SBUS_RD_USER_MEMORY            0x1E
#define SBUS_RD_PROGRAM_LINE           0x1F
#define SBUS_RD_PROGRAM_VERSION        0x20
#define SBUS_RD_TEXT                   0x21
#define SBUS_RD_ACTIVE_TRANSITION      0x22
#define SBUS_WR_USER_MEMORY            0x23
#define SBUS_WR_PROGRAM_LINE           0x24
#define SBUS_WR_TEXT                   0x25
#define SBUS_RUN_PROCEDURE_CPU0        0x28
#define SBUS_RUN_PROCEDURE_CPU1        0x29
#define SBUS_RUN_PROCEDURE_CPU2        0x2A
#define SBUS_RUN_PROCEDURE_CPU3        0x2B
#define SBUS_RUN_PROCEDURE_CPU4        0x2C
#define SBUS_RUN_PROCEDURE_CPU5        0x2D
#define SBUS_RUN_PROCEDURE_CPU6        0x2E
#define SBUS_RUN_PROCEDURE_OWN         0x2F
#define SBUS_RUN_PROCEDURE_ALL         0x30
#define SBUS_RESTART_COLD_CPU1         0x32
#define SBUS_RESTART_COLD_CPU2         0x33
#define SBUS_RESTART_COLD_CPU3         0x34
#define SBUS_RESTART_COLD_CPU4         0x35
#define SBUS_RESTART_COLD_CPU5         0x36
#define SBUS_RESTART_COLD_CPU6         0x37
#define SBUS_RESTART_COLD_OWN          0x38
#define SBUS_RESTART_COLD_ALL          0x39
#define SBUS_STOP_PROCEDURE_CPU0       0x3C
#define SBUS_STOP_PROCEDURE_CPU1       0x3D
#define SBUS_STOP_PROCEDURE_CPU2       0x3E
#define SBUS_STOP_PROCEDURE_CPU3       0x3F
#define SBUS_STOP_PROCEDURE_CPU4       0x40
#define SBUS_STOP_PROCEDURE_CPU5       0x41
#define SBUS_STOP_PROCEDURE_CPU6       0x42
#define SBUS_STOP_PROCEDURE_OWN        0x43
#define SBUS_STOP_PROCEDURE_ALL        0x44
#define SBUS_RD_STATUSFLAG_ACCU        0x46
#define SBUS_RD_BYTE                   0x47
#define SBUS_RD_HALT_FAILURE_REG       0x48
#define SBUS_RD_INDEX_REGISTER         0x49
#define SBUS_RD_INSTRUCTION_POINTER    0x4A
#define SBUS_FIND_HISTORY              0x4B
#define SBUS_WR_STATUSFLAG_ACCU        0x50
#define SBUS_WR_BYTE                   0x51
#define SBUS_WR_INDEX_REGISTER         0x52
#define SBUS_WR_INSTRUCTION_POINTER    0x53
#define SBUS_CLEAR_ALL                 0x5A
#define SBUS_CLEAR_FLAGS               0x5B
#define SBUS_CLEAR_OUTPUTS             0x5C
#define SBUS_CLEAR_REGISTERS           0x5D
#define SBUS_CLEAR_TIMERS              0x5E
#define SBUS_RESTART_WARM_CPU1         0x64
#define SBUS_RESTART_WARM_CPU2         0x65
#define SBUS_RESTART_WARM_CPU3         0x66
#define SBUS_RESTART_WARM_CPU4         0x67
#define SBUS_RESTART_WARM_CPU5         0x68
#define SBUS_RESTART_WARM_CPU6         0x69
#define SBUS_RESTART_WARM_OWN          0x6A
#define SBUS_RESTART_WARM_ALL          0x6B
#define SBUS_CHANGE_BLOCK              0x6E
#define SBUS_CLEAR_HISTORY_FAILURE     0x6F
#define SBUS_DELETE_PROGRAM_LINE       0x70
#define SBUS_GO_CONDITIONAL            0x71
#define SBUS_INSERT_PROGRAM_LINE       0x72
#define SBUS_LOCAL_CYCLE               0x73
#define SBUS_ALL_CYCLES                0x74
#define SBUS_MAKE_TEXT                 0x75
#define SBUS_EXECUTE_SINGLE_INSTR      0x76
#define SBUS_SINGLE_STEP               0x77
#define SBUS_XOB_17_INTERRUPT          0x82
#define SBUS_XOB_18_INTERRUPT          0x83
#define SBUS_XOB_19_INTERRUPT          0x84
#define SBUS_RD_HANGUP_TIMEOUT         0x91
#define SBUS_RD_DATA_BLOCK             0x96
#define SBUS_WR_DATA_BLOCK             0x97
#define SBUS_MAKE_DATA_BLOCK           0x98
#define SBUS_CLEAR_DATA_BLOCK          0x99
#define SBUS_CLEAR_TEXT                0x9A
#define SBUS_RD_BLOCK_ADDRESSES        0x9B
#define SBUS_RD_BLOCK_SIZES            0x9C
#define SBUS_RD_CURRENT_BLOCK          0x9D
#define SBUS_RD_CALL_STACK             0x9E
#define SBUS_RD_DBX                    0x9F
#define SBUS_RD_USER_EEPROM_REGISTER   0xA1
#define SBUS_WR_USER_EEPROM_REGISTER   0xA3
#define SBUS_ERASE_FLASH               0xA5
#define SBUS_RESTART_COLD_FLAG         0xA6
#define SBUS_WR_SYSTEM_BUFFER          0xA7
#define SBUS_RD_SYSTEM_BUFFER          0xA8
#define SBUS_RD_WR_PCD_BLOCK           0xA9
#define SBUS_GET_DIAGNOSTIC            0xAA
#define SBUS_RD_SYSTEM_INFORMATION     0xAB
#define SBUS_CHANGE_BLOCKS_ON_RUN      0xAC
#define SBUS_FLASHCARD_TELEGRAM        0xAD
#define SBUS_DOWNLOAD_FIRMWARE         0xAE
#define SBUS_WEB_SERVER_SERIAL_COMM    0xAF

/* Bitfield in the arithmetic flags and accu*/
#define F_ACCU      (1<<0)           /* Accumulator of PCD              */
#define F_ERROR     (1<<1)           /* Error flag of PCD               */
#define F_NEGATIVE  (1<<2)           /* Negative arithmetic status flag */
#define F_ZERO      (1<<3)           /* Zero arithmetic status flag     */

/* Bitfield in the system information*/
/*#define F_EMPTY      (1<<0)          always 0                         */
#define F_MEMSIZE      (1<<1)        /* Memory size information         */
#define F_TRACE        (1<<2)        /* Trace buffer feature            */
#define F_INFO_B1      (1<<3)        /* EEPROM information of slot B1   */
#define F_INFO_B2      (1<<4)        /* EEPROM information of slot B2   */
#define F_PGU_BAUD (1<<5)            /* PGU baudrate can be switched    */


/* Read/write block command codes*/
#define SBUS_WR_START_OF_STREAM        0x00
#define SBUS_WR_BLOCK_DATA_STREAM      0x01
#define SBUS_WR_BLOCK_END_OF_STREAM    0x02
#define SBUS_WR_ABORT_BLOCK_STREAM     0x07
#define SBUS_WR_BLOCK_DATA_BYTES       0x08
#define SBUS_RD_BLOCK_START_OF_STREAM  0X10
#define SBUS_RD_BLOCK_DATA_STREAM      0x11
#define SBUS_RD_ABORT_BLOCK_STREAM     0x17
#define SBUS_RD_BLOCK_DATA_BYTES       0x18
#define SBUS_DELETE_BLOCK              0x20
#define SBUS_GET_BLOCK_SIZE            0x21
#define SBUS_GET_PROGRAM_BLOCK_LIST    0x22

/* Read/write block types*/
#define SBUS_RD_WR_CONFIGURATION_FILE  0x20
#define SBUS_RD_WR_PROGRAM_BLOCK_FILE  0x21
#define SBUS_RD_WR_UNKNOWN_BLOCK_TYPE  0x83

/* Read/write block error codes*/
#define SBUS_RD_WR_NAK                 0x80
#define SBUS_RD_WR_NAK_INVALID_SIZE    0x8A

/* Initialize the protocol and registered fields */
static int proto_sbus = -1;
static int hf_sbus_length = -1;
static int hf_sbus_version = -1;
static int hf_sbus_protocol = -1;
static int hf_sbus_sequence = -1;
static int hf_sbus_attribut = -1;
static int hf_sbus_dest = -1;
static int hf_sbus_address = -1;
static int hf_sbus_command = -1;
static int hf_sbus_command_extension = -1;
static int hf_sbus_rcount = -1;
static int hf_sbus_wcount = -1;
static int hf_sbus_wcount_calculated = -1;
static int hf_sbus_fio_count = -1;
static int hf_sbus_addr_rtc = -1;
static int hf_sbus_addr_iof = -1;
static int hf_sbus_addr_eeprom = -1;
static int hf_sbus_addr_prog = -1;
static int hf_sbus_addr_68k = -1;
static int hf_sbus_block_type = -1;
static int hf_sbus_block_nr = -1;
static int hf_sbus_nbr_elements = -1;
static int hf_sbus_display_register = -1;
static int hf_sbus_data_rtc = -1;
static int hf_sbus_data_byte = -1;
static int hf_sbus_data_byte_hex = -1;
static int hf_sbus_data_iof = -1;
static int hf_sbus_cpu_type = -1;
static int hf_sbus_fw_version = -1;
static int hf_sbus_sysinfo_nr = -1;
static int hf_sbus_sysinfo0_1 = -1;
static int hf_sbus_sysinfo0_2 = -1;
static int hf_sbus_sysinfo0_3 = -1;
static int hf_sbus_sysinfo0_4 = -1;
static int hf_sbus_sysinfo0_5 = -1;
static int hf_sbus_sysinfo_length = -1;
static int hf_sbus_f_module_type = -1;
static int hf_sbus_harware_version = -1;
static int hf_sbus_hardware_modification = -1;
static int hf_sbus_various = -1;
static int hf_sbus_acknackcode = -1;
static int hf_sbus_cpu_status = -1;
static int hf_sbus_week_day = -1;
static int hf_sbus_date = -1;
static int hf_sbus_time = -1;
static int hf_sbus_crc = -1;
static int hf_sbus_crc_bad = -1;
static int hf_sbus_retry = -1;
static int hf_sbus_flags_accu = -1;
static int hf_sbus_flags_error = -1;
static int hf_sbus_flags_negative = -1;
static int hf_sbus_flags_zero = -1;
/* Web server telegram */
static int hf_sbus_web_size = -1;
static int hf_sbus_web_aid = -1;
static int hf_sbus_web_seq = -1;
/* Read/Write block telegram*/
static int hf_sbus_rdwr_block_length = -1;
static int hf_sbus_rdwr_block_length_ext = -1;
static int hf_sbus_rdwr_telegram_type = -1;
static int hf_sbus_rdwr_telegram_sequence = -1;
static int hf_sbus_rdwr_block_size = -1;
static int hf_sbus_rdwr_block_addr = -1;
static int hf_sbus_rdwr_file_name = -1;
static int hf_sbus_rdwr_list_type = -1;
static int hf_sbus_rdwr_acknakcode = -1;
/* Request-Response tracking */
static int hf_sbus_response_in = -1;
static int hf_sbus_response_to = -1;
static int hf_sbus_response_time = -1;
static int hf_sbus_timeout = -1;
static int hf_sbus_request_in = -1;

/* Initialize the subtree pointers */
static gint ett_sbus = -1;
static gint ett_sbus_ether = -1;
static gint ett_sbus_data = -1;

/* True/False strings*/
static const true_false_string tfs_sbus_flags= {
       "Is high",
       "Is low"
};

static const true_false_string tfs_sbus_present= {
       "Is present",
       "Is not present"
};

/* value to string definitions*/
/* telegram types*/
static const value_string sbus_att_vals[] = {
       {0, "Request"},
       {1, "Response"},
       {2, "ACK/NAK"},
       {0, NULL}
};
/* Block types*/
static const value_string sbus_block_types[] = {
       {0x00, "COB"},                        /* Cyclic organization block */
       {0x01, "XOB"},                        /* Exception organization block */
       {0x02, "PB"},                         /* Program block */
       {0x03, "FB"},                         /* Function block */
       {0x04, "ST"},                         /* Step of Graftec structure*/
       {0x05, "TR"},                         /* Transition of Graftec structure*/
       {0x04, "TEXT"},                       /* Text*/
       {0x05, "DB"},                         /* Data Block*/
       {0x08, "SB"},                         /* Sequential Block (Graftec)*/
       {0x09, "DBX"},                        /* Special Data Block*/
       {0x10, "BACnet"},                     /* BACnet configuration block */
       {0x11, "CANopen"},                    /* CANopen configuration */
       {0x12, "LONIP"},                      /* LONIP configuration */
       {0x20, "Configuration file"},         /* LONIP configuration */
       {0x21, "Program block file"},         /* LONIP configuration */
       {0xFE, "All configuration blocks"},   /* all configuration blocks (delete blocks only) */
       {0xFF, "All blocks"},                 /* all blocks (incl. program blocks) (delete blocks only) */
       {0, NULL}
};
/* ACK NAK values*/
static const value_string sbus_CPU_status[] = {
       {0x43, "C"},
       {0x44, "D"},
       {0x48, "Halt"},
       {0x52, "Run"},
       {0x53, "Stop"},
       {0x58, "X, Exceptional Intermediate Status (MODEMS+)"},
       {0, NULL}
};
/* CPU status*/
static const value_string sbus_ack_nak_vals[] = {
       {0, "ACK (Acknowledged)"},
       {1, "NAK, no reason specified"},
       {2, "NAK, because of password"},
       {3, "NAK, PGU port is in reduced protocol"},
       {4, "NAK, PGU port is already used"},
       {0, NULL}
};
/* S-Bus commands*/
static const value_string sbus_command_vals[] = {
       {0x00, "Read counter(s)"},
       {0x01, "Read display register"},
       {0x02, "Read flag(s)"},
       {0x03, "Read input(s)"},
       {0x04, "Read real time clock"},
       {0x05, "Read output(s)"},
       {0x06, "Read register(s)"},
       {0x07, "Read timer(s)"},
       {0x0A, "Write counter(s)"},
       {0x0B, "Write flag(s)"},
       {0x0C, "Write real time clock"},
       {0x0D, "Write output(s)"},
       {0x0E, "Write register(s)"},
       {0x0F, "Write timer(s)"},
       {0x14, "Read PCD status, CPU 0"},
       {0x15, "Read PCD status, CPU 1"},
       {0x16, "Read PCD status, CPU 2"},
       {0x17, "Read PCD status, CPU 3"},
       {0x18, "Read PCD status, CPU 4"},
       {0x19, "Read PCD status, CPU 5"},
       {0x1A, "Read PCD status, CPU 6"},
       {0x1B, "Read PCD status (own)"},
       {0x1D, "Read S-Bus station number"},
       {0x1E, "Read user memory*"},
       {0x1F, "Read program line*"},
       {0x20, "Read firmware version"},
       {0x21, "Read text*"},
       {0x22, "Read active transition*"},
       {0x23, "Write user memory*"},
       {0x24, "Write program line*"},
       {0x25, "Write text*"},
       {0x28, "Run procedure*, CPU 0"},
       {0x29, "Run procedure*, CPU 1"},
       {0x2A, "Run procedure*, CPU 2"},
       {0x2B, "Run procedure*, CPU 3"},
       {0x2C, "Run procedure*, CPU 4"},
       {0x2D, "Run procedure*, CPU 5"},
       {0x2E, "Run procedure*, CPU 6"},
       {0x2F, "Run procedure* (own CPU)"},
       {0x30, "Run procedure* (All CPUs)"},
       {0x32, "Restart cold CPU 1*"},
       {0x33, "Restart cold CPU 2*"},
       {0x34, "Restart cold CPU 3*"},
       {0x35, "Restart cold CPU 4*"},
       {0x36, "Restart cold CPU 5*"},
       {0x37, "Restart cold CPU 6*"},
       {0x38, "Restart cold own CPU*"},
       {0x39, "Restart cold all CPUs*"},
       {0x3C, "Stop procedure*, CPU 0"},
       {0x3D, "Stop procedure*, CPU 1"},
       {0x3E, "Stop procedure*, CPU 2"},
       {0x3F, "Stop procedure*, CPU 3"},
       {0x40, "Stop procedure*, CPU 4"},
       {0x41, "Stop procedure*, CPU 5"},
       {0x42, "Stop procedure*, CPU 6"},
       {0x43, "Stop procedure*, (own CPU)"},
       {0x44, "Stop procedure*, (All CPUs)"},
       {0x46, "Read arithmetic status and ACCU*"},
       {0x47, "Read byte"},
       {0x48, "Read halt failure register*"},
       {0x49, "Read index register*"},
       {0x4A, "Read instruction pointer*"},
       {0x4B, "Find history*"},
       {0x50, "Write arithmetic staus and ACCU*"},
       {0x51, "Write byte*"},
       {0x52, "Write index register"},
       {0x53, "Write instruction pointer*"},
       {0x5A, "Clear all (F, O, R, T)*"},
       {0x5B, "Clear flags*"},
       {0x5C, "Clear outputs*"},
       {0x5D, "Clear registers*"},
       {0x5E, "Clear timers*"},
       {0x64, "Restart warm CPU 1*"},
       {0x65, "Restart warm CPU 2*"},
       {0x66, "Restart warm CPU 3*"},
       {0x67, "Restart warm CPU 4*"},
       {0x68, "Restart warm CPU 5*"},
       {0x69, "Restart warm CPU 6*"},
       {0x6A, "Restart warm (own CPU)*"},
       {0x6B, "Restart warm (All CPUs)*"},
       {0x6E, "Change block*"},
       {0x6F, "Clear history failure*"},
       {0x70, "Delete program line*"},
       {0x71, "Go conditional*"},
       {0x72, "Insert program line*"},
       {0x73, "Local cycles*"},
       {0x74, "All cycles*"},
       {0x75, "Make text*"},
       {0x76, "Execute single instruction*"},
       {0x77, "Single step*"},
       {0x82, "XOB 17 interrupt"},
       {0x83, "XOB 18 interrupt"},
       {0x84, "XOB 19 interrupt"},
       {0x91, "Read hangup timeout"},
       {0x96, "Read data block"},
       {0x97, "Write data block"},
       {0x98, "Make data block*"},
       {0x99, "Clear data block*"},
       {0x9A, "Clear text*"},
       {0x9B, "Read block address"},
       {0x9C, "Read block sizes"},
       {0x9D, "Read current block*"},
       {0x9E, "Read call stack*"},
       {0x9F, "Read DBX"},
       {0xA1, "Read user EEPROM register"},
       {0xA3, "Write user EEPROM register"},
       {0xA5, "Erase flash*"},
       {0xA6, "Restart cold flag*"},
       {0xA7, "Write system buffer"},
       {0xA8, "Read system buffer"},
       {0xA9, "Read/write block data*"},
       {0xAA, "Get diagnostic*"},
       {0xAB, "Read system information*"},
       {0xAC, "Changes blocks on run*"},
       {0xAD, "Flashcard telegram*"},
       {0xAE, "Download FW*"},
       {0xAF, "Web server serial communication*"},
       {0, NULL}
};

static const value_string webserver_aid_vals[] = {
       {0x01, "Partial request"},
       {0x02, "Request end"},
       {0x07, "Get Data"},
       {0x10, "Transfer OK"},
       {0x11, "Partial answer"},
       {0x12, "Last part of answer"},
       {0x13, "Server not ready"},
       {0, NULL}
};
static const value_string rdwrblock_vals[] = {
       {0x00, "WR block start of stream"},
       {0x01, "WR block data stream"},
       {0x02, "WR block end of stream"},
       {0x07, "Abort block WR stream"},
       {0x08, "WR block data"},
       {0x10, "RD block start of stream"},
       {0x11, "RD block data stream"},
       {0x17, "Abort block RD stream"},
       {0x18, "RD block data"},
       {0x20, "Delete block"},
       {0x21, "Get block size"},
       {0x22, "Get program block list"},
       {0, NULL}
};

static const value_string rdwrblock_sts[] = {
       {0x00, "ACK (Acknowledged)"},
       {0x01, "Data"},
       {0x02, "Busy"},
       {0x03, "End of stream"},
       {0x04, "Data EOF reached"},
       {0x80, "NAK"},
       {0x81, "NAK, unknown Tlg_Type"},
       {0x82, "NAK, not supported  Tlg_Type"},
       {0x83, "NAK, unknown Block Type"},
       {0x84, "NAK, out of sequence"},
       {0x85, "NAK, not supported Block number"},
       {0x86, "NAK, Block Size invalid (to big)"},
       {0x87, "NAK, Block Address invalid"},
       {0x88, "NAK, CRC invalid"},
       {0x89, "NAK, invalid status"},
       {0x8A, "NAK, invalid command size (w-count)"},
       {0xFF, "Abort (stream)"},
       {0, NULL}
};

static const value_string rdwrblock_list_type_vals[] = {
       {0x40, "Start request of program block"},
       {0x41, "Get next program block"},
       {0xFF, "Abort get list"},
       {0, NULL}
};

static const guint crc_table[] = {
       0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
       0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
       0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
       0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
       0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
       0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
       0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
       0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
       0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
       0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
       0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
       0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
       0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
       0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
       0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
       0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

/* Conversion values passing structure*/
typedef struct {
       guint32 conversation;  /*Conversation ID*/
       guint16 sequence;      /*Sequence number of request telegram*/
} sbus_request_key;

typedef struct {
       guint8 cmd_code;       /*command code from request*/
       guint8 count;          /*rcount value*/
       guint8 sysinfo;        /*system information number*/
       guint8 block_tlg;      /*telegram type of RD/WR block telegrams*/
       guint8 retry_count;    /*number of retries*/
       guint32 req_frame;     /*frame number of last request*/
       guint32 resp_frame;    /*frame number of response*/
       nstime_t req_time;     /*time of the last request*/
} sbus_request_val;

/* The hash structure (for conversations)*/
static GHashTable *sbus_request_hash = NULL;

static guint crc_calc (guint crc, guint val)
{
       int index;
       guint ncrc;

       index = (((crc >> 8) ^ val) & 0xff);
       ncrc = crc_table[index] ^ ((crc << 8) & 0xffff);

       return ncrc;
}

/* Hash functions*/
static gint sbus_equal(gconstpointer v, gconstpointer w)
{
       sbus_request_key *v1 = (sbus_request_key *)v;
       sbus_request_key *v2 = (sbus_request_key *)w;

       if (v1->conversation == v2->conversation &&
           v1->sequence == v2->sequence) {
              return 1;
       }
       return 0;
}

static guint sbus_hash(gconstpointer v)
{
       sbus_request_key *key = (sbus_request_key *)v;
       guint val;
       val = key->conversation + key->sequence;
       return val;
}

/*Protocol initialisation*/
static void sbus_init_protocol(void){
       if (sbus_request_hash){
              g_hash_table_destroy(sbus_request_hash);
       }
       sbus_request_hash = g_hash_table_new(sbus_hash, sbus_equal);
}

/* check whether the packet looks like SBUS or not */
static gboolean
is_sbus_pdu(tvbuff_t *tvb)
{
       guint32 length;

       /* we need at least 8 bytes to determine whether this is sbus or
          not*/
       if(tvb_length(tvb)<8){
              return FALSE;
       }

       /* the length must be >= 8 bytes to accomodate the header,
          it also must be <65536 to fit inside a udp packet
       */
       length=tvb_get_ntohl(tvb, 0);
       if ( (length<8) || (length>65535) ) {
              return FALSE;
       }
       if (tvb_reported_length(tvb) != length) {
              return FALSE;
       }
       /* First four byte indicate the length which must be at least 12 bytes*/
       if (tvb_get_ntohl(tvb, 0) < 12) {
              return (FALSE);
       }
       /* Fifth byte indicates protocol version which can be 0 or 1*/
       if (tvb_get_guint8(tvb, 4) > 0x01) {
              return (FALSE);
       }
       /* Sixth byte indicates protocol type and must be 0*/
       if ( tvb_get_guint8(tvb, 5) > 0x01 ) {
              return (FALSE);
       }
       /* Seventh and eigth byte indicates the packet sequence number and can
          be 0 to 65565 (--> check does not make sense)*/
       /* Ninth byte the "attributes character" and must be either 0, 1 or 2
          (request, response or ACK/NAK)*/
       if (tvb_get_guint8(tvb, 8) > 0x02 ) {
              return (FALSE);
       }
       return TRUE;
}

/*Dissect the telegram*/
static int
dissect_sbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

/* Set up structures needed to add the protocol subtree and manage it */
       proto_item *ti, *et, *dt, *hi, *cs;
       proto_tree *sbus_tree, *ethsbus_tree, *sbusdata_tree;

       gint i;        /*for CRC calculation*/
       gint j;        /*for CRC calculation*/
       gint offset;
       gint sbus_eth_len;
       guint sbus_crc_calc;
       guint8 sbus_attribut;
       guint8 sbus_media_cnt;
       guint8 sbus_fio_cnt;
       guint8 sbus_cmd_code;
       guint8 sbus_web_size;
       guint8 sbus_web_aid;
       guint8 sbus_web_seq;
       guint8 sbus_rdwr_type;
       guint8 sbus_rdwr_sequence;
       guint8 sbus_rdwr_block_tlg;
       guint8 sbus_rdwr_block_type;
       guint8 sbus_rdwr_ack_nak;
       guint8 sbus_quint8_helper0;
       guint32 sbus_binarymasked;
       guint32 sbus_binaries;
       guint16 sbus_ack_code;
       guint32 sbus_show_bin;
       guint32 sbus_rdwr_length;
       guint32 sbus_helper;
       guint32 sbus_helper1;
       guint32 sbus_helper2;
       char *tmp_string;
       nstime_t ns; /*we use this for the response time*/

/* Set up conversations*/
       conversation_t *conversation = NULL;
       sbus_request_key request_key, *new_request_key;
       sbus_request_val *request_val = NULL;

       /* does this look like an sbus pdu? */
       if(!is_sbus_pdu(tvb)){
           return 0;
       }

       conversation = find_or_create_conversation(pinfo);

       request_key.conversation = conversation->index;
       request_key.sequence = tvb_get_ntohs(tvb,6);

       request_val = (sbus_request_val *) g_hash_table_lookup(sbus_request_hash,
                            &request_key);
       /*Get type of telegram for finding retries
        *As we are storing the info in a hash table we need to update the info
        *also in case this is no retry*/
       sbus_attribut = tvb_get_guint8(tvb,8);
       if (request_val && sbus_attribut == SBUS_REQUEST) {
              if (request_val->req_frame < pinfo->fd->num){ /*a retry; req_frame smaller this frame*/
                     request_val->retry_count +=1;
              }
              else { /*we have a conversation but this is not a retry so we store the packet info*/
                     request_val->retry_count = 0;
                     request_val->req_frame = pinfo->fd->num; /*store actual frame nr.*/
                     request_val->req_time = pinfo->fd->abs_ts;
              }
       }
       if (request_val && (sbus_attribut == SBUS_RESPONSE ||
                                      sbus_attribut == SBUS_ACKNAK)) { /*a response*/
            request_val->resp_frame = pinfo->fd->num; /*so store this frame nr.*/
       }
       /* Only allocate a new hash element when it's a request*/
       sbus_attribut = tvb_get_guint8(tvb,8);

       if ( !request_val && sbus_attribut == 0 ) {/* request telegram */
              new_request_key = se_alloc(sizeof(sbus_request_key));
              *new_request_key = request_key;

              request_val = se_alloc(sizeof(sbus_request_val));
              request_val->cmd_code=tvb_get_guint8(tvb,10);
              request_val->retry_count=0;
              request_val->req_frame = pinfo->fd->num; /*store actual frame nr.*/
              request_val->req_time = pinfo->fd->abs_ts;
              request_val->resp_frame = 0; /*response frame is not known yet*/

              if (((request_val->cmd_code) == SBUS_RD_USER_EEPROM_REGISTER) ||
                  ((request_val->cmd_code) == SBUS_WR_USER_EEPROM_REGISTER)) {
                     request_val->count=((tvb_get_guint8(tvb,12))+1);
              } else {
                     request_val->count=((tvb_get_guint8(tvb,11))+1);
              }

              /*Enter system info or telegram type (for rd/wr block telegrams)*/
              if ((request_val->cmd_code) == SBUS_RD_SYSTEM_INFORMATION) {
                     request_val->sysinfo=(tvb_get_guint8(tvb,12));
                     request_val->block_tlg=0x0;
              } else if ((request_val->cmd_code) == SBUS_RD_WR_PCD_BLOCK) {
                     request_val->sysinfo=0x0;
                     request_val->block_tlg=(tvb_get_guint8(tvb,12));
              } else {
                     request_val->sysinfo=0x0;
                     request_val->block_tlg=0x0;
              }

              g_hash_table_insert(sbus_request_hash, new_request_key, request_val);
       }
/* End of attaching data to hash table*/

/* Make entries in Protocol column and Info column on summary display */
       col_set_str(pinfo->cinfo, COL_PROTOCOL, "S-Bus");

       col_clear(pinfo->cinfo, COL_INFO);
       offset = 0;

       if (check_col(pinfo->cinfo, COL_INFO)) {
              switch (sbus_attribut){
                     case SBUS_REQUEST:
                            sbus_cmd_code = tvb_get_guint8(tvb,10);
                            switch (sbus_cmd_code){
                                   case SBUS_WEB_SERVER_SERIAL_COMM:
                                          /* Special treatment of web server request
                                           * as is is very helpful to see more information in the packetlist */
                                          sbus_web_aid = tvb_get_guint8(tvb,12);
                                          sbus_web_seq = tvb_get_guint8(tvb,13);
                                          col_add_fstr(pinfo->cinfo, COL_INFO,
                                                       "Web Server Request: %s (Seq No: %d)",
                                                       val_to_str_const(sbus_web_aid,
                                                                        webserver_aid_vals, "Unknown Request!"),
                                                       sbus_web_seq);
                                          break;
                                   case SBUS_RD_WR_PCD_BLOCK:
                                          sbus_rdwr_type = tvb_get_guint8(tvb, 12);
                                          col_add_fstr( pinfo->cinfo, COL_INFO,
                                                        "Request:  %s", val_to_str_const( sbus_rdwr_type, rdwrblock_vals,
                                                                                          "This RD/WR block telegram is not implemented"));
                                          /* Add name of file to be written in case of start of file stream */
                                          if (sbus_rdwr_type == SBUS_WR_START_OF_STREAM) {
                                                 sbus_rdwr_block_type = tvb_get_guint8(tvb, 14);
                                                 if ((sbus_rdwr_block_type == SBUS_RD_WR_CONFIGURATION_FILE) ||
                                                     (sbus_rdwr_block_type == SBUS_RD_WR_PROGRAM_BLOCK_FILE)) {
                                                        sbus_quint8_helper0=0;
                                                        for (i=19; i<43; i++) { /*max length is 24 chars*/
                                                               /*find zero-termination of string*/
                                                               if ((tvb_get_guint8(tvb, i)) == 0x00) {
                                                                      break;
                                                               }
                                                               sbus_quint8_helper0 += 1;
                                                        }
                                                        tmp_string = tvb_get_ephemeral_string(tvb , 19,
                                                                                              sbus_quint8_helper0);
                                                        col_append_fstr(pinfo->cinfo, COL_INFO,
                                                                        ": (File: %s)", tmp_string);
                                                 }
                                          } else if (sbus_rdwr_type == SBUS_RD_BLOCK_START_OF_STREAM) {
                                                 sbus_rdwr_block_type = tvb_get_guint8(tvb, 14);
                                                 if ((sbus_rdwr_block_type == SBUS_RD_WR_CONFIGURATION_FILE) ||
                                                     (sbus_rdwr_block_type == SBUS_RD_WR_PROGRAM_BLOCK_FILE)) {
                                                        sbus_quint8_helper0=0;
                                                        for (i=15; i<39; i++) { /*max length is 24 chars*/
                                                               /*find zero-termination of string*/
                                                               if ((tvb_get_guint8(tvb, i)) == 0x00) {
                                                                      break;
                                                               }
                                                               sbus_quint8_helper0 += 1;
                                                        }
                                                        tmp_string = tvb_get_ephemeral_string(tvb , 15,
                                                                                              sbus_quint8_helper0);
                                                        col_append_fstr(pinfo->cinfo, COL_INFO,
                                                                        ": (File: %s)", tmp_string);
                                                 }
                                          }

                                          break;


                                   default:
                                          /* All other requests */
                                          col_add_fstr(pinfo->cinfo, COL_INFO,
                                                       "Request: %s", val_to_str_const(sbus_cmd_code,
                                                                                       sbus_command_vals, "Unknown Command!"));
                                          break;
                            }
                            /*mark retries*/
                            if (request_val->retry_count>0) {
                                   col_append_str(pinfo->cinfo, COL_INFO,
                                   " (Retry)");
                            } /*no retry number as it is not always correctly calculated*/
                            break;

                     case SBUS_RESPONSE:
                            /* Special treatment of web server request
                             * as is is very helpful to see more information in the packetlist */
                            if (request_val && ((request_val->cmd_code) == SBUS_WEB_SERVER_SERIAL_COMM)) {
                                   sbus_web_size = tvb_get_guint8(tvb,9);
                                   sbus_web_aid = tvb_get_guint8(tvb,10);
                                   col_add_fstr(pinfo->cinfo, COL_INFO,
                                          "Response: %s",
                                          val_to_str_const(sbus_web_aid,
                                                           webserver_aid_vals, "Unknown Request!"));
                                   if (sbus_web_size > 1) {
                                          sbus_web_seq = tvb_get_guint8(tvb,11);
                                          col_append_fstr(pinfo->cinfo, COL_INFO,
                                              " (Seq No: %d)",
                                              sbus_web_seq);
                                   }
                            } else if (request_val && ((request_val->cmd_code) == SBUS_RD_WR_PCD_BLOCK)) {
                                   /* Treat the ACK/NAK telgrams in a special way*/
                                   switch (request_val->block_tlg) {
                                          case SBUS_WR_START_OF_STREAM:
                                          case SBUS_WR_BLOCK_DATA_STREAM:
                                          case SBUS_WR_BLOCK_END_OF_STREAM:
                                          case SBUS_WR_ABORT_BLOCK_STREAM:
                                          case SBUS_WR_BLOCK_DATA_BYTES:
                                          case SBUS_DELETE_BLOCK:
                                          case SBUS_RD_ABORT_BLOCK_STREAM:
                                                 sbus_rdwr_ack_nak = tvb_get_guint8(tvb, 10);
                                                 col_add_fstr( pinfo->cinfo, COL_INFO,
                                                               "Response: %s", val_to_str_const(sbus_rdwr_ack_nak,
                                                                                                rdwrblock_sts, "Unknown response!"));
                                                 break;
                                          default:
                                                 sbus_rdwr_type = tvb_get_guint8(tvb, 9);
                                                 col_add_fstr( pinfo->cinfo, COL_INFO,
                                                               "Response: (%d byte)", sbus_rdwr_type);
                                                 break;
                                   }

                            } else {
                                   col_set_str(pinfo->cinfo, COL_INFO, "Response");
                            }
                            break;

                     case SBUS_ACKNAK:
                            sbus_ack_code = tvb_get_ntohs(tvb,9);
                            col_add_fstr(pinfo->cinfo, COL_INFO,
                                         "%s", val_to_str_const(sbus_ack_code,
                                                                sbus_ack_nak_vals,
                                                                "Unknown NAK response code!"));
                            break;

                     default:
                            col_set_str(pinfo->cinfo, COL_INFO, "Unknown attribute");
                            break;
              }

       }
/* create display subtree for the protocol */
       if (tree) {

              ti = proto_tree_add_item(tree, proto_sbus, tvb, offset, -1, ENC_NA);
              sbus_tree = proto_item_add_subtree(ti, ett_sbus);

/*Add subtree for Ether-S-Bus header*/
              et = proto_tree_add_text(sbus_tree, tvb, offset, 8, "Ether-S-Bus header");
              ethsbus_tree = proto_item_add_subtree(et, ett_sbus_ether);

/* add an item to the subtree*/
              sbus_eth_len = tvb_get_ntohl(tvb,offset);
              proto_tree_add_item(ethsbus_tree,
                                  hf_sbus_length, tvb, offset, 4, ENC_BIG_ENDIAN);
              offset += 4;

              proto_tree_add_item(ethsbus_tree,
                                  hf_sbus_version, tvb, offset, 1, ENC_BIG_ENDIAN);
              offset += 1;

              proto_tree_add_item(ethsbus_tree,
                                  hf_sbus_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
              offset += 1;

              proto_tree_add_item(ethsbus_tree,
                                  hf_sbus_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
              offset += 2;

/* Continue adding stuff to the main tree*/
              sbus_attribut = tvb_get_guint8(tvb,offset);
              proto_tree_add_item(sbus_tree,
                                  hf_sbus_attribut, tvb, offset, 1, ENC_BIG_ENDIAN);
              offset += 1;

              if (sbus_attribut == SBUS_REQUEST) {
                     proto_tree_add_item(sbus_tree,
                                         hf_sbus_dest, tvb, offset, 1, ENC_BIG_ENDIAN);
                     offset += 1;
                     sbus_cmd_code = tvb_get_guint8(tvb,offset);
                     proto_tree_add_item(sbus_tree,
                                         hf_sbus_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                     offset += 1;
                     if (request_val && request_val->retry_count > 0) {/*this is a retry telegram*/
                            hi = proto_tree_add_boolean(sbus_tree,
                                                        hf_sbus_retry, tvb, 0, 0, TRUE);
                            PROTO_ITEM_SET_GENERATED(hi);
                            expert_add_info_format(pinfo, hi, PI_SEQUENCE, PI_NOTE,
                                                   "Repeated telegram (due to timeout?)");
                            nstime_delta(&ns, &pinfo->fd->abs_ts, &request_val->req_time);
                            proto_tree_add_time(sbus_tree, hf_sbus_timeout,
                                                tvb, 0, 0, &ns);
                            proto_tree_add_uint(sbus_tree, hf_sbus_request_in, tvb, 0, 0,
                                                request_val->req_frame);
                     }
                     if (request_val && request_val->resp_frame > pinfo->fd->num){
                            proto_tree_add_uint(sbus_tree, hf_sbus_response_in, tvb, 0, 0,
                                                request_val->resp_frame);
                     }
                     switch (sbus_cmd_code) {
                            /*Read Counter, Register or Timer*/
                            case SBUS_RD_COUNTER:
                            case SBUS_RD_REGISTER:
                            case SBUS_RD_TIMER:
                                   sbus_media_cnt = (tvb_get_guint8(tvb,offset))+1;
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_rcount, tvb, offset, 1, sbus_media_cnt);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_rtc, tvb, offset, 2, ENC_BIG_ENDIAN);
                                   offset += 2;
                                   break;

                                   /*Read Flag, Input or Output*/
                            case SBUS_RD_FLAG:
                            case SBUS_RD_INPUT:
                            case SBUS_RD_OUTPUT:
                                   sbus_media_cnt = (tvb_get_guint8(tvb,offset))+1;
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_rcount, tvb, offset, 1, sbus_media_cnt);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_iof, tvb, offset, 2, ENC_BIG_ENDIAN);
                                   offset += 2;
                                   break;

                                   /*Write Register Timer Counter*/
                            case SBUS_WR_COUNTER:
                            case SBUS_WR_REGISTER:
                            case SBUS_WR_TIMER:
                                   sbus_media_cnt = (tvb_get_guint8(tvb,offset));
                                   sbus_media_cnt = ((sbus_media_cnt - 1)/4);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_wcount_calculated, tvb, offset,
                                                       1, sbus_media_cnt);
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_wcount, tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_rtc, tvb, offset, 2, ENC_BIG_ENDIAN);
                                   offset += 2;
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            ((sbus_media_cnt) * 4),"Data");

                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);
                                   for (i=((sbus_media_cnt)); i>0; i--) {
                                          proto_tree_add_item(sbusdata_tree,
                                                              hf_sbus_data_rtc, tvb, offset,
                                                              4, ENC_BIG_ENDIAN);
                                          offset += 4;
                                   }
                                   break;

                                   /* Write flags and outputs*/
                            case SBUS_WR_FLAG:
                            case SBUS_WR_OUTPUT:
                                   sbus_media_cnt = (tvb_get_guint8(tvb,offset));
                                   sbus_media_cnt = (sbus_media_cnt - 2);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_wcount_calculated, tvb, offset,
                                                       1, sbus_media_cnt);
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_wcount, tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_iof, tvb, offset, 2, ENC_BIG_ENDIAN);
                                   offset += 2;
                                   sbus_fio_cnt = (tvb_get_guint8(tvb,offset));
                                   sbus_fio_cnt = ((sbus_fio_cnt + 1));
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_fio_count, tvb, offset, 1, sbus_fio_cnt);
                                   offset += 1;
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            sbus_media_cnt,"Data");

                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);
                                   for (i=sbus_media_cnt; i>0; i--) {
                                          sbus_helper = 1;
                                          sbus_show_bin = 0;
                                          sbus_binarymasked = 0x01;
                                          sbus_binaries = tvb_get_guint8(tvb, offset);
                                          for (j=0; j<8; j++) {
                                                 if ((sbus_binarymasked & sbus_binaries) != 0) {
                                                        sbus_show_bin = (sbus_show_bin + sbus_helper);
                                                 }
                                                 sbus_binarymasked = sbus_binarymasked<<1;
                                                 sbus_helper = 10 * sbus_helper;
                                          }

                                          proto_tree_add_uint_format(sbusdata_tree,
                                                                     hf_sbus_data_iof, tvb, offset, 1, sbus_show_bin,
                                                                     "Binary data: %08u", sbus_show_bin);
                                          offset += 1;
                                   }
                                   break;

                                   /* Request: Write Real time clock*/
                            case SBUS_WR_RTC:
                                   sbus_helper = tvb_get_guint8(tvb, (offset +5));  /*hours*/
                                   sbus_helper1 = tvb_get_guint8(tvb, (offset +6)); /*minutes*/
                                   sbus_helper2 = tvb_get_guint8(tvb, (offset +7)); /*seconds*/
                                   proto_tree_add_text(sbus_tree, tvb, (offset +5), 3,
                                                       "Time (HH:MM:SS): %02x:%02x:%02x", sbus_helper, sbus_helper1, sbus_helper2);
                                   sbus_helper = tvb_get_guint8(tvb, (offset +2));  /*year*/
                                   sbus_helper1 = tvb_get_guint8(tvb, (offset +3)); /*month*/
                                   sbus_helper2 = tvb_get_guint8(tvb, (offset +4)); /*day*/
                                   proto_tree_add_text(sbus_tree, tvb, (offset +2), 3,
                                                       "Date (YY/MM/DD): %02x/%02x/%02x", sbus_helper, sbus_helper1, sbus_helper2);
                                   sbus_helper = tvb_get_guint8(tvb, (offset));  /*year-week*/
                                   sbus_helper1 = tvb_get_guint8(tvb, (offset +1)); /*week-day*/
                                   proto_tree_add_text(sbus_tree, tvb, offset, 2,
                                                       "Calendar week: %x, Week day: %x", sbus_helper, sbus_helper1);
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            8, "Clock data");
                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);

                                   proto_tree_add_item(sbusdata_tree,
                                                       hf_sbus_week_day, tvb, offset, 2, ENC_BIG_ENDIAN);
                                   offset += 2;
                                   proto_tree_add_item(sbusdata_tree,
                                                       hf_sbus_date, tvb, offset, 3, ENC_BIG_ENDIAN);
                                   offset += 3;
                                   proto_tree_add_item(sbusdata_tree,
                                                       hf_sbus_time, tvb, offset, 3, ENC_BIG_ENDIAN);
                                   offset += 3;
                                   break;

                                   /* Read user memory or program line*/
                            case SBUS_RD_USER_MEMORY:
                            case SBUS_RD_PROGRAM_LINE:
                                   sbus_media_cnt = (tvb_get_guint8(tvb,offset))+1;
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_rcount, tvb, offset, 1, sbus_media_cnt);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_prog, tvb, offset, 3, ENC_BIG_ENDIAN);
                                   offset += 3;
                                   break;

                                   /*Write user memory*/
                            case SBUS_WR_USER_MEMORY:
                                   sbus_media_cnt = (tvb_get_guint8(tvb,offset));
                                   sbus_media_cnt = ((sbus_media_cnt - 2)/4);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_wcount_calculated, tvb, offset,
                                                       1, sbus_media_cnt);
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_wcount, tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_68k, tvb, offset, 3, ENC_BIG_ENDIAN);
                                   offset += 3;
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            ((sbus_media_cnt) * 4),"Program lines");

                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);
                                   for (i=((sbus_media_cnt)); i>0; i--) {
                                          proto_tree_add_item(sbusdata_tree,
                                                              hf_sbus_data_rtc, tvb, offset,
                                                              4, ENC_BIG_ENDIAN);
                                          offset += 4;

                                   }
                                   break;

                                   /* Read byte*/
                            case SBUS_RD_BYTE:
                                   sbus_media_cnt = (tvb_get_guint8(tvb,offset))+1;
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_rcount, tvb, offset, 1, sbus_media_cnt);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_68k, tvb, offset, 3, ENC_BIG_ENDIAN);
                                   offset += 3;
                                   break;

                                   /* Write byte */
                            case SBUS_WR_BYTE:
                                   sbus_media_cnt = (tvb_get_guint8(tvb,offset));
                                   sbus_media_cnt = (sbus_media_cnt - 2);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_wcount_calculated, tvb, offset,
                                                       1, sbus_media_cnt);
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_wcount, tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_68k, tvb, offset, 3, ENC_BIG_ENDIAN);
                                   offset += 3;
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            ((sbus_media_cnt) * 4),"Data (bytes)");

                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);
                                   for (i=sbus_media_cnt; i>0; i--) {
                                          proto_tree_add_item(sbusdata_tree,
                                                              hf_sbus_data_byte, tvb, offset,
                                                              1, ENC_BIG_ENDIAN);
                                          offset += 1;
                                   }
                                   break;

                                   /*Read EEPROM register*/
                            case SBUS_RD_USER_EEPROM_REGISTER:
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_command_extension, tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset += 1;
                                   sbus_media_cnt = (tvb_get_guint8(tvb,offset))+1;
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_rcount, tvb, offset, 1, sbus_media_cnt);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_eeprom, tvb, offset, 2, ENC_BIG_ENDIAN);
                                   offset += 2;
                                   break;

                                   /*Request for reading system info*/
                                   /*Syinfo 05 is not implemented as no serial baud is possible*/
                            case SBUS_RD_SYSTEM_INFORMATION:
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_sysinfo_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_sysinfo_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset += 1;
                                   break;

                                   /* WebServer Request */
                            case SBUS_WEB_SERVER_SERIAL_COMM:
                                   sbus_web_size = tvb_get_guint8(tvb,offset);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_web_size, tvb, offset,
                                                       1, sbus_web_size);
                                   offset += 1;

                                   sbus_web_aid = tvb_get_guint8(tvb,offset);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_web_aid, tvb, offset,
                                                       1, sbus_web_aid);
                                   offset += 1;

                                   sbus_web_seq = tvb_get_guint8(tvb,offset);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_web_seq, tvb, offset,
                                                       1, sbus_web_seq);
                                   offset += 1;

                                   if (sbus_web_size > 1) {
                                          dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                                   (sbus_web_size - 1),"Data (bytes)");

                                          sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);
                                          for (i=sbus_web_size -1 ; i>0; i--) {
                                                 proto_tree_add_item(sbusdata_tree,
                                                                     hf_sbus_data_byte, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                          }
                                   }
                                   break;
                                   /* Read/write block request */
                            case SBUS_RD_WR_PCD_BLOCK:
                                   if (tvb_get_guint8(tvb,offset) == 0xff){
                                          sbus_rdwr_length = ((tvb_get_ntohl(tvb,0))-15);
                                          proto_tree_add_uint(sbus_tree,
                                                              hf_sbus_rdwr_block_length_ext, tvb, 0, 4, sbus_rdwr_length);
                                          offset += 1;
                                   } else {
                                          sbus_rdwr_length = tvb_get_guint8(tvb,offset);
                                          proto_tree_add_uint(sbus_tree,
                                                              hf_sbus_rdwr_block_length, tvb, offset,
                                                              1, sbus_rdwr_length);
                                          offset += 1;
                                   }
                                   sbus_rdwr_type = tvb_get_guint8(tvb,offset);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_rdwr_telegram_type, tvb, offset,
                                                       1, sbus_rdwr_type);
                                   offset += 1;
                                   switch(sbus_rdwr_type) {
                                          case SBUS_WR_START_OF_STREAM:
                                                 sbus_rdwr_block_type = tvb_get_guint8(tvb, 14);
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_rdwr_telegram_sequence, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_block_type, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;

                                                 /* Check for file or block download */
                                                 if ((sbus_rdwr_block_type == SBUS_RD_WR_CONFIGURATION_FILE) ||
                                                     (sbus_rdwr_block_type == SBUS_RD_WR_PROGRAM_BLOCK_FILE)) {
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_rdwr_block_size, tvb, offset,
                                                                            4, ENC_BIG_ENDIAN);
                                                        offset += 4;
                                                        sbus_quint8_helper0=0;
                                                        /*find zero-termination of string*/
                                                        for (i=19; i<43; i++) { /*max length string is 24 char*/
                                                               if ((tvb_get_guint8(tvb, i)) == 0x00) {
                                                                      break;
                                                               }
                                                               sbus_quint8_helper0 += 1;
                                                        }
                                                        tmp_string = tvb_get_ephemeral_string(tvb , 19, sbus_quint8_helper0);
                                                        proto_tree_add_string(sbus_tree,
                                                                              hf_sbus_rdwr_file_name, tvb, offset,
                                                                              sbus_quint8_helper0, tmp_string);
                                                        offset += sbus_quint8_helper0;
                                                        /*do not display a field for block data (skip)*/
                                                        offset += (sbus_rdwr_length-6-sbus_quint8_helper0);
                                                 } else { /* block write telegram, no file write*/
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_block_nr, tvb, offset,
                                                                            2, ENC_BIG_ENDIAN);
                                                        offset += 2;
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_rdwr_block_size, tvb, offset,
                                                                            4, ENC_BIG_ENDIAN);
                                                        offset += 4;
                                                        /*do not display a field for block data (skip)*/
                                                        offset += (sbus_rdwr_length-8);
                                                 }
                                                 break;
                                          case SBUS_WR_BLOCK_DATA_STREAM:
                                                 sbus_rdwr_sequence = tvb_get_guint8(tvb,offset);
                                                 proto_tree_add_uint(sbus_tree,
                                                                     hf_sbus_rdwr_telegram_sequence, tvb, offset,
                                                                     1, sbus_rdwr_sequence);
                                                 offset += 1;
                                                 /*do not display a field for block data (skip)*/
                                                 offset += (sbus_rdwr_length-1);
                                                 break;
                                          case SBUS_WR_BLOCK_END_OF_STREAM:
                                                 sbus_rdwr_sequence = tvb_get_guint8(tvb,offset);
                                                 proto_tree_add_uint(sbus_tree,
                                                                     hf_sbus_rdwr_telegram_sequence, tvb, offset,
                                                                     1, sbus_rdwr_sequence);
                                                 offset += 1;
                                                 /*do not display a field for block data (skip it)*/
                                                 offset += (sbus_rdwr_length-5);
                                                 /*do not display a field for block CRC (skip it)*/
                                                 offset += 4;
                                                 break;
                                          case SBUS_WR_ABORT_BLOCK_STREAM:
                                          case SBUS_RD_ABORT_BLOCK_STREAM:
                                                 break;
                                          case SBUS_WR_BLOCK_DATA_BYTES:
                                                 sbus_rdwr_block_type = tvb_get_guint8(tvb, 14);
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_block_type, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;

                                                 /* Check for file or block download */
                                                 if ((sbus_rdwr_block_type == SBUS_RD_WR_CONFIGURATION_FILE) ||
                                                     (sbus_rdwr_block_type == SBUS_RD_WR_PROGRAM_BLOCK_FILE)) {
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_rdwr_block_addr, tvb, offset,
                                                                            4, ENC_BIG_ENDIAN);
                                                        offset += 4;
                                                        sbus_quint8_helper0=0;
                                                        /*find zero-termination of string*/
                                                        for (i=19; i<43; i++) { /*max length string is 24 char*/
                                                               if ((tvb_get_guint8(tvb, i)) == 0x00) {
                                                                      break;
                                                               }
                                                               sbus_quint8_helper0 += 1;
                                                        }
                                                        tmp_string = tvb_get_ephemeral_string(tvb, 19, sbus_quint8_helper0);
                                                        proto_tree_add_string(sbus_tree,
                                                                              hf_sbus_rdwr_file_name, tvb, offset,
                                                                              sbus_quint8_helper0, tmp_string);
                                                        offset += sbus_quint8_helper0;
                                                        /*do not display a field for block data (skip)*/
                                                        offset += (sbus_rdwr_length-6-sbus_quint8_helper0);
                                                 } else { /* block write telegram, no file write*/
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_block_nr, tvb, offset,
                                                                            2, ENC_BIG_ENDIAN);
                                                        offset += 2;
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_rdwr_block_addr, tvb, offset,
                                                                            4, ENC_BIG_ENDIAN);
                                                        offset += 4;
                                                        /*do not display a field for block data (skip)*/
                                                        offset += (sbus_rdwr_length-8);
                                                 }
                                                 break;
                                          case SBUS_RD_BLOCK_START_OF_STREAM:
                                                 sbus_rdwr_block_type = tvb_get_guint8(tvb, 14);
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_rdwr_telegram_sequence, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_block_type, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;

                                                 /* Check for file or block download */
                                                 if ((sbus_rdwr_block_type == SBUS_RD_WR_CONFIGURATION_FILE) ||
                                                     (sbus_rdwr_block_type == SBUS_RD_WR_PROGRAM_BLOCK_FILE)) {
                                                        sbus_quint8_helper0=0;
                                                        /*find zero-termination of string*/
                                                        for (i=14; i<38; i++) { /*max length string is 24 char*/
                                                               if ((tvb_get_guint8(tvb, i)) == 0x00) {
                                                                      break;
                                                               }
                                                               sbus_quint8_helper0 += 1;
                                                        }
                                                        tmp_string = tvb_get_ephemeral_string(tvb, 14, sbus_quint8_helper0);
                                                        proto_tree_add_string(sbus_tree,
                                                                              hf_sbus_rdwr_file_name, tvb, offset,
                                                                              sbus_quint8_helper0, tmp_string);
                                                        offset += sbus_quint8_helper0;
                                                 } else { /* block write telegram, no file write*/
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_block_nr, tvb, offset,
                                                                            2, ENC_BIG_ENDIAN);
                                                        offset += 2;
                                                 }
                                                 break;
                                          case SBUS_RD_BLOCK_DATA_STREAM:
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_rdwr_telegram_sequence, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                                 break;
                                          case SBUS_RD_BLOCK_DATA_BYTES:
                                                 sbus_rdwr_block_type = tvb_get_guint8(tvb, 13);
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_block_type, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                                 /* Check for file or block read */
                                                 if ((sbus_rdwr_block_type == SBUS_RD_WR_CONFIGURATION_FILE) ||
                                                     (sbus_rdwr_block_type == SBUS_RD_WR_PROGRAM_BLOCK_FILE)) {
                                                        /*reading from a file*/
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_rdwr_block_addr, tvb, offset,
                                                                            4, ENC_BIG_ENDIAN);
                                                        offset += 4;
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_rdwr_block_size, tvb, offset,
                                                                            4, ENC_BIG_ENDIAN);
                                                        offset += 4;
                                                        sbus_quint8_helper0=0;
                                                        /*find zero-termination of string*/
                                                        for (i=22; i<46; i++) { /*max length string is 24 char*/
                                                               if ((tvb_get_guint8(tvb, i)) == 0x00) {
                                                                      break;
                                                               }
                                                               sbus_quint8_helper0 += 1;
                                                        }
                                                        tmp_string = tvb_get_ephemeral_string(tvb, 22, sbus_quint8_helper0);
                                                        proto_tree_add_string(sbus_tree,
                                                                              hf_sbus_rdwr_file_name, tvb, offset,
                                                                              sbus_quint8_helper0, tmp_string);
                                                        offset += sbus_quint8_helper0 + 1;
                                                 } else { /* block read telegram, no file read*/
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_block_nr, tvb, offset,
                                                                            2, ENC_BIG_ENDIAN);
                                                        offset += 2;
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_rdwr_block_addr, tvb, offset,
                                                                            4, ENC_BIG_ENDIAN);
                                                        offset += 4;
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_rdwr_block_size, tvb, offset,
                                                                            4, ENC_BIG_ENDIAN);
                                                        offset += 4;
                                                 }
                                                 break;
                                          case SBUS_DELETE_BLOCK:
                                          case SBUS_GET_BLOCK_SIZE:
                                                 sbus_rdwr_block_type = tvb_get_guint8(tvb, 13);
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_block_type, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                                 /* Check for file or block deletion */
                                                 if ((sbus_rdwr_block_type == SBUS_RD_WR_CONFIGURATION_FILE) ||
                                                     (sbus_rdwr_block_type == SBUS_RD_WR_PROGRAM_BLOCK_FILE)) {
                                                        /*delete a file*/
                                                        sbus_quint8_helper0=0;
                                                        /*find zero-termination of string*/
                                                        for (i=14; i<38; i++) { /*max length string is 24 char*/
                                                               if ((tvb_get_guint8(tvb, i)) == 0x00) {
                                                                      break;
                                                               }
                                                               sbus_quint8_helper0 += 1;
                                                        }
                                                        tmp_string = tvb_get_ephemeral_string(tvb, 14, sbus_quint8_helper0);
                                                        proto_tree_add_string(sbus_tree,
                                                                              hf_sbus_rdwr_file_name, tvb, offset,
                                                                              sbus_quint8_helper0, tmp_string);
                                                        offset += sbus_quint8_helper0 + 1;
                                                 } else { /* delete a block*/
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_block_nr, tvb, offset,
                                                                            2, ENC_BIG_ENDIAN);
                                                        offset += 2;
                                                 }
                                                 break;
                                          case SBUS_GET_PROGRAM_BLOCK_LIST:
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_rdwr_list_type, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                                 break;

                                          default:
                                                 break;
                                   }

                                   break;

                            /*Inform that command was not dissected and add remaining length*/
                            default:
                                   if (sbus_eth_len > 13) { /*13 bytes is the minimal length of a request telegram...*/
                                          sbus_helper = sbus_eth_len - (offset + 2);
                                          proto_tree_add_text(sbus_tree, tvb, offset, sbus_helper,
                                                              "This telegram isn't implemented in the dissector.");
                                          offset = offset + sbus_helper;
                                   }
                                   break;
                     }
              }

              /* Response dissection*/
              if (sbus_attribut == SBUS_RESPONSE && request_val) {
                     /*add response time*/
                     nstime_delta(&ns, &pinfo->fd->abs_ts, &request_val->req_time);
                     proto_tree_add_time(sbus_tree, hf_sbus_response_time,
                           tvb, 0, 0, &ns);
                     /*add reference to request telegram*/
                     proto_tree_add_uint(sbus_tree, hf_sbus_response_to, tvb, 0, 0,
                          request_val->req_frame);

                     switch (request_val->cmd_code) {
                            /* Response: 32 bit values*/
                            case SBUS_RD_COUNTER:
                            case SBUS_RD_REGISTER:
                            case SBUS_RD_TIMER:
                            case SBUS_RD_USER_MEMORY:
                            case SBUS_RD_PROGRAM_LINE:
                            case SBUS_RD_USER_EEPROM_REGISTER:
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            ((request_val->count) * 4),"Data");
                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);
                                   for (i=(request_val->count); i>0; i--) {
                                          proto_tree_add_item(sbusdata_tree,
                                                              hf_sbus_data_rtc, tvb, offset,
                                                              4, ENC_BIG_ENDIAN);
                                          offset += 4;
                                   }
                                   break;

                                   /* Response: PCD Display register*/
                            case SBUS_RD_DISPLAY_REGISTER:
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_display_register, tvb, offset, 4, ENC_BIG_ENDIAN);
                                   offset += 4;
                                   break;

                                   /* Add binary data I, O, F*/
                            case SBUS_RD_FLAG:
                            case SBUS_RD_INPUT:
                            case SBUS_RD_OUTPUT:
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            (((request_val->count) + 7) / 8), "Data");
                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);

                                   for (i=(((request_val->count) + 7) / 8); i>0; i--) {
                                          sbus_helper = 1;
                                          sbus_show_bin = 0;
                                          sbus_binarymasked = 0x01;
                                          sbus_binaries = tvb_get_guint8(tvb, offset);
                                          for (j=0; j<8; j++){
                                                 if ((sbus_binarymasked & sbus_binaries) != 0) {
                                                        sbus_show_bin = (sbus_show_bin + sbus_helper);
                                                 }
                                                 sbus_binarymasked = sbus_binarymasked<<1;
                                                 sbus_helper = 10 * sbus_helper;
                                          }

                                          proto_tree_add_uint_format(sbusdata_tree,
                                                                     hf_sbus_data_iof, tvb, offset, 1, sbus_show_bin,
                                                                     "Binary data: %08u", sbus_show_bin);
                                          offset += 1;
                                   }
                                   break;

                                   /* Response: Real time clock value*/
                            case SBUS_RD_RTC:
                                   sbus_helper = tvb_get_guint8(tvb, (offset +5));  /*hours*/
                                   sbus_helper1 = tvb_get_guint8(tvb, (offset +6)); /*minutes*/
                                   sbus_helper2 = tvb_get_guint8(tvb, (offset +7)); /*seconds*/
                                   proto_tree_add_text(sbus_tree, tvb, (offset +5), 3,
                                                       "Time (HH:MM:SS): %02x:%02x:%02x", sbus_helper, sbus_helper1, sbus_helper2);
                                   sbus_helper = tvb_get_guint8(tvb, (offset +2));  /*year*/
                                   sbus_helper1 = tvb_get_guint8(tvb, (offset +3)); /*month*/
                                   sbus_helper2 = tvb_get_guint8(tvb, (offset +4)); /*day*/
                                   proto_tree_add_text(sbus_tree, tvb, (offset +2), 3,
                                                       "Date (YY/MM/DD): %02x/%02x/%02x", sbus_helper, sbus_helper1, sbus_helper2);
                                   sbus_helper = tvb_get_guint8(tvb, (offset));  /*year-week*/
                                   sbus_helper1 = tvb_get_guint8(tvb, (offset +1)); /*week-day*/
                                   proto_tree_add_text(sbus_tree, tvb, offset, 2,
                                                       "Calendar week: %x, Week day: %x", sbus_helper, sbus_helper1);
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            8, "Clock data");
                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);

                                   proto_tree_add_item(sbusdata_tree,
                                                       hf_sbus_week_day, tvb, offset, 2, ENC_BIG_ENDIAN);
                                   offset += 2;
                                   proto_tree_add_item(sbusdata_tree,
                                                       hf_sbus_date, tvb, offset, 3, ENC_BIG_ENDIAN);
                                   offset += 3;
                                   proto_tree_add_item(sbusdata_tree,
                                                       hf_sbus_time, tvb, offset, 3, ENC_BIG_ENDIAN);
                                   offset += 3;
                                   break;

                                   /* Response: CPU status, the command codes 14..1B are concerned*/
                            case SBUS_RD_PCD_STATUS_CPU0:
                            case SBUS_RD_PCD_STATUS_CPU1:
                            case SBUS_RD_PCD_STATUS_CPU2:
                            case SBUS_RD_PCD_STATUS_CPU3:
                            case SBUS_RD_PCD_STATUS_CPU4:
                            case SBUS_RD_PCD_STATUS_CPU5:
                            case SBUS_RD_PCD_STATUS_CPU6:
                            case SBUS_RD_PCD_STATUS_OWN:
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_cpu_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset += 1;
                                   break;

                                   /* Response: Station address*/
                            case SBUS_RD_SBUS_STN_NBR:
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_address, tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset += 1;
                                   break;

                                   /* Response: Firmware version */
                            case SBUS_RD_PROGRAM_VERSION:
                                   /*PCD type*/
                                   tmp_string = tvb_get_ephemeral_string(tvb , offset, 5);
                                   proto_tree_add_string(sbus_tree,
                                                         hf_sbus_cpu_type, tvb, offset, 5, tmp_string);
                                   offset += 5;
                                   /*FW version*/
                                   tmp_string = tvb_get_ephemeral_string(tvb , offset, 3);
                                   proto_tree_add_string(sbus_tree,
                                                         hf_sbus_fw_version, tvb, offset, 3, tmp_string);
                                   offset += 4;
                                   break;

                                   /* Response for Status Flags*/
                            case SBUS_RD_STATUSFLAG_ACCU:
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            1,"ACCU and arithmetic status");
                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);

                                   proto_tree_add_item(sbusdata_tree, hf_sbus_flags_accu,
                                                       tvb, offset, 1, ENC_BIG_ENDIAN);
                                   proto_tree_add_item(sbusdata_tree, hf_sbus_flags_error,
                                                       tvb, offset, 1, ENC_BIG_ENDIAN);
                                   proto_tree_add_item(sbusdata_tree, hf_sbus_flags_negative,
                                                       tvb, offset, 1, ENC_BIG_ENDIAN);
                                   proto_tree_add_item(sbusdata_tree, hf_sbus_flags_zero,
                                                       tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset +=1;
                                   break;

                                   /* Response for Read byte */
                            case SBUS_RD_BYTE:
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            (request_val->count),"Data (bytes)");

                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);
                                   for (i=(request_val->count); i>0; i--) {
                                          proto_tree_add_item(sbusdata_tree,
                                                              hf_sbus_data_byte, tvb, offset,
                                                              1, ENC_BIG_ENDIAN);
                                          offset += 1;
                                   }
                                   break;

                                   /* Response for Read Index register */
                            case SBUS_RD_INDEX_REGISTER:
                                   /*Add subtree for Data*/
                                   dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                            2,"Data (hex bytes)");

                                   sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);
                                   for (i=0; i<2; i++) { /*2 bytes*/
                                          proto_tree_add_item(sbusdata_tree,
                                                              hf_sbus_data_byte_hex, tvb, offset,
                                                              1, ENC_BIG_ENDIAN);
                                          offset += 1;
                                   }
                                   break;

                                   /* Response: Instruction pointer*/
                            case SBUS_RD_INSTRUCTION_POINTER:
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_prog, tvb, offset, 3, ENC_BIG_ENDIAN);
                                   offset += 3;
                                   break;

                                   /*Response for Find History*/
                            case SBUS_FIND_HISTORY:
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_addr_68k, tvb, offset, 3, ENC_BIG_ENDIAN);
                                   offset += 3;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_nbr_elements, tvb, offset, 2, ENC_BIG_ENDIAN);
                                   offset += 2;
                                   break;

                                   /* Response: Read current block*/
                            case SBUS_RD_CURRENT_BLOCK:
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                                   offset += 1;
                                   proto_tree_add_item(sbus_tree,
                                                       hf_sbus_block_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
                                   offset += 2;
                                   break;

                                   /* Response: Read system infomation (without interpretation of module info)*/
                            case SBUS_RD_SYSTEM_INFORMATION:
                                   if (request_val->sysinfo == 0x00){ /*sysinfo 0*/
                                          offset += 1; /* this byte is always 0x01*/
                                          /*Add subtree for Data*/
                                          dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                                   1,"System info");
                                          sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);

                                          proto_tree_add_item(sbusdata_tree, hf_sbus_sysinfo0_1,
                                                              tvb, offset, 1, ENC_BIG_ENDIAN);
                                          proto_tree_add_item(sbusdata_tree, hf_sbus_sysinfo0_2,
                                                              tvb, offset, 1, ENC_BIG_ENDIAN);
                                          proto_tree_add_item(sbusdata_tree, hf_sbus_sysinfo0_3,
                                                              tvb, offset, 1, ENC_BIG_ENDIAN);
                                          proto_tree_add_item(sbusdata_tree, hf_sbus_sysinfo0_4,
                                                              tvb, offset, 1, ENC_BIG_ENDIAN);
                                          proto_tree_add_item(sbusdata_tree, hf_sbus_sysinfo0_5,
                                                              tvb, offset, 1, ENC_BIG_ENDIAN);
                                          offset += 1;
                                   } else {
                                          /*do not dissect all system info telegrams as there is no need*/
                                          offset = (tvb_get_guint8(tvb,9) + 10);
                                   }
                                   break;

                                   /* Response: Webserver request */
                            case SBUS_WEB_SERVER_SERIAL_COMM:
                                   sbus_web_size = tvb_get_guint8(tvb,offset);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_web_size, tvb, offset,
                                                       1, sbus_web_size);
                                   offset += 1;

                                   sbus_web_aid = tvb_get_guint8(tvb,offset);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_web_aid, tvb, offset,
                                                       1, sbus_web_aid);
                                   offset += 1;

                                   if (sbus_web_size > 1) {
                                          sbus_web_seq = tvb_get_guint8(tvb,offset);
                                          proto_tree_add_uint(sbus_tree,
                                                              hf_sbus_web_seq, tvb, offset,
                                                              1, sbus_web_seq);
                                          offset += 1;

                                          dt = proto_tree_add_text(sbus_tree, tvb, offset,
                                                                   (sbus_web_size - 2),"Data (bytes)");

                                          sbusdata_tree = proto_item_add_subtree(dt, ett_sbus_data);
                                          for (i=sbus_web_size - 2; i>0; i--) {
                                                 proto_tree_add_item(sbusdata_tree,
                                                                     hf_sbus_data_byte, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                          }
                                   }
                                   break;
                                   /* Response: Read/Write block data */
                            case SBUS_RD_WR_PCD_BLOCK:
                                   sbus_rdwr_block_tlg = request_val->block_tlg;
                                   sbus_rdwr_length = tvb_get_guint8(tvb,offset);
                                   proto_tree_add_uint(sbus_tree,
                                                       hf_sbus_rdwr_block_length, tvb, offset,
                                                       1, sbus_rdwr_length);
                                   offset += 1;
                                   hi = proto_tree_add_item(sbus_tree,
                                                            hf_sbus_rdwr_acknakcode, tvb, offset,
                                                            1, ENC_BIG_ENDIAN);
                                   if ((tvb_get_guint8(tvb, offset) >= SBUS_RD_WR_NAK)&&
                                       (tvb_get_guint8(tvb, offset) <= SBUS_RD_WR_NAK_INVALID_SIZE)) {
                                          expert_add_info_format(pinfo, hi, PI_RESPONSE_CODE, PI_CHAT,
                                                                 "Telegram not acknowledged by PCD");
                                   }
                                   offset += 1;
                                   switch(sbus_rdwr_block_tlg) {
                                          case SBUS_WR_START_OF_STREAM:
                                          case SBUS_WR_BLOCK_DATA_STREAM:
                                          case SBUS_WR_BLOCK_END_OF_STREAM:
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_rdwr_telegram_sequence, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                                 break;
                                          case SBUS_WR_ABORT_BLOCK_STREAM:
                                          case SBUS_RD_ABORT_BLOCK_STREAM:
                                          case SBUS_WR_BLOCK_DATA_BYTES:
                                          case SBUS_DELETE_BLOCK:
                                                 break;
                                          case SBUS_RD_BLOCK_START_OF_STREAM:
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_rdwr_telegram_sequence, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_rdwr_block_size, tvb, offset,
                                                                     4, ENC_BIG_ENDIAN);
                                                 offset += 4;
                                                 /*do not display a field for block data (skip)*/
                                                 offset += (sbus_rdwr_length-6);
                                                 break;
                                          case SBUS_RD_BLOCK_DATA_STREAM:
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_rdwr_telegram_sequence, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                                 /*do not display a field for block data (skip)*/
                                                 offset += (sbus_rdwr_length-2);
                                                 break;
                                          case SBUS_RD_BLOCK_DATA_BYTES:
                                                 /*do not display a field for block data (skip)*/
                                                 offset += (sbus_rdwr_length-1);
                                                 break;
                                          case SBUS_GET_BLOCK_SIZE:
                                                 sbus_rdwr_block_type = tvb_get_guint8(tvb, 10);
                                                 /* Check for unknown block type */
                                                 if (sbus_rdwr_block_type == SBUS_RD_WR_UNKNOWN_BLOCK_TYPE) {
                                                        /*unknown block, no more data follows*/
                                                 } else { /* add block size and CRC32 in case of known block*/
                                                        proto_tree_add_item(sbus_tree,
                                                                            hf_sbus_rdwr_block_size, tvb, offset,
                                                                            4, ENC_BIG_ENDIAN);
                                                        offset += 4;
                                                        /*Now the CRC32 follows, but I don't bother calculating it*/
                                                        offset += 4;
                                                 }
                                                 break;
                                          case SBUS_GET_PROGRAM_BLOCK_LIST:
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_block_type, tvb, offset,
                                                                     1, ENC_BIG_ENDIAN);
                                                 offset += 1;
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_block_nr, tvb, offset,
                                                                     2, ENC_BIG_ENDIAN);
                                                 offset += 2;
                                                 proto_tree_add_item(sbus_tree,
                                                                     hf_sbus_rdwr_block_size, tvb, offset,
                                                                     4, ENC_BIG_ENDIAN);
                                                 offset += 4;
                                                 /*do not display block_timestamp as no description is available*/
                                                 offset += (sbus_rdwr_length-8);
                                                 break;
                                          default:
                                                 break;
                                   }
                                   break;

                            /*Inform that response was not dissected and add remaining length*/
                            default:
                                   sbus_helper = sbus_eth_len - (offset + 2);
                                   proto_tree_add_text(sbus_tree, tvb, offset, sbus_helper,
                                                       "This telegram isn't implemented in the dissector.");
                                   offset = offset + sbus_helper;
                                   break;
                     }
              } else if (sbus_attribut == SBUS_RESPONSE && (!request_val)) {
                     /*calculate the offset in case the request telegram was not found or was broadcasted*/
                     sbus_eth_len = tvb_get_ntohl(tvb,0);
                     sbus_helper = sbus_eth_len - 11;
                     proto_tree_add_text(sbus_tree, tvb, offset, sbus_helper,
                            "Not dissected, could not find request telegram");
                     offset = sbus_eth_len - 2;
              }

              if (sbus_attribut == SBUS_ACKNAK) {
                     /*Add response time if possible*/
                     if (request_val) {
                           nstime_delta(&ns, &pinfo->fd->abs_ts, &request_val->req_time);
                           proto_tree_add_time(sbus_tree, hf_sbus_response_time,
                                               tvb, 0, 0, &ns);
                           /*add reference to request telegram*/
                           proto_tree_add_uint(sbus_tree, hf_sbus_response_to, tvb, 0, 0,
                                               request_val->req_frame);
                     }
                     hi = proto_tree_add_item(sbus_tree,
                         hf_sbus_acknackcode, tvb, offset, 2, ENC_BIG_ENDIAN);
                     if (tvb_get_guint8(tvb, (offset+1)) > 0) {
                            expert_add_info_format(pinfo, hi, PI_RESPONSE_CODE, PI_CHAT,
                                                   "Telegram not acknowledged by PCD");
                     }
                     offset += 2;
              }

              /* Calclulate CRC */
              sbus_crc_calc = 0;
              for (i = 0; i < sbus_eth_len - 2; i++)
                     sbus_crc_calc = crc_calc (sbus_crc_calc, tvb_get_guint8(tvb, i));
              /*Show CRC and add hidden item for wrong CRC*/
              sbus_helper = tvb_get_ntohs(tvb, offset);
              if (sbus_helper == sbus_crc_calc) {
                     proto_tree_add_uint_format(sbus_tree,
                                                hf_sbus_crc, tvb, offset, 2, sbus_helper,
                                                "Checksum: 0x%04x (correct)", sbus_helper);
              } else {
                     cs = proto_tree_add_uint_format(sbus_tree,
                                                     hf_sbus_crc, tvb, offset, 2, sbus_helper,
                                                     "Checksum: 0x%04x (NOT correct)", sbus_helper);
                     expert_add_info_format(pinfo, cs, PI_CHECKSUM, PI_ERROR,
                                            "Bad checksum");
                     hi = proto_tree_add_boolean(sbus_tree,
                                                 hf_sbus_crc_bad, tvb, offset, 2, TRUE);
                     PROTO_ITEM_SET_HIDDEN(hi);
                     PROTO_ITEM_SET_GENERATED(hi);
              }
              offset += 2; /*now at the end of the telegram*/
       }
       return tvb_length(tvb);
/*End of dissect_sbus*/
}

/* Register the protocol with Wireshark */

void
proto_register_sbus(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
       static hf_register_info hf[] = {
              { &hf_sbus_length,
                     { "Length (bytes)",           "sbus.len",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     "SAIA Ether-S-Bus telegram length", HFILL }
              },
              { &hf_sbus_version,
                     { "Version",           "sbus.vers",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "SAIA Ether-S-Bus version", HFILL }
              },
              { &hf_sbus_protocol,
                     { "Protocol type",           "sbus.proto",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "SAIA Ether-S-Bus protocol type", HFILL }
              },
              { &hf_sbus_sequence,
                     { "Sequence",           "sbus.seq",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     "SAIA Ether-S-Bus sequence number", HFILL }
              },

              { &hf_sbus_attribut,
                     { "Telegram attribute",           "sbus.att",
                     FT_UINT8, BASE_HEX, VALS(sbus_att_vals), 0,
                     "SAIA Ether-S-Bus telegram attribute, indicating type of telegram", HFILL }
              },

              { &hf_sbus_dest,
                     { "Destination",           "sbus.destination",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "SAIA S-Bus destination address", HFILL }
              },

              { &hf_sbus_address,
                     { "S-Bus address",           "sbus.address",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "SAIA S-Bus station address", HFILL }
              },

              { &hf_sbus_command,
                     { "Command",           "sbus.cmd",
                     FT_UINT8, BASE_HEX, VALS(sbus_command_vals), 0,
                     "SAIA S-Bus command", HFILL }
              },

              { &hf_sbus_command_extension,
                     { "Command extension",           "sbus.cmd_extn",
                     FT_UINT8, BASE_HEX, NULL, 0,
                     "SAIA S-Bus command extension", HFILL }
              },

              { &hf_sbus_rcount,
                     { "R-count",           "sbus.rcount",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "Number of elements expected in response", HFILL }
              },

              { &hf_sbus_wcount,
                     { "W-count (raw)",           "sbus.wcount",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "Number of bytes to be written", HFILL }
              },

              { &hf_sbus_wcount_calculated,
                     { "W-count (32 bit values)",           "sbus.wcount_calc",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "Number of elements to be written", HFILL }
              },

              { &hf_sbus_fio_count,
                     { "FIO Count (amount of bits)",           "sbus.fio_count",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "Number of binary elements to be written", HFILL }
              },

              { &hf_sbus_addr_rtc,
                     { "Base address RTC",           "sbus.addr_RTC",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     "Base address of 32 bit elements to read", HFILL }
              },

              { &hf_sbus_addr_iof,
                     { "Base address IOF",           "sbus.addr_IOF",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     "Base address of binary elements to read", HFILL }
              },

              { &hf_sbus_addr_eeprom,
                     { "Base address of EEPROM register",           "sbus.addr_EEPROM",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     "Base address of 32 bit EEPROM register to read or write", HFILL }
              },

              { &hf_sbus_addr_prog,
                     { "Base address of user memory or program lines",           "sbus.addr_prog",
                     FT_UINT24, BASE_DEC, NULL, 0,
                     "Base address of the user memory or program lines (read or write)", HFILL }
              },

              { &hf_sbus_addr_68k,
                     { "Base address of bytes",           "sbus.addr_68k",
                     FT_UINT24, BASE_HEX, NULL, 0,
                     "Base address of bytes to read or write (68k address)", HFILL }
              },

              { &hf_sbus_block_type,
                     { "Block type",           "sbus.block_type",
                     FT_UINT8, BASE_HEX, VALS(sbus_block_types), 0,
                     "Program block type", HFILL }
              },

              { &hf_sbus_block_nr,
                     { "Block/Element nr",           "sbus.block_nr",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     "Program block / DatatBlock number", HFILL }
              },

              { &hf_sbus_nbr_elements,
                     { "Number of elements",           "sbus.nbr_elements",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     "Number of elements or characters", HFILL }
              },

              { &hf_sbus_display_register,
                     { "PCD Display register",      "sbus.data_display_register",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     "The PCD display register (32 bit value)", HFILL }
              },

              { &hf_sbus_data_rtc,
                     { "S-Bus 32-bit data",      "sbus.data_rtc",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     "One regiser/timer of counter (32 bit value)", HFILL }
              },

              { &hf_sbus_data_byte,
                     { "Data bytes",      "sbus.data_byte",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "One byte from PCD", HFILL }
              },

              { &hf_sbus_data_byte_hex,
                     { "Data bytes (hex)",      "sbus.data_byte_hex",
                     FT_UINT8, BASE_HEX, NULL, 0,
                     "One byte from PCD (hexadecimal)", HFILL }
              },

              { &hf_sbus_data_iof,
                     { "S-Bus binary data",      "sbus.data_iof",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     "8 binaries", HFILL }
              },

              { &hf_sbus_cpu_type,
                     { "PCD type",      "sbus.pcd_type",
                     FT_STRING, BASE_NONE, NULL, 0,
                     "PCD type (short form)", HFILL }
              },

              { &hf_sbus_fw_version,
                     { "Firmware version",      "sbus.fw_version",
                     FT_STRING, BASE_NONE, NULL, 0,
                     "Firmware version of the PCD or module", HFILL }
              },

              { &hf_sbus_sysinfo_nr,
                     { "System information number",           "sbus.sysinfo",
                     FT_UINT8, BASE_HEX, NULL, 0,
                     "System information number (extension to command code)", HFILL }
              },

              { &hf_sbus_sysinfo0_1,
                     { "Mem size info",      "sbus.sysinfo0.mem",
                     FT_BOOLEAN, 8, TFS(&tfs_sbus_present), F_MEMSIZE,
                     "Availability of memory size information", HFILL }
              },
              { &hf_sbus_sysinfo0_2,
                     { "Trace buffer",      "sbus.sysinfo0.trace",
                     FT_BOOLEAN, 8, TFS(&tfs_sbus_present), F_TRACE,
                     "Availability of trace buffer feature", HFILL }
              },
              { &hf_sbus_sysinfo0_3,
                     { "Slot B1",      "sbus.sysinfo0.b1",
                     FT_BOOLEAN, 8, TFS(&tfs_sbus_present), F_INFO_B1,
                     "Presence of EEPROM information on slot B1", HFILL }
              },
              { &hf_sbus_sysinfo0_4,
                     { "Slot B2",      "sbus.sysinfo0.b2",
                     FT_BOOLEAN, 8, TFS(&tfs_sbus_present), F_INFO_B2,
                     "Presence of EEPROM information on slot B2", HFILL }
              },
              { &hf_sbus_sysinfo0_5,
                     { "PGU baud",      "sbus.sysinfo0.pgubaud",
                     FT_BOOLEAN, 8, TFS(&tfs_sbus_present), F_PGU_BAUD,
                     "Availability of PGU baud switch feature", HFILL }
              },

              { &hf_sbus_sysinfo_length,
                     { "System information length",           "sbus.sysinfo_length",
                     FT_UINT8, BASE_HEX, NULL, 0,
                     "System information length in response", HFILL }
              },

              { &hf_sbus_f_module_type,
                     { "F-module type",      "sbus.fmodule_type",
                     FT_STRING, BASE_NONE, NULL, 0,
                     "Module type mounted on B1/2 slot", HFILL }
              },

              { &hf_sbus_harware_version,
                     { "Hardware version",      "sbus.hw_version",
                     FT_STRING, BASE_NONE, NULL, 0,
                     "Hardware version of the PCD or the module", HFILL }
              },

              { &hf_sbus_hardware_modification,
                     { "Hardware modification",      "sbus.hw_modification",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "Hardware modification of the PCD or module", HFILL }
              },

              { &hf_sbus_various,
                     { "Various data",      "sbus.various",
                     FT_NONE, BASE_NONE, NULL, 0,
                     "Various data contained in telegrams but nobody will search for it", HFILL }
              },

              { &hf_sbus_acknackcode,
                     { "ACK/NAK code",      "sbus.nakcode",
                     FT_UINT16, BASE_HEX, VALS(sbus_ack_nak_vals), 0,
                     "SAIA S-Bus ACK/NAK response", HFILL }
              },

              { &hf_sbus_cpu_status,
                     { "CPU status",      "sbus.CPU_status",
                     FT_UINT8, BASE_HEX, VALS(sbus_CPU_status), 0,
                     "SAIA PCD CPU status", HFILL }
              },

              { &hf_sbus_week_day,
                     { "RTC calendar week and week day",           "sbus.rtc.week_day",
                     FT_UINT16, BASE_HEX, NULL, 0,
                     "Calendar week and week day number of the real time clock", HFILL }
              },

              { &hf_sbus_date,
                     { "RTC date (YYMMDD)",           "sbus.rtc.date",
                     FT_UINT24, BASE_HEX, NULL, 0,
                     "Year, month and day of the real time clock", HFILL }
              },

              { &hf_sbus_time,
                     { "RTC time (HHMMSS)",           "sbus.rtc.time",
                     FT_UINT24, BASE_HEX, NULL, 0,
                     "Time of the real time clock", HFILL }
              },

              { &hf_sbus_web_size,
                     { "Web server packet size",      "sbus.web.size",
                     FT_UINT8, BASE_HEX, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_sbus_web_aid,
                     { "AID",      "sbus.web.aid",
                     FT_UINT8, BASE_HEX, NULL, 0,
                     "Web server command/status code (AID)", HFILL }
              },

              { &hf_sbus_web_seq,
                     { "Sequence",      "sbus.web.seq",
                     FT_UINT8, BASE_HEX, NULL, 0,
                     "Web server sequence nr (PACK_N)", HFILL }
              },

              { &hf_sbus_rdwr_block_length,
                     { "Read/write block telegram length",      "sbus.block.length",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_sbus_rdwr_block_length_ext,
                     { "Extended length (bytes)",           "sbus.len_ext",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_sbus_rdwr_telegram_type,
                     { "Read/write block telegram type",      "sbus.block.tlgtype",
                     FT_UINT8, BASE_HEX, VALS(rdwrblock_vals), 0,
                     "Type of RD/WR block telegram", HFILL }
              },

              { &hf_sbus_rdwr_telegram_sequence,
                     { "Sequence",           "sbus.block.seq",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     "Sequence number of block data stream telegram", HFILL }
              },

              { &hf_sbus_rdwr_block_size,
                     { "Block size in bytes",      "sbus.block.size",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     "The size of the block in bytes", HFILL }
              },

              { &hf_sbus_rdwr_block_addr,
                     { "Address inside block",      "sbus.block.addr",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     "The address inside a block", HFILL }
              },


              { &hf_sbus_rdwr_file_name,
                     { "File name",      "sbus.block.filename",
                     FT_STRING, BASE_NONE, NULL, 0,
                     "Name of file to in RD/WR block telegram", HFILL }
              },

              { &hf_sbus_rdwr_list_type,
                     { "Get program block list, command type",      "sbus.block.getlisttype",
                     FT_UINT8, BASE_HEX, VALS(rdwrblock_list_type_vals), 0,
                     "Type of the Get Program Block list request", HFILL }
              },

              { &hf_sbus_rdwr_acknakcode,
                     { "ACK/NAK code",      "sbus.block.nakcode",
                     FT_UINT8, BASE_HEX, VALS(rdwrblock_sts), 0,
                     "ACK/NAK response for block write requests", HFILL }
              },

              { &hf_sbus_crc,
                     { "Checksum",      "sbus.crc",
                     FT_UINT16, BASE_HEX, NULL, 0,
                     "CRC 16", HFILL }
              },

              { &hf_sbus_crc_bad,
                     { "Bad Checksum",      "sbus.crc_bad",
                     FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                     "A bad checksum in the telegram", HFILL }},

              { &hf_sbus_retry,
                     { "Retry",      "sbus.retry", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                     "Repeated request telegram (due to wrong or missing answer)", HFILL }},

              { &hf_sbus_flags_accu,
                     { "ACCU", "sbus.flags.accu",
                     FT_BOOLEAN, 8, TFS(&tfs_sbus_flags), F_ACCU,
                     "PCD Accumulator", HFILL }
              },

              { &hf_sbus_flags_error,
                     { "Error flag", "sbus.flags.error",
                     FT_BOOLEAN, 8, TFS(&tfs_sbus_flags), F_ERROR,
                     "PCD error flag", HFILL }
              },

              { &hf_sbus_flags_negative,
                     { "N-flag", "sbus.flags.nflag",
                     FT_BOOLEAN, 8, TFS(&tfs_sbus_flags), F_NEGATIVE,
                     "Negative status flag", HFILL }
              },

              { &hf_sbus_flags_zero,
                     { "Z-flag", "sbus.flags.zflag",
                     FT_BOOLEAN, 8, TFS(&tfs_sbus_flags), F_ZERO,
                     "Zero status flag", HFILL }
              },

              { &hf_sbus_response_in,
                     { "Response in frame nr.", "sbus.response_in",
                     FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                     "The response to this Ether-S-Bus request is in this frame", HFILL }
              },

              { &hf_sbus_response_to,
                     { "Request in frame nr.", "sbus.response_to",
                     FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                     "This is a response to the Ether-S-Bus request in this frame", HFILL }
              },

              { &hf_sbus_response_time,
                     { "Response time", "sbus.response_time",
                     FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                     "The time between the request and the response", HFILL }
              },

              { &hf_sbus_timeout,
                     { "Time passed since first request", "sbus.timeout",
                     FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                     "The time between the first (identical) request and the repetition", HFILL }
              },

              { &hf_sbus_request_in,
                     { "First request in frame nr.", "sbus.request_in",
                     FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                     "The first request of this repeated request is in this frame", HFILL }
              }

       };

/* Setup protocol subtree array */
       static gint *ett[] = {
              &ett_sbus,
              &ett_sbus_ether,
              &ett_sbus_data
       };

/* Register the protocol name and description */
       proto_sbus = proto_register_protocol("SAIA S-Bus", "SBUS", "sbus");

/* Required function calls to register the header fields and subtrees used */
       proto_register_field_array(proto_sbus, hf, array_length(hf));
       proto_register_subtree_array(ett, array_length(ett));
       register_init_routine(&sbus_init_protocol);
}

void
proto_reg_handoff_sbus(void)
{
       dissector_handle_t sbus_handle;

       sbus_handle = new_create_dissector_handle(dissect_sbus, proto_sbus);
       dissector_add_uint("udp.port", 5050, sbus_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 7
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=7 tabstop=8 expandtab:
 * :indentSize=7:tabSize=8:noTabs=true:
 */
