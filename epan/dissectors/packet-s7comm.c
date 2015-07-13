/* packet-s7comm.c
 *
 * Author:      Thomas Wiens, 2014 (th.wiens@gmx.de)
 * Description: Wireshark dissector for S7-Communication
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

#include "packet-s7comm.h"
#include "packet-s7comm_szl_ids.h"

#define PROTO_TAG_S7COMM                    "S7COMM"

/* Min. telegram length for heuristic check */
#define S7COMM_MIN_TELEGRAM_LENGTH          10

/* Protocol identifier */
#define S7COMM_PROT_ID                      0x32

/* Wireshark ID of the S7COMM protocol */
static int proto_s7comm = -1;

/* Forward declarations */
void proto_reg_handoff_s7comm(void);
void proto_register_s7comm (void);

/**************************************************************************
 * Function call tree of the dissect process

dissect_s7comm()
    +
    +-------s7comm_decode_req_resp()
    +        +        +
    +     response  request
    +        +        +
    +        +        +------ s7comm_decode_param_item()
    +        +        +       s7comm_decode_response_read_data()
    +        +        +
    +        +        +------ s7comm_decode_pdu_setup_communication()
    +        +        +------ s7comm_decode_plc_controls_param_hex1x()
    +        +        +------ s7comm_decode_plc_controls_param_hex28()
    +        +        +------ s7comm_decode_plc_controls_param_hex29()
    +        +
    +        +------ s7comm_decode_response_read_data()
    +        +------ s7comm_decode_response_write_data()
    +        +------ s7comm_decode_pdu_setup_communication()
    +
    +
    +-------s7comm_decode_ud()
             +
             +------ s7comm_decode_ud_prog_subfunc()
             +                  +
             +                  +------- s7comm_decode_ud_prog_vartab_req_item()
             +                  +------- s7comm_decode_ud_prog_vartab_res_item()
             +                  +------- s7comm_decode_ud_prog_reqdiagdata()
             +
             +------ s7comm_decode_ud_cyclic_subfunc()
             +                  +
             +                  +------- s7comm_decode_param_item()
             +                  +------- s7comm_decode_response_read_data()
             +
             +------ s7comm_decode_ud_block_subfunc()
             +------ s7comm_decode_ud_szl_subfunc()
             +                  +
             +                  +------- s7comm_decode_szl_id_XXXX_idx_XXXX()
             +
             +------ s7comm_decode_ud_security_subfunc()
             +------ s7comm_decode_ud_time_subfunc()

 **************************************************************************/



/**************************************************************************
 * PDU types
 */
#define S7COMM_ROSCTR_JOB                   0x01
#define S7COMM_ROSCTR_ACK                   0x02
#define S7COMM_ROSCTR_ACK_DATA              0x03
#define S7COMM_ROSCTR_USERDATA              0x07

static const value_string rosctr_names[] = {
    { S7COMM_ROSCTR_JOB,                    "Job" },        /* Request: job with acknowledgement */
    { S7COMM_ROSCTR_ACK,                    "Ack" },        /* acknowledgement without additional field */
    { S7COMM_ROSCTR_ACK_DATA,               "Ack_Data" },   /* Response: acknowledgement with additional field */
    { S7COMM_ROSCTR_USERDATA,               "Userdata" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Error classes in header
 */
#define S7COMM_ERRCLS_NONE                  0x00
#define S7COMM_ERRCLS_APPREL                0x81
#define S7COMM_ERRCLS_OBJDEF                0x82
#define S7COMM_ERRCLS_RESSOURCE             0x83
#define S7COMM_ERRCLS_SERVICE               0x84
#define S7COMM_ERRCLS_SUPPLIES              0x85
#define S7COMM_ERRCLS_ACCESS                0x87

static const value_string errcls_names[] = {
    { S7COMM_ERRCLS_NONE,                   "No error" },
    { S7COMM_ERRCLS_APPREL,                 "Application relationship" },
    { S7COMM_ERRCLS_OBJDEF,                 "Object definition" },
    { S7COMM_ERRCLS_RESSOURCE,              "No ressources available" },
    { S7COMM_ERRCLS_SERVICE,                "Error on service processing" },
    { S7COMM_ERRCLS_SUPPLIES,               "Error on supplies" },
    { S7COMM_ERRCLS_ACCESS,                 "Access error" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Error code in parameter part
 */
#define S7COMM_PERRCOD_NO_ERROR                     0x0000
#define S7COMM_PERRCOD_INVALID_BLOCK_TYPE_NUM       0x0110
#define S7COMM_PERRCOD_INVALID_PARAM                0x0112
#define S7COMM_PERRCOD_PG_RESOURCE_ERROR            0x011A
#define S7COMM_PERRCOD_PLC_RESOURCE_ERROR           0x011B
#define S7COMM_PERRCOD_PROTOCOL_ERROR               0x011C
#define S7COMM_PERRCOD_USER_BUFFER_TOO_SHORT        0x011F
#define S7COMM_PERRCOD_REQ_INI_ERR                  0x0141
#define S7COMM_PERRCOD_VERSION_MISMATCH             0x01C0
#define S7COMM_PERRCOD_NOT_IMPLEMENTED              0x01F0
#define S7COMM_PERRCOD_L7_INVALID_CPU_STATE         0x8001
#define S7COMM_PERRCOD_L7_PDU_SIZE_ERR              0x8500
#define S7COMM_PERRCOD_L7_INVALID_SZL_ID            0xD401
#define S7COMM_PERRCOD_L7_INVALID_INDEX             0xD402
#define S7COMM_PERRCOD_L7_DGS_CONN_ALREADY_ANNOU    0xD403
#define S7COMM_PERRCOD_L7_MAX_USER_NB               0xD404
#define S7COMM_PERRCOD_L7_DGS_FKT_PAR_SYNTAX_ERR    0xD405
#define S7COMM_PERRCOD_L7_NO_INFO                   0xD406
#define S7COMM_PERRCOD_L7_PRT_FKT_PAR_SYNTAX_ERR    0xD601
#define S7COMM_PERRCOD_L7_INVALID_VAR_ADDR          0xD801
#define S7COMM_PERRCOD_L7_UNKNOWN_REQ               0xD802
#define S7COMM_PERRCOD_L7_INVALID_REQ_STATUS        0xD803

static const value_string param_errcode_names[] = {
    { S7COMM_PERRCOD_NO_ERROR,                      "No error" },
    { S7COMM_PERRCOD_INVALID_BLOCK_TYPE_NUM,        "Invalid block type number" },
    { S7COMM_PERRCOD_INVALID_PARAM,                 "Invalid parameter" },
    { S7COMM_PERRCOD_PG_RESOURCE_ERROR,             "PG ressource error" },
    { S7COMM_PERRCOD_PLC_RESOURCE_ERROR,            "PLC ressource error" },
    { S7COMM_PERRCOD_PROTOCOL_ERROR,                "Protocol error" },
    { S7COMM_PERRCOD_USER_BUFFER_TOO_SHORT,         "User buffer too short" },
    { S7COMM_PERRCOD_REQ_INI_ERR,                   "Request error" },
    { S7COMM_PERRCOD_VERSION_MISMATCH,              "Version mismatch" },
    { S7COMM_PERRCOD_NOT_IMPLEMENTED,               "Not implemented" },
    { S7COMM_PERRCOD_L7_INVALID_CPU_STATE,          "L7 invalid CPU state" },
    { S7COMM_PERRCOD_L7_PDU_SIZE_ERR,               "L7 PDU size error" },
    { S7COMM_PERRCOD_L7_INVALID_SZL_ID,             "L7 invalid SZL ID" },
    { S7COMM_PERRCOD_L7_INVALID_INDEX,              "L7 invalid index" },
    { S7COMM_PERRCOD_L7_DGS_CONN_ALREADY_ANNOU,     "L7 DGS Connection already announced" },
    { S7COMM_PERRCOD_L7_MAX_USER_NB,                "L7 Max user NB" },
    { S7COMM_PERRCOD_L7_DGS_FKT_PAR_SYNTAX_ERR,     "L7 DGS function parameter syntax error" },
    { S7COMM_PERRCOD_L7_NO_INFO,                    "L7 no info" },
    { S7COMM_PERRCOD_L7_PRT_FKT_PAR_SYNTAX_ERR,     "L7 PRT function parameter syntax error" },
    { S7COMM_PERRCOD_L7_INVALID_VAR_ADDR,           "L7 invalid variable address" },
    { S7COMM_PERRCOD_L7_UNKNOWN_REQ,                "L7 unknown request" },
    { S7COMM_PERRCOD_L7_INVALID_REQ_STATUS,         "L7 invalid request status" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Function codes in parameter part
 */
#define S7COMM_SERV_CPU                     0x00
#define S7COMM_SERV_SETUPCOMM               0xF0
#define S7COMM_SERV_READVAR                 0x04
#define S7COMM_SERV_WRITEVAR                0x05

#define S7COMM_FUNCREQUESTDOWNLOAD          0x1A
#define S7COMM_FUNCDOWNLOADBLOCK            0x1B
#define S7COMM_FUNCDOWNLOADENDED            0x1C
#define S7COMM_FUNCSTARTUPLOAD              0x1D
#define S7COMM_FUNCUPLOAD                   0x1E
#define S7COMM_FUNCENDUPLOAD                0x1F
#define S7COMM_FUNC_PLC_CONTROL             0x28
#define S7COMM_FUNC_PLC_STOP                0x29

static const value_string param_functionnames[] = {
    { S7COMM_SERV_CPU,                      "CPU services" },
    { S7COMM_SERV_SETUPCOMM,                "Setup communication" },
    { S7COMM_SERV_READVAR,                  "Read Var" },
    { S7COMM_SERV_WRITEVAR,                 "Write Var" },
    /* Block management services */
    { S7COMM_FUNCREQUESTDOWNLOAD,           "Request download" },
    { S7COMM_FUNCDOWNLOADBLOCK,             "Download block" },
    { S7COMM_FUNCDOWNLOADENDED,             "Download ended" },
    { S7COMM_FUNCSTARTUPLOAD,               "Start upload" },
    { S7COMM_FUNCUPLOAD,                    "Upload" },
    { S7COMM_FUNCENDUPLOAD,                 "End upload" },
    { S7COMM_FUNC_PLC_CONTROL,              "PLC Control" },
    { S7COMM_FUNC_PLC_STOP,                 "PLC Stop" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Area names
 */
#define S7COMM_AREA_SYSINFO                 0x03        /* System info of 200 family */
#define S7COMM_AREA_SYSFLAGS                0x05        /* System flags of 200 family */
#define S7COMM_AREA_ANAIN                   0x06        /* analog inputs of 200 family */
#define S7COMM_AREA_ANAOUT                  0x07        /* analog outputs of 200 family */
#define S7COMM_AREA_P                       0x80        /* direct peripheral access */
#define S7COMM_AREA_INPUTS                  0x81
#define S7COMM_AREA_OUTPUTS                 0x82
#define S7COMM_AREA_FLAGS                   0x83
#define S7COMM_AREA_DB                      0x84        /* data blocks */
#define S7COMM_AREA_DI                      0x85        /* instance data blocks */
#define S7COMM_AREA_LOCAL                   0x86        /* local data (should not be accessible over network) */
#define S7COMM_AREA_V                       0x87        /* previous (Vorgaenger) local data (should not be accessible over network)  */
#define S7COMM_AREA_COUNTER                 28          /* S7 counters */
#define S7COMM_AREA_TIMER                   29          /* S7 timers */
#define S7COMM_AREA_COUNTER200              30          /* IEC counters (200 family) */
#define S7COMM_AREA_TIMER200                31          /* IEC timers (200 family) */

static const value_string item_areanames[] = {
    { S7COMM_AREA_SYSINFO,                  "System info of 200 family" },
    { S7COMM_AREA_SYSFLAGS,                 "System flags of 200 family" },
    { S7COMM_AREA_ANAIN,                    "Analog inputs of 200 family" },
    { S7COMM_AREA_ANAOUT,                   "Analog outputs of 200 family" },
    { S7COMM_AREA_P,                        "Direct peripheral access (P)" },
    { S7COMM_AREA_INPUTS,                   "Inputs (I)" },
    { S7COMM_AREA_OUTPUTS,                  "Outputs (Q)" },
    { S7COMM_AREA_FLAGS,                    "Flags (M)" },
    { S7COMM_AREA_DB,                       "Data blocks (DB)" },
    { S7COMM_AREA_DI,                       "Instance data blocks (DI)" },
    { S7COMM_AREA_LOCAL,                    "Local data (L)" },
    { S7COMM_AREA_V,                        "Unknown yet (V)" },
    { S7COMM_AREA_COUNTER,                  "S7 counters (C)" },
    { S7COMM_AREA_TIMER,                    "S7 timers (T)" },
    { S7COMM_AREA_COUNTER200,               "IEC counters (200 family)" },
    { S7COMM_AREA_TIMER200,                 "IEC timers (200 family)" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Transport sizes in item data
 */
    /* types of 1 byte length */
#define S7COMM_TRANSPORT_SIZE_BIT           1
#define S7COMM_TRANSPORT_SIZE_BYTE          2
#define S7COMM_TRANSPORT_SIZE_CHAR          3
    /* types of 2 bytes length */
#define S7COMM_TRANSPORT_SIZE_WORD          4
#define S7COMM_TRANSPORT_SIZE_INT           5
    /* types of 4 bytes length */
#define S7COMM_TRANSPORT_SIZE_DWORD         6
#define S7COMM_TRANSPORT_SIZE_DINT          7
#define S7COMM_TRANSPORT_SIZE_REAL          8
    /* Special types */
#define S7COMM_TRANSPORT_SIZE_DATE          9
#define S7COMM_TRANSPORT_SIZE_TOD           10
#define S7COMM_TRANSPORT_SIZE_TIME          11
#define S7COMM_TRANSPORT_SIZE_S5TIME        12
#define S7COMM_TRANSPORT_SIZE_DT            15
    /* Timer or counter */
#define S7COMM_TRANSPORT_SIZE_COUNTER       28
#define S7COMM_TRANSPORT_SIZE_TIMER         29
#define S7COMM_TRANSPORT_SIZE_IEC_COUNTER   30
#define S7COMM_TRANSPORT_SIZE_IEC_TIMER     31
#define S7COMM_TRANSPORT_SIZE_HS_COUNTER    32
static const value_string item_transportsizenames[] = {
    { S7COMM_TRANSPORT_SIZE_BIT,            "BIT" },
    { S7COMM_TRANSPORT_SIZE_BYTE,           "BYTE" },
    { S7COMM_TRANSPORT_SIZE_CHAR,           "CHAR" },
    { S7COMM_TRANSPORT_SIZE_WORD,           "WORD" },
    { S7COMM_TRANSPORT_SIZE_INT,            "INT" },
    { S7COMM_TRANSPORT_SIZE_DWORD,          "DWORD" },
    { S7COMM_TRANSPORT_SIZE_DINT,           "DINT" },
    { S7COMM_TRANSPORT_SIZE_REAL,           "REAL" },
    { S7COMM_TRANSPORT_SIZE_TOD,            "TOD" },
    { S7COMM_TRANSPORT_SIZE_TIME,           "TIME" },
    { S7COMM_TRANSPORT_SIZE_S5TIME,         "S5TIME" },
    { S7COMM_TRANSPORT_SIZE_DT,             "DATE_AND_TIME" },
    { S7COMM_TRANSPORT_SIZE_COUNTER,        "COUNTER" },
    { S7COMM_TRANSPORT_SIZE_TIMER,          "TIMER" },
    { S7COMM_TRANSPORT_SIZE_IEC_COUNTER,    "IEC TIMER" },
    { S7COMM_TRANSPORT_SIZE_IEC_TIMER,      "IEC COUNTER" },
    { S7COMM_TRANSPORT_SIZE_HS_COUNTER,     "HS COUNTER" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Syntax Ids of variable specification
 */
#define S7COMM_SYNTAXID_S7ANY               0x10        /* Address data S7-Any pointer-like DB1.DBX10.2 */
#define S7COMM_SYNTAXID_PBC_ID              0x13        /* R_ID for PBC */
#define S7COMM_SYNTAXID_DRIVEESANY          0xa2        /* seen on Drive ES Starter with routing over S7 */
#define S7COMM_SYNTAXID_1200SYM             0xb2        /* Symbolic address mode of S7-1200 */
#define S7COMM_SYNTAXID_DBREAD              0xb0        /* Kind of DB block read, seen only at an S7-400 */
#define S7COMM_SYNTAXID_NCK                 0x82        /* Sinumerik NCK HMI access */

static const value_string item_syntaxid_names[] = {
    { S7COMM_SYNTAXID_S7ANY,                "S7ANY" },
    { S7COMM_SYNTAXID_PBC_ID,               "PBC-R_ID" },
    { S7COMM_SYNTAXID_DRIVEESANY,           "DRIVEESANY" },
    { S7COMM_SYNTAXID_1200SYM,              "1200SYM" },
    { S7COMM_SYNTAXID_DBREAD,               "DBREAD" },
    { S7COMM_SYNTAXID_NCK,                  "NCK" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Transport sizes in data
 */
#define S7COMM_DATA_TRANSPORT_SIZE_NULL     0
#define S7COMM_DATA_TRANSPORT_SIZE_BBIT     3           /* bit access, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BBYTE    4           /* byte/word/dword acces, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BINT     5           /* integer access, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BDINT    6           /* integer access, len is in bytes */
#define S7COMM_DATA_TRANSPORT_SIZE_BREAL    7           /* real access, len is in bytes */
#define S7COMM_DATA_TRANSPORT_SIZE_BSTR     9           /* octet string, len is in bytes */

static const value_string data_transportsizenames[] = {
    { S7COMM_DATA_TRANSPORT_SIZE_NULL,      "NULL" },
    { S7COMM_DATA_TRANSPORT_SIZE_BBIT,      "BIT" },
    { S7COMM_DATA_TRANSPORT_SIZE_BBYTE,     "BYTE/WORD/DWORD" },
    { S7COMM_DATA_TRANSPORT_SIZE_BINT,      "INTEGER" },
    { S7COMM_DATA_TRANSPORT_SIZE_BDINT,     "DINTEGER" },
    { S7COMM_DATA_TRANSPORT_SIZE_BREAL,     "REAL" },
    { S7COMM_DATA_TRANSPORT_SIZE_BSTR,      "OCTET STRING" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Returnvalues of an item response
 */

const value_string s7comm_item_return_valuenames[] = {
    { S7COMM_ITEM_RETVAL_RESERVED,              "Reserved" },
    { S7COMM_ITEM_RETVAL_DATA_HW_FAULT,         "Hardware error" },
    { S7COMM_ITEM_RETVAL_DATA_ACCESS_FAULT,     "Accessing the object not allowed" },
    { S7COMM_ITEM_RETVAL_DATA_OUTOFRANGE,       "Invalid address" },
    { S7COMM_ITEM_RETVAL_DATA_NOT_SUP,          "Data type not supported" },
    { S7COMM_ITEM_RETVAL_DATA_SIZEMISMATCH,     "Data type inconsistent" },
    { S7COMM_ITEM_RETVAL_DATA_ERR,              "Object does not exist" },
    { S7COMM_ITEM_RETVAL_DATA_OK,               "Success" },
    { 0,                                        NULL }
};
/**************************************************************************
 * Block Types
 */
#define S7COMM_BLOCKTYPE_OB                 '8'
#define S7COMM_BLOCKTYPE_DB                 'A'
#define S7COMM_BLOCKTYPE_SDB                'B'
#define S7COMM_BLOCKTYPE_FC                 'C'
#define S7COMM_BLOCKTYPE_SFC                'D'
#define S7COMM_BLOCKTYPE_FB                 'E'
#define S7COMM_BLOCKTYPE_SFB                'F'

static const value_string blocktype_names[] = {
    { S7COMM_BLOCKTYPE_OB,                  "OB" },
    { S7COMM_BLOCKTYPE_DB,                  "DB" },
    { S7COMM_BLOCKTYPE_SDB,                 "SDB" },
    { S7COMM_BLOCKTYPE_FC,                  "FC" },
    { S7COMM_BLOCKTYPE_SFC,                 "SFC" },
    { S7COMM_BLOCKTYPE_FB,                  "FB" },
    { S7COMM_BLOCKTYPE_SFB,                 "SFB" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Subblk types
 */
#define S7COMM_SUBBLKTYPE_OB                0x08
#define S7COMM_SUBBLKTYPE_DB                0x0a
#define S7COMM_SUBBLKTYPE_SDB               0x0b
#define S7COMM_SUBBLKTYPE_FC                0x0c
#define S7COMM_SUBBLKTYPE_SFC               0x0d
#define S7COMM_SUBBLKTYPE_FB                0x0e
#define S7COMM_SUBBLKTYPE_SFB               0x0f

static const value_string subblktype_names[] = {
    { S7COMM_SUBBLKTYPE_OB,                 "OB" },
    { S7COMM_SUBBLKTYPE_DB,                 "DB" },
    { S7COMM_SUBBLKTYPE_SDB,                "SDB" },
    { S7COMM_SUBBLKTYPE_FC,                 "FC" },
    { S7COMM_SUBBLKTYPE_SFC,                "SFC" },
    { S7COMM_SUBBLKTYPE_FB,                 "FB" },
    { S7COMM_SUBBLKTYPE_SFB,                "SFB" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Block security
 */
#define S7COMM_BLOCKSECURITY_OFF            0
#define S7COMM_BLOCKSECURITY_KNOWHOWPROTECT 3

static const value_string blocksecurity_names[] = {
    { S7COMM_BLOCKSECURITY_OFF,             "None" },
    { S7COMM_BLOCKSECURITY_KNOWHOWPROTECT,  "Kow How Protect" },
    { 0,                                    NULL }
};
/**************************************************************************
 * Block Languages
 */
static const value_string blocklanguage_names[] = {
    { 0x00,                                 "Not defined" },
    { 0x01,                                 "AWL" },
    { 0x02,                                 "KOP" },
    { 0x03,                                 "FUP" },
    { 0x04,                                 "SCL" },
    { 0x05,                                 "DB" },
    { 0x06,                                 "GRAPH" },
    { 0x07,                                 "SDB" },
    { 0x08,                                 "CPU-DB" },                     /* DB was created from Plc programm (CREAT_DB) */
    { 0x11,                                 "SDB (after overall reset)" },  /* another SDB, don't know what it means, in SDB 1 and SDB 2, uncertain*/
    { 0x12,                                 "SDB (Routing)" },              /* another SDB, in SDB 999 and SDB 1000 (routing information), uncertain */
    { 0x29,                                 "ENCRYPT" },                    /* block is encrypted with S7-Block-Privacy */
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of types in userdata parameter part
 */

static const value_string userdata_type_names[] = {
    { S7COMM_UD_TYPE_PUSH,                  "Push" },         /* this type occurs when 2 telegrams follow after another from the same partner, or initiated from PLC */
    { S7COMM_UD_TYPE_REQ,                   "Request" },
    { S7COMM_UD_TYPE_RES,                   "Response" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Userdata Parameter, last data unit
 */
#define S7COMM_UD_LASTDATAUNIT_YES          0x00
#define S7COMM_UD_LASTDATAUNIT_NO           0x01

static const value_string userdata_lastdataunit_names[] = {
    { S7COMM_UD_LASTDATAUNIT_YES,           "Yes" },
    { S7COMM_UD_LASTDATAUNIT_NO,            "No" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of Function groups in userdata parameter part
 */
#define S7COMM_UD_FUNCGROUP_PROG            0x1
#define S7COMM_UD_FUNCGROUP_CYCLIC          0x2
#define S7COMM_UD_FUNCGROUP_BLOCK           0x3
#define S7COMM_UD_FUNCGROUP_CPU             0x4
#define S7COMM_UD_FUNCGROUP_SEC             0x5                     /* Security funnctions e.g. plc password */
#define S7COMM_UD_FUNCGROUP_PBC             0x6                     /* PBC = Programmable Block Communication (PBK in german) */
#define S7COMM_UD_FUNCGROUP_TIME            0x7

static const value_string userdata_functiongroup_names[] = {
    { S7COMM_UD_FUNCGROUP_PROG,             "Programmer commands" },
    { S7COMM_UD_FUNCGROUP_CYCLIC,           "Cyclic data" },        /* to read data from plc without a request */
    { S7COMM_UD_FUNCGROUP_BLOCK,            "Block functions" },
    { S7COMM_UD_FUNCGROUP_CPU,              "CPU functions" },
    { S7COMM_UD_FUNCGROUP_SEC,              "Security" },
    { S7COMM_UD_FUNCGROUP_PBC,              "PBC BSEND/BRECV" },
    { S7COMM_UD_FUNCGROUP_TIME,             "Time functions" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Vartab: Typ of data in data part, first two bytes
 */
#define S7COMM_UD_SUBF_PROG_VARTAB_TYPE_REQ 0x14
#define S7COMM_UD_SUBF_PROG_VARTAB_TYPE_RES 0x04

static const value_string userdata_prog_vartab_type_names[] = {
    { S7COMM_UD_SUBF_PROG_VARTAB_TYPE_REQ,  "Request" },            /* Request of data areas */
    { S7COMM_UD_SUBF_PROG_VARTAB_TYPE_RES,  "Response" },           /* Response from plc with data */
    { 0,                                    NULL }
};

/**************************************************************************
 * Vartab: area of data request
 *
 * Low       Hi
 * 0=M       1=BYTE
 * 1=E       2=WORD
 * 2=A       3=DWORD
 * 3=PEx
 * 7=DB
 * 54=TIMER
 * 64=COUNTER
 */
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_MB      0x01
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_MW      0x02
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_MD      0x03
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_EB      0x11
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_EW      0x12
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_ED      0x13
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_AB      0x21
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_AW      0x22
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_AD      0x23
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEB     0x31
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEW     0x32
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_PED     0x33
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBB     0x71
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBW     0x72
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBD     0x73
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_T       0x54
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_C       0x64

static const value_string userdata_prog_vartab_area_names[] = {
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_MB,       "MB" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_MW,       "MW" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_MD,       "MD" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_EB,       "IB" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_EW,       "IW" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_ED,       "ID" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_AB,       "QB" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_AW,       "QW" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_AD,       "QD" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEB,      "PIB" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEW,      "PIW" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_PED,      "PID" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBB,      "DBB" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBW,      "DBW" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBD,      "DBD" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_T,        "TIMER" },
    { S7COMM_UD_SUBF_PROG_VARTAB_AREA_C,        "COUNTER" },
    { 0,                                        NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 1 (Programmer commands)
 */
#define S7COMM_UD_SUBF_PROG_REQDIAGDATA1    0x01
#define S7COMM_UD_SUBF_PROG_VARTAB1         0x02
#define S7COMM_UD_SUBF_PROG_ERASE           0x0c
#define S7COMM_UD_SUBF_PROG_READDIAGDATA    0x0e
#define S7COMM_UD_SUBF_PROG_REMOVEDIAGDATA  0x0f
#define S7COMM_UD_SUBF_PROG_FORCE           0x10
#define S7COMM_UD_SUBF_PROG_REQDIAGDATA2    0x13

static const value_string userdata_prog_subfunc_names[] = {
    { S7COMM_UD_SUBF_PROG_REQDIAGDATA1,     "Request diag data (Type 1)" },     /* Start online block view */
    { S7COMM_UD_SUBF_PROG_VARTAB1,          "VarTab" },                         /* Variable table */
    { S7COMM_UD_SUBF_PROG_READDIAGDATA,     "Read diag data" },                 /* online block view */
    { S7COMM_UD_SUBF_PROG_REMOVEDIAGDATA,   "Remove diag data" },               /* Stop online block view */
    { S7COMM_UD_SUBF_PROG_ERASE,            "Erase" },
    { S7COMM_UD_SUBF_PROG_FORCE,            "Forces" },
    { S7COMM_UD_SUBF_PROG_REQDIAGDATA2,     "Request diag data (Type2)" },      /* Start online block view */
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 2 (cyclic data)
 */
#define S7COMM_UD_SUBF_CYCLIC_MEM           0x01
#define S7COMM_UD_SUBF_CYCLIC_UNSUBSCRIBE   0x04

static const value_string userdata_cyclic_subfunc_names[] = {
    { S7COMM_UD_SUBF_CYCLIC_MEM,            "Memory" },                         /* read data from memory (DB/M/etc.) */
    { S7COMM_UD_SUBF_CYCLIC_UNSUBSCRIBE,    "Unsubscribe" },                    /* Unsubcribe (diable) cyclic data */
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 3 (Block functions)
 */
#define S7COMM_UD_SUBF_BLOCK_LIST           0x01
#define S7COMM_UD_SUBF_BLOCK_LISTTYPE       0x02
#define S7COMM_UD_SUBF_BLOCK_BLOCKINFO      0x03

static const value_string userdata_block_subfunc_names[] = {
    { S7COMM_UD_SUBF_BLOCK_LIST,            "List blocks" },
    { S7COMM_UD_SUBF_BLOCK_LISTTYPE,        "List blocks of type" },
    { S7COMM_UD_SUBF_BLOCK_BLOCKINFO,       "Get block info" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 4 (CPU functions)
 */

static const value_string userdata_cpu_subfunc_names[] = {
    { S7COMM_UD_SUBF_CPU_READSZL,           "Read SZL" },
    { S7COMM_UD_SUBF_CPU_MSGS,              "Message service" },                /* Header constant is also different here */
    { S7COMM_UD_SUBF_CPU_TRANSSTOP,         "Transition to STOP" },             /* PLC changed state to STOP */
    { S7COMM_UD_SUBF_CPU_ALARMIND,          "ALARM indication" },               /* PLC is indicating a ALARM message */
    { S7COMM_UD_SUBF_CPU_ALARMINIT,         "ALARM initiate" },                 /* HMI/SCADA initiating ALARM subscription */
    { S7COMM_UD_SUBF_CPU_ALARMACK1,         "ALARM ack 1" },                    /* Alarm was acknowledged in HMI/SCADA */
    { S7COMM_UD_SUBF_CPU_ALARMACK2,         "ALARM ack 2" },                    /* Alarm was acknowledged in HMI/SCADA */
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 5 (Security?)
 */
#define S7COMM_UD_SUBF_SEC_PASSWD           0x01

static const value_string userdata_sec_subfunc_names[] = {
    { S7COMM_UD_SUBF_SEC_PASSWD,            "PLC password" },
    { 0,                                    NULL }
};

/**************************************************************************
 * Names of userdata subfunctions in group 7 (Time functions)
 */
#define S7COMM_UD_SUBF_TIME_READ            0x01
#define S7COMM_UD_SUBF_TIME_SET             0x02
#define S7COMM_UD_SUBF_TIME_READF           0x03
#define S7COMM_UD_SUBF_TIME_SET2            0x04

static const value_string userdata_time_subfunc_names[] = {
    { S7COMM_UD_SUBF_TIME_READ,             "Read clock" },
    { S7COMM_UD_SUBF_TIME_SET,              "Set clock" },
    { S7COMM_UD_SUBF_TIME_READF,            "Read clock (following)" },
    { S7COMM_UD_SUBF_TIME_SET2,             "Set clock" },
    { 0,                                    NULL }
};

/*******************************************************************************************************
 * Weekday names in DATE_AND_TIME
 */
static const value_string weekdaynames[] = {
    { 0,                                    "Undefined" },
    { 1,                                    "Sunday" },
    { 2,                                    "Monday" },
    { 3,                                    "Tuesday" },
    { 4,                                    "Wednesday" },
    { 5,                                    "Thursday" },
    { 6,                                    "Friday" },
    { 7,                                    "Saturday" },
    { 0,                                    NULL }
};

/**************************************************************************
 **************************************************************************/

/**************************************************************************
 * Flags for LID access
 */
#define S7COMM_TIA1200_VAR_ENCAPS_LID       0x2
#define S7COMM_TIA1200_VAR_ENCAPS_IDX       0x3
#define S7COMM_TIA1200_VAR_OBTAIN_LID       0x4
#define S7COMM_TIA1200_VAR_OBTAIN_IDX       0x5
#define S7COMM_TIA1200_VAR_PART_START       0x6
#define S7COMM_TIA1200_VAR_PART_LEN         0x7

static const value_string tia1200_var_lid_flag_names[] = {
    { S7COMM_TIA1200_VAR_ENCAPS_LID,        "Encapsulated LID" },
    { S7COMM_TIA1200_VAR_ENCAPS_IDX,        "Encapsulated Index" },
    { S7COMM_TIA1200_VAR_OBTAIN_LID,        "Obtain by LID" },
    { S7COMM_TIA1200_VAR_OBTAIN_IDX,        "Obtain by Index" },
    { S7COMM_TIA1200_VAR_PART_START,        "Part Start Address" },
    { S7COMM_TIA1200_VAR_PART_LEN,          "Part Length" },
    { 0,                                    NULL }
};

/**************************************************************************
 * TIA 1200 Area Names for variable access
 */
#define S7COMM_TIA1200_VAR_ITEM_AREA1_DB    0x8a0e              /* Reading DB, 2 byte DB-Number following */
#define S7COMM_TIA1200_VAR_ITEM_AREA1_IQMCT 0x0000              /* Reading I/Q/M/C/T, 2 Byte detail area following */

static const value_string tia1200_var_item_area1_names[] = {
    { S7COMM_TIA1200_VAR_ITEM_AREA1_DB,     "DB" },
    { S7COMM_TIA1200_VAR_ITEM_AREA1_IQMCT,  "IQMCT" },
    { 0,                                    NULL }
};

#define S7COMM_TIA1200_VAR_ITEM_AREA2_I     0x50
#define S7COMM_TIA1200_VAR_ITEM_AREA2_Q     0x51
#define S7COMM_TIA1200_VAR_ITEM_AREA2_M     0x52
#define S7COMM_TIA1200_VAR_ITEM_AREA2_C     0x53
#define S7COMM_TIA1200_VAR_ITEM_AREA2_T     0x54

static const value_string tia1200_var_item_area2_names[] = {
    { S7COMM_TIA1200_VAR_ITEM_AREA2_I,      "Inputs (I)" },
    { S7COMM_TIA1200_VAR_ITEM_AREA2_Q,      "Outputs (Q)" },
    { S7COMM_TIA1200_VAR_ITEM_AREA2_M,      "Flags (M)" },
    { S7COMM_TIA1200_VAR_ITEM_AREA2_C,      "Counter (C)" },
    { S7COMM_TIA1200_VAR_ITEM_AREA2_T,      "Timer (T)" },
    { 0,                                    NULL }
};

/**************************************************************************
 * NCK areas
 */
#define S7COMM_NCK_AREA_N_NCK               0
#define S7COMM_NCK_AREA_B_MODEGROUP         1
#define S7COMM_NCK_AREA_C_CHANNEL           2
#define S7COMM_NCK_AREA_A_AXIS              3
#define S7COMM_NCK_AREA_T_TOOL              4
#define S7COMM_NCK_AREA_V_FEEDDRIVE         5
#define S7COMM_NCK_AREA_H_MAINDRIVE         6
#define S7COMM_NCK_AREA_M_MMC               7

static const value_string nck_area_names[] = {
    { S7COMM_NCK_AREA_N_NCK,                "N - NCK" },
    { S7COMM_NCK_AREA_B_MODEGROUP,          "B - Mode group" },
    { S7COMM_NCK_AREA_C_CHANNEL,            "C - Channel" },
    { S7COMM_NCK_AREA_A_AXIS,               "A - Axis" },
    { S7COMM_NCK_AREA_T_TOOL,               "T - Tool" },
    { S7COMM_NCK_AREA_V_FEEDDRIVE,          "V - Feed drive" },
    { S7COMM_NCK_AREA_H_MAINDRIVE,          "M - Main drive" },
    { S7COMM_NCK_AREA_M_MMC,                "M - MMC" },
    { 0,                                    NULL }
};

static const value_string nck_module_names[] = {
    { 0x10,                                 "Y - Global system data" },
    { 0x11,                                 "YNCFL - NCK instruction groups" },
    { 0x12,                                 "FU - NCU global settable frames" },
    { 0x13,                                 "FA - Active NCU global frames" },
    { 0x14,                                 "TO - Tool data" },
    { 0x15,                                 "RP - Arithmetic parameters" },
    { 0x16,                                 "SE - Setting data" },
    { 0x17,                                 "SGUD - SGUD-Block" },
    { 0x18,                                 "LUD - Local userdata" },
    { 0x19,                                 "TC - Toolholder parameters" },
    { 0x1a,                                 "M - Machine data" },
    { 0x1c,                                 "WAL - Working area limitation" },
    { 0x1e,                                 "DIAG - Internal diagnostic data" },
    { 0x1f,                                 "CC - Unknown" },
    { 0x20,                                 "FE - Channel-specific external frame" },
    { 0x21,                                 "TD - Tool data: General data" },
    { 0x22,                                 "TS - Tool edge data: Monitoring data" },
    { 0x23,                                 "TG - Tool data: Grinding-specific data" },
    { 0x24,                                 "TU - Tool data" },
    { 0x25,                                 "TUE - Tool edge data, userdefined data" },
    { 0x26,                                 "TV - Tool data, directory" },
    { 0x27,                                 "TM - Magazine data: General data" },
    { 0x28,                                 "TP - Magazine data: Location data" },
    { 0x29,                                 "TPM - Magazine data: Multiple assignment of location data" },
    { 0x2a,                                 "TT - Magazine data: Location typ" },
    { 0x2b,                                 "TMV - Magazine data: Directory" },
    { 0x2c,                                 "TMC - Magazine data: Configuration data" },
    { 0x2d,                                 "MGUD - MGUD-Block" },
    { 0x2e,                                 "UGUD - UGUD-Block" },
    { 0x2f,                                 "GUD4 - GUD4-Block" },
    { 0x30,                                 "GUD5 - GUD5-Block" },
    { 0x31,                                 "GUD6 - GUD6-Block" },
    { 0x32,                                 "GUD7 - GUD7-Block" },
    { 0x33,                                 "GUD8 - GUD8-Block" },
    { 0x34,                                 "GUD9 - GUD9-Block" },
    { 0x35,                                 "PA - Channel-specific protection zones" },
    { 0x36,                                 "GD1 - SGUD-Block GD1" },
    { 0x37,                                 "NIB - State data: Nibbling" },
    { 0x38,                                 "ETP - Types of events" },
    { 0x39,                                 "ETPD - Data lists for protocolling" },
    { 0x3a,                                 "SYNACT - Channel-specific synchronous actions" },
    { 0x3b,                                 "DIAGN - Diagnostic data" },
    { 0x3c,                                 "VSYN - Channel-specific user variables for synchronous actions" },
    { 0x3d,                                 "TUS - Tool data: user monitoring data" },
    { 0x3e,                                 "TUM - Tool data: user magazine data" },
    { 0x3f,                                 "TUP - Tool data: user magatine place data" },
    { 0x40,                                 "TF - Parametrizing, return parameters of _N_TMGETT, _N_TSEARC" },
    { 0x41,                                 "FB - Channel-specific base frames" },
    { 0x42,                                 "SSP2 - State data: Spindle" },
    { 0x43,                                 "PUD - programmglobale Benutzerdaten" },
    { 0x44,                                 "TOS - Edge-related location-dependent fine total offsets" },
    { 0x45,                                 "TOST - Edge-related location-dependent fine total offsets, transformed" },
    { 0x46,                                 "TOE - Edge-related coarse total offsets, setup offsets" },
    { 0x47,                                 "TOET - Edge-related coarse total offsets, transformed setup offsets" },
    { 0x48,                                 "AD - Adapter data" },
    { 0x49,                                 "TOT - Edge data: Transformed offset data" },
    { 0x4a,                                 "AEV - Working offsets: Directory" },
    { 0x4b,                                 "YFAFL - NCK instruction groups (Fanuc)" },
    { 0x4c,                                 "FS - System-Frame" },
    { 0x4d,                                 "SD - Servo data" },
    { 0x4e,                                 "TAD - Application-specific data" },
    { 0x4f,                                 "TAO - Aplication-specific cutting edge data" },
    { 0x50,                                 "TAS - Application-specific monitoring data" },
    { 0x51,                                 "TAM - Application-specific magazine data" },
    { 0x52,                                 "TAP - Application-specific magazine location data" },
    { 0x53,                                 "MEM - Unknown" },
    { 0x54,                                 "SALUC - Alarm actions: List in reverse chronological order" },
    { 0x55,                                 "AUXFU - Auxiliary functions" },
    { 0x56,                                 "TDC - Tool/Tools" },
    { 0x57,                                 "CP - Generic coupling" },
    { 0x6e,                                 "SDME - Unknown" },
    { 0x6f,                                 "SPARPI - Program pointer on interruption" },
    { 0x70,                                 "SEGA - State data: Geometry axes in tool offset memory (extended)" },
    { 0x71,                                 "SEMA - State data: Machine axes (extended)" },
    { 0x72,                                 "SSP - State data: Spindle" },
    { 0x73,                                 "SGA - State data: Geometry axes in tool offset memory" },
    { 0x74,                                 "SMA - State data: Machine axes" },
    { 0x75,                                 "SALAL - Alarms: List organized according to time" },
    { 0x76,                                 "SALAP - Alarms: List organized according to priority" },
    { 0x77,                                 "SALA - Alarms: List organized according to time" },
    { 0x78,                                 "SSYNAC - Synchronous actions" },
    { 0x79,                                 "SPARPF - Program pointers for block search and stop run" },
    { 0x7a,                                 "SPARPP - Program pointer in automatic operation" },
    { 0x7b,                                 "SNCF - Active G functions" },
    { 0x7d,                                 "SPARP - Part program information" },
    { 0x7e,                                 "SINF - Part-program-specific status data" },
    { 0x7f,                                 "S - State data" },
    { 0x80,                                 "0x80 - Unknown" },
    { 0x81,                                 "0x81 - Unknown" },
    { 0x82,                                 "0x82 - Unknown" },
    { 0x83,                                 "0x83 - Unknown" },
    { 0x84,                                 "0x84 - Unknown" },
    { 0x85,                                 "0x85 - Unknown" },
    { 0xfd,                                 "0 - Internal" },
    { 0,                                    NULL }
};
static value_string_ext nck_module_names_ext = VALUE_STRING_EXT_INIT(nck_module_names);

static gint hf_s7comm_tia1200_item_reserved1 = -1;          /* 1 Byte Reserved (always 0xff?) */
static gint hf_s7comm_tia1200_item_area1 = -1;              /* 2 Byte2 Root area (DB or IQMCT) */
static gint hf_s7comm_tia1200_item_area2 = -1;              /* 2 Bytes detail area (I/Q/M/C/T) */
static gint hf_s7comm_tia1200_item_area2unknown = -1;       /* 2 Bytes detail area for possible unknown or not seen areas */
static gint hf_s7comm_tia1200_item_dbnumber = -1;           /* 2 Bytes DB number */
static gint hf_s7comm_tia1200_item_crc = -1;                /* 4 Bytes CRC */

static gint hf_s7comm_tia1200_substructure_item = -1;       /* Substructure */
static gint hf_s7comm_tia1200_var_lid_flags = -1;           /* LID Flags */
static gint hf_s7comm_tia1200_item_value = -1;

/**************************************************************************
 **************************************************************************/

/* Header Block */
static gint hf_s7comm_header = -1;
static gint hf_s7comm_header_protid = -1;                   /* Header Byte  0 */
static gint hf_s7comm_header_rosctr = -1;                   /* Header Bytes 1 */
static gint hf_s7comm_header_redid = -1;                    /* Header Bytes 2, 3 */
static gint hf_s7comm_header_pduref = -1;                   /* Header Bytes 4, 5 */
static gint hf_s7comm_header_parlg = -1;                    /* Header Bytes 6, 7 */
static gint hf_s7comm_header_datlg = -1;                    /* Header Bytes 8, 9 */
static gint hf_s7comm_header_errcls = -1;                   /* Header Byte 10, only available at type 2 or 3 */
static gint hf_s7comm_header_errcod = -1;                   /* Header Byte 11, only available at type 2 or 3 */
/* Parameter Block */
static gint hf_s7comm_param = -1;
static gint hf_s7comm_param_errcod = -1;                    /* Parameter part: Error code */
static gint hf_s7comm_param_service = -1;                   /* Parameter part: service */
static gint hf_s7comm_param_itemcount = -1;                 /* Parameter part: item count */
static gint hf_s7comm_param_data = -1;                      /* Parameter part: data */
static gint hf_s7comm_param_neg_pdu_length = -1;            /* Parameter part: Negotiate PDU length */
static gint hf_s7comm_param_setup_reserved1 = -1;           /* Parameter part: Reserved byte in communication setup pdu*/

static gint hf_s7comm_param_maxamq_calling = -1;            /* Parameter part: Max AmQ calling */
static gint hf_s7comm_param_maxamq_called = -1;             /* Parameter part: Max AmQ called */

/* Item data */
static gint hf_s7comm_param_item = -1;
static gint hf_s7comm_param_subitem = -1;                   /* Substructure */
static gint hf_s7comm_item_varspec = -1;                    /* Variable specification */
static gint hf_s7comm_item_varspec_length = -1;             /* Length of following address specification */
static gint hf_s7comm_item_syntax_id = -1;                  /* Syntax Id */
static gint hf_s7comm_item_transport_size = -1;             /* Transport size, 1 Byte*/
static gint hf_s7comm_item_length = -1;                     /* length, 2 Bytes*/
static gint hf_s7comm_item_db = -1;                         /* DB/M/E/A, 2 Bytes */
static gint hf_s7comm_item_area = -1;                       /* Area code, 1 byte */
static gint hf_s7comm_item_address = -1;                    /* Bit address, 3 Bytes */
static gint hf_s7comm_item_address_byte = -1;               /* address: Byte address */
static gint hf_s7comm_item_address_bit = -1;                /* address: Bit address */
static gint hf_s7comm_item_address_nr = -1;                 /* address: Timer/Counter/block number */
/* Special variable read with Syntax-Id 0xb0 (DBREAD) */
static gint hf_s7comm_item_dbread_numareas = -1;            /* Number of areas following, 1 Byte*/
static gint hf_s7comm_item_dbread_length = -1;              /* length, 1 Byte*/
static gint hf_s7comm_item_dbread_db = -1;                  /* DB number, 2 Bytes*/
static gint hf_s7comm_item_dbread_startadr = -1;            /* Start address, 2 Bytes*/
/* NCK access with Syntax-Id 0x82 */
static gint hf_s7comm_item_nck_areaunit = -1;               /* Bitmask: aaauuuuu: a=area, u=unit */
static gint hf_s7comm_item_nck_area = -1;
static gint hf_s7comm_item_nck_unit = -1;
static gint hf_s7comm_item_nck_column = -1;
static gint hf_s7comm_item_nck_line = -1;
static gint hf_s7comm_item_nck_module = -1;
static gint hf_s7comm_item_nck_linecount = -1;

static gint hf_s7comm_data = -1;
static gint hf_s7comm_data_returncode = -1;                 /* return code, 1 byte */
static gint hf_s7comm_data_transport_size = -1;             /* transport size 1 byte */
static gint hf_s7comm_data_length = -1;                     /* Length of data, 2 Bytes */

static gint hf_s7comm_data_item = -1;

static gint hf_s7comm_readresponse_data = -1;
static gint hf_s7comm_data_fillbyte = -1;

/* timefunction: s7 timestamp */
static gint hf_s7comm_data_ts = -1;
static gint hf_s7comm_data_ts_reserved = -1;
static gint hf_s7comm_data_ts_year1 = -1;                   /* first byte of BCD coded year, should be ignored */
static gint hf_s7comm_data_ts_year2 = -1;                   /* second byte of BCD coded year, if 00...89 then it's 2000...2089, else 1990...1999*/
static gint hf_s7comm_data_ts_month = -1;
static gint hf_s7comm_data_ts_day = -1;
static gint hf_s7comm_data_ts_hour = -1;
static gint hf_s7comm_data_ts_minute = -1;
static gint hf_s7comm_data_ts_second = -1;
static gint hf_s7comm_data_ts_millisecond = -1;
static gint hf_s7comm_data_ts_weekday = -1;

/* userdata, block services */
static gint hf_s7comm_userdata_data = -1;

static gint hf_s7comm_userdata_param_head = -1;
static gint hf_s7comm_userdata_param_len = -1;
static gint hf_s7comm_userdata_param_reqres2 = -1;          /* unknown */
static gint hf_s7comm_userdata_param_type = -1;
static gint hf_s7comm_userdata_param_funcgroup = -1;
static gint hf_s7comm_userdata_param_subfunc_prog = -1;
static gint hf_s7comm_userdata_param_subfunc_cyclic = -1;
static gint hf_s7comm_userdata_param_subfunc_block = -1;
static gint hf_s7comm_userdata_param_subfunc_cpu = -1;
static gint hf_s7comm_userdata_param_subfunc_sec = -1;
static gint hf_s7comm_userdata_param_subfunc_time = -1;
static gint hf_s7comm_userdata_param_subfunc = -1;          /* for all other subfunctions */
static gint hf_s7comm_userdata_param_seq_num = -1;
static gint hf_s7comm_userdata_param_dataunitref = -1;
static gint hf_s7comm_userdata_param_dataunit = -1;

/* block functions, list blocks of type */
static gint hf_s7comm_ud_blockinfo_block_type = -1;         /* Block type, 1 byte, stringlist blocktype_names */
static gint hf_s7comm_ud_blockinfo_block_num = -1;          /* Block number, 2 bytes as int */
static gint hf_s7comm_ud_blockinfo_block_cnt = -1;          /* Count, 2 bytes as int */
static gint hf_s7comm_ud_blockinfo_block_flags = -1;        /* Block flags (unknown), 1 byte */
static gint hf_s7comm_ud_blockinfo_block_lang = -1;         /* Block language, 1 byte, stringlist blocklanguage_names */
/* block functions, get block infos */
static gint hf_s7comm_ud_blockinfo_block_num_ascii = -1;    /* Block number, 5 bytes, ASCII*/
static gint hf_s7comm_ud_blockinfo_filesys = -1;            /* Filesystem, 1 byte, ASCII*/
static gint hf_s7comm_ud_blockinfo_res_const1 = -1;         /* Constant 1, 1 byte, HEX*/
static gint hf_s7comm_ud_blockinfo_res_infolength = -1;     /* Length of Info, 2 bytes as int */
static gint hf_s7comm_ud_blockinfo_res_unknown2 = -1;       /* Unknown blockinfo 2, 2 bytes, HEX*/
static gint hf_s7comm_ud_blockinfo_res_const3 = -1;         /* Constant 3, 2 bytes, ASCII */
static gint hf_s7comm_ud_blockinfo_res_unknown = -1;        /* Unknown byte(s) */
static gint hf_s7comm_ud_blockinfo_subblk_type = -1;        /* Subblk type, 1 byte, stringlist subblktype_names */
static gint hf_s7comm_ud_blockinfo_load_mem_len = -1;       /* Length load memory, 4 bytes, int */
static gint hf_s7comm_ud_blockinfo_blocksecurity = -1;      /* Block Security, 4 bytes, stringlist blocksecurity_names*/
static gint hf_s7comm_ud_blockinfo_interface_timestamp = -1;/* Interface Timestamp, string */
static gint hf_s7comm_ud_blockinfo_code_timestamp = -1;     /* Code Timestamp, string */
static gint hf_s7comm_ud_blockinfo_ssb_len = -1;            /* SSB length, 2 bytes, int */
static gint hf_s7comm_ud_blockinfo_add_len = -1;            /* ADD length, 2 bytes, int */
static gint hf_s7comm_ud_blockinfo_localdata_len = -1;      /* Length localdata, 2 bytes, int */
static gint hf_s7comm_ud_blockinfo_mc7_len = -1;            /* Length MC7 code, 2 bytes, int */
static gint hf_s7comm_ud_blockinfo_author = -1;             /* Author, 8 bytes, ASCII */
static gint hf_s7comm_ud_blockinfo_family = -1;             /* Family, 8 bytes, ASCII */
static gint hf_s7comm_ud_blockinfo_headername = -1;         /* Name (Header), 8 bytes, ASCII */
static gint hf_s7comm_ud_blockinfo_headerversion = -1;      /* Version (Header), 8 bytes, ASCII */
static gint hf_s7comm_ud_blockinfo_checksum = -1;           /* Block checksum, 2 bytes, HEX */
static gint hf_s7comm_ud_blockinfo_reserved1 = -1;          /* Reserved 1, 4 bytes, HEX */
static gint hf_s7comm_ud_blockinfo_reserved2 = -1;          /* Reserved 2, 4 bytes, HEX */

static gint hf_s7comm_userdata_blockinfo_flags = -1;        /* Some flags in Block info response */
static gint hf_s7comm_userdata_blockinfo_linked = -1;       /* Some flags in Block info response */
static gint hf_s7comm_userdata_blockinfo_standard_block = -1;
static gint hf_s7comm_userdata_blockinfo_nonretain = -1;    /* Some flags in Block info response */
static gint ett_s7comm_userdata_blockinfo_flags = -1;
static const int *s7comm_userdata_blockinfo_flags_fields[] = {
    &hf_s7comm_userdata_blockinfo_linked,
    &hf_s7comm_userdata_blockinfo_standard_block,
    &hf_s7comm_userdata_blockinfo_nonretain,
    NULL
};

/* Programmer commands, diagnostic data */
static gint hf_s7comm_diagdata_req_askheadersize = -1;      /* Ask header size, 2 bytes as int */
static gint hf_s7comm_diagdata_req_asksize = -1;            /* Ask size, 2 bytes as int */
static gint hf_s7comm_diagdata_req_unknown = -1;            /* for all unknown bytes */
static gint hf_s7comm_diagdata_req_answersize = -1;         /* Answer size, 2 bytes as int */
static gint hf_s7comm_diagdata_req_block_type = -1;         /* Block type, 1 byte, stringlist subblktype_names */
static gint hf_s7comm_diagdata_req_block_num = -1;          /* Block number, 2 bytes as int */
static gint hf_s7comm_diagdata_req_startaddr_awl = -1;      /* Start address AWL, 2 bytes as int */
static gint hf_s7comm_diagdata_req_saz = -1;                /* Step address counter (SAZ), 2 bytes as int */
static gint hf_s7comm_diagdata_req_number_of_lines = -1;    /* Number of lines, 1 byte as int */
static gint hf_s7comm_diagdata_req_line_address = -1;       /* Address, 2 bytes as int */

/* Flags for requested registers in diagnostic data telegrams */
static gint hf_s7comm_diagdata_registerflag = -1;           /* Registerflags */
static gint hf_s7comm_diagdata_registerflag_stw = -1;       /* STW = Status word */
static gint hf_s7comm_diagdata_registerflag_accu1 = -1;     /* Accumulator 1 */
static gint hf_s7comm_diagdata_registerflag_accu2 = -1;     /* Accumulator 2 */
static gint hf_s7comm_diagdata_registerflag_ar1 = -1;       /* Addressregister 1 */
static gint hf_s7comm_diagdata_registerflag_ar2 = -1;       /* Addressregister 2 */
static gint hf_s7comm_diagdata_registerflag_db1 = -1;       /* Datablock register 1 */
static gint hf_s7comm_diagdata_registerflag_db2 = -1;       /* Datablock register 2 */
static gint ett_s7comm_diagdata_registerflag = -1;
static const int *s7comm_diagdata_registerflag_fields[] = {
    &hf_s7comm_diagdata_registerflag_stw,
    &hf_s7comm_diagdata_registerflag_accu1,
    &hf_s7comm_diagdata_registerflag_accu2,
    &hf_s7comm_diagdata_registerflag_ar1,
    &hf_s7comm_diagdata_registerflag_ar2,
    &hf_s7comm_diagdata_registerflag_db1,
    &hf_s7comm_diagdata_registerflag_db2,
    NULL
};

/* Function 0x28 (PLC control functions) */
static gint hf_s7comm_data_plccontrol_part1_unknown = -1;   /* Unknown bytes */
static gint hf_s7comm_data_plccontrol_part1_len = -1;       /* Length part 1 in bytes, 2 Bytes Int */
static gint hf_s7comm_data_plccontrol_argument = -1;        /* Argument, 2 Bytes as char */
static gint hf_s7comm_data_plccontrol_block_cnt = -1;       /* Number of blocks, 1 Byte as int */
static gint hf_s7comm_data_plccontrol_part1_unknown2 = -1;  /* Unknown 1 byte */
static gint hf_s7comm_data_plccontrol_block_unknown = -1;   /* Unknown 1 byte, as ASCII */
static gint hf_s7comm_data_plccontrol_block_type = -1;      /* Block type, 1 Byte, stringlist blocktype_names */
static gint hf_s7comm_data_plccontrol_block_num = -1;       /* Block number, 5 Bytes as ASCII */
static gint hf_s7comm_data_plccontrol_dest_filesys = -1;    /* Destination filesystem, 1 Byte as ASCII */
static gint hf_s7comm_data_plccontrol_part2_len = -1;       /* Length part 2 in bytes, 1 Byte as Int */
static gint hf_s7comm_data_plccontrol_pi_service = -1;      /* PI (program invocation) Service, String as ASCII */

/* block control functions */
static gint hf_s7comm_data_blockcontrol_unknown1 = -1;      /* for all unknown bytes in blockcontrol */
static gint hf_s7comm_data_blockcontrol_errorcode = -1;     /* Error code 2 bytes as int, 0 is no error */
static gint hf_s7comm_data_blockcontrol_part1_len = -1;     /* Length of part 1, 1 byte as int */
static gint hf_s7comm_data_blockcontrol_file_ident = -1;    /* File identifier, as ASCII */
static gint hf_s7comm_data_blockcontrol_block_unknown = -1; /* unknown prefix before block type, ASCII */
static gint hf_s7comm_data_blockcontrol_block_type = -1;    /* Block type, 1 Byte, stringlist blocktype_names */
static gint hf_s7comm_data_blockcontrol_block_num = -1;     /* Block number, 5 Bytes, als ASCII */
static gint hf_s7comm_data_blockcontrol_dest_filesys = -1;  /* Destination filesystem, 1 Byte, ASCII */
static gint hf_s7comm_data_blockcontrol_part2_len = -1;     /* Length part 2 in bytes, 1 Byte Int */
static gint hf_s7comm_data_blockcontrol_part2_unknown = -1; /* Unknown char, ASCII */
static gint hf_s7comm_data_blockcontrol_loadmem_len = -1;   /* Length load memory in bytes, ASCII */
static gint hf_s7comm_data_blockcontrol_mc7code_len = -1;   /* Length of MC7 code in bytes, ASCII */

/* Variable table */
static gint hf_s7comm_vartab_data_type = -1;                /* Type of data, 1 byte, stringlist userdata_prog_vartab_type_names */
static gint hf_s7comm_vartab_byte_count = -1;               /* Byte count, 2 bytes, int */
static gint hf_s7comm_vartab_unknown = -1;                  /* Unknown byte(s), hex */
static gint hf_s7comm_vartab_item_count = -1;               /* Item count, 2 bytes, int */
static gint hf_s7comm_vartab_req_memory_area = -1;          /* Memory area, 1 byte, stringlist userdata_prog_vartab_area_names  */
static gint hf_s7comm_vartab_req_repetition_factor = -1;    /* Repetition factor, 1 byte as int */
static gint hf_s7comm_vartab_req_db_number = -1;            /* DB number, 2 bytes as int */
static gint hf_s7comm_vartab_req_startaddress = -1;         /* Startaddress, 2 bytes as int */

/* cyclic data */
static gint hf_s7comm_cycl_interval_timebase = -1;          /* Interval timebase, 1 byte, int */
static gint hf_s7comm_cycl_interval_time = -1;              /* Interval time, 1 byte, int */

/* PBC, Programmable Block Functions */
static gint hf_s7comm_pbc_unknown = -1;                     /* unknown, 1 byte */
static gint hf_s7comm_pbc_r_id = -1;                        /* Request ID R_ID, 4 bytes as hex */

/* These are the ids of the subtrees that we are creating */
static gint ett_s7comm = -1;                                /* S7 communication tree, parent of all other subtree */
static gint ett_s7comm_header = -1;                         /* Subtree for header block */
static gint ett_s7comm_param = -1;                          /* Subtree for parameter block */
static gint ett_s7comm_param_item = -1;                     /* Subtree for items in parameter block */
static gint ett_s7comm_param_subitem = -1;                  /* Subtree for subitems under items in parameter block */
static gint ett_s7comm_data = -1;                           /* Subtree for data block */
static gint ett_s7comm_data_item = -1;                      /* Subtree for an item in data block */
static gint ett_s7comm_item_address = -1;                   /* Subtree for an address (byte/bit) */

static const char mon_names[][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/*******************************************************************************************************
 *
 * Converts a siemens special timestamp to a string of 25+1 bytes length (e.g. "Apr 15, 2009 12:49:30.520").
 * The timestamp is 6 bytes long, one word is the number of days since 1.1.1984, and 4 bytes millisecods of the day
 *
 *******************************************************************************************************/
static void
s7comm_get_timestring_from_s7time(tvbuff_t *tvb, guint offset, char *str, gint max)
{
    guint16 days;
    guint32 day_msec;
    struct tm *mt;
    time_t t;

    day_msec = tvb_get_ntohl(tvb, offset);
    days = tvb_get_ntohs(tvb, offset + 4);

    t = 441763200L;             /* 1.1.1984 00:00:00 */
    t += days * (24*60*60);
    t += day_msec / 1000;
    mt = gmtime(&t);
    str[0] = '\0';
    if (mt != NULL) {
        g_snprintf(str, max, "%s %2d, %d %02d:%02d:%02d.%03d", mon_names[mt->tm_mon], mt->tm_mday,
            mt->tm_year + 1900, mt->tm_hour, mt->tm_min, mt->tm_sec, day_msec % 1000);
    }
}

/*******************************************************************************************************
 *
 * Helper for time functions
 * Get int from bcd
 *
 *******************************************************************************************************/
static guint8
s7comm_guint8_from_bcd(guint8 i)
{
    return 10 * (i /16) + (i % 16);
}

/*******************************************************************************************************
 *
 * Helper for time functions
 * Add a BCD coded timestamp (10 Bytes length) to tree
 *
 *******************************************************************************************************/
static guint32
s7comm_add_timestamp_to_tree(tvbuff_t *tvb,
                             proto_tree *tree,
                             guint32 offset,
                             gboolean append_text)
{
    guint8 timestamp[10];
    guint8 i;
    guint8 tmp;
    guint8 year_org;
    guint16 msec;
    nstime_t tv;
    proto_item *item = NULL;
    proto_item *time_tree = NULL;
    struct tm mt;

    /* The low nibble of byte 10 is weekday, the high nibble the LSD of msec */
    for (i = 0;i < 9; i++) {
        timestamp[i] = s7comm_guint8_from_bcd(tvb_get_guint8(tvb, offset + i));
    }
    tmp = tvb_get_guint8(tvb, offset + 9) >> 4;
    timestamp[9] = s7comm_guint8_from_bcd(tmp);

    msec = (guint16)timestamp[8] * 10 + (guint16)timestamp[9];
    year_org = timestamp[1];
    /* year special: ignore the first byte, since some cpus give 1914 for 2014
     * if second byte is below 89, it's 2000..2089, if over 90 it's 1990..1999
     */
    if (timestamp[2] < 89) {
        timestamp[1] = 20;
    }
    /* convert time to nstime_t */
    mt.tm_year = (timestamp[1] * 100 + timestamp[2]) - 1900;
    mt.tm_mon = timestamp[3] - 1;
    mt.tm_mday = timestamp[4];
    mt.tm_hour = timestamp[5];
    mt.tm_min = timestamp[6];
    mt.tm_sec = timestamp[7];
    mt.tm_isdst = -1;
    tv.secs = mktime(&mt);
    tv.nsecs = msec * 1000000;
    item = proto_tree_add_time_format(tree, hf_s7comm_data_ts, tvb, offset, 10, &tv,
        "S7 Timestamp: %s %2d, %d %02d:%02d:%02d.%03d", mon_names[mt.tm_mon], mt.tm_mday,
        mt.tm_year + 1900, mt.tm_hour, mt.tm_min, mt.tm_sec,
        msec);
    time_tree = proto_item_add_subtree(item, ett_s7comm_data_item);

    /* timefunction: s7 timestamp */
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_reserved, tvb, offset, 1, timestamp[0]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_year1, tvb, offset, 1, year_org);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_year2, tvb, offset, 1, timestamp[2]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_month, tvb, offset, 1, timestamp[3]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_day, tvb, offset, 1, timestamp[4]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_hour, tvb, offset, 1, timestamp[5]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_minute, tvb, offset, 1, timestamp[6]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_second, tvb, offset, 1, timestamp[7]);
    offset += 1;
    proto_tree_add_uint(time_tree, hf_s7comm_data_ts_millisecond, tvb, offset, 2, msec);
    proto_tree_add_item(time_tree, hf_s7comm_data_ts_weekday, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (append_text == TRUE) {
        proto_item_append_text(tree, "(Timestamp: %s %2d, %d %02d:%02d:%02d.%03d)", mon_names[mt.tm_mon], mt.tm_mday,
            mt.tm_year + 1900, mt.tm_hour, mt.tm_min, mt.tm_sec,
            msec);
    }
    return offset;
}

/*******************************************************************************************************
 *
 * Generate a comma separated string for registerflags
 *
 *******************************************************************************************************/
static void
make_registerflag_string(gchar *str, guint8 flags, gint max)
{
    g_strlcpy(str, "", max);
    if (flags & 0x01) g_strlcat(str, "STW, ", max);
    if (flags & 0x02) g_strlcat(str, "ACCU1, ", max);
    if (flags & 0x04) g_strlcat(str, "ACCU2, ", max);
    if (flags & 0x08) g_strlcat(str, "AR1, ", max);
    if (flags & 0x10) g_strlcat(str, "AR2, ", max);
    if (flags & 0x20) g_strlcat(str, "DB1, ", max);
    if (flags & 0x40) g_strlcat(str, "DB2, ", max);
    if (strlen(str) > 2)
        str[strlen(str) - 2 ] = '\0';
}

/*******************************************************************************************************
 *
 * Dissect the parameter details of a read/write request (Items)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_param_item(tvbuff_t *tvb,
                          guint32 offset,
                          proto_tree *sub_tree,
                          guint8 item_no)
{
    guint32 a_address = 0;
    guint32 bytepos = 0;
    guint32 bitpos = 0;
    guint8 t_size = 0;
    guint16 len = 0;
    guint16 db = 0;
    guint16 i;
    guint8 area = 0;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;
    proto_tree *sub_item_tree = NULL;
    proto_item *address_item = NULL;
    proto_tree *address_item_tree = NULL;
    guint8 number_of_areas = 0;

    guint8 var_spec_type = 0;
    guint8 var_spec_length = 0;
    guint8 var_spec_syntax_id = 0;
    proto_item *sub_item = NULL;
    guint16 tia_var_area1 = 0;
    guint16 tia_var_area2 = 0;
    guint8 tia_lid_flags = 0;
    guint32 tia_value = 0;

    guint8 nck_area = 0;
    guint8 nck_unit = 0;
    guint16 nck_column = 0;
    guint16 nck_line = 0;
    guint8 nck_module = 0;

    /* At first check type and length of variable specification */
    var_spec_type = tvb_get_guint8(tvb, offset);
    var_spec_length = tvb_get_guint8(tvb, offset + 1);
    var_spec_syntax_id = tvb_get_guint8(tvb, offset + 2);

    /* Classic S7:  type = 0x12, len=10, syntax-id=0x10 for ANY-Pointer
     * TIA S7-1200: type = 0x12, len=14, syntax-id=0xb2 (symbolic addressing??)
     * Drive-ES Starter with routing: type = 0x12, len=10, syntax-id=0xa2 for ANY-Pointer
     */

    /* Insert a new tree for every item */
    item = proto_tree_add_item(sub_tree, hf_s7comm_param_item, tvb, offset, var_spec_length + 2, ENC_NA);
    item_tree = proto_item_add_subtree(item, ett_s7comm_param_item);

    proto_item_append_text(item, " [%d]:", item_no + 1);

    /* Item head, constant 3 bytes */
    proto_tree_add_item(item_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(item_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(item_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /****************************************************************************/
    /************************** Step 7 Classic 300 400 **************************/
    if (var_spec_type == 0x12 && var_spec_length == 10 && var_spec_syntax_id == S7COMM_SYNTAXID_S7ANY) {
        /* Transport size, 1 byte */
        t_size = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(item_tree, hf_s7comm_item_transport_size, tvb, offset, 1, t_size);
        offset += 1;
        /* Length, 2 bytes */
        len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(item_tree, hf_s7comm_item_length, tvb, offset, 2, len);
        offset += 2;
        /* DB number, 2 bytes */
        db = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(item_tree, hf_s7comm_item_db, tvb, offset, 2, db);
        offset += 2;
        /* Area, 1 byte */
        area = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(item_tree, hf_s7comm_item_area, tvb, offset, 1, area);
        offset += 1;
        /* Address, 3 bytes */
        a_address = tvb_get_ntoh24(tvb, offset);
        address_item = proto_tree_add_uint(item_tree, hf_s7comm_item_address, tvb, offset, 3, a_address);
        address_item_tree = proto_item_add_subtree(address_item, ett_s7comm_item_address);
        bytepos = a_address / 8;
        bitpos = a_address % 8;
        /* build a full address to show item data directly beside the item */
        switch (area) {
            case (S7COMM_AREA_P):
                proto_item_append_text(item_tree, " (P");
                break;
            case (S7COMM_AREA_INPUTS):
                proto_item_append_text(item_tree, " (I");
                break;
            case (S7COMM_AREA_OUTPUTS):
                proto_item_append_text(item_tree, " (Q");
                break;
            case (S7COMM_AREA_FLAGS):
                proto_item_append_text(item_tree, " (M");
                break;
            case (S7COMM_AREA_DB):
                proto_item_append_text(item_tree, " (DB%d.DBX", db);
                break;
            case (S7COMM_AREA_DI):
                proto_item_append_text(item_tree, " (DI%d.DIX", db);
                break;
            case (S7COMM_AREA_LOCAL):
                proto_item_append_text(item_tree, " (L");
                break;
            case (S7COMM_AREA_COUNTER):
                proto_item_append_text(item_tree, " (C");
                break;
            case (S7COMM_AREA_TIMER):
                proto_item_append_text(item_tree, " (T");
                break;
            default:
                proto_item_append_text(item_tree, " (unknown area");
                break;
        }
        if (area == S7COMM_AREA_TIMER || area == S7COMM_AREA_COUNTER) {
            proto_item_append_text(item_tree, " %d)", a_address);
            proto_tree_add_uint(address_item_tree, hf_s7comm_item_address_nr, tvb, offset, 3, a_address);
        } else {
            proto_tree_add_uint(address_item_tree, hf_s7comm_item_address_byte, tvb, offset, 3, a_address);
            proto_tree_add_uint(address_item_tree, hf_s7comm_item_address_bit, tvb, offset, 3, a_address);
            proto_item_append_text(item_tree, " %d.%d %s %d)",
                bytepos, bitpos, val_to_str(t_size, item_transportsizenames, "Unknown transport size: 0x%02x"), len);
        }
        offset += 3;
    /****************************************************************************/
    /******************** S7-400 special address mode (kind of cyclic read) *****/
    /* The response to this kind of request can't be decoded, because in the response
     * the data fields don't contain any header information. There is only one byte
     */
    } else if (var_spec_type == 0x12 && var_spec_length >= 7 && var_spec_syntax_id == S7COMM_SYNTAXID_DBREAD) {
        /* Number of data area specifications following, 1 Byte */
        number_of_areas = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(item_tree, hf_s7comm_item_dbread_numareas, tvb, offset, 1, number_of_areas);
        proto_item_append_text(item_tree, " (%d Data-Areas of Syntax-Id DBREAD)", number_of_areas);
        offset += 1;
        for (i = 1; i <= number_of_areas; i++) {
            sub_item = proto_tree_add_item(item_tree, hf_s7comm_param_subitem, tvb, offset, 5, ENC_NA);
            sub_item_tree = proto_item_add_subtree(sub_item, ett_s7comm_param_subitem);
            /* Number of Bytes to read, 1 Byte */
            len = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(sub_item_tree, hf_s7comm_item_dbread_length, tvb, offset, 1, len);
            offset += 1;
            /* DB number, 2 Bytes */
            db = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(sub_item_tree, hf_s7comm_item_dbread_db, tvb, offset, 2, db);
            offset += 2;
            /* Start address, 2 Bytes */
            bytepos = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(sub_item_tree, hf_s7comm_item_dbread_startadr, tvb, offset, 2, bytepos);
            offset += 2;
            /* Display as pseudo S7-Any Format */
            proto_item_append_text(sub_item, " [%d]: (DB%d.DBB %d BYTE %d)", i, db, bytepos, len);
        }
    /****************************************************************************/
    /******************** TIA S7 1200 symbolic address mode *********************/
    } else if (var_spec_type == 0x12 && var_spec_length >= 14 && var_spec_syntax_id == S7COMM_SYNTAXID_1200SYM) {
        proto_item_append_text(item_tree, " 1200 symbolic address");
        /* first byte in address seems always be 0xff */
        proto_tree_add_item(item_tree, hf_s7comm_tia1200_item_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* When Bytes 2/3 == 0, then Bytes 4/5 defines the area as known from classic 300/400 address mode
         * when Bytes 2/3 == 0x8a0e then bytes 4/5 are containing the DB number
         */
        tia_var_area1 = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(item_tree, hf_s7comm_tia1200_item_area1, tvb, offset, 2, tia_var_area1);
        offset += 2;
        tia_var_area2 = tvb_get_ntohs(tvb, offset);
        if (tia_var_area1 == S7COMM_TIA1200_VAR_ITEM_AREA1_IQMCT) {
            proto_tree_add_uint(item_tree, hf_s7comm_tia1200_item_area2, tvb, offset, 2, tia_var_area2);
            proto_item_append_text(item_tree, " - Accessing %s", val_to_str(tia_var_area2, tia1200_var_item_area2_names, "Unknown IQMCT Area: 0x%04x"));
            offset += 2;
        } else if (tia_var_area1 == S7COMM_TIA1200_VAR_ITEM_AREA1_DB) {
            proto_tree_add_uint(item_tree, hf_s7comm_tia1200_item_dbnumber, tvb, offset, 2, tia_var_area2);
            proto_item_append_text(item_tree, " - Accessing DB%d", tia_var_area2);
            offset += 2;
        } else {
            /* for current unknown areas, I don't know if there are other valid areas */
            proto_tree_add_uint(item_tree, hf_s7comm_tia1200_item_area2unknown, tvb, offset, 2, tia_var_area2);
            proto_item_append_text(item_tree, " - Unknown area specification");
            offset += 2;
        }
        proto_tree_add_item(item_tree, hf_s7comm_tia1200_item_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        for (i = 0; i < (var_spec_length - 10) / 4; i++) {
            /* Insert a new tree for every sub-struct */
            sub_item = proto_tree_add_item(item_tree, hf_s7comm_tia1200_substructure_item, tvb, offset, 4, ENC_NA);
            sub_item_tree = proto_item_add_subtree(sub_item, ett_s7comm_param_subitem);
            tia_lid_flags = tvb_get_guint8(tvb, offset) >> 4;
            proto_tree_add_item(sub_item_tree, hf_s7comm_tia1200_var_lid_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
            tia_value = tvb_get_ntohl(tvb, offset) & 0x0fffffff;
            proto_item_append_text(sub_item, " [%d]: %s, Value: %u", i + 1,
                val_to_str(tia_lid_flags, tia1200_var_lid_flag_names, "Unknown flags: 0x%02x"),
                tia_value
            );
            proto_tree_add_item(sub_item_tree, hf_s7comm_tia1200_item_value, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
    /****************************************************************************/
    /******************** Sinumerik NCK access **********************************/
    } else if (var_spec_type == 0x12 && var_spec_length == 8 && var_spec_syntax_id == S7COMM_SYNTAXID_NCK) {
        area = tvb_get_guint8(tvb, offset);
        nck_area = area >> 5;
        nck_unit = area & 0x1f;
        proto_tree_add_item(item_tree, hf_s7comm_item_nck_areaunit, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(item_tree, hf_s7comm_item_nck_area, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(item_tree, hf_s7comm_item_nck_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        nck_column = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(item_tree, hf_s7comm_item_nck_column, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        nck_line = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(item_tree, hf_s7comm_item_nck_line, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        nck_module = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(item_tree, hf_s7comm_item_nck_module, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(item_tree, hf_s7comm_item_nck_linecount, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_item_append_text(item_tree, " (NCK Area:%d Unit:%d Column:%d Line:%d Module:0x%02x)",
            nck_area, nck_unit, nck_column, nck_line, nck_module);
    }
    else {
        /* var spec, length and syntax id are still added to tree here */
        offset += var_spec_length - 1;
        proto_item_append_text(item_tree, " Unknown variable specification");
    }
    return offset;
}

/*******************************************************************************************************
 *
 * Decode parameter part of a PDU for setup communication
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_pdu_setup_communication(tvbuff_t *tvb,
                                     proto_tree *tree,
                                     guint32 offset)
{
    proto_tree_add_item(tree, hf_s7comm_param_setup_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_param_maxamq_calling, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_param_maxamq_called, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_s7comm_param_neg_pdu_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Response -> Function Write  -> Data part
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_response_write_data(tvbuff_t *tvb,
                                 proto_tree *tree,
                                 guint8 item_count,
                                 guint32 offset)
{
    guint8 ret_val = 0;
    guint8 i = 0;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;

    for (i = 1; i <= item_count; i++) {
        ret_val = tvb_get_guint8(tvb, offset);
        /* Insert a new tree for every item */
        item = proto_tree_add_item(tree, hf_s7comm_data_item, tvb, offset, 1, ENC_NA);
        item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
        proto_item_append_text(item, " [%d]: (%s)", i, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));
        proto_tree_add_uint(item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
        offset += 1;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Response -> Function Read  -> Data part
 *           Request  -> Function Write -> Data part
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_response_read_data(tvbuff_t *tvb,
                                 proto_tree *tree,
                                 guint8 item_count,
                                 guint32 offset)
{
    guint8 ret_val = 0;
    guint8 tsize = 0;
    guint16 len = 0, len2 = 0;
    guint16 head_len = 4;           /* 1 byte res-code, 1 byte transp-size, 2 bytes len */
    guint8 i = 0;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;

    for (i = 1; i <= item_count; i++) {
        ret_val = tvb_get_guint8(tvb, offset);
        if (ret_val == S7COMM_ITEM_RETVAL_RESERVED ||
            ret_val == S7COMM_ITEM_RETVAL_DATA_OK ||
            ret_val == S7COMM_ITEM_RETVAL_DATA_ERR
            ) {
            tsize = tvb_get_guint8(tvb, offset + 1);
            len = tvb_get_ntohs(tvb, offset + 2);
            /* calculate length in bytes */
            if (tsize == S7COMM_DATA_TRANSPORT_SIZE_BBIT ||
                tsize == S7COMM_DATA_TRANSPORT_SIZE_BBYTE ||
                tsize == S7COMM_DATA_TRANSPORT_SIZE_BINT
                ) {     /* given length is in number of bits */
                if (len % 8) { /* len is not a multiple of 8, then round up to next number */
                    len /= 8;
                    len = len + 1;
                } else {
                    len /= 8;
                }
            }

            /* the PLC places extra bytes at the end of all but last result, if length is not a multiple of 2 */
            if ((len % 2) && (i < item_count)) {
                len2 = len + 1;
            } else {
                len2 = len;
            }
        }
        /* Insert a new tree for every item */
        item = proto_tree_add_item(tree, hf_s7comm_data_item, tvb, offset, len + head_len, ENC_NA);
        item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
        proto_item_append_text(item, " [%d]: (%s)", i, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));

        proto_tree_add_uint(item_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
        proto_tree_add_uint(item_tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);
        proto_tree_add_uint(item_tree, hf_s7comm_data_length, tvb, offset + 2, 2, len);
        offset += head_len;

        if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK || ret_val == S7COMM_ITEM_RETVAL_RESERVED) {
            proto_tree_add_item(item_tree, hf_s7comm_readresponse_data, tvb, offset, len, ENC_NA);
            offset += len;
            if (len != len2) {
                proto_tree_add_item(item_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
        }
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response -> Function 0x28 (PLC control functions)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_plc_controls_param_hex28(tvbuff_t *tvb,
                      packet_info *pinfo,
                      proto_tree *tree,
                      guint32 offset)
{
    guint16 len;
    guint8 count;
    guint8 i;
    guint8 *str;

    /* The first byte 0x28 is checked and inserted to tree outside, so skip it here */
    offset += 1;

    /* First part is unknown, 7 bytes */
    proto_tree_add_item(tree, hf_s7comm_data_plccontrol_part1_unknown, tvb, offset, 7, ENC_NA);
    offset += 7;
    /* Part 1 */
    len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_s7comm_data_plccontrol_part1_len, tvb, offset, 2, len);
    offset += 2;
    /* no block function, cold start e.g. */
    if (len == 2) {
        /* C = cold start */
        proto_tree_add_item(tree, hf_s7comm_data_plccontrol_argument, tvb, offset, 2, ENC_ASCII|ENC_NA);
        offset +=2;
    } else if (len > 2) {
        count = tvb_get_guint8(tvb, offset);            /* number of blocks following */
        proto_tree_add_uint(tree, hf_s7comm_data_plccontrol_block_cnt, tvb, offset, 1, count);
        offset += 1;
        /* Next byte reserved? is 0x00 */
        proto_tree_add_item(tree, hf_s7comm_data_plccontrol_part1_unknown2, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        for (i = 0; i < count; i++) {
            /* First byte of block type seems to be every time '0' as single char*/
            proto_tree_add_item(tree, hf_s7comm_data_plccontrol_block_unknown, tvb, offset, 1, ENC_ASCII|ENC_NA);
            offset +=1;
            proto_tree_add_item(tree, hf_s7comm_data_plccontrol_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Type:[%s]", val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type: 0x%02x"));
            offset += 1;
            proto_tree_add_item(tree, hf_s7comm_data_plccontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA);
            str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 5, ENC_ASCII);
            col_append_fstr(pinfo->cinfo, COL_INFO, " No.:[%s]", str);
            offset += 5;
            /* 'P', 'B' or 'A' is following
             Destination filesystem?
                P = passive filesystem
                A = active filesystem?
             */
            proto_tree_add_item(tree, hf_s7comm_data_plccontrol_dest_filesys, tvb, offset, 1, ENC_ASCII|ENC_NA);
            offset += 1;
        }
    }
    /* Part 2 */
    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_s7comm_data_plccontrol_part2_len, tvb, offset, 1, len);
    offset += 1;
    /* Function (PI_SERVICE) as string  (program invocation)
     *    Known functions:
     *   _INSE = Activate a module
     *   _DELE = Delete a passive module
     *   _PROGRAM = Start/Stop the PLC
     *   _PLC_MEMORYRESET = Reset the PLC memory
     */
    proto_tree_add_item(tree, hf_s7comm_data_plccontrol_pi_service, tvb, offset, len, ENC_ASCII|ENC_NA);
    offset += len;

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response -> Function 0x29 (PLC control functions -> STOP)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_plc_controls_param_hex29(tvbuff_t *tvb,
                      proto_tree *tree,
                      guint32 offset)
{
    guint8 len;

    /* The first byte 0x29 is checked and inserted to tree outside, so skip it here */
    offset += 1;
    /* Meaning of first 5 bytes (Part 1) is unknown */
    proto_tree_add_item(tree, hf_s7comm_data_plccontrol_part1_unknown, tvb, offset, 5, ENC_NA);
    offset += 5;
    /* Part 2 */
    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_s7comm_data_plccontrol_part2_len, tvb, offset, 1, len);
    offset += 1;
    /* Function as string */
    proto_tree_add_item(tree, hf_s7comm_data_plccontrol_pi_service, tvb, offset, len, ENC_ASCII|ENC_NA);
    offset += len;

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response -> Function 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f (block control functions)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_plc_controls_param_hex1x(tvbuff_t *tvb,
                      packet_info *pinfo,
                      proto_tree *tree,
                      guint16 plength,
                      guint32 offset)
{
    guint8 len;
    guint8 function;
    guint8 *str;

    function = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* Meaning of first byte is unknown */
    proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 1, ENC_NA);
    offset += 1;
    /* These 2 bytes seems to be an error code. If an upload fails, this value is also shown in Manager as errorcode. Zero on success. */
    proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_errorcode, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* unknown 4 bytes */
    proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_unknown1, tvb, offset, 4, ENC_NA);
    offset += 4;
    if (plength <= 8) {
        /* Upload or End upload functions have no other data */
        return offset;
    }

    /* Part 1: Block information*/
    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_s7comm_data_blockcontrol_part1_len, tvb, offset, 1, len);
    offset += 1;
    /* Prefix
     *   File identifier:
     *   _ means: "complete module"
     *   $ means: "Module header for up-loading"
     */
    proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_file_ident, tvb, offset, 1, ENC_ASCII|ENC_NA);
    offset += 1;
    /* First byte of block type is every time '0' */
    proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_block_unknown, tvb, offset, 1, ENC_ASCII|ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Type:[%s]", val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type: 0x%02x"));
    offset += 1;

    str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 5, ENC_ASCII);
    proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_block_num, tvb, offset, 5, ENC_ASCII|ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, " No.:[%s]", str);
    offset += 5;
    /* 'P', 'B' or 'A' is following */
    proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_dest_filesys, tvb, offset, 1, ENC_ASCII|ENC_NA);
    offset += 1;

    /* Part 2, only available in "request download" */
    if (function == S7COMM_FUNCREQUESTDOWNLOAD && plength > 18) {
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_s7comm_data_blockcontrol_part2_len, tvb, offset, 1, len);
        offset += 1;
        /* first byte unknown '1' */
        proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_part2_unknown, tvb, offset, 1, ENC_ASCII|ENC_NA);
        offset += 1;
        proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_loadmem_len, tvb, offset, 6, ENC_ASCII|ENC_NA);
        offset += 6;
        proto_tree_add_item(tree, hf_s7comm_data_blockcontrol_mc7code_len, tvb, offset, 6, ENC_ASCII|ENC_NA);
        offset += 6;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Request diagnostic data (0x13 or 0x01)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_prog_reqdiagdata(tvbuff_t *tvb,
                                    proto_tree *data_tree,
                                    guint8 subfunc,             /* Subfunction */
                                    guint32 offset)             /* Offset on data part +4 */
{
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;
    guint16 line_nr;
    guint16 line_cnt;
    guint16 ask_size;
    guint16 item_size = 4;
    guint8 registerflags;
    gchar str_flags[80];

    proto_tree_add_item(data_tree, hf_s7comm_diagdata_req_askheadersize, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    ask_size = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(data_tree, hf_s7comm_diagdata_req_asksize, tvb, offset, 2, ask_size);
    offset += 2;
    proto_tree_add_item(data_tree, hf_s7comm_diagdata_req_unknown, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(data_tree, hf_s7comm_diagdata_req_answersize, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(data_tree, hf_s7comm_diagdata_req_unknown, tvb, offset, 13, ENC_NA);
    offset += 13;
    proto_tree_add_item(data_tree, hf_s7comm_diagdata_req_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_s7comm_diagdata_req_block_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(data_tree, hf_s7comm_diagdata_req_startaddr_awl, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(data_tree, hf_s7comm_diagdata_req_saz, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(data_tree, hf_s7comm_diagdata_req_unknown, tvb, offset, 1, ENC_NA);
    offset += 1;
    if (subfunc == 0x13) {
        line_cnt = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(data_tree, hf_s7comm_diagdata_req_number_of_lines, tvb, offset, 2, line_cnt);
        offset += 1;
        proto_tree_add_item(data_tree, hf_s7comm_diagdata_req_unknown, tvb, offset, 1, ENC_NA);
        offset += 1;
    } else {
        line_cnt = (ask_size - 2) / 2;
    }
    proto_tree_add_bitmask(data_tree, tvb, offset, hf_s7comm_diagdata_registerflag,
        ett_s7comm_diagdata_registerflag, s7comm_diagdata_registerflag_fields, ENC_BIG_ENDIAN);
    offset += 1;

    if (subfunc == 0x13) {
        item_size = 4;
    } else {
        item_size = 2;
    }
    for (line_nr = 0; line_nr < line_cnt; line_nr++) {

        item = proto_tree_add_item(data_tree, hf_s7comm_data_item, tvb, offset, item_size, ENC_NA);
        item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
        if (subfunc == 0x13) {
            proto_tree_add_item(item_tree, hf_s7comm_diagdata_req_line_address, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        proto_tree_add_item(item_tree, hf_s7comm_diagdata_req_unknown, tvb, offset, 1, ENC_NA);
        offset += 1;

        registerflags = tvb_get_guint8(tvb, offset);
        make_registerflag_string(str_flags, registerflags, sizeof(str_flags));
        proto_item_append_text(item, " [%d]: (%s)", line_nr+1, str_flags);
        proto_tree_add_bitmask(item_tree, tvb, offset, hf_s7comm_diagdata_registerflag,
            ett_s7comm_diagdata_registerflag, s7comm_diagdata_registerflag_fields, ENC_BIG_ENDIAN);
        offset += 1;
    }

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Variable table -> request
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_prog_vartab_req_item(tvbuff_t *tvb,
                          guint32 offset,
                          proto_tree *sub_tree,
                          guint16 item_no)
{
    guint32 bytepos = 0;
    guint16 len = 0;
    guint16 db = 0;
    guint8 area = 0;
    proto_item *item = NULL;

    /* Insert a new tree with 6 bytes for every item */
    item = proto_tree_add_item(sub_tree, hf_s7comm_param_item, tvb, offset, 6, ENC_NA);

    sub_tree = proto_item_add_subtree(item, ett_s7comm_param_item);

    proto_item_append_text(item, " [%d]:", item_no + 1);

    /* Area, 1 byte */
    area = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(sub_tree, hf_s7comm_vartab_req_memory_area, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Length (repetition factor), 1 byte */
    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(sub_tree, hf_s7comm_vartab_req_repetition_factor, tvb, offset, 1, len);
    offset += 1;

    /* DB number, 2 bytes */
    db = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(sub_tree, hf_s7comm_vartab_req_db_number, tvb, offset, 2, db);
    offset += 2;

    /* byte offset, 2 bytes */
    bytepos = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(sub_tree, hf_s7comm_vartab_req_startaddress, tvb, offset, 2, bytepos);
    offset += 2;

    /* build a full address to show item data directly beside the item */
    switch (area) {
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_MB:
            proto_item_append_text(sub_tree, " (M%d.0 BYTE %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_MW:
            proto_item_append_text(sub_tree, " (M%d.0 WORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_MD:
            proto_item_append_text(sub_tree, " (M%d.0 DWORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_EB:
            proto_item_append_text(sub_tree, " (I%d.0 BYTE %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_EW:
            proto_item_append_text(sub_tree, " (I%d.0 WORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_ED:
            proto_item_append_text(sub_tree, " (I%d.0 DWORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_AB:
            proto_item_append_text(sub_tree, " (Q%d.0 BYTE %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_AW:
            proto_item_append_text(sub_tree, " (Q%d.0 WORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_AD:
            proto_item_append_text(sub_tree, " (Q%d.0 DWORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEB:
            proto_item_append_text(sub_tree, " (PI%d.0 BYTE %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEW:
            proto_item_append_text(sub_tree, " (PI%d.0 WORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_PED:
            proto_item_append_text(sub_tree, " (PI%d.0 DWORD %d)", bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBB:
            proto_item_append_text(sub_tree, " (DB%d.DX%d.0 BYTE %d)", db, bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBW:
            proto_item_append_text(sub_tree, " (DB%d.DX%d.0 WORD %d)", db, bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBD:
            proto_item_append_text(sub_tree, " (DB%d.DX%d.0 DWORD %d)", db, bytepos, len);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_T:
            /* it's possible to read multiple timers */
            if (len >1)
                proto_item_append_text(sub_tree, " (T %d..%d)", bytepos, bytepos + len - 1);
            else
                proto_item_append_text(sub_tree, " (T %d)", bytepos);
            break;
        case S7COMM_UD_SUBF_PROG_VARTAB_AREA_C:
            /* it's possible to read multiple counters */
            if (len >1)
                proto_item_append_text(sub_tree, " (C %d..%d)", bytepos, bytepos + len - 1);
            else
                proto_item_append_text(sub_tree, " (C %d)", bytepos);
            break;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands -> Variable table -> response
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_prog_vartab_res_item(tvbuff_t *tvb,
                          guint32 offset,
                          proto_tree *sub_tree,
                          guint16 item_no)
{
    guint16 len = 0, len2 = 0;
    guint8 ret_val = 0;
    guint8 tsize = 0;
    guint8 head_len = 4;

    proto_item *item = NULL;

    ret_val = tvb_get_guint8(tvb, offset);
    if (ret_val == S7COMM_ITEM_RETVAL_RESERVED ||
        ret_val == S7COMM_ITEM_RETVAL_DATA_OK ||
        ret_val == S7COMM_ITEM_RETVAL_DATA_ERR
        ) {
        tsize = tvb_get_guint8(tvb, offset + 1);
        len = tvb_get_ntohs(tvb, offset + 2);

        if (tsize == S7COMM_DATA_TRANSPORT_SIZE_BBYTE || tsize == S7COMM_DATA_TRANSPORT_SIZE_BINT) {
            len /= 8;
        }
        /* the PLC places extra bytes at the end if length is not a multiple of 2 */
        if (len % 2) {
            len2 = len + 1;
        }else {
            len2 = len;
        }
    }
    /* Insert a new tree for every item */
    item = proto_tree_add_item(sub_tree, hf_s7comm_data_item, tvb, offset, len + head_len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_s7comm_data_item);

    proto_item_append_text(item, " [%d]: (%s)", item_no + 1, val_to_str(ret_val, s7comm_item_return_valuenames, "Unknown code: 0x%02x"));

    proto_tree_add_uint(sub_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
    proto_tree_add_uint(sub_tree, hf_s7comm_data_transport_size, tvb, offset + 1, 1, tsize);
    proto_tree_add_uint(sub_tree, hf_s7comm_data_length, tvb, offset + 2, 2, len);

    offset += head_len;
    if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK || ret_val == S7COMM_ITEM_RETVAL_RESERVED) {
        proto_tree_add_item(sub_tree, hf_s7comm_readresponse_data, tvb, offset, len, ENC_NA);
        offset += len;
        if (len != len2) {
            proto_tree_add_item(sub_tree, hf_s7comm_data_fillbyte, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 5 -> Security functions?
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_security_subfunc(tvbuff_t *tvb,
                                    proto_tree *data_tree,
                                    guint16 dlength,            /* length of data part given in header */
                                    guint32 offset)             /* Offset on data part +4 */
{
    /* Display dataset as raw bytes. Maybe this part can be extended with further knowledge. */
    proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4, ENC_NA);
    offset += dlength;

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 6 -> PBC, Programmable Block Functions (e.g. BSEND/BRECV)
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_pbc_subfunc(tvbuff_t *tvb,
                             proto_tree *data_tree,
                             guint16 dlength,                   /* length of data part given in header */
                             guint32 offset)                    /* Offset on data part +4 */
{
    proto_tree_add_item(data_tree, hf_s7comm_item_varspec, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_s7comm_item_varspec_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_s7comm_item_syntax_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_s7comm_pbc_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_s7comm_pbc_r_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* Only in the first telegram of possible several segments, an int16 of full data length is following.
     * As the dissector can't check this, don't display the information
     * and display the data as payload bytes.
     */
    dlength = dlength - 4 - 8;  /* 4 bytes data header, 8 bytes varspec */
    if (dlength > 0) {
        proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength, ENC_NA);
        offset += dlength;
    }

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 7 -> time functions
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_time_subfunc(tvbuff_t *tvb,
                                    proto_tree *data_tree,
                                    guint8 type,                /* Type of data (request/response) */
                                    guint8 subfunc,             /* Subfunction */
                                    guint8 ret_val,             /* Return value in data part */
                                    guint16 dlength,            /* length of data part given in header */
                                    guint32 offset)             /* Offset on data part +4 */
{
    gboolean know_data = FALSE;

    switch (subfunc) {
        case S7COMM_UD_SUBF_TIME_READ:
        case S7COMM_UD_SUBF_TIME_READF:
            if (type == S7COMM_UD_TYPE_RES) {                   /*** Response ***/
                if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
                    proto_item_append_text(data_tree, ": ");
                    offset = s7comm_add_timestamp_to_tree(tvb, data_tree, offset, TRUE);
                }
                know_data = TRUE;
            }
            break;
        case S7COMM_UD_SUBF_TIME_SET:
        case S7COMM_UD_SUBF_TIME_SET2:
            if (type == S7COMM_UD_TYPE_REQ) {                   /*** Request ***/
                if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
                    proto_item_append_text(data_tree, ": ");
                    offset = s7comm_add_timestamp_to_tree(tvb, data_tree, offset, TRUE);
                }
                know_data = TRUE;
            }
            break;
        default:
            break;
    }

    if (know_data == FALSE && dlength > 4) {
        proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4, ENC_NA);
        offset += dlength;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 3 -> block functions
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_block_subfunc(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *data_tree,
                                    guint8 type,                /* Type of data (request/response) */
                                    guint8 subfunc,             /* Subfunction */
                                    guint8 ret_val,             /* Return value in data part */
                                    guint8 tsize,               /* transport size in data part */
                                    guint16 len,                /* length given in data part */
                                    guint16 dlength,            /* length of data part given in header */
                                    guint32 offset)             /* Offset on data part +4 */
{
    guint16 count;
    guint16 i;
    guint8 *pBlocknumber;
    guint16 blocknumber;
    guint8 blocktype;
    gboolean know_data = FALSE;
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;
    char str_timestamp[30];
    char str_number[10];
    char str_version[10];

    switch (subfunc) {
        /*************************************************
         * List blocks
         */
        case S7COMM_UD_SUBF_BLOCK_LIST:
            if (type == S7COMM_UD_TYPE_REQ) {                       /*** Request ***/
                /* Is this a possible combination? Never seen it... */

            } else if (type == S7COMM_UD_TYPE_RES) {                /*** Response ***/
                count = len / 4;
                for(i = 0; i < count; i++) {
                    /* Insert a new tree of 4 byte length for every item */
                    item = proto_tree_add_item(data_tree, hf_s7comm_data_item, tvb, offset, 4, ENC_NA);
                    item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);
                    offset += 1; /* skip first byte */
                    proto_item_append_text(item, " [%d]: (Block type %s)", i+1, val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type: 0x%02x"));
                    proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_cnt, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                }
                know_data = TRUE;
            }
            break;
        /*************************************************
         * List blocks of type
         */
        case S7COMM_UD_SUBF_BLOCK_LISTTYPE:
            if (type == S7COMM_UD_TYPE_REQ) {                       /*** Request ***/
                if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL) {
                    offset += 1; /* skip first byte */
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Type:[%s]",
                        val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type: 0x%02x"));
                    proto_item_append_text(data_tree, ": (%s)",
                        val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type: 0x%02x"));
                    offset += 1;
                }
                know_data = TRUE;

            }else if (type == S7COMM_UD_TYPE_RES) {                 /*** Response ***/
                if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL) {
                    count = len / 4;

                    for(i = 0; i < count; i++) {
                        /* Insert a new tree of 4 byte length for every item */
                        item = proto_tree_add_item(data_tree, hf_s7comm_data_item, tvb, offset, 4, ENC_NA);
                        item_tree = proto_item_add_subtree(item, ett_s7comm_data_item);

                        proto_item_append_text(item, " [%d]: (Block number %d)", i+1, tvb_get_ntohs(tvb, offset));
                        proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        /* The first Byte is unknown, kind of flags? */
                        proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(item_tree, hf_s7comm_ud_blockinfo_block_lang, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                }
                know_data = TRUE;
            }
            break;
        /*************************************************
         * Get block infos
         */
        case S7COMM_UD_SUBF_BLOCK_BLOCKINFO:
            if (type == S7COMM_UD_TYPE_REQ) {                       /*** Request ***/
                if (tsize != S7COMM_DATA_TRANSPORT_SIZE_NULL) {
                    /* 8 Bytes of Data follow, 1./ 2. type, 3-7 blocknumber as ascii number */
                    offset += 1; /* skip first byte */
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_item_append_text(data_tree, ": (Block type: %s",
                        val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type: 0x%02x"));
                    /* Add block type and number to info column */
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Type:[%s]",
                        val_to_str(tvb_get_guint8(tvb, offset), blocktype_names, "Unknown Block type: 0x%02x"));
                    offset += 1;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_num_ascii, tvb, offset, 5, ENC_ASCII|ENC_NA);
                    pBlocknumber = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 5, ENC_ASCII);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " No.:[%s]", pBlocknumber);
                    proto_item_append_text(data_tree, ", Number: %s)", pBlocknumber);
                    offset += 5;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_filesys, tvb, offset, 1, ENC_ASCII|ENC_NA);
                    offset += 1;
                }
                know_data = TRUE;

            }else if (type == S7COMM_UD_TYPE_RES) {             /*** Response ***/
                /* 78 Bytes */
                if (ret_val == S7COMM_ITEM_RETVAL_DATA_OK) {
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_const1, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_infolength, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_unknown2, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_const3, tvb, offset, 2, ENC_ASCII|ENC_NA);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_unknown, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    /* Configuration flags or Bits?
                     * Bits: 0 0 0 0   0 0 0 0   0 0 0 0   0 0 0 0
                     * Pos : 31 ..                             ..0
                     *
                     * Bit : 0 -> DB Linked = true
                     * Bit : 5 -> DB Non Retain = true
                     * Standard FC/FC/DB -> 0x0101        0x0100 -> is this bit (8) in FBs for multiinstance?
                     * SFC:  0x0009  SFB: 0x0109 or 0x010d (e.g. SFB8, 414)
                     */

                    proto_tree_add_bitmask(data_tree, tvb, offset, hf_s7comm_userdata_blockinfo_flags,
                        ett_s7comm_userdata_blockinfo_flags, s7comm_userdata_blockinfo_flags_fields, ENC_BIG_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_block_lang, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    blocktype = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_subblk_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    /* Add block type and number to info column */
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Type:[%s]",
                        val_to_str(blocktype, subblktype_names, "Unknown Subblk type: 0x%02x"));
                    proto_item_append_text(data_tree, ": (Subblk type: %s",
                        val_to_str(blocktype, subblktype_names, "Unknown Subblk type: 0x%02x"));
                    offset += 1;
                    blocknumber = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_uint(data_tree, hf_s7comm_ud_blockinfo_block_num, tvb, offset, 2, blocknumber);
                    g_snprintf(str_number, sizeof(str_number), "%05d", blocknumber);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " No.:[%s]", str_number);
                    proto_item_append_text(data_tree, ", Number: %05d)", blocknumber);
                    offset += 2;
                    /* "Length Load mem" -> the length in Step7 Manager seems to be this length +6 bytes */
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_load_mem_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_blocksecurity, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    s7comm_get_timestring_from_s7time(tvb, offset, str_timestamp, sizeof(str_timestamp));
                    proto_tree_add_string(data_tree, hf_s7comm_ud_blockinfo_code_timestamp, tvb, offset, 6, str_timestamp);
                    offset += 6;
                    s7comm_get_timestring_from_s7time(tvb, offset, str_timestamp, sizeof(str_timestamp));
                    proto_tree_add_string(data_tree, hf_s7comm_ud_blockinfo_interface_timestamp, tvb, offset, 6, str_timestamp);
                    offset += 6;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_ssb_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_add_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_localdata_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_mc7_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_author, tvb, offset, 8, ENC_ASCII|ENC_NA);
                    offset += 8;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_family, tvb, offset, 8, ENC_ASCII|ENC_NA);
                    offset += 8;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_headername, tvb, offset, 8, ENC_ASCII|ENC_NA);
                    offset += 8;
                    g_snprintf(str_version, sizeof(str_version), "%d.%d", ((tvb_get_guint8(tvb, offset) & 0xf0) >> 4), tvb_get_guint8(tvb, offset) & 0x0f);
                    proto_tree_add_string(data_tree, hf_s7comm_ud_blockinfo_headerversion, tvb, offset, 1, str_version);
                    offset += 1;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_res_unknown, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_reserved1, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(data_tree, hf_s7comm_ud_blockinfo_reserved2, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                }
                know_data = TRUE;
            }
            break;
        default:
            break;
    }
    if (know_data == FALSE && dlength > 4) {
        proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4, ENC_NA);
        offset += dlength;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 2 -> cyclic data
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_cyclic_subfunc(tvbuff_t *tvb,
                                    proto_tree *data_tree,
                                    guint8 type,                /* Type of data (request/response) */
                                    guint8 subfunc,             /* Subfunction */
                                    guint16 dlength,            /* length of data part given in header */
                                    guint32 offset)             /* Offset on data part +4 */
{
    gboolean know_data = FALSE;
    guint32 offset_old;
    guint32 len_item;
    guint8 item_count;
    guint8 i;

    switch (subfunc)
    {
        case S7COMM_UD_SUBF_CYCLIC_MEM:
            item_count = tvb_get_guint8(tvb, offset + 1);     /* first byte reserved??? */
            proto_tree_add_uint(data_tree, hf_s7comm_param_itemcount, tvb, offset, 2, item_count);
            offset += 2;
            if (type == S7COMM_UD_TYPE_REQ) {                   /* Request to PLC to send cyclic data */
                proto_tree_add_item(data_tree, hf_s7comm_cycl_interval_timebase, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(data_tree, hf_s7comm_cycl_interval_time, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* parse item data */
                for (i = 0; i < item_count; i++) {
                    offset_old = offset;
                    offset = s7comm_decode_param_item(tvb, offset, data_tree, i);
                    /* if length is not a multiple of 2 and this is not the last item, then add a fill-byte */
                    len_item = offset - offset_old;
                    if ((len_item % 2) && (i < item_count)) {
                        offset += 1;
                    }
                }

            } else if (type == S7COMM_UD_TYPE_RES || type == S7COMM_UD_TYPE_PUSH) {   /* Response from PLC with the requested data */
                /* parse item data */
                offset = s7comm_decode_response_read_data(tvb, data_tree, item_count, offset);
            }
            know_data = TRUE;
            break;
    }

    if (know_data == FALSE && dlength > 4) {
        proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4, ENC_NA);
        offset += dlength;
    }
    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: User Data -> Function group 1 -> Programmer commands
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_ud_prog_subfunc(tvbuff_t *tvb,
                                    proto_tree *data_tree,
                                    guint8 type,                /* Type of data (request/response) */
                                    guint8 subfunc,             /* Subfunction */
                                    guint16 dlength,            /* length of data part given in header */
                                    guint32 offset)             /* Offset on data part +4 */
{
    gboolean know_data = FALSE;

    guint8 data_type;
    guint16 byte_count;
    guint16 item_count;
    guint16 i;

    switch(subfunc)
    {
        case S7COMM_UD_SUBF_PROG_REQDIAGDATA1:
        case S7COMM_UD_SUBF_PROG_REQDIAGDATA2:
            /* start variable table or block online view */
            /* TODO: Can only handle requests/response, not the "following" telegrams because it's necessary to correlate them
                with the previous request */
            if (type != S7COMM_UD_TYPE_PUSH) {
                offset = s7comm_decode_ud_prog_reqdiagdata(tvb, data_tree, subfunc, offset);
                know_data = TRUE;
            }
            break;

        case S7COMM_UD_SUBF_PROG_VARTAB1:
            /* online status in variable table */
            offset += 1; /* 1 Byte const 0, skip */
            data_type = tvb_get_guint8(tvb, offset);         /* 1 Byte type: 0x14 = Request, 0x04 = Response */
            proto_tree_add_uint(data_tree, hf_s7comm_vartab_data_type, tvb, offset, 1, data_type);
            offset += 1;

            byte_count = tvb_get_ntohs(tvb, offset);            /* 2 Bytes: Number of bytes of item-data including item-count */
            proto_tree_add_uint(data_tree, hf_s7comm_vartab_byte_count, tvb, offset, 2, byte_count);
            offset += 2;

            switch (data_type)
            {
                case S7COMM_UD_SUBF_PROG_VARTAB_TYPE_REQ:
                    /*** Request of data areas ***/

                    /* 20 Bytes unknown part */
                    proto_tree_add_item(data_tree, hf_s7comm_vartab_unknown, tvb, offset, 20, ENC_NA);
                    offset += 20;

                    item_count = tvb_get_ntohs(tvb, offset);    /* 2 Bytes header: number of items following */
                    proto_tree_add_uint(data_tree, hf_s7comm_vartab_item_count, tvb, offset, 2, item_count);
                    offset += 2;

                    /* parse item data */
                    for (i = 0; i < item_count; i++) {
                        offset = s7comm_decode_ud_prog_vartab_req_item(tvb, offset, data_tree, i);
                    }
                    know_data = TRUE;
                    break;

                case S7COMM_UD_SUBF_PROG_VARTAB_TYPE_RES:
                    /*** Response of PLC to requested data-areas ***/

                    /* 4 Bytes unknown part */
                    proto_tree_add_item(data_tree, hf_s7comm_vartab_unknown, tvb, offset, 4, ENC_NA);
                    offset += 4;

                    item_count = tvb_get_ntohs(tvb, offset);    /* 2 Bytes: number of items following */
                    proto_tree_add_uint(data_tree, hf_s7comm_vartab_item_count, tvb, offset, 2, item_count);
                    offset += 2;

                    /* parse item data */
                    for (i = 0; i < item_count; i++) {
                        offset = s7comm_decode_ud_prog_vartab_res_item(tvb, offset, data_tree, i);
                    }
                    know_data = TRUE;
                    break;
            }
    }

    if (know_data == FALSE && dlength > 4) {
        proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4, ENC_NA);
        offset += dlength;
    }
    return offset;
}

/*******************************************************************************************************
 *******************************************************************************************************
 *
 * PDU Type: User Data
 *
 *******************************************************************************************************
 *******************************************************************************************************/
static guint32
s7comm_decode_ud(tvbuff_t *tvb,
                       packet_info *pinfo,
                       proto_tree *tree,
                       guint16 plength,
                       guint16 dlength,
                       guint32 offset)
{
    proto_item *item = NULL;
    proto_tree *param_tree = NULL;
    proto_tree *data_tree = NULL;

    guint8 ret_val;
    guint8 tsize;
    guint16 len;
    guint32 offset_temp;

    guint8 type;
    guint8 funcgroup;
    guint8 subfunc;
    guint8 data_unit_ref = 0;
    guint8 last_data_unit = 0;

    /* Add parameter tree */
    item = proto_tree_add_item(tree, hf_s7comm_param, tvb, offset, plength, ENC_NA);
    param_tree = proto_item_add_subtree(item, ett_s7comm_param);

    /* Try do decode some functions...
     * Some functions may use data that does't fit one telegram
     */
    offset_temp = offset;   /* Save offset */
    /* 3 bytes constant head */
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_head, tvb, offset_temp, 3, ENC_BIG_ENDIAN);
    offset_temp += 3;
    /* 1 byte length of following parameter (8 or 12 bytes) */
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_len, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
    offset_temp += 1;
    /* 1 byte unknown, maybe indicating request/response */
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_reqres2, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
    offset_temp += 1;
    /* High nibble (following/request/response) */
    type = (tvb_get_guint8(tvb, offset_temp) & 0xf0) >> 4;
    funcgroup = (tvb_get_guint8(tvb, offset_temp) & 0x0f);
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_type, tvb, offset_temp, 1, ENC_BIG_ENDIAN);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Function:[%s] -> [%s]",
        val_to_str(type, userdata_type_names, "Unknown type: 0x%02x"),
        val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function: 0x%02x")
        );

    proto_item_append_text(param_tree, ": (%s)", val_to_str(type, userdata_type_names, "Unknown type: 0x%02x"));
    proto_item_append_text(param_tree, " ->(%s)", val_to_str(funcgroup, userdata_functiongroup_names, "Unknown function: 0x%02x"));

    /* Low nibble function group  */
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_funcgroup, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
    offset_temp += 1;
    /* 1 Byte subfunction  */
    subfunc = tvb_get_guint8(tvb, offset_temp);
    switch (funcgroup){
        case S7COMM_UD_FUNCGROUP_PROG:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_prog, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_prog_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_prog_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_CYCLIC:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_cyclic, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_cyclic_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_cyclic_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_BLOCK:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_block, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_block_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_block_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_CPU:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_cpu, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_cpu_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_cpu_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_SEC:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_sec, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_sec_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_sec_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        case S7COMM_UD_FUNCGROUP_TIME:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc_time, tvb, offset_temp, 1, subfunc);
            col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]",
                val_to_str(subfunc, userdata_time_subfunc_names, "Unknown subfunc: 0x%02x"));
            proto_item_append_text(param_tree, " ->(%s)", val_to_str(subfunc, userdata_time_subfunc_names, "Unknown subfunc: 0x%02x"));
            break;
        default:
            proto_tree_add_uint(param_tree, hf_s7comm_userdata_param_subfunc, tvb, offset_temp, 1, subfunc);
            break;
    }
    offset_temp += 1;
    /* 1 Byte sequence number  */
    proto_tree_add_item(param_tree, hf_s7comm_userdata_param_seq_num, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
    offset_temp += 1;
    if (plength >= 12) {
        /* 1 Byte data unit reference. If packet is fragmented, all packets with this number belong together */
        data_unit_ref = tvb_get_guint8(tvb, offset_temp);
        proto_tree_add_item(param_tree, hf_s7comm_userdata_param_dataunitref, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
        offset_temp += 1;
        /* 1 Byte fragmented flag, if this is not the last data unit (telegram is fragmented) this is != 0 */
        last_data_unit = tvb_get_guint8(tvb, offset_temp);
        proto_tree_add_item(param_tree, hf_s7comm_userdata_param_dataunit, tvb, offset_temp, 1, ENC_BIG_ENDIAN);
        offset_temp += 1;
        proto_tree_add_item(param_tree, hf_s7comm_param_errcod, tvb, offset_temp, 2, ENC_BIG_ENDIAN);
    }

    /**********************************
     * Add data tree
     */
    offset += plength;          /* set offset to the beginning of the data part */
    item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
    data_tree = proto_item_add_subtree(item, ett_s7comm_data);

    /* the first 4 bytes of the  data part of a userdata telegram are the same for all types */
    if (dlength >= 4) {
        ret_val = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(data_tree, hf_s7comm_data_returncode, tvb, offset, 1, ret_val);
        offset += 1;
        /* Not definitely known part, kind of "transport size"? constant 0x09, 1 byte
         * The position is the same as in a data response/write telegram,
         */
        tsize = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(data_tree, hf_s7comm_data_transport_size, tvb, offset, 1, tsize);
        offset += 1;
        len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(data_tree, hf_s7comm_data_length, tvb, offset, 2, len);
        offset += 2;

        /* Call function to decode the rest of the data part
         * decode only when there is a data part length greater 4 bytes
         */
        if (dlength > 4) {
            switch (funcgroup){
                case S7COMM_UD_FUNCGROUP_PROG:
                    offset = s7comm_decode_ud_prog_subfunc(tvb, data_tree, type, subfunc, dlength, offset);
                    break;
                case S7COMM_UD_FUNCGROUP_CYCLIC:
                    offset = s7comm_decode_ud_cyclic_subfunc(tvb, data_tree, type, subfunc, dlength, offset);
                    break;
                case S7COMM_UD_FUNCGROUP_BLOCK:
                    offset = s7comm_decode_ud_block_subfunc(tvb, pinfo, data_tree, type, subfunc, ret_val, tsize, len, dlength, offset);
                    break;
                case S7COMM_UD_FUNCGROUP_CPU:
                    if (subfunc == S7COMM_UD_SUBF_CPU_READSZL) {
                        offset = s7comm_decode_ud_cpu_szl_subfunc(tvb, pinfo, data_tree, type, ret_val, len, dlength, data_unit_ref, last_data_unit, offset);
                    } else {
                        /* print other currently unknown data as raw bytes */
                        proto_tree_add_item(data_tree, hf_s7comm_userdata_data, tvb, offset, dlength - 4, ENC_NA);
                    }
                    break;
                case S7COMM_UD_FUNCGROUP_SEC:
                    offset = s7comm_decode_ud_security_subfunc(tvb, data_tree, dlength, offset);
                    break;
                case S7COMM_UD_FUNCGROUP_PBC:
                    offset = s7comm_decode_ud_pbc_subfunc(tvb, data_tree, dlength, offset);
                    break;
                case S7COMM_UD_FUNCGROUP_TIME:
                    offset = s7comm_decode_ud_time_subfunc(tvb, data_tree, type, subfunc, ret_val, dlength, offset);
                    break;
                default:
                    break;
            }
        }
    }

    return offset;
}

/*******************************************************************************************************
 *
 * PDU Type: Request or Response
 *
 *******************************************************************************************************/
static guint32
s7comm_decode_req_resp(tvbuff_t *tvb,
                      packet_info *pinfo,
                      proto_tree *tree,
                      guint16 plength,
                      guint16 dlength,
                      guint32 offset,
                      guint8 rosctr)
{
    proto_item *item = NULL;
    proto_tree *param_tree = NULL;
    proto_tree *data_tree = NULL;
    guint8 function = 0;
    guint8 item_count = 0;
    guint8 i;
    guint32 offset_old;
    guint32 len;

    if (plength > 0) {
        /* Add parameter tree */
        item = proto_tree_add_item(tree, hf_s7comm_param, tvb, offset, plength, ENC_NA);
        param_tree = proto_item_add_subtree(item, ett_s7comm_param);
        /* Analyze function */
        function = tvb_get_guint8(tvb, offset);
        /* add param.function to info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " Function:[%s]", val_to_str(function, param_functionnames, "Unknown function: 0x%02x"));
        proto_tree_add_uint(param_tree, hf_s7comm_param_service, tvb, offset, 1, function);
        /* show param.function code at the tree */
        proto_item_append_text(param_tree, ": (%s)", val_to_str(function, param_functionnames, "Unknown function: 0x%02x"));
        offset += 1;

        if (rosctr == S7COMM_ROSCTR_JOB) {
            switch (function){
                case S7COMM_SERV_READVAR:
                case S7COMM_SERV_WRITEVAR:
                    item_count = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint(param_tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
                    offset += 1;
                    /* parse item data */
                    for (i = 0; i < item_count; i++) {
                        offset_old = offset;
                        offset = s7comm_decode_param_item(tvb, offset, param_tree, i);
                        /* if length is not a multiple of 2 and this is not the last item, then add a fill-byte */
                        len = offset - offset_old;
                        if ((len % 2) && (i < item_count)) {
                            offset += 1;
                        }
                    }
                    /* in write-function there is a data part */
                    if ((function == S7COMM_SERV_WRITEVAR) && (dlength > 0)) {
                        item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
                        data_tree = proto_item_add_subtree(item, ett_s7comm_data);
                        /* Add returned data to data-tree */
                        offset = s7comm_decode_response_read_data(tvb, data_tree, item_count, offset);
                    }
                    break;
                case S7COMM_SERV_SETUPCOMM:
                    offset = s7comm_decode_pdu_setup_communication(tvb, param_tree, offset);
                    break;
                /* Special functions */
                case S7COMM_FUNCREQUESTDOWNLOAD:
                case S7COMM_FUNCDOWNLOADBLOCK:
                case S7COMM_FUNCDOWNLOADENDED:
                case S7COMM_FUNCSTARTUPLOAD:
                case S7COMM_FUNCUPLOAD:
                case S7COMM_FUNCENDUPLOAD:
                    offset = s7comm_decode_plc_controls_param_hex1x(tvb, pinfo, param_tree, plength, offset -1);
                    break;
                case S7COMM_FUNC_PLC_CONTROL:
                    offset = s7comm_decode_plc_controls_param_hex28(tvb, pinfo, param_tree, offset -1);
                    break;
                case S7COMM_FUNC_PLC_STOP:
                    offset = s7comm_decode_plc_controls_param_hex29(tvb, param_tree, offset -1);
                    break;

                default:
                    /* Print unknown part as raw bytes */
                    if (plength > 1) {
                        proto_tree_add_item(param_tree, hf_s7comm_param_data, tvb, offset, plength - 1, ENC_NA);
                    }
                    offset += plength - 1; /* 1 byte function code */
                    if (dlength > 0) {
                        /* Add data tree
                         * First 2 bytes in data seem to be a length indicator of (dlength -4 ), so next 2 bytes
                         * seem to indicate something else. But I'm not sure, so leave it as it is.....
                         */
                        item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
                        data_tree = proto_item_add_subtree(item, ett_s7comm_data);
                        proto_tree_add_item(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength, ENC_NA);
                        offset += dlength;
                    }
                    break;
            }
        } else if (rosctr == S7COMM_ROSCTR_ACK_DATA) {
            switch (function){
                case S7COMM_SERV_READVAR:
                case S7COMM_SERV_WRITEVAR:
                    /* This is a read-response, so the requested data may follow when address in request was ok */
                    item_count = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint(param_tree, hf_s7comm_param_itemcount, tvb, offset, 1, item_count);
                    offset += 1;
                    /* Add data tree */
                    item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
                    data_tree = proto_item_add_subtree(item, ett_s7comm_data);
                    /* Add returned data to data-tree */
                    if ((function == S7COMM_SERV_READVAR) && (dlength > 0)) {
                        offset = s7comm_decode_response_read_data(tvb, data_tree, item_count, offset);
                    } else if ((function == S7COMM_SERV_WRITEVAR) && (dlength > 0)) {
                        offset = s7comm_decode_response_write_data(tvb, data_tree, item_count, offset);
                    }
                    break;
                case S7COMM_SERV_SETUPCOMM:
                    offset = s7comm_decode_pdu_setup_communication(tvb, param_tree, offset);
                    break;
                default:
                    /* Print unknown part as raw bytes */
                    if (plength > 1) {
                        proto_tree_add_item(param_tree, hf_s7comm_param_data, tvb, offset, plength - 1, ENC_NA);
                    }
                    offset += plength - 1; /* 1 byte function code */
                    if (dlength > 0) {
                        /* Add data tree
                         * First 2 bytes in data seem to be a length indicator of (dlength -4 ), so next 2 bytes
                         * seem to indicate something else. But I'm not sure, so leave it as it is.....
                         */
                        item = proto_tree_add_item(tree, hf_s7comm_data, tvb, offset, dlength, ENC_NA);
                        data_tree = proto_item_add_subtree(item, ett_s7comm_data);
                        proto_tree_add_item(data_tree, hf_s7comm_readresponse_data, tvb, offset, dlength, ENC_NA);
                        offset += dlength;
                    }
                    break;
            }
        }
    }
    return offset;
}

/*******************************************************************************************************
 *******************************************************************************************************
 *
 * S7-Protocol (main tree)
 *
 *******************************************************************************************************
 *******************************************************************************************************/
static gboolean
dissect_s7comm(tvbuff_t *tvb,
                packet_info *pinfo,
                proto_tree *tree,
                void *data _U_)
{
    proto_item *s7comm_item = NULL;
    proto_item *s7comm_sub_item = NULL;
    proto_tree *s7comm_tree = NULL;
    proto_tree *s7comm_header_tree = NULL;

    guint32 offset = 0;

    guint8 rosctr = 0;
    guint8 hlength = 10;                /* Header 10 Bytes, when type 2 or 3 (Response) -> 12 Bytes */
    guint16 plength = 0;
    guint16 dlength = 0;

    /*----------------- Heuristic Checks - Begin */
    /* 1) check for minimum length */
    if(tvb_captured_length(tvb) < S7COMM_MIN_TELEGRAM_LENGTH)
        return FALSE;
    /* 2) first byte must be 0x32 */
    if (tvb_get_guint8(tvb, 0) != S7COMM_PROT_ID)
        return FALSE;
    /* 3) second byte is a type field and only can contain values between 0x01-0x07 (1/2/3/7) */
    if (tvb_get_guint8(tvb, 1) < 0x01 || tvb_get_guint8(tvb, 1) > 0x07)
        return FALSE;
    /*----------------- Heuristic Checks - End */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_S7COMM);
    col_clear(pinfo->cinfo, COL_INFO);

    rosctr = tvb_get_guint8(tvb, 1);                            /* Get the type byte */
    if (rosctr == 2 || rosctr == 3) hlength = 12;               /* Header 10 Bytes, when type 2 or 3 (response) -> 12 Bytes */

    /* display some infos in info-column of wireshark */
    col_add_fstr(pinfo->cinfo, COL_INFO, "ROSCTR:[%-8s]", val_to_str(rosctr, rosctr_names, "Unknown: 0x%02x"));

    s7comm_item = proto_tree_add_item(tree, proto_s7comm, tvb, 0, -1, ENC_NA);
    s7comm_tree = proto_item_add_subtree(s7comm_item, ett_s7comm);

    /* insert header tree */
    s7comm_sub_item = proto_tree_add_item(s7comm_tree, hf_s7comm_header,
                      tvb, offset, hlength, ENC_NA);

    /* insert sub-items in header tree */
    s7comm_header_tree = proto_item_add_subtree(s7comm_sub_item, ett_s7comm_header);

    /* Protocol Identifier, constant 0x32 */
    proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_protid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* ROSCTR (Remote Operating Service Control) - PDU Type */
    proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_rosctr, tvb, offset, 1, rosctr);
    /* Show pdu type beside the header tree */
    proto_item_append_text(s7comm_header_tree, ": (%s)", val_to_str(rosctr, rosctr_names, "Unknown ROSCTR: 0x%02x"));
    offset += 1;
    /* Redundacy ID, reserved */
    proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_redid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* Protocol Data Unit Reference */
    proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_pduref, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* Parameter length */
    plength = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_parlg, tvb, offset, 2, plength);
    offset += 2;
    /* Data length */
    dlength = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(s7comm_header_tree, hf_s7comm_header_datlg, tvb, offset, 2, dlength);
    offset += 2;
    /* when type is 2 or 3 there are 2 bytes with errorclass and errorcode */
    if (hlength == 12) {
        proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_errcls, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(s7comm_header_tree, hf_s7comm_header_errcod, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    switch (rosctr) {
        case S7COMM_ROSCTR_JOB:
        case S7COMM_ROSCTR_ACK_DATA:
            s7comm_decode_req_resp(tvb, pinfo, s7comm_tree, plength, dlength, offset, rosctr);
            break;
        case S7COMM_ROSCTR_USERDATA:
            s7comm_decode_ud(tvb, pinfo, s7comm_tree, plength, dlength, offset);
            break;
    }
    /*else {  Unknown pdu, maybe passed to another dissector? }
    */
    return TRUE;
}

/*******************************************************************************************************
 *******************************************************************************************************/
void
proto_register_s7comm (void)
{
    /* format:
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
     */
    static hf_register_info hf[] = {
        { &hf_s7comm_header,
        { "Header", "s7comm.header", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is the header of S7 communication", HFILL }},
        { &hf_s7comm_header_protid,
        { "Protocol Id", "s7comm.header.protid", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Protocol Identification, 0x32 for S7", HFILL }},
        { &hf_s7comm_header_rosctr,
        { "ROSCTR", "s7comm.header.rosctr", FT_UINT8, BASE_DEC, VALS(rosctr_names), 0x0,
          "Remote Operating Service Control", HFILL }},
        { &hf_s7comm_header_redid,
        { "Redundancy Identification (Reserved)", "s7comm.header.redid", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Redundancy Identification (Reserved), should be always 0x0000", HFILL }},
        { &hf_s7comm_header_pduref,
        { "Protocol Data Unit Reference", "s7comm.header.pduref", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_header_parlg,
        { "Parameter length", "s7comm.header.parlg", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Specifies the entire length of the parameter block in bytes", HFILL }},
        { &hf_s7comm_header_datlg,
        { "Data length", "s7comm.header.datlg", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Specifies the entire length of the data block in bytes", HFILL }},
        { &hf_s7comm_header_errcls,
        { "Error class", "s7comm.header.errcls", FT_UINT8, BASE_HEX, VALS(errcls_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_header_errcod,
        { "Error code", "s7comm.header.errcod", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_param,
        { "Parameter", "s7comm.param", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is the parameter part of S7 communication", HFILL }},
        { &hf_s7comm_param_errcod,
        { "Error code", "s7comm.param.errcod", FT_UINT16, BASE_HEX, VALS(param_errcode_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_service,
        { "Function", "s7comm.param.func", FT_UINT8, BASE_HEX, VALS(param_functionnames), 0x0,
          "Indicates the function of parameter/data", HFILL }},
        { &hf_s7comm_param_maxamq_calling,
        { "Max AmQ (parallel jobs with ack) calling", "s7comm.param.maxamq_calling", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_maxamq_called,
        { "Max AmQ (parallel jobs with ack) called", "s7comm.param.maxamq_called", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_setup_reserved1,
        { "Reserved", "s7comm.param.setup_reserved1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_neg_pdu_length,
        { "PDU length", "s7comm.param.pdu_length", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Negotiated PDU length", HFILL }},
        { &hf_s7comm_param_itemcount,
        { "Item count", "s7comm.param.itemcount", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Number of Items in parameter/data part", HFILL }},
        { &hf_s7comm_param_data,
        { "Parameter data", "s7comm.param.data", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_item,
        { "Item", "s7comm.param.item", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_param_subitem,
        { "Subitem", "s7comm.param.subitem", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_varspec,
        { "Variable specification", "s7comm.param.item.varspec", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_varspec_length,
        { "Length of following address specification", "s7comm.param.item.varspec_length", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_syntax_id,
        { "Syntax Id", "s7comm.param.item.syntaxid", FT_UINT8, BASE_HEX, VALS(item_syntaxid_names), 0x0,
          "Syntax Id, format type of following address specification", HFILL }},
        { &hf_s7comm_item_transport_size,
        { "Transport size", "s7comm.param.item.transp_size", FT_UINT8, BASE_DEC, VALS(item_transportsizenames), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_length,
        { "Length", "s7comm.param.item.length", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_db,
        { "DB number", "s7comm.param.item.db", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_area,
        { "Area", "s7comm.param.item.area", FT_UINT8, BASE_HEX, VALS(item_areanames), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_address,
        { "Address", "s7comm.param.item.address", FT_UINT24, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_address_byte,
        { "Byte Address", "s7comm.param.item.address.byte", FT_UINT24, BASE_DEC, NULL, 0x7fff8,
          NULL, HFILL }},
        { &hf_s7comm_item_address_bit,
        { "Bit Address", "s7comm.param.item.address.bit", FT_UINT24, BASE_DEC, NULL, 0x000007,
          NULL, HFILL }},
        { &hf_s7comm_item_address_nr,
        { "Number (T/C/BLOCK)", "s7comm.param.item.address.number", FT_UINT24, BASE_DEC, NULL, 0x00ffff,
          NULL, HFILL }},
        /* Special variable read with Syntax-Id 0xb0 (DBREAD) */
        { &hf_s7comm_item_dbread_numareas,
        { "Number of areas", "s7comm.param.item.dbread.numareas", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Number of area specifications following", HFILL }},
        { &hf_s7comm_item_dbread_length,
        { "Bytes to read", "s7comm.param.item.dbread.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Number of bytes to read", HFILL }},
        { &hf_s7comm_item_dbread_db,
        { "DB number", "s7comm.param.item.dbread.db", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_dbread_startadr,
        { "Start address", "s7comm.param.item.dbread.startaddress", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        /* NCK access with Syntax-Id 0x82 */
        { &hf_s7comm_item_nck_areaunit,
        { "NCK Area/Unit", "s7comm.param.item.nck.area_unit", FT_UINT8, BASE_HEX, NULL, 0x0,
          "NCK Area/Unit: Bitmask aaauuuuu: a=area, u=unit", HFILL }},
        { &hf_s7comm_item_nck_area,
        { "NCK Area", "s7comm.param.item.nck.area", FT_UINT8, BASE_DEC, VALS(nck_area_names), 0xe0,
          NULL, HFILL }},
        { &hf_s7comm_item_nck_unit,
        { "NCK Unit", "s7comm.param.item.nck.unit", FT_UINT8, BASE_DEC, NULL, 0x1f,
          NULL, HFILL }},
        { &hf_s7comm_item_nck_column,
        { "NCK Column number", "s7comm.param.item.nck.column", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_nck_line,
        { "NCK Line number", "s7comm.param.item.nck.line", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_nck_module,
        { "NCK Module", "s7comm.param.item.nck.module", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &nck_module_names_ext, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_item_nck_linecount,
        { "NCK Linecount", "s7comm.param.item.nck.linecount", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_data,
        { "Data", "s7comm.data", FT_NONE, BASE_NONE, NULL, 0x0,
          "This is the data part of S7 communication", HFILL }},
        { &hf_s7comm_data_returncode,
        { "Return code", "s7comm.data.returncode", FT_UINT8, BASE_HEX, VALS(s7comm_item_return_valuenames), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_transport_size,
        { "Transport size", "s7comm.data.transportsize", FT_UINT8, BASE_HEX, VALS(data_transportsizenames), 0x0,
          "Data type / Transport size. If 3, 4 or 5 the following length gives the number of bits, otherwise the number of bytes.", HFILL }},
        { &hf_s7comm_data_length,
        { "Length", "s7comm.data.length", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of data", HFILL }},

        { &hf_s7comm_data_item,
        { "Item", "s7comm.data.item", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_readresponse_data,
        { "Data", "s7comm.resp.data", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_fillbyte,
        { "Fill byte", "s7comm.data.fillbyte", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_userdata_data,
        { "Data", "s7comm.data.userdata", FT_BYTES, BASE_NONE, NULL, 0x0,
          "Userdata data", HFILL }},

        /* Userdata parameter 8/12 Bytes len*/
        { &hf_s7comm_userdata_param_head,
        { "Parameter head", "s7comm.param.userdata.head", FT_UINT24, BASE_HEX, NULL, 0x0,
          "Header before parameter (constant 0x000112)", HFILL }},
        { &hf_s7comm_userdata_param_len,
        { "Parameter length", "s7comm.param.userdata.length", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length of following parameter data (without head)", HFILL }},
        { &hf_s7comm_userdata_param_reqres2,
        { "Unknown (Request/Response)", "s7comm.param.userdata.reqres1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Unknown part, possible request/response (0x11, 0x12), but not in programmer commands", HFILL }},

        { &hf_s7comm_userdata_param_type,
        { "Type", "s7comm.param.userdata.type", FT_UINT8, BASE_DEC, VALS(userdata_type_names), 0xf0,
          "Type of parameter", HFILL }},

        { &hf_s7comm_userdata_param_funcgroup,
        { "Function group", "s7comm.param.userdata.funcgroup", FT_UINT8, BASE_DEC, VALS(userdata_functiongroup_names), 0x0f,
          NULL, HFILL }},

        { &hf_s7comm_userdata_param_subfunc_prog,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_prog_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_cyclic,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_cyclic_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_block,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_block_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_cpu,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_cpu_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_sec,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_sec_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc_time,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_DEC, VALS(userdata_time_subfunc_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_userdata_param_subfunc,
        { "Subfunction", "s7comm.param.userdata.subfunc", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_userdata_param_seq_num,
        { "Sequence number", "s7comm.param.userdata.seq_num", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_s7comm_userdata_param_dataunitref,
        { "Data unit reference number", "s7comm.param.userdata.dataunitref", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Data unit reference number if PDU is fragmented", HFILL }},

        { &hf_s7comm_userdata_param_dataunit,
        { "Last data unit", "s7comm.param.userdata.lastdataunit", FT_UINT8, BASE_HEX, VALS(userdata_lastdataunit_names), 0x0,
          NULL, HFILL }},

        /* block functions / info */
        { &hf_s7comm_ud_blockinfo_block_type,
        { "Block type", "s7comm.blockinfo.blocktype", FT_UINT8, BASE_DEC, VALS(blocktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_block_cnt,
        { "Block count", "s7comm.blockinfo.block_count", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_block_num,
        { "Block number", "s7comm.blockinfo.block_num", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_block_flags,
        { "Block flags (unknown)", "s7comm.blockinfo.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_block_lang,
        { "Block language", "s7comm.blockinfo.block_lang", FT_UINT8, BASE_DEC, VALS(blocklanguage_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_block_num_ascii,
        { "Block number", "s7comm.data.blockinfo.block_number", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_filesys,
        { "Filesystem", "s7comm.data.blockinfo.filesys", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_res_const1,
        { "Constant 1", "s7comm.blockinfo.res_const1", FT_UINT8, BASE_HEX, NULL, 0x0,
          "Possible constant 1", HFILL }},
        { &hf_s7comm_ud_blockinfo_res_infolength,
        { "Length of Info", "s7comm.blockinfo.res_infolength", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of Info in bytes", HFILL }},
        { &hf_s7comm_ud_blockinfo_res_unknown2,
        { "Unknown blockinfo 2", "s7comm.blockinfo.res_unknown2", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_res_const3,
        { "Constant 3", "s7comm.blockinfo.res_const3", FT_STRING, BASE_NONE, NULL, 0x0,
          "Possible constant 3, seems to be always 'pp'", HFILL }},
        { &hf_s7comm_ud_blockinfo_res_unknown,
        { "Unknown byte(s) blockinfo", "s7comm.blockinfo.res_unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_subblk_type,
        { "Subblk type", "s7comm.blockinfo.subblk_type", FT_UINT8, BASE_DEC, VALS(subblktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_load_mem_len,
        { "Length load memory", "s7comm.blockinfo.load_mem_len", FT_UINT32, BASE_DEC, NULL, 0x0,
          "Length of load memory in bytes", HFILL }},
        { &hf_s7comm_ud_blockinfo_blocksecurity,
        { "Block Security", "s7comm.blockinfo.blocksecurity", FT_UINT32, BASE_DEC, VALS(blocksecurity_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_interface_timestamp,
        { "Interface timestamp", "s7comm.blockinfo.interface_timestamp", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_code_timestamp,
        { "Code timestamp", "s7comm.blockinfo.code_timestamp", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_ssb_len,
        { "SSB length", "s7comm.blockinfo.ssb_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_add_len,
        { "ADD length", "s7comm.blockinfo.add_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_localdata_len,
        { "Localdata length", "s7comm.blockinfo.localdata_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of localdata in bytes", HFILL }},
        { &hf_s7comm_ud_blockinfo_mc7_len,
        { "MC7 code length", "s7comm.blockinfo.mc7_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of MC7 code in bytes", HFILL }},
        { &hf_s7comm_ud_blockinfo_author,
        { "Author", "s7comm.blockinfo.author", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_family,
        { "Family", "s7comm.blockinfo.family", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_headername,
        { "Name (Header)", "s7comm.blockinfo.headername", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_headerversion,
        { "Version (Header)", "s7comm.blockinfo.headerversion", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_checksum,
        { "Block checksum", "s7comm.blockinfo.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_reserved1,
        { "Reserved 1", "s7comm.blockinfo.reserved1", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_ud_blockinfo_reserved2,
        { "Reserved 2", "s7comm.blockinfo.reserved2", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        /* Flags in blockinfo response */
        { &hf_s7comm_userdata_blockinfo_flags,
        { "Block flags", "s7comm.param.userdata.blockinfo.flags", FT_UINT8, BASE_HEX, NULL, 0xff,
          "Some block configuration flags", HFILL }},
         /* Bit : 0 -> DB Linked = true */
        { &hf_s7comm_userdata_blockinfo_linked,
        { "Linked", "s7comm.param.userdata.blockinfo.linked", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
          NULL, HFILL }},
        /* Bit : 1 -> Standard block = true */
        { &hf_s7comm_userdata_blockinfo_standard_block,
        { "Standard block", "s7comm.param.userdata.blockinfo.standard_block", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
          NULL, HFILL }},
        /* Bit : 5 -> DB Non Retain = true */
        { &hf_s7comm_userdata_blockinfo_nonretain,
        { "Non Retain", "s7comm.param.userdata.blockinfo.nonretain", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
          NULL, HFILL }},

        /* Programmer commands, diagnostic data */
        { &hf_s7comm_diagdata_req_askheadersize,
        { "Ask header size", "s7comm.diagdata.req.askheadersize", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_asksize,
        { "Ask size", "s7comm.diagdata.req.asksize", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_unknown,
        { "Unknown byte(s) diagdata", "s7comm.diagdata.req.unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_answersize,
        { "Answer size", "s7comm.diagdata.req.answersize", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_block_type,
        { "Block type", "s7comm.diagdata.req.blocktype", FT_UINT8, BASE_DEC, VALS(subblktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_block_num,
        { "Block number", "s7comm.diagdata.req.blocknumber", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_startaddr_awl,
        { "Start address AWL", "s7comm.diagdata.req.startaddr_awl", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_saz,
        { "Step address counter (SAZ)", "s7comm.diagdata.req.saz", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_number_of_lines,
        { "Number of lines", "s7comm.diagdata.req.number_of_lines", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_diagdata_req_line_address,
        { "Address", "s7comm.diagdata.req.line_address", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

         /* Flags for requested registers in diagnostic data telegrams */
        { &hf_s7comm_diagdata_registerflag,
        { "Registers", "s7comm.diagdata.register", FT_UINT8, BASE_HEX, NULL, 0x00,
          "Requested registers", HFILL }},
        { &hf_s7comm_diagdata_registerflag_stw,
        { "STW", "s7comm.diagdata.register.stw", FT_BOOLEAN, 8, NULL, 0x01,
          "STW / Status word", HFILL }},
        { &hf_s7comm_diagdata_registerflag_accu1,
        { "ACCU1", "s7comm.diagdata.register.accu1", FT_BOOLEAN, 8, NULL, 0x02,
          "ACCU1 / Accumulator 1", HFILL }},
        { &hf_s7comm_diagdata_registerflag_accu2,
        { "ACCU2", "s7comm.diagdata.register.accu2", FT_BOOLEAN, 8, NULL, 0x04,
          "ACCU2 / Accumulator 2", HFILL }},
        { &hf_s7comm_diagdata_registerflag_ar1,
        { "AR1", "s7comm.diagdata.register.ar1", FT_BOOLEAN, 8, NULL, 0x08,
          "AR1 / Addressregister 1", HFILL }},
        { &hf_s7comm_diagdata_registerflag_ar2,
        { "AR2", "s7comm.diagdata.register.ar2", FT_BOOLEAN, 8, NULL, 0x10,
          "AR2 / Addressregister 2", HFILL }},
        { &hf_s7comm_diagdata_registerflag_db1,
        { "DB1", "s7comm.diagdata.register.db1", FT_BOOLEAN, 8, NULL, 0x20,
          "DB1 (global)/ Datablock register 1", HFILL }},
        { &hf_s7comm_diagdata_registerflag_db2,
        { "DB2", "s7comm.diagdata.register.db2", FT_BOOLEAN, 8, NULL, 0x40,
          "DB2 (instance) / Datablock register 2", HFILL }},

        /* timefunction: s7 timestamp */
        { &hf_s7comm_data_ts,
        { "S7 Timestamp", "s7comm.data.ts", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
          "S7 Timestamp, BCD coded", HFILL }},
        { &hf_s7comm_data_ts_reserved,
        { "S7 Timestamp - Reserved", "s7comm.data.ts_reserved", FT_UINT8, BASE_HEX, NULL, 0x00,
          "S7 Timestamp: Reserved byte", HFILL }},
        { &hf_s7comm_data_ts_year1,
        { "S7 Timestamp - Year 1", "s7comm.data.ts_year1", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded year thousands/hundreds, should be ignored (19 or 20)", HFILL }},
        { &hf_s7comm_data_ts_year2,
        { "S7 Timestamp - Year 2", "s7comm.data.ts_year2", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded year, if 00...89 then it's 2000...2089, else 1990...1999", HFILL }},
        { &hf_s7comm_data_ts_month,
        { "S7 Timestamp - Month", "s7comm.data.ts_month", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded month", HFILL }},
        { &hf_s7comm_data_ts_day,
        { "S7 Timestamp - Day", "s7comm.data.ts_day", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded day", HFILL }},
        { &hf_s7comm_data_ts_hour,
        { "S7 Timestamp - Hour", "s7comm.data.ts_hour", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded hour", HFILL }},
        { &hf_s7comm_data_ts_minute,
        { "S7 Timestamp - Minute", "s7comm.data.ts_minute", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded minute", HFILL }},
        { &hf_s7comm_data_ts_second,
        { "S7 Timestamp - Second", "s7comm.data.ts_second", FT_UINT8, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded second", HFILL }},
        { &hf_s7comm_data_ts_millisecond,
        { "S7 Timestamp - Milliseconds", "s7comm.data.ts_millisecond", FT_UINT16, BASE_DEC, NULL, 0x00,
          "S7 Timestamp: BCD coded milliseconds (left 3 nibbles)", HFILL }},
        { &hf_s7comm_data_ts_weekday,
        { "S7 Timestamp - Weekday", "s7comm.data.ts_weekday", FT_UINT16, BASE_DEC, VALS(weekdaynames), 0x000f,
          "S7 Timestamp: Weekday number (right nibble, 1=Su,2=Mo,..)", HFILL }},

        /* Function 0x28 (PLC control functions) ans 0x29 */
        { &hf_s7comm_data_plccontrol_part1_unknown,
        { "Part 1 unknown bytes", "s7comm.data.plccontrol.part1_unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_plccontrol_part1_len,
        { "Length part 1", "s7comm.data.plccontrol.part1_len", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Length of part 1 in bytes", HFILL }},
        { &hf_s7comm_data_plccontrol_argument,
        { "Argument", "s7comm.data.plccontrol.argument", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_plccontrol_block_cnt,
        { "Number of blocks", "s7comm.data.plccontrol.block_cnt", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_plccontrol_part1_unknown2,
        { "Unknown byte", "s7comm.data.plccontrol.part1_unknown2", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_plccontrol_block_unknown,
        { "Unknown char before Block type", "s7comm.data.plccontrol.block_unknown", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_plccontrol_block_type,
        { "Block type", "s7comm.data.plccontrol.block_type", FT_UINT8, BASE_DEC, VALS(blocktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_plccontrol_block_num,
        { "Block number", "s7comm.data.plccontrol.block_number", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_plccontrol_dest_filesys,
        { "Destination filesystem", "s7comm.data.plccontrol.dest_filesys", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_plccontrol_part2_len,
        { "Length part 2", "s7comm.data.plccontrol.part2_len", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length of part 2 in bytes", HFILL }},
        { &hf_s7comm_data_plccontrol_pi_service,
        { "PI (program invocation) Service", "s7comm.data.plccontrol.pi_service", FT_STRING, BASE_NONE, NULL, 0x0,
          "Known: _INSE = Activate a module, _DELE = Delete a passive module, _PROGRAM = Start/Stop the PLC, _PLC_MEMORYRESET = Reset the PLC memory" , HFILL }},

        /* block control functions */
        { &hf_s7comm_data_blockcontrol_unknown1,
        { "Unknown byte(s) in blockcontrol", "s7comm.data.blockcontrol.unknown1", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_errorcode,
        { "Errorcode", "s7comm.data.blockcontrol.errorcode", FT_UINT16, BASE_HEX, NULL, 0x0,
          "Errorcode, 0 on success", HFILL }},
        { &hf_s7comm_data_blockcontrol_part1_len,
        { "Length part 1", "s7comm.data.blockcontrol.part1_len", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length of part 1 in bytes", HFILL }},
        { &hf_s7comm_data_blockcontrol_file_ident,
        { "File identifier", "s7comm.data.blockcontrol.file_identifier", FT_STRING, BASE_NONE, NULL, 0x0,
          "File identifier: '_'=complete module; '$'=Module header for up-loading", HFILL }},
        { &hf_s7comm_data_blockcontrol_block_unknown,
        { "Unknown char before Block type", "s7comm.data.blockcontrol.block_unknown", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_block_type,
        { "Block type", "s7comm.data.blockcontrol.block_type", FT_UINT8, BASE_DEC, VALS(blocktype_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_block_num,
        { "Block number", "s7comm.data.blockcontrol.block_number", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_dest_filesys,
        { "Destination filesystem", "s7comm.data.blockcontrol.dest_filesys", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_part2_len,
        { "Length part 2", "s7comm.data.blockcontrol.part2_len", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length of part 2 in bytes", HFILL }},
        { &hf_s7comm_data_blockcontrol_part2_unknown,
        { "Unknown char before load mem", "s7comm.data.blockcontrol.part2_unknown", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_data_blockcontrol_loadmem_len,
        { "Length of load memory", "s7comm.data.blockcontrol.loadmem_len", FT_STRING, BASE_NONE, NULL, 0x0,
          "Length of load memory in bytes", HFILL }},
        { &hf_s7comm_data_blockcontrol_mc7code_len,
        { "Length of MC7 code", "s7comm.data.blockcontrol.mc7code_len", FT_STRING, BASE_NONE, NULL, 0x0,
          "Length of MC7 code in bytes", HFILL }},

        /* Variable table */
        { &hf_s7comm_vartab_data_type,
        { "Type of data", "s7comm.vartab.data_type", FT_UINT8, BASE_DEC, VALS(userdata_prog_vartab_type_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_vartab_byte_count,
        { "Byte count", "s7comm.vartab.byte_count", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_vartab_unknown,
        { "Unknown byte(s) vartab", "s7comm.vartab.unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_vartab_item_count,
        { "Item count", "s7comm.vartab.item_count", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_vartab_req_memory_area,
        { "Memory area", "s7comm.vartab.req.memory_area", FT_UINT8, BASE_DEC, VALS(userdata_prog_vartab_area_names), 0x0,
          NULL, HFILL }},
        { &hf_s7comm_vartab_req_repetition_factor,
        { "Repetition factor", "s7comm.vartab.req.repetition_factor", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_vartab_req_db_number,
        { "DB number", "s7comm.vartab.req.db_number", FT_UINT16, BASE_DEC, NULL, 0x0,
          "DB number, when area is DB", HFILL }},
        { &hf_s7comm_vartab_req_startaddress,
        { "Startaddress", "s7comm.vartab.req.startaddress", FT_UINT16, BASE_DEC, NULL, 0x0,
          "Startaddress / byteoffset", HFILL }},

        /* cyclic data */
        { &hf_s7comm_cycl_interval_timebase,
        { "Interval timebase", "s7comm.cyclic.interval_timebase", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_cycl_interval_time,
        { "Interval time", "s7comm.cyclic.interval_time", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        /* PBC, Programmable Block Functions */
        { &hf_s7comm_pbc_unknown,
        { "PBC BSEND/BRECV unknown", "s7comm.pbc.bsend.unknown", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_pbc_r_id,
        { "PBC BSEND/BRECV R_ID", "s7comm.pbc.req.bsend.r_id", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        /* TIA Portal stuff */
        { &hf_s7comm_tia1200_item_reserved1,
        { "1200 sym Reserved", "s7comm.tiap.item.reserved1", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tia1200_item_area1,
        { "1200 sym root area 1", "s7comm.tiap.item.area1", FT_UINT16, BASE_HEX, VALS(tia1200_var_item_area1_names), 0x0,
          "Area from where to read: DB or Inputs, Outputs, etc.", HFILL }},
        { &hf_s7comm_tia1200_item_area2,
        { "1200 sym root area 2", "s7comm.tiap.item.area2", FT_UINT16, BASE_HEX, VALS(tia1200_var_item_area2_names), 0x0,
          "Specifies the area from where to read", HFILL }},
        { &hf_s7comm_tia1200_item_area2unknown,
        { "1200 sym root area 2 unknown", "s7comm.tiap.item.area2unknown", FT_UINT16, BASE_HEX, NULL, 0x0,
          "For current unknown areas", HFILL }},
        { &hf_s7comm_tia1200_item_dbnumber,
        { "1200 sym root DB number", "s7comm.tiap.item.dbnumber", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tia1200_item_crc,
        { "1200 sym CRC", "s7comm.tiap.item.crc", FT_UINT32, BASE_HEX, NULL, 0x0,
          "CRC generated out of symbolic name with (x^32+x^31+x^30+x^29+x^28+x^26+x^23+x^21+x^19+x^18+x^15+x^14+x^13+x^12+x^9+x^8+x^4+x+1)", HFILL }},
        { &hf_s7comm_tia1200_var_lid_flags,
        { "LID flags", "s7comm.tiap.item.lid_flags", FT_UINT8, BASE_DEC, VALS(tia1200_var_lid_flag_names), 0xf0,
          NULL, HFILL }},
        { &hf_s7comm_tia1200_substructure_item,
        { "Substructure", "s7comm.tiap.item.substructure", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
        { &hf_s7comm_tia1200_item_value,
        { "Value", "s7comm.tiap.item.value", FT_UINT32, BASE_DEC, NULL, 0x0fffffff,
          NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_s7comm,
        &ett_s7comm_header,
        &ett_s7comm_param,
        &ett_s7comm_param_item,
        &ett_s7comm_param_subitem,
        &ett_s7comm_data,
        &ett_s7comm_data_item,
        &ett_s7comm_item_address,
        &ett_s7comm_diagdata_registerflag,
        &ett_s7comm_userdata_blockinfo_flags,
    };

    proto_s7comm = proto_register_protocol (
            "S7 Communication",         /* name */
            "S7COMM",                   /* short name */
            "s7comm"                    /* abbrev */
            );

    proto_register_field_array(proto_s7comm, hf, array_length (hf));

    s7comm_register_szl_types(proto_s7comm);

    proto_register_subtree_array(ett, array_length (ett));
}

/* Register this protocol */
void
proto_reg_handoff_s7comm(void)
{
    /* register ourself as an heuristic cotp (ISO 8073) payload dissector */
    heur_dissector_add("cotp", dissect_s7comm, "S7 Communication over COTP", "s7comm_cotp", proto_s7comm, HEURISTIC_ENABLE);
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
