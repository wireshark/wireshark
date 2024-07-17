/* packet-cemi.c
 * Routines for cEMI (Common External Message Interface) dissection
 * By Jan Kessler <kessler@ise.de>
 * Copyright 2004, Jan Kessler <kessler@ise.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-knxip.h"

void proto_register_cemi(void);
void proto_reg_handoff_cemi(void);

/* cEMI Message Codes
*/
#define CEMI_L_BUSMON_IND     0x2B
#define CEMI_L_RAW_IND        0x2D
#define CEMI_L_RAW_REQ        0x10
#define CEMI_L_RAW_CON        0x2F
#define CEMI_L_DATA_REQ       0x11
#define CEMI_L_DATA_CON       0x2E
#define CEMI_L_DATA_IND       0x29
#define CEMI_L_POLL_DATA_REQ  0x13
#define CEMI_L_POLL_DATA_CON  0x25
#define CEMI_T_DATA_INDIVIDUAL_REQ 0x4A
#define CEMI_T_DATA_INDIVIDUAL_IND 0x94
#define CEMI_T_DATA_CONNECTED_REQ 0x41
#define CEMI_T_DATA_CONNECTED_IND 0x89
#define CEMI_M_PROPREAD_REQ   0xFC
#define CEMI_M_PROPREAD_CON   0xFB
#define CEMI_M_PROPWRITE_REQ  0xF6
#define CEMI_M_PROPWRITE_CON  0xF5
#define CEMI_M_PROPINFO_IND   0xF7
#define CEMI_M_FUNCPROPCMD_REQ  0xF8
#define CEMI_M_FUNCPROPREAD_REQ  0xF9
#define CEMI_M_FUNCPROP_CON   0xFA
#define CEMI_M_RESET_REQ      0xF1
#define CEMI_M_RESET_IND      0xF0

/* Additional Information Types
*/
                                    /* 0x00  Reserved. */
#define CEMI_PL_MEDIUM_INFORMATION     0x01  /*!< (2 octets) Domain Address used by PL medium; Client <-> Server */
#define CEMI_RF_MEDIUM_INFORMATION     0x02  /*!< (7 octet)  RF-Control byte and serial number/DoA;
                                                             Client <-> Server Busmonitor */
#define CEMI_STATUS_INFO               0x03  /*!< (1 octet)  Busmonitor Error Flags; see clause 2.5.5.5; Client <- Server */
#define CEMI_TIMESTAMP_RELATIVE        0x04  /*!< (2 octets) Relative timestamp; e.g. for L_Raw.ind; Client <- Server */
#define CEMI_TIME_DELAY_UNTIL_SENDING  0x05  /*!< (4 octets) Time delay (L_Raw.req, see clause 2.5.5.3); Client <- Server */
                                    /* 0x06-0xFE  Not used. */
                                    /* 0xFF       For future system extension (ESC Code). */

/* Error Codes
*/
#define CEMI_UNSPECIFIED_ERROR       0x00  /*!< Unknown error (R/W). */
#define CEMI_OUT_OF_RANGE            0x01  /*!< Write value not allowed (general, if not error 2 or 3) (W). */
#define CEMI_OUT_OF_MAXRANGE         0x02  /*!< Write value to high (W). */
#define CEMI_OUT_OF_MINRANGE         0x03  /*!< Write value to low (W). */
#define CEMI_MEMORY_ERROR            0x04  /*!< Memory can not be written or only with fault(s) (W). */
#define CEMI_READ_ONLY               0x05  /*!< Write access to a 'read only' or a write protected property (W). */
#define CEMI_ILLEGAL_COMMAND         0x06  /*!< COMMAND not valid or not supported (W). */
#define CEMI_VOID_DP                 0x07  /*!< Read or write access to an non existing property (R/W). */
#define CEMI_TYPE_CONFLICT           0x08  /*!< Write access with a wrong data type (datapoint length) (W). */
#define CEMI_PROP_INDEX_RANGE_ERROR  0x09  /* Read or write access to a non existing property array index (R/W). */

/* Common EMI specific device server properties
*/
#define CEMI_PID_DOMAIN_ADDRESS  0x70  /*!< Domain Address of a PL medium (cEMI server) device.
                                            PDT_UNSIGNED_INT O - r/w */
#define CEMI_PID_IO_LIST         0x71  /*!< List of Interface Objects in the (cEMI server) device.
                                            PDT_UNSIGNED_INT O - r/w */

#define CEMI_PID_MEDIUM_TYPE          0x51  /*!< Media Type(s) supported by cEMI server.
                                                 DPT_Media M - read only */
#define CEMI_PID_COMM_MODE            0x52  /*!< Link Layer / Raw (Busmonitor) / Transport L.
                                                 DPT_CommMode O - r/w */
#define CEMI_PID_MEDIUM_AVAILABILITY  0x53  /*!< Bus available (1) or not (0) ?
                                                 DPT_Media O - read only */
#define CEMI_PID_ADD_INFO_TYPES       0x54  /*!< cEMI supported Additional Information Types.
                                                 DPT_AddInfoTypes O - read only */
#define CEMI_PID_TRANSP_ENABLE        0x56  /*!< LL Transparency Mode of cEMI server.
                                                 DPT_Enable O - r/w */
                                   /* 0x57  Reserved for cEMI client's subnetwork address.
                                            PDT_UNSIGNED_CHAR O - r/w */
                                   /* 0x58  Reserved for cEMI client's device address.
                                            PDT_UNSIGNED_CHAR O - r/w */
                                   /* 0x59  t.b.d.*/
                                   /* 0x60  t.b.d.*/
                                   /* 0x61  DoA Filter. t.b.d. O - read only */

#define CEMI_PID_MEDIUM_TYPE_TP0    0x0001  /*!< TP 0 */
#define CEMI_PID_MEDIUM_TYPE_TP1    0x0002  /*!< TP 1 */
#define CEMI_PID_MEDIUM_TYPE_PL110  0x0004  /*!< PL 110 */
#define CEMI_PID_MEDIUM_TYPE_PL132  0x0008  /*!< PL 132 */
#define CEMI_PID_MEDIUM_TYPE_RF     0x0010  /*!< RF */

#define CEMI_PID_COMM_MODE_LL   0x00  /*!< Link Layer = default comm. mode. */
#define CEMI_PID_COMM_MODE_LLB  0x01  /*!< Link Layer Busmonitor. */
#define CEMI_PID_COMM_MODE_LLR  0x02  /*!< Link Layer Raw Frames. */
                             /* 0x03  Reserved for Network Layer. */
                             /* 0x04  Reserved for TL group oriented. */
                             /* 0x05  Reserved for TL connection oriented. */
                             /* 0x05-0xFF  Reserved for other 'destination layers'. */

/* - - - - - - -  T R E E   V I E W   I D E N T I F I E R  - - - - - - - -
*/

/* Initialize the protocol identifier that is needed for the
 protocol hook and to register the fields in the protocol tree
*/
static int proto_cemi;

/* Initialize the registered fields identifiers. These fields
 will be registered with the protocol during initialization.
 Protocol fields are like type definitions. The protocol dissector
 later on adds items of these types to the protocol tree.
*/
static int hf_bytes;
static int hf_folder;
static int hf_cemi_mc;
static int hf_cemi_error;
static int hf_cemi_ai_length;
static int hf_cemi_aie_type;
static int hf_cemi_aie_length;
static int hf_cemi_ot;
static int hf_cemi_oi;
static int hf_cemi_ox;
static int hf_cemi_px;
static int hf_cemi_pid;
static int hf_cemi_ne;
static int hf_cemi_sx;
static int hf_cemi_ft;
static int hf_cemi_rep;
static int hf_cemi_bt;
static int hf_cemi_prio;
static int hf_cemi_ack;
static int hf_cemi_ce;
static int hf_cemi_at;
static int hf_cemi_hc;
static int hf_cemi_eff;
static int hf_cemi_sa;
static int hf_cemi_da;
static int hf_cemi_len;
static int hf_cemi_tpt;
static int hf_cemi_tst;
static int hf_cemi_num;
static int hf_cemi_tc;
static int hf_cemi_ac;
static int hf_cemi_ad;
static int hf_cemi_ad_memory_length;
static int hf_cemi_ad_channel;
static int hf_cemi_ad_type;
static int hf_cemi_ax;
static int hf_cemi_pw;
static int hf_cemi_pdt;
static int hf_cemi_me;
static int hf_cemi_ra;
static int hf_cemi_wa;
static int hf_cemi_ext_oi;
static int hf_cemi_ext_pid;
static int hf_cemi_ext_ne;
static int hf_cemi_ext_sx;
static int hf_cemi_ext_dt;
static int hf_cemi_ext_px;
static int hf_cemi_ext_memory_length;
static int hf_cemi_ext_memory_address;
static int hf_cemi_memory_length;
static int hf_cemi_memory_address;
static int hf_cemi_memory_address_ext;
static int hf_cemi_level;
static int hf_cemi_snp_pid;
static int hf_cemi_snp_reserved;
static int hf_cemi_dpt_major;
static int hf_cemi_dpt_minor;
static int hf_cemi_scf;
static int hf_cemi_scf_t;
static int hf_cemi_scf_sai;
static int hf_cemi_scf_sbc;
static int hf_cemi_scf_svc;
static int hf_cemi_adc_count;

/* Initialize the subtree pointers. These pointers are needed to
 display the protocol in a structured tree. Subtrees hook on
 already defined fields or (the topmost) on the protocol itself
*/
static int ett_cemi;
static int ett_cemi_ai;
static int ett_cemi_aie;
static int ett_cemi_ctrl1;
static int ett_cemi_ctrl2;
static int ett_cemi_tpci;
static int ett_cemi_apci;
static int ett_cemi_range;
static int ett_cemi_pd;
static int ett_cemi_dpt;
static int ett_cemi_scf;
static int ett_cemi_decrypted;

/* - - - - - - - - - - -  V A L U E   T A B L E S  - - - - - - - - - - - -
*/

/* See following docs:

  "AN033 v03 cEMI.pdf",
  "AN057 v01 System B RfV.pdf",
  "KSG259 2004.02.03 Identifiers.pdf",
  "03_07_03 Standardized Identifier Tables.pdf"
*/

/* Message Code
*/
static const value_string mc_vals[] = {
  { CEMI_L_BUSMON_IND, "L_Busmon.ind" },
  { CEMI_L_RAW_IND, "L_Raw.ind" },
  { CEMI_L_RAW_REQ, "L_Raw.req" },
  { CEMI_L_RAW_CON, "L_Raw.con" },
  { CEMI_L_DATA_REQ, "L_Data.req" },
  { CEMI_L_DATA_CON, "L_Data.con" },
  { CEMI_L_DATA_IND, "L_Data.ind" },
  { CEMI_L_POLL_DATA_REQ, "L_PollData.req" },
  { CEMI_L_POLL_DATA_CON, "L_PollData.con" },
  { CEMI_T_DATA_INDIVIDUAL_REQ, "T_Data_Individual.req" },
  { CEMI_T_DATA_INDIVIDUAL_IND, "T_Data_Individual.ind" },
  { CEMI_T_DATA_CONNECTED_REQ, "T_Data_Connected.req" },
  { CEMI_T_DATA_CONNECTED_IND, "T_Data_Connected.ind" },
  { CEMI_M_PROPREAD_REQ, "M_PropRead.req" },
  { CEMI_M_PROPREAD_CON, "M_PropRead.con" },
  { CEMI_M_PROPWRITE_REQ, "M_PropWrite.req" },
  { CEMI_M_PROPWRITE_CON, "M_PropWrite.con" },
  { CEMI_M_PROPINFO_IND, "M_PropInfo.ind" },
  { CEMI_M_FUNCPROPCMD_REQ, "M_FuncPropCmd.req" },
  { CEMI_M_FUNCPROPREAD_REQ, "M_FuncPropRead.req" },
  { CEMI_M_FUNCPROP_CON, "M_FuncProp.con" },
  { CEMI_M_RESET_REQ, "M_Reset.req" },
  { CEMI_M_RESET_IND, "M_Reset.ind" },
  { 0, NULL }
};

/* Property access flags
*/
#define PA_RESPONSE     0x01
#define PA_DATA         0x02

/* Additional Info Element Type
*/
static const value_string aiet_vals[] = {
  { 1, "PL Medium Info" },
  { 2, "RF Medium Info" },
  { 3, "BusMonitor Status Info" },
  { 4, "Timestamp Relative" },
  { 5, "Time Delay Until Sending" },
  { 6, "Extended Relative Timestamp" },
  { 7, "BiBat Info" },
  { 0, NULL }
};

/* Frame Type
*/
static const value_string ft_vals[] = {
  { 0, "Extended" },
  { 1, "Standard" },
  { 0, NULL }
};

/* Broadcast Type
*/
static const value_string bt_vals[] = {
  { 0, "System" },
  { 1, "Domain" },
  { 0, NULL }
};

/* Priority
*/
static const value_string prio_vals[] = {
  { 0, "System" },
  { 2, "Urgent" },
  { 1, "Normal" },
  { 3, "Low" },
  { 0, NULL }
};

/* Address Type
*/
static const value_string at_vals[] = {
  { 0, "Individual" },
  { 1, "Group" },
  { 0, NULL }
};

/* Packet Type
*/
static const value_string pt_vals[] = {
  { 0, "Data" },
  { 1, "Control" },
  { 0, NULL }
};

/* Sequence Type
*/
static const value_string st_vals[] = {
  { 0, "Unnumbered" },
  { 1, "Numbered" },
  { 0, NULL }
};

/* Transport Layer Code
*/
static const value_string tc_vals[] = {
  { 0, "Connect" },
  { 1, "Disconnect" },
  { 2, "ACK" },
  { 3, "NAK" },
  { 0, NULL }
};

/* Application Layer Code
*/
#define AC_GroupValueRead     0
#define AC_GroupValueResp     1
#define AC_GroupValueWrite    2
#define AC_IndAddrWrite       3
#define AC_IndAddrRead        4
#define AC_IndAddrResp        5
#define AC_AdcRead            6
#define AC_AdcResp            7
#define AC_MemRead            8
#define AC_MemResp            9
#define AC_MemWrite           10
#define AC_UserMsg            11
#define AC_DevDescrRead       12
#define AC_DevDescrResp       13
#define AC_Restart            14
#define AC_Escape             15

static const value_string ac_vals[] =
{
  { AC_GroupValueRead, "GroupValueRead" },
  { AC_GroupValueResp, "GroupValueResp" },
  { AC_GroupValueWrite, "GroupValueWrite" },
  { AC_IndAddrWrite, "IndAddrWrite" },
  { AC_IndAddrRead, "IndAddrRead" },
  { AC_IndAddrResp, "IndAddrResp" },
  { AC_AdcRead, "AdcRead" },
  { AC_AdcResp, "AdcResp" },
  { AC_MemRead, "MemRead" },
  { AC_MemResp, "MemResp" },
  { AC_MemWrite, "MemWrite" },
  { AC_UserMsg, "UserMsg" },
  { AC_DevDescrRead, "DevDescrRead" },
  { AC_DevDescrResp, "DevDescrResp" },
  { AC_Restart, "Restart" },
  { AC_Escape, "Escape" },
  { 0, NULL }
};

/* Extended AL codes
*/
#define AX_SysNwkParamRead  0x1C8
#define AX_SysNwkParamResp  0x1C9
#define AX_SysNwkParamWrite  0x1CA
#define AX_PropExtValueRead  0x1CC
#define AX_PropExtValueResp  0x1CD
#define AX_PropExtValueWriteCon  0x1CE
#define AX_PropExtValueWriteConRes  0x1CF
#define AX_PropExtValueWriteUnCon  0x1D0
#define AX_PropExtValueInfoReport  0x1D1
#define AX_PropExtDescrRead  0x1D2
#define AX_PropExtDescrResp  0x1D3
#define AX_FuncPropExtCmd  0x1D4
#define AX_FuncPropExtRead  0x1D5
#define AX_FuncPropExtResp  0x1D6
#define AX_MemExtWrite  0x1FB
#define AX_MemExtWriteResp  0x1FC
#define AX_MemExtRead  0x1FD
#define AX_MemExtReadResp  0x1FE
#define AX_UserMemRead  0x2C0
#define AX_UserMemResp  0x2C1
#define AX_UserMemWrite  0x2C2
#define AX_UserMemBitWrite  0x2C4
#define AX_UserMfrInfoRead  0x2C5
#define AX_UserMfrInfoResp  0x2C6
#define AX_FuncPropCmd  0x2C7
#define AX_FuncPropRead  0x2C8
#define AX_FuncPropResp  0x2C9
#define AX_Restart  0x380
#define AX_RestartReq  0x381
#define AX_RestartResp  0x3A1
#define AX_RoutingTableOpen  0x3C0
#define AX_RoutingTableRead  0x3C1
#define AX_RoutingTableResp  0x3C2
#define AX_RoutingTableWrite  0x3C3
#define AX_RouterMemRead  0x3C8
#define AX_RouterMemResp  0x3C9
#define AX_RouterMemWrite  0x3CA
#define AX_RouterStatusRead  0x3CD
#define AX_RouterStatusResp  0x3CE
#define AX_RouterStatusWrite  0x3CF
#define AX_MemBitWrite  0x3D0
#define AX_AuthReq  0x3D1
#define AX_AuthResp  0x3D2
#define AX_KeyWrite  0x3D3
#define AX_KeyResp  0x3D4
#define AX_PropValueRead  0x3D5
#define AX_PropValueResp  0x3D6
#define AX_PropValueWrite  0x3D7
#define AX_PropDescrRead  0x3D8
#define AX_PropDescrResp  0x3D9
#define AX_NwkParamRead  0x3DA
#define AX_NwkParamResp  0x3DB
#define AX_IndAddrSerNumRead  0x3DC
#define AX_IndAddrSerNumResp  0x3DD
#define AX_IndAddrSerNumWrite  0x3DE
#define AX_DomAddrWrite  0x3E0
#define AX_DomAddrRead  0x3E1
#define AX_DomAddrResp  0x3E2
#define AX_DomAddrSelRead  0x3E3
#define AX_NwkParamWrite  0x3E4
#define AX_LinkRead  0x3E5
#define AX_LinkResp  0x3E6
#define AX_LinkWrite  0x3E7
#define AX_GroupPropValueRead  0x3E8
#define AX_GroupPropValueResp  0x3E9
#define AX_GroupPropValueWrite  0x3EA
#define AX_GroupPropValueInfo  0x3EB
#define AX_DomAddrSerNumRead  0x3EC
#define AX_DomAddrSerNumResp  0x3ED
#define AX_DomAddrSerNumWrite  0x3EE
#define AX_FileStreamInfo  0x3F0
#define AX_DataSec  0x3F1

static const value_string ax_vals[] =
{
  { AX_SysNwkParamRead, "SysNwkParamRead" },
  { AX_SysNwkParamResp, "SysNwkParamResp" },
  { AX_SysNwkParamWrite, "SysNwkParamWrite" },
  { AX_PropExtValueRead, "PropExtValueRead" },
  { AX_PropExtValueResp, "PropExtValueResp" },
  { AX_PropExtValueWriteCon, "PropExtValueWriteCon" },
  { AX_PropExtValueWriteConRes, "PropExtValueWriteConRes" },
  { AX_PropExtValueWriteUnCon, "PropExtValueWriteUnCon" },
  { AX_PropExtDescrRead, "PropExtDescrRead" },
  { AX_PropExtDescrResp, "PropExtDescrResp" },
  { AX_FuncPropExtCmd, "FuncPropExtCmd" },
  { AX_FuncPropExtRead, "FuncPropExtRead" },
  { AX_FuncPropExtResp, "FuncPropExtResp" },
  { AX_MemExtWrite, "MemExtWrite" },
  { AX_MemExtWriteResp, "MemExtWriteResp" },
  { AX_MemExtRead, "MemExtRead" },
  { AX_MemExtReadResp, "MemExtReadResp" },
  { AX_UserMemRead, "UserMemRead" },
  { AX_UserMemResp, "UserMemResp" },
  { AX_UserMemWrite, "UserMemWrite" },
  { AX_UserMemBitWrite, "UserMemBitWrite" },
  { AX_UserMfrInfoRead, "UserMfrInfoRead" },
  { AX_UserMfrInfoResp, "UserMfrInfoResp" },
  { AX_FuncPropCmd, "FuncPropCmd" },
  { AX_FuncPropRead, "FuncPropRead" },
  { AX_FuncPropResp, "FuncPropResp" },
  { AX_Restart, "Restart" },
  { AX_RestartReq, "RestartReq" },
  { AX_RestartResp, "RestartResp" },
  { AX_RoutingTableOpen, "RoutingTableOpen" },
  { AX_RoutingTableRead, "RoutingTableRead" },
  { AX_RoutingTableResp, "RoutingTableResp" },
  { AX_RoutingTableWrite, "RoutingTableWrite" },
  { AX_RouterMemRead, "RouterMemRead" },
  { AX_RouterMemResp, "RouterMemResp" },
  { AX_RouterMemWrite, "RouterMemWrite" },
  { AX_RouterStatusRead, "RouterStatusRead" },
  { AX_RouterStatusResp, "RouterStatusResp" },
  { AX_RouterStatusWrite, "RouterStatusWrite" },
  { AX_MemBitWrite, "MemBitWrite" },
  { AX_AuthReq, "AuthReq" },
  { AX_AuthResp, "AuthResp" },
  { AX_KeyWrite, "KeyWrite" },
  { AX_KeyResp, "KeyResp" },
  { AX_PropValueRead, "PropValueRead" },
  { AX_PropValueResp, "PropValueResp" },
  { AX_PropValueWrite, "PropValueWrite" },
  { AX_PropDescrRead, "PropDescrRead" },
  { AX_PropDescrResp, "PropDescrResp" },
  { AX_NwkParamRead, "NwkParamRead" },
  { AX_NwkParamResp, "NwkParamResp" },
  { AX_IndAddrSerNumRead, "IndAddrSerNumRead" },
  { AX_IndAddrSerNumResp, "IndAddrSerNumResp" },
  { AX_IndAddrSerNumWrite, "IndAddrSerNumWrite" },
  { AX_DomAddrWrite, "DomAddrWrite" },
  { AX_DomAddrRead, "DomAddrRead" },
  { AX_DomAddrResp, "DomAddrResp" },
  { AX_DomAddrSelRead, "DomAddrSelRead" },
  { AX_NwkParamWrite, "NwkParamWrite" },
  { AX_LinkRead, "LinkRead" },
  { AX_LinkResp, "LinkResp" },
  { AX_LinkWrite, "LinkWrite" },
  { AX_GroupPropValueRead, "GroupPropValueRead" },
  { AX_GroupPropValueResp, "GroupPropValueResp" },
  { AX_GroupPropValueWrite, "GroupPropValueWrite" },
  { AX_GroupPropValueInfo, "GroupPropValueInfo" },
  { AX_DomAddrSerNumRead, "DomAddrSerNumRead" },
  { AX_DomAddrSerNumResp, "DomAddrSerNumResp" },
  { AX_DomAddrSerNumWrite, "DomAddrSerNumWrite" },
  { AX_FileStreamInfo, "FileStreamInfo" },
  { AX_DataSec, "DataSec" },
  { 0, NULL }
};

/* SCF (Security Control Field)
*/
static const value_string scf_vals[] =
{
  { 0x00, "CCM S-A_Data with Authentication-only" },
  { 0x10, "CCM S-A_Data with Authentication+Confidentiality" },
  { 0x12, "CCM S-A_Sync_Req with Authentication+Confidentiality" },
  { 0x13, "CCM S-A_Sync_Res with Authentication+Confidentiality" },
  { 0x08, "CCM S-A_Data with Authentication-only, System Broadcast" },
  { 0x18, "CCM S-A_Data with Authentication+Confidentiality, System Broadcast" },
  { 0x1a, "CCM S-A_Sync_Req with Authentication+Confidentiality, System Broadcast" },
  { 0x1b, "CCM S-A_Sync_Res with Authentication+Confidentiality, System Broadcast" },
  { 0x80, "CCM S-A_Data with Authentication-only, Tool Access" },
  { 0x90, "CCM S-A_Data with Authentication+Confidentiality, Tool Access" },
  { 0x92, "CCM S-A_Sync_Req with Authentication+Confidentiality, Tool Access" },
  { 0x93, "CCM S-A_Sync_Res with Authentication+Confidentiality, Tool Access" },
  { 0x88, "CCM S-A_Data with Authentication-only, System Broadcast, Tool Access" },
  { 0x98, "CCM S-A_Data with Authentication+Confidentiality, Tool Access, System Broadcast" },
  { 0x9a, "CCM S-A_Sync_Req with Authentication+Confidentiality, Tool Access, System Broadcast" },
  { 0x9b, "CCM S-A_Sync_Res with Authentication+Confidentiality, Tool Access, System Broadcast" },
  { 0, NULL }
};

/* SCF (Security Control Field).
*/
static const value_string scf_short_vals[] =
{
  { 0x00, "Data+A" },
  { 0x10, "Data+A+C" },
  { 0x12, "SyncReq" },
  { 0x13, "SyncRes" },
  { 0x08, "Data+A+SBC" },
  { 0x18, "Data+A+C+SBC" },
  { 0x1a, "SyncReq+SBC" },
  { 0x1b, "SyncRes+SBC" },
  { 0x80, "Data+A+T" },
  { 0x90, "Data+A+C+T" },
  { 0x92, "SyncReq+T" },
  { 0x93, "SyncRes+T" },
  { 0x88, "Data+A+T+SBC" },
  { 0x98, "Data+A+C+T+SBC" },
  { 0x9a, "SyncReq+T+SBC" },
  { 0x9b, "SyncRes+T+SBC" },
  { 0, NULL }
};

/* SCF.SAI (Security Algorithm Identifier)
*/
static const value_string scf_sai_vals[] =
{
  { 0, "CCM A" },
  { 1, "CCM A+S" },
  { 0, NULL }
};

/* SCF.Service
*/
static const value_string scf_svc_vals[] =
{
  { 0, "Data" },
  { 2, "Sync_Req" },
  { 3, "Sync_Res" },
  { 0, NULL }
};

/* See KNX documents:
* "03_07_03 Standardized Identifier Tables v01.03.01 AS"
* "03_05_01 Resources v01.09.03 AS"
*/

/* Property Data Types
* See "4 Property Datatypes Identifiers" in "03_07_03 Standardized Identifier Tables v01.03.01 AS"
*/
static const value_string pdt_vals[] = {
  { 0x00, "PDT_CONTROL" },
  { 0x01, "PDT_CHAR" },
  { 0x02, "PDT_UNSIGNED_CHAR" },
  { 0x03, "PDT_INT" },
  { 0x04, "PDT_UNSIGNED_INT" },
  { 0x05, "PDT_KNX_FLOAT" },
  { 0x06, "PDT_DATE" },
  { 0x07, "PDT_TIME" },
  { 0x08, "PDT_LONG" },
  { 0x09, "PDT_UNSIGNED_LONG" },
  { 0x0A, "PDT_FLOAT" },
  { 0x0B, "PDT_DOUBLE" },
  { 0x0C, "PDT_CHAR_BLOCK" },
  { 0x0D, "PDT_POLL_GROUP_SETTINGS" },
  { 0x0E, "PDT_SHORT_CHAR_BLOCK" },
  { 0x0F, "PDT_DATE_TIME" },
  { 0x10, "PDT_VARIABLE_LENGTH" },
  { 0x11, "PDT_GENERIC_01" },
  { 0x12, "PDT_GENERIC_02" },
  { 0x13, "PDT_GENERIC_03" },
  { 0x14, "PDT_GENERIC_04" },
  { 0x15, "PDT_GENERIC_05" },
  { 0x16, "PDT_GENERIC_06" },
  { 0x17, "PDT_GENERIC_07" },
  { 0x18, "PDT_GENERIC_08" },
  { 0x19, "PDT_GENERIC_09" },
  { 0x1A, "PDT_GENERIC_10" },
  { 0x1B, "PDT_GENERIC_11" },
  { 0x1C, "PDT_GENERIC_12" },
  { 0x1D, "PDT_GENERIC_13" },
  { 0x1E, "PDT_GENERIC_14" },
  { 0x1F, "PDT_GENERIC_15" },
  { 0x20, "PDT_GENERIC_16" },
  { 0x21, "PDT_GENERIC_17" },
  { 0x22, "PDT_GENERIC_18" },
  { 0x23, "PDT_GENERIC_19" },
  { 0x24, "PDT_GENERIC_20" },
  { 0x2F, "PDT_UTF-8" },
  { 0x30, "PDT_VERSION" },
  { 0x31, "PDT_ALARM_INFO" },
  { 0x32, "PDT_BINARY_INFORMATION" },
  { 0x33, "PDT_BITSET8" },
  { 0x34, "PDT_BITSET16" },
  { 0x35, "PDT_ENUM8" },
  { 0x36, "PDT_SCALING" },
  { 0x3C, "PDT_NE_VL" },
  { 0x3D, "PDT_NE_FL" },
  { 0x3E, "PDT_FUNCTION" },
  { 0x3F, "PDT_ESCAPE" },
  { 0, NULL }
};

/* Interface Object Types
* See "2 Interface Object Types" in "03_07_03 Standardized Identifier Tables v01.03.01 AS"
*/
static const value_string ot_vals[] = {
  { 0, "Device" },
  { 1, "Address Table" },
  { 2, "Association Table" },
  { 3, "Application Program" },
  { 4, "Interface Program" },
  { 5, "KNX-Object Association Table" },
  { 6, "Router" },
  { 7, "LTE Address Routing Table" },
  { 8, "cEMI Server" },
  { 9, "Group Object Table" },
  { 10, "Polling Master" },
  { 11, "KNXnet/IP Parameter" },
  { 13, "File Server" },
  { 17, "Data Security" },
  { 0, NULL }
};

/* IOT independent PIDs
* See "3.2 Interface Object Type independent standard Properties" in "03_07_03 Standardized Identifier Tables v01.03.01 AS"
* See "4.2 Interface Object Type independent Properties" in "03_05_01 Resources v01.09.03 AS"
*/
static const value_string pid_vals[] = {
  { 1, "PID_OBJECT_TYPE" },
  { 2, "PID_OBJECT_NAME" },
  { 3, "PID_SEMAPHOR" },
  { 4, "PID_GROUP_OBJECT_REFERENCE" },
  { 5, "PID_LOAD_STATE_CONTROL" },
  { 6, "PID_RUN_STATE_CONTROL" },
  { 7, "PID_TABLE_REFERENCE" },
  { 8, "PID_SERVICE_CONTROL" },
  { 9, "PID_FIRMWARE_REVISION" },
  { 10, "PID_SERVICES_SUPPORTED" },
  { 11, "PID_SERIAL_NUMBER" },
  { 12, "PID_MANUFACTURER_ID" },
  { 13, "PID_PROGRAM_VERSION" },
  { 14, "PID_DEVICE_CONTROL" },
  { 15, "PID_ORDER_INFO" },
  { 16, "PID_PEI_TYPE" },
  { 17, "PID_PORT_CONFIGURATION" },
  { 18, "PID_POLL_GROUP_SETTINGS" },
  { 19, "PID_MANUFACTURER_DATA" },
  { 21, "PID_DESCRIPTION" },
  { 23, "PID_TABLE" },
  { 24, "PID_ENROL" },
  { 25, "PID_VERSION" },
  { 26, "PID_GROUP_OBJECT_LINK" },
  { 27, "PID_MCB_TABLE" },
  { 28, "PID_ERROR_CODE" },
  { 29, "PID_OBJECT_INDEX" },
  { 30, "PID_DOWNLOAD_COUNTER" },
  { 0, NULL }
};

/* PIDs for IOT = 0 (Device)
* See "3.3.1 Device Object Interface Object (Object Type = 0)" in "03_07_03 Standardized Identifier Tables v01.03.01 AS"
* See "4.3 Device Object (Object Type 0)" in "03_05_01 Resources v01.09.03 AS"
*/
static const value_string pid0_vals[] = {
  { 51, "PID_ROUTING_COUNT" },
  { 52, "PID_MAX_RETRY_COUNT" },
  { 53, "PID_ERROR_FLAGS" },
  { 54, "PID_PROGMODE" },
  { 55, "PID_PRODUCT_ID" },
  { 56, "PID_MAX_APDULENGTH" },
  { 57, "PID_SUBNET_ADDR" },
  { 58, "PID_DEVICE_ADDR" },
  { 59, "PID_PB_CONFIG" },
  { 60, "PID_ADDR_REPORT" },
  { 61, "PID_ADDR_CHECK" },
  { 62, "PID_OBJECT_VALUE" },
  { 63, "PID_OBJECTLINK" },
  { 64, "PID_APPLICATION" },
  { 65, "PID_PARAMETER" },
  { 66, "PID_OBJECTADDRESS" },
  { 67, "PID_PSU_TYPE" },
  { 68, "PID_PSU_STATUS" },
  { 69, "PID_PSU_ENABLE" },
  { 70, "PID_DOMAIN_ADDRESS" },
  { 71, "PID_IO_LIST" },
  { 72, "PID_MGT_DESCRIPTOR_01" },
  { 73, "PID_PL110_PARAM" },
  { 74, "PID_RF_REPEAT_COUNTER" },
  { 75, "PID_RECEIVE_BLOCK_TABLE" },
  { 76, "PID_RANDOM_PAUSE_TABLE" },
  { 77, "PID_RECEIVE_BLOCK_NR" },
  { 78, "PID_HARDWARE_TYPE" },
  { 79, "PID_RETRANSMITTER_NUMBER" },
  { 80, "PID_SERIAL_NR_TABLE" },
  { 81, "PID_BIBATMASTER_ADDRESS" },
  { 82, "PID_RF_DOMAIN_ADDRESS" },
  { 83, "PID_DEVICE_DESCRIPTOR" },
  { 84, "PID_METERING_FILTER_TABLE" },
  { 85, "PID_GROUP_TELEGR_RATE_LIMIT_TIME_BASE" },
  { 86, "PID_GROUP_TELEGR_RATE_LIMIT_NO_OF_TELEGR" },
  { 0, NULL }
};

/* PIDs for IOT = 1 (Address Table)
* See "4.10.6 Group Address Table - Realisation Type 6" in "03_05_01 Resources v01.09.03 AS"
* See "4.10.7 Group Address Table - Realisation Type 7" in "03_05_01 Resources v01.09.03 AS"
*/
static const value_string pid1_vals[] = {
  { 51, "PID_EXT_FRAMEFORMAT" },
  { 52, "PID_ADDRTAB1" },
  { 53, "PID_GROUP_RESPONSER_TABLE" },
  { 0, NULL }
};

/* PIDs for IOT = 6 (Router)
* See "4.4 Router Object (Object Type 6)" in "03_05_01 Resources v01.09.03 AS"
* See "2.4.4 Router Object" in "AN161 v05 Coupler Model 2.0 AS"
*/
static const value_string pid6_vals[] = {
  { 51, "PID_MEDIUM_STATUS" },  /* alias "PID_LINE_STATUS" */
  { 52, "PID_MAIN_LCCONFIG" },
  { 53, "PID_SUB_LCCONFIG" },
  { 54, "PID_MAIN_LCGRPCONFIG" },
  { 55, "PID_SUB_LCGRPCONFIG" },
  { 56, "PID_ROUTETABLE_CONTROL" },
  { 57, "PID_COUPL_SERV_CONTROL" },
  { 58, "PID_MAX_APDU_LENGTH" },
  { 59, "PID_L2_COUPLER_TYPE" },
  { 61, "PID_HOP_COUNT" },
  { 63, "PID_MEDIUM" },
  { 67, "PID_FILTER_TABLE_USE" },
  { 104, "PID_PL110_SBC_CONTROL" },
  { 105, "PID_PL110_DOA" },
  { 112, "PID_RF_SBC_CONTROL" },
  { 0, NULL }
};

/* PIDs for IOT = 7 (LTE Address Routing Table)
* See "4.5 LTE Address Routing Table Object (Object Type 7)" in "03_05_01 Resources v01.09.03 AS"
*/
static const value_string pid7_vals[] = {
  { 51, "PID_LTE_ROUTESELECT" },
  { 52, "PID_LTE_ROUTETABLE" },
  { 0, NULL }
};

/* PIDs for IOT = 8 (cEMI Server)
* See "4.6 cEMI Server Object (Object Type 8)" in "03_05_01 Resources v01.09.03 AS"
*/
static const value_string pid8_vals[] = {
  { 51, "PID_MEDIUM_TYPE" },
  { 52, "PID_COMM_MODE" },
  { 53, "PID_MEDIUM_AVAILABILITY" },
  { 54, "PID_ADD_INFO_TYPES" },
  { 55, "PID_TIME_BASE" },
  { 56, "PID_TRANSP_ENABLE" },
  { 59, "PID_BIBAT_NEXTBLOCK" },
  { 60, "PID_RF_MODE_SELECT" },
  { 61, "PID_RF_MODE_SUPPORT" },
  { 62, "PID_RF_FILTERING_MODE_SELECT" },
  { 63, "PID_RF_FILTERING_MODE_SUPPORT" },
  { 0, NULL }
};

/* PIDs for IOT = 9 (Group Object Table)
* See "4.12.4 Group Object Table - Realisation Type 6" in "03_05_01 Resources v01.09.03 AS"
*/
static const value_string pid9_vals[] = {
  { 51, "PID_GRPOBJTABLE" },
  { 52, "PID_EXT_GRPOBJREFERENCE" },
  { 0, NULL }
};

/* PIDs for IOT = 11 (KNXnet/IP Parameter),
* See "2.5 KNXnet/IP Parameter Object" in "03_08_03 Management v01.06.02 AS"
* See "2.3.1 KNXnet/IP Parameter Object" in "AN159 v06 KNXnet-IP Secure AS"
*/
static const value_string pid11_vals[] = {
  { 51, "PID_PROJECT_INSTALLATION_ID" },
  { 52, "PID_KNX_INDIVIDUAL_ADDRESS" },
  { 53, "PID_ADDITIONAL_INDIVIDUAL_ADDRESSES" },
  { 54, "PID_CURRENT_IP_ASSIGNMENT_METHOD" },
  { 55, "PID_IP_ASSIGNMENT_METHOD" },
  { 56, "PID_IP_CAPABILITIES" },
  { 57, "PID_CURRENT_IP_ADDRESS" },
  { 58, "PID_CURRENT_SUBNET_MASK" },
  { 59, "PID_CURRENT_DEFAULT_GATEWAY" },
  { 60, "PID_IP_ADDRESS" },
  { 61, "PID_SUBNET_MASK" },
  { 62, "PID_DEFAULT_GATEWAY" },
  { 63, "PID_DHCP_BOOTP_SERVER" },
  { 64, "PID_MAC_ADDRESS" },
  { 65, "PID_SYSTEM_SETUP_MULTICAST_ADDRESS" },
  { 66, "PID_ROUTING_MULTICAST_ADDRESS" },
  { 67, "PID_TTL" },
  { 68, "PID_KNXNETIP_DEVICE_CAPABILITIES" },
  { 69, "PID_KNXNETIP_DEVICE_STATE" },
  { 70, "PID_KNXNETIP_ROUTING_CAPABILITIES" },
  { 71, "PID_PRIORITY_FIFO_ENABLED" },
  { 72, "PID_QUEUE_OVERFLOW_TO_IP" },
  { 73, "PID_QUEUE_OVERFLOW_TO_KNX" },
  { 74, "PID_MSG_TRANSMIT_TO_IP" },
  { 75, "PID_MSG_TRANSMIT_TO_KNX" },
  { 76, "PID_FRIENDLY_NAME" },
  { 78, "PID_ROUTING_BUSY_WAIT_TIME" },
  { 91, "PID_BACKBONE_KEY" },
  { 92, "PID_DEVICE_AUTHENTICATION_CODE" },
  { 93, "PID_PASSWORD_HASHES" },
  { 94, "PID_SECURED_SERVICE_FAMILIES" },
  { 95, "PID_MULTICAST_LATENCY_TOLERANCE" },
  { 96, "PID_SYNC_LATENCY_FRACTION" },
  { 97, "PID_TUNNELLING_USERS" },
  { 0, NULL }
};

/* PIDs for IOT = 17 (Security)
* See "2.3.5 Security Interface Object" in "KSG638-26.03 KNX Data Security"
*/
static const value_string pid17_vals[] = {
  { 51, "PID_SECURITY_MODE" },
  { 52, "PID_P2P_KEY_TABLE" },
  { 53, "PID_GRP_KEY_TABLE" },
  { 54, "PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE" },
  { 55, "PID_SECURITY_FAILURES_LOG" },
  { 56, "PID_TOOL_KEY" },
  { 57, "PID_SECURITY_REPORT" },
  { 58, "PID_SECURITY_REPORT_CONTROL" },
  { 59, "PID_SEQUENCE_NUMBER_SENDING" },
  { 60, "PID_ZONE_KEY_TABLE" },
  { 61, "PID_GO_SECURITY_FLAGS" },
  { 62, "PID_ROLE_TABLE" },
  { 0, NULL }
};

/* - - - - - - - - -  H E L P E R   F U N C T I O N S  - - - - - - - - - -
*/

/* Add raw data to list view, tree view, and parent folder
*/
static proto_item* proto_tree_add_data( proto_tree* tree, tvbuff_t* tvb, int offset, int length, column_info* cinfo, proto_item* item,
  const char* name, const char* text1, const char* text2 )
{
  proto_item* new_item = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, length, NULL, "%s: $", name );
  if( text1 ) col_append_str( cinfo, COL_INFO, text1 );
  if( text2 ) proto_item_append_text( item, "%s", text2 );

  while( length > 0 )
  {
    uint8_t value = tvb_get_uint8( tvb, offset );
    if( text1 ) col_append_fstr( cinfo, COL_INFO, "%02X", value );
    if( text2 ) proto_item_append_text( item, "%02X", value );
    proto_item_append_text( new_item, " %02X", value );
    offset++;
    length--;
  }

  return new_item;
}

static const char* get_pid_name( int ot, int pid )
{
  if( pid <= 50 )
  {
    return try_val_to_str( pid, pid_vals );
  }
  {
    const value_string* vals = NULL;
    switch( ot )
    {
    case 0:
      vals = pid0_vals;
      break;
    case 1:
      vals = pid1_vals;
      break;
    case 6:
      vals = pid6_vals;
      break;
    case 7:
      vals = pid7_vals;
      break;
    case 8:
      vals = pid8_vals;
      break;
    case 9:
      vals = pid9_vals;
      break;
    case 11:
      vals = pid11_vals;
      break;
    case 17:
      vals = pid17_vals;
      break;
    }
    if( vals )
    {
      return try_val_to_str( pid, vals );
    }
  }
  return NULL;
}

/* Decrypt data security APDU with a specific key.
*/
static const uint8_t* decrypt_data_security_data_with_key( wmem_allocator_t *pool, const uint8_t* key, const uint8_t* encrypted, int encrypted_size, const uint8_t* cemi, int cemi_size )
{
  uint8_t ctr_0[ KNX_KEY_LENGTH ];
  uint8_t b_0[ KNX_KEY_LENGTH ];
  uint8_t mac[ KNX_KEY_LENGTH ];
  uint8_t* a_bytes = 0;
  const uint8_t* p_bytes = NULL;
  int a_length = 0;
  int p_length = 0;

  uint8_t* decrypted = NULL;

  if( encrypted_size > 4 )  // contains 4 bytes MAC
  {
    if( cemi_size >= 2 )
    {
      int additionalInfoLength = cemi[ 1 ];
      int offsetToData = additionalInfoLength + 11;
      if( offsetToData + 6 <= cemi_size )
      {
        /* 1 byte Security Control Field */
        uint8_t scf = cemi[ offsetToData ];

        // Get A and P.
        if( (scf & 0x30) == 0x10 ) // A+C
        {
          p_bytes = encrypted;
          p_length = encrypted_size - 4;
        }

        // Build b_0.
        b_0[ 0 ] = cemi[ offsetToData + 1 ]; // SeqNr
        b_0[ 1 ] = cemi[ offsetToData + 2 ];
        b_0[ 2 ] = cemi[ offsetToData + 3 ];
        b_0[ 3 ] = cemi[ offsetToData + 4 ];
        b_0[ 4 ] = cemi[ offsetToData + 5 ];
        b_0[ 5 ] = cemi[ offsetToData + 6 ];
        b_0[ 6 ] = cemi[ additionalInfoLength + 4 ]; // SA
        b_0[ 7 ] = cemi[ additionalInfoLength + 5 ];
        b_0[ 8 ] = cemi[ additionalInfoLength + 6 ]; // DA
        b_0[ 9 ] = cemi[ additionalInfoLength + 7 ];
        b_0[ 10 ] = 0; // cemi[additionalInfoLength + 2] & 0x80; // FT
        b_0[ 11 ] = cemi[ additionalInfoLength + 3 ] & 0x8F; // AT (AT+EFF)
        b_0[ 12 ] = cemi[ additionalInfoLength + 9 ]; // TPCI + ApciSec
        b_0[ 13 ] = cemi[ additionalInfoLength + 10 ];
        b_0[ 14 ] = 0;
        b_0[ 15 ] = (uint8_t) p_length;

        // Build ctr_0.
        ctr_0[ 0 ] = cemi[ offsetToData + 1 ]; // SeqNr
        ctr_0[ 1 ] = cemi[ offsetToData + 2 ];
        ctr_0[ 2 ] = cemi[ offsetToData + 3 ];
        ctr_0[ 3 ] = cemi[ offsetToData + 4 ];
        ctr_0[ 4 ] = cemi[ offsetToData + 5 ];
        ctr_0[ 5 ] = cemi[ offsetToData + 6 ];
        ctr_0[ 6 ] = cemi[ additionalInfoLength + 4 ]; // SA
        ctr_0[ 7 ] = cemi[ additionalInfoLength + 5 ];
        ctr_0[ 8 ] = cemi[ additionalInfoLength + 6 ]; // DA
        ctr_0[ 9 ] = cemi[ additionalInfoLength + 7 ];
        ctr_0[ 10 ] = 0;
        ctr_0[ 11 ] = 0;
        ctr_0[ 12 ] = 0;
        ctr_0[ 13 ] = 0;
        ctr_0[ 14 ] = 0x01;
        ctr_0[ 15 ] = 0;

        decrypted = knx_ccm_encrypt( 0, key, p_bytes, p_length, encrypted + encrypted_size - 4, 4, ctr_0, 4 );

        a_bytes = (uint8_t*) wmem_alloc( pool, encrypted_size );
        if( (scf & 0x30) == 0x10 ) // A+C
        {
          a_bytes[ 0 ] = scf;
          a_length = 1;
          p_bytes = decrypted;
          p_length = encrypted_size - 4;
        }
        else if( (scf & 0x30) == 0x00 ) // A
        {
          a_bytes[ 0 ] = scf;
          memcpy( a_bytes + 1, decrypted, encrypted_size - 4 );
          a_length = encrypted_size - 3;
        }

        knx_ccm_calc_cbc_mac( mac, key, a_bytes, a_length, p_bytes, p_length, b_0 );
        wmem_free( pool, a_bytes );

        if( memcmp( mac, decrypted + p_length, 4 ) != 0 )
        {
          // Wrong mac. Return 0.
          wmem_free( pool, decrypted );
          decrypted = NULL;
        }
      }
    }
  }

  return decrypted;
}

/* Context info for decrypt_data_security_data
*/
struct data_security_info
{
  uint16_t source;       // KNX source address
  uint16_t dest;         // KNX source address
  uint8_t multicast;     // KNX multicast (group addressed)?
  uint64_t seq_nr;       // 6-byte data security sequence number
  char output_text[ 128 ];  // buffer for diagnostic output text
};

/* Decrypt data security APDU.
*/
static const uint8_t* decrypt_data_security_data( wmem_allocator_t *pool, const uint8_t* encrypted, int encrypted_size, const uint8_t* cemi, int cemi_size, struct data_security_info* info )
{
  const uint8_t* key = NULL;
  const uint8_t* decrypted = NULL;
  uint8_t keys_found = 0;

  // Get context info
  uint16_t source = info->source;
  uint16_t dest = info->dest;
  uint8_t multicast = info->multicast;

  char* output = info->output_text;
  int output_max = sizeof info->output_text;
  snprintf( output, output_max, "with " );
  while( *output ) { ++output; --output_max; }

  // Try keys from keyring.XML
  if( multicast )
  {
    // Try keys associated with GA
    struct knx_keyring_ga_keys* ga_key;

    for( ga_key = knx_keyring_ga_keys; ga_key; ga_key = ga_key->next )
    {
      if( ga_key->ga == dest )
      {
        keys_found = 1;
        key = ga_key->key;
        decrypted = decrypt_data_security_data_with_key( pool, key, encrypted, encrypted_size, cemi, cemi_size );

        if( decrypted )
        {
          snprintf( output, output_max, "GA " );
          while( *output ) { ++output; --output_max; }
          break;
        }
      }
    }
  }
  else
  {
    // Try keys associated with dest IA
    struct knx_keyring_ia_keys* ia_key;

    for( ia_key = knx_keyring_ia_keys; ia_key; ia_key = ia_key->next )
    {
      if( ia_key->ia == dest )
      {
        keys_found = 1;
        key = ia_key->key;
        decrypted = decrypt_data_security_data_with_key( pool, key, encrypted, encrypted_size, cemi, cemi_size );

        if( decrypted )
        {
          snprintf( output, output_max, "dest IA " );
          while( *output ) { ++output; --output_max; }
          break;
        }
      }
    }
  }

  if( !decrypted )
  {
    // Try keys associated with source IA
    struct knx_keyring_ia_keys* ia_key;

    for( ia_key = knx_keyring_ia_keys; ia_key; ia_key = ia_key->next )
    {
      if( ia_key->ia == source )
      {
        keys_found = 1;
        key = ia_key->key;
        decrypted = decrypt_data_security_data_with_key( pool, key, encrypted, encrypted_size, cemi, cemi_size );

        if( decrypted )
        {
          snprintf( output, output_max, "source IA " );
          while( *output ) { ++output; --output_max; }
          break;
        }
      }
    }
  }

  if( !decrypted && knx_decryption_key_count )
  {
    // Try all explicitly specified keys
    uint8_t key_index;

    for( key_index = 0; key_index < knx_decryption_key_count; ++key_index )
    {
      keys_found = 1;
      key = knx_decryption_keys[ key_index ];
      decrypted = decrypt_data_security_data_with_key( pool, key, encrypted, encrypted_size, cemi, cemi_size );

      if( decrypted )
      {
        break;
      }
    }
  }

  if( decrypted )
  {
    uint8_t count;

    snprintf( output, output_max, "key" );

    for( count = 16; count; --count )
    {
      while( *output ) { ++output; --output_max; }
      snprintf( output, output_max, " %02X", *key++ );
    }
  }
  else
  {
    snprintf( info->output_text, sizeof info->output_text, keys_found ? "failed" : "no keys found" );
  }

  return decrypted;
}

/* Dissect Object Index (1 byte)
*/
static uint8_t dissect_ox( tvbuff_t *tvb, packet_info *pinfo, proto_item *node, proto_tree *list, int *p_offset, int end_pos, uint8_t *p_error )
{
  int offset = *p_offset;

  if( offset < end_pos )
  {
    uint8_t ox = tvb_get_uint8( tvb, offset );
    column_info *cinfo = pinfo->cinfo;

    col_append_fstr( cinfo, COL_INFO, " OX=%u", ox );
    proto_item_append_text( node, ", OX=%u", ox );
    proto_tree_add_item( list, hf_cemi_ox, tvb, offset, 1, ENC_BIG_ENDIAN );

    *p_offset = ++offset;
    return ox;
  }

  proto_tree_add_expert_format( list, pinfo, KIP_ERROR, tvb, offset, 0, "? Object Index: expected 1 byte" );

  if( p_error )
  {
    *p_error = 1;
  }

  return 0;
}

/* Dissect Object Type (2 bytes)
*/
static uint16_t dissect_ot( tvbuff_t *tvb, packet_info *pinfo, proto_item *node, proto_tree *list, int *p_offset, int end_pos, uint8_t *p_error )
{
  int offset = *p_offset;

  if( offset + 1 < end_pos )
  {
    uint16_t ot = tvb_get_ntohs( tvb, offset );
    column_info *cinfo = pinfo->cinfo;

    col_append_fstr( cinfo, COL_INFO, " OT=%u", ot );
    proto_item_append_text( node, ", OT=%u", ot );

    proto_tree_add_item( list, hf_cemi_ot, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    *p_offset = offset;
    return ot;
  }

  node = proto_tree_add_bytes_format( list, hf_bytes, tvb, offset, end_pos - offset, NULL, "? Object Type" );
  expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );

  if( p_error )
  {
    *p_error = 1;
  }

  *p_offset = end_pos;
  return 0;
}

/* Dissect Property Identifier (1 byte)
*/
static uint8_t dissect_pid( tvbuff_t *tvb, packet_info *pinfo, proto_item *node, proto_tree *list, int *p_offset, int end_pos, int ot, uint8_t show, uint8_t *p_error )
{
  int offset = *p_offset;

  if( offset < end_pos )
  {
    uint8_t pid = tvb_get_uint8( tvb, offset );
    column_info *cinfo = pinfo->cinfo;
    const char* name;

    if( pid || show )
    {
      col_append_fstr( cinfo, COL_INFO, " P=%u", pid );
      proto_item_append_text( node, ", PID=%u", pid );
    }

    if( list )
    {
      node = proto_tree_add_item( list, hf_cemi_pid, tvb, offset, 1, ENC_BIG_ENDIAN );
      name = get_pid_name( ot, pid );
      if( name )
      {
        proto_item_append_text( node, " = %s", name );
      }
    }

    *p_offset = ++offset;
    return pid;
  }

  proto_tree_add_expert_format( list, pinfo, KIP_ERROR, tvb, offset, 0, "? Property ID: expected 1 byte" );

  if( p_error )
  {
    *p_error = 1;
  }

  return 0;
}

/* Dissect Property Index (1 byte)
*/
static uint8_t dissect_px( tvbuff_t *tvb, packet_info *pinfo, proto_item *node, proto_tree *list, int *p_offset, int end_pos, uint8_t show, uint8_t *p_error )
{
  int offset = *p_offset;

  if( offset < end_pos )
  {
    uint8_t px = tvb_get_uint8( tvb, offset );

    if( show )
    {
      column_info *cinfo = pinfo->cinfo;
      col_append_fstr( cinfo, COL_INFO, " PX=%u", px );
      proto_item_append_text( node, ", PX=%u", px );
    }

    proto_tree_add_item( list, hf_cemi_px, tvb, offset, 1, ENC_BIG_ENDIAN );

    *p_offset = ++offset;
    return px;
  }

  proto_tree_add_expert_format( list, pinfo, KIP_ERROR, tvb, offset, 0, "? Property Index: expected 1 byte" );

  if( p_error )
  {
    *p_error = 1;
  }

  return 0;
}

/* Dissect Property Range (2 bytes: Number Of Elements (4 bits), Start Index (12 bits))
  and subsequent Data
*/
static void dissect_range( tvbuff_t *tvb, packet_info *pinfo, proto_item *node, proto_tree *list, int *p_offset, int end_pos, uint8_t pa_flags, uint8_t *p_error )
{
  int offset = *p_offset;
  uint8_t error = 0;

  if( offset + 1 >= end_pos )
  {
    node = proto_tree_add_bytes_format( list, hf_bytes, tvb, offset, end_pos - offset, NULL, "? Range" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );

    *p_offset = end_pos;
    error = 1;
  }
  else
  {
    column_info *cinfo = pinfo->cinfo;
    proto_item *cemi_node = node;
    uint16_t sx = tvb_get_ntohs( tvb, offset );
    uint8_t ne = sx >> 12;
    sx &= 0x0FFF;

    /* 4 bits Number Of Elements */
    if( ne != 1 )
    {
      col_append_fstr( cinfo, COL_INFO, " N=%u", ne );
      proto_item_append_text( node, ", N=%u", ne );

      if( ne == 0 && !(pa_flags & PA_RESPONSE) )
      {
        error = 1;
      }
      else if( sx == 0 )
      {
        error = 2;
      }
    }

    /* 12 bits Start Index */
    if( sx != 1 )
    {
      col_append_fstr( cinfo, COL_INFO, " X=%u", sx );
      proto_item_append_text( node, ", X=%u", sx );
    }

    if( list )
    {
      proto_item *range_node = proto_tree_add_none_format( list, hf_folder, tvb, offset, 2, "Range: %u element%s at position %u", ne, (ne == 1) ? "" : "s", sx );
      proto_tree *range_list = proto_item_add_subtree( range_node, ett_cemi_range );

      /* 4 bits Number Of Elements */
      node = proto_tree_add_item( range_list, hf_cemi_ne, tvb, offset, 1, ENC_BIG_ENDIAN );

      if( error )
      {
        proto_item_prepend_text( range_node, "? " );
        proto_item_prepend_text( node, "? " );
        expert_add_info_format( pinfo, node, KIP_ERROR, (error == 1) ? "Expected: >= 1 element(s)" : "Expected: 1 element" );
      }

      /* 12 bits Start Index */
      proto_tree_add_item( range_list, hf_cemi_sx, tvb, offset, 2, ENC_BIG_ENDIAN );
    }

    offset += 2;

    /* Data */
    {
      int length = end_pos - offset;
      if( length > 0 )
      {
        node = proto_tree_add_data( list, tvb, offset, length, cinfo, cemi_node, "Data", " $", ", $" );
        if( !pa_flags )
        {
          proto_item_prepend_text( node, "? " );
          expert_add_info_format( pinfo, node, KIP_ERROR, "Unexpected" );
          error = 1;
        }
        else if( (pa_flags & PA_RESPONSE) && (!(pa_flags & PA_DATA) || ne == 0) && length != 1 )
        {
          proto_item_prepend_text( node, "? " );
          expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: max 1 byte" );
          error = 1;
        }
        else if( pa_flags & PA_DATA )
        {
          if( ne == 1 && sx == 0 && length != 2 )
          {
            proto_item_prepend_text( node, "? " );
            expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
            error = 1;
          }
          else if( ne >= 2 && (length % ne) != 0 )
          {
            proto_item_prepend_text( node, "? " );
            expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: multiple of %u bytes", ne );
            error = 1;
          }
        }
      }
    }

    *p_offset = end_pos;
  }

  if( error && p_error )
  {
    *p_error = 1;
  }
}

/* Dissect Property Description: PDT (1 byte), Max Count (2 bytes), Access Levels (1 byte)
*/
static void dissect_prop_descr( tvbuff_t* tvb, packet_info* pinfo, proto_item* cemi_node, proto_tree* cemi_list, int* p_offset, int size, uint8_t* p_error )
{
  int offset = *p_offset;
  column_info* cinfo = pinfo->cinfo;
  uint8_t error = 0;

  /* 4 bytes Property Description */
  if( offset + 4 > size )
  {
    proto_item* node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Property Description" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 4 bytes" );

    error = 1;
    offset = size;
  }
  else
  {
    /* 1 bit Writability, 1 bit reserved, 6 bits Property Data Type */
    uint8_t pdt = tvb_get_uint8( tvb, offset );
    uint8_t writable = (pdt & 0x80) != 0;
    pdt &= 0x3F;
    col_append_fstr( cinfo, COL_INFO, " T=%u", pdt );
    proto_item_append_text( cemi_node, ", T=%u", pdt );

    /* 4 bits reserved, 12 bits Max Elements */
    uint16_t me = tvb_get_ntohs( tvb, offset + 1) & 0x0FFF;
    if( me != 1 )
    {
      col_append_fstr( cinfo, COL_INFO, " N=%u", me );
      proto_item_append_text( cemi_node, ", N=%u", me );
    }

    /* 4 bits Read Access, 4 bits Write Access */
    uint8_t wa = tvb_get_uint8( tvb, offset + 3 );
    uint8_t ra = (wa & 0xF0) >> 4;
    wa &= 0x0F;
    col_append_fstr( cinfo, COL_INFO, " R=%u", ra );
    if( writable )
      col_append_fstr( cinfo, COL_INFO, " W=%u", wa );
    proto_item_append_text( cemi_node, ", R=%u", ra );
    if( writable )
      proto_item_append_text( cemi_node, ", W=%u", wa );

    if( cemi_list )
    {
      proto_item *pd_node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 4, "Property Description: " );
      proto_tree *pd_list = proto_item_add_subtree( pd_node, ett_cemi_pd );

      const char* pdt_name = try_val_to_str( pdt, pdt_vals );
      if( pdt_name )
        proto_item_append_text( pd_node, "%s", pdt_name );
      else
        proto_item_append_text( pd_node, "PDT = 0x%02X", pdt );

      if( me != 1 )
        proto_item_append_text( pd_node, ", Max Elements = %u", me );

      proto_item_append_text( pd_node, ", Read = %u", ra );
      if( writable )
        proto_item_append_text( pd_node, ", Write = %u", wa );

      proto_tree_add_item( pd_list, hf_cemi_pw, tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( pd_list, hf_cemi_pdt, tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( pd_list, hf_cemi_me, tvb, offset + 1, 2, ENC_BIG_ENDIAN );
      proto_tree_add_item( pd_list, hf_cemi_ra, tvb, offset + 3, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( pd_list, hf_cemi_wa, tvb, offset + 3, 1, ENC_BIG_ENDIAN );
    }

    offset += 4;
  }

  if( error && p_error )
  {
    *p_error = 1;
  }

  *p_offset = offset;
}

/* Dissect OT (2 bytes), OI (12 bits), and PID (12 bits) for PropertyExt services
*/
static void dissect_pid_ext( tvbuff_t *tvb, packet_info *pinfo, proto_item *cemi_node, proto_tree *cemi_list, int *p_offset, int size, uint8_t *p_error )
{
  int offset = *p_offset;
  column_info* cinfo = pinfo->cinfo;
  uint8_t error = 0;

  /* 2 bytes Object Type */
  uint16_t ot = dissect_ot( tvb, pinfo, cemi_node, cemi_list, &offset, size, &error );

  if( offset + 3 > size )
  {
    proto_item* node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Object Instance, PID" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 3 bytes" );

    error = 1;
    offset = size;
  }
  else
  {
    /* 12 bits Object Instance */
    uint16_t cc = tvb_get_ntohs( tvb, offset ) >> 4;
    col_append_fstr( cinfo, COL_INFO, " OI=%u", cc );
    proto_item_append_text( cemi_node, ", OI=%u", cc );
    proto_tree_add_item( cemi_list, hf_cemi_ext_oi, tvb, offset, 2, ENC_BIG_ENDIAN );
    ++offset;

    /* 12 bits Property ID */
    cc = tvb_get_ntohs( tvb, offset ) & 0x0FFF;
    col_append_fstr( cinfo, COL_INFO, " P=%u", cc );
    proto_item_append_text( cemi_node, ", PID=%u", cc );

    if( cemi_list )
    {
      proto_item* node = proto_tree_add_item( cemi_list, hf_cemi_ext_pid, tvb, offset, 2, ENC_BIG_ENDIAN );
      const char* name = get_pid_name( ot, cc );
      if( name )
      {
        proto_item_append_text( node, " = %s", name );
      }
    }

    offset += 2;
  }

  if( error && p_error )
  {
    *p_error = 1;
  }

  *p_offset = offset;
}

/* Dissect cEMI Management packet
  (M_PropRead.req, M_PropRead.con, M_PropWrite.req, M_PropWrite.con, M_PropInfo.ind, M_Reset.req, M_Reset.ind)
*/
static void dissect_cemi_mgmt_packet( tvbuff_t* tvb, packet_info* pinfo, proto_item *cemi_node, proto_tree *cemi_list, uint8_t mc, int *p_offset, int size, uint8_t* p_pa_flags, uint8_t *p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  uint8_t min_size = 1;

  switch( mc )
  {
  case CEMI_M_PROPREAD_REQ:
    pa_flags = 0;
    goto case_CEMI_M_PROP;

  case CEMI_M_PROPWRITE_CON:
    pa_flags = PA_RESPONSE;
    goto case_CEMI_M_PROP;

  case CEMI_M_PROPREAD_CON:
    pa_flags = PA_RESPONSE | PA_DATA;
    goto case_CEMI_M_PROP;

  case CEMI_M_PROPWRITE_REQ:
  case CEMI_M_PROPINFO_IND:
    //pa_flags = PA_DATA;

  case_CEMI_M_PROP:
    min_size = 7;
    break;

  case CEMI_M_FUNCPROPCMD_REQ:
  case CEMI_M_FUNCPROPREAD_REQ:
  case CEMI_M_FUNCPROP_CON:
    //pa_flags = PA_DATA;
    min_size = 5;
    break;

  case CEMI_M_RESET_REQ:
  case CEMI_M_RESET_IND:
    pa_flags = 0;
    break;
  }

  if( min_size >= 5 )
  {
    /* 2 bytes Object Type */
    uint16_t ot = dissect_ot( tvb, pinfo, cemi_node, cemi_list, &offset, size, &error );

    /* 1 byte Object Instance */
    if( size < 4 )
    {
      proto_tree_add_expert_format( cemi_list, pinfo, KIP_ERROR, tvb, offset, 0, "? Object Instance: expected 1 byte" );
      error = 1;
    }
    else
    {
      uint8_t oi = tvb_get_uint8( tvb, 3 );
      if( oi != 1 )
      {
        col_append_fstr( cinfo, COL_INFO, " OI=%u", oi );
        proto_item_append_text( cemi_node, ", OI=%u", oi );
      }
      proto_tree_add_item( cemi_list, hf_cemi_oi, tvb, 3, 1, ENC_BIG_ENDIAN );
      offset = 4;
    }

    /* 1 byte Property ID
    */
    dissect_pid( tvb, pinfo, cemi_node, cemi_list, &offset, size, ot, 1, &error );

    if( min_size >= 7 )
    {
      /* Range (Start Index, Number Of Elements) and Data
      */
      dissect_range( tvb, pinfo, cemi_node, cemi_list, &offset, size, pa_flags, &error );
      pa_flags = 0;
    }
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect A_MemoryExt service */
static void dissect_memory_ext_service( tvbuff_t* tvb, packet_info* pinfo, proto_item* cemi_node, proto_tree* cemi_list,
  uint16_t ax, int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  /* 4 bytes Range (1 byte Memory Length, 3 bytes Memory Address) */
  if( offset + 4 > size )
  {
    proto_item* node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Range" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 4 bytes" );
    error = 1;
    offset = size;
  }
  else
  {
    /* 1 byte Memory Length or Error Code */
    uint8_t is_response = (ax == AX_MemExtReadResp || ax == AX_MemExtWriteResp);
    uint8_t n = tvb_get_uint8( tvb, offset );
    if( is_response )
    {
      if( n != 0 )
      {
        col_append_fstr( cinfo, COL_INFO, " E=$%02X", n );
        proto_item_append_text( cemi_node, ", E=$%02X", n );
      }
    }
    else
    {
      if( n != 1 )
      {
        col_append_fstr( cinfo, COL_INFO, " N=%u", n );
        proto_item_append_text( cemi_node, ", N=%u", n );
      }
    }

    /* 3 bytes Memory Address */
    uint32_t x = tvb_get_uint24( tvb, offset + 1, ENC_BIG_ENDIAN );
    col_append_fstr( cinfo, COL_INFO, " X=$%06" PRIX32, x );
    proto_item_append_text( cemi_node, ", X=$%06" PRIX32, x );

    if( is_response )
    {
      proto_tree_add_item( cemi_list, hf_cemi_error, tvb, offset, 1, ENC_BIG_ENDIAN );
    }
    else
    {
      proto_tree_add_item( cemi_list, hf_cemi_ext_memory_length, tvb, offset, 1, ENC_BIG_ENDIAN );
    }

    proto_tree_add_item( cemi_list, hf_cemi_ext_memory_address, tvb, offset + 1, 3, ENC_BIG_ENDIAN );

    offset += 4;
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect A_UserMemory service */
static void dissect_user_memory_service( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* cemi_node, proto_tree* cemi_list,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node;
  proto_tree* list;

  /* 3 bytes Range (Memory Length, Memory Address) */
  if( offset + 3 > size )
  {
    node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Range" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 3 bytes" );
    error = 1;
    offset = size;
  }
  else
  {
    uint8_t c2 = tvb_get_uint8( tvb, offset );
    uint8_t c1 = c2 >> 4;
    uint32_t c3 = tvb_get_ntohs( tvb, offset + 1 );
    c2 &= 0x0F;
    c3 |= c1 << 16UL;
    if( c2 != 1 )
      col_append_fstr( cinfo, COL_INFO, " N=%u", c2 );
    col_append_fstr( cinfo, COL_INFO, " X=$%05X", c3 );
    if( tree )
    {
      if( c2 != 1 )
        proto_item_append_text( cemi_node, ", N=%u", c2 );
      proto_item_append_text( cemi_node, ", X=$%05X", c3 );
      node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 1,
        "Range: %u byte%s at address $%05X", c2, (c2 == 1) ? "" : "s", c3 );
      list = proto_item_add_subtree( node, ett_cemi_range );
      proto_tree_add_item( list, hf_cemi_memory_address_ext, tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( list, hf_cemi_memory_length, tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( list, hf_cemi_memory_address, tvb, offset + 1, 2, ENC_BIG_ENDIAN );
    }
    offset += 3;
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect A_FunctionProperty service */
static void dissect_function_property_service( tvbuff_t* tvb, packet_info* pinfo, proto_item* cemi_node, proto_tree* cemi_list,
  int* p_offset, int size, uint8_t* p_error )
{
  /* 1 byte Object Index */
  dissect_ox( tvb, pinfo, cemi_node, cemi_list, p_offset, size, p_error );

  /* 1 byte Property ID */
  dissect_pid( tvb, pinfo, cemi_node, cemi_list, p_offset, size, -1, 1, p_error );
}

/* Dissect (obsolete) A_Router service */
static void dissect_router_service( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* cemi_node, proto_tree* cemi_list,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node;
  proto_tree* list;

  /* 3 bytes Range (1 byte Memory Length, 2 bytes Memory Address) */
  if( offset + 3 > size )
  {
    node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Range" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 3 bytes" );
    error = 1;
    offset = size;
  }
  else
  {
    uint8_t c = tvb_get_uint8( tvb, offset );
    uint16_t cc = tvb_get_ntohs( tvb, offset + 1 );
    if( c != 1 )
      col_append_fstr( cinfo, COL_INFO, " N=%u", c );
    col_append_fstr( cinfo, COL_INFO, " X=$%04X", cc );
    if( tree )
    {
      proto_item_append_text( cemi_node, ", N=%u, X=$%04X", c, cc );
      node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 3,
        "Range: %u byte%s at address $%04X", c, (c == 1) ? "" : "s", cc );
      list = proto_item_add_subtree( node, ett_cemi_range );
      proto_tree_add_item( list, hf_cemi_ext_memory_length, tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( list, hf_cemi_ext_memory_address, tvb, offset + 1, 2, ENC_BIG_ENDIAN );
    }
    offset += 3;
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect A_Authenticate or A_Key service */
static void dissect_authenticate_service( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* cemi_node, proto_tree* cemi_list,
  uint16_t ax, int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  /* 1 byte Level */
  if( offset >= size )
  {
    proto_tree_add_expert_format( cemi_list, pinfo, KIP_ERROR, tvb, offset, 0, "? Level: expected 1 byte" );
    error = 1;
  }
  else
  {
    uint8_t c = tvb_get_uint8( tvb, offset );
    if( ax != AX_AuthReq || c != 0 )
    {
      col_append_fstr( cinfo, COL_INFO, " L=%u", c );
      if( tree )
      {
        proto_item_append_text( cemi_node, ", L=%u", c );
      }
    }
    if( tree )
    {
      proto_tree_add_item( cemi_list, hf_cemi_level, tvb, offset, 1, ENC_BIG_ENDIAN );
    }
    offset++;
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect A_PropertyValue service */
static void dissect_property_value_service( tvbuff_t* tvb, packet_info* pinfo, proto_item* cemi_node, proto_tree* cemi_list,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  /* 1 byte Object Index */
  dissect_ox( tvb, pinfo, cemi_node, cemi_list, p_offset, size, p_error );

  /* 1 byte Property ID */
  dissect_pid( tvb, pinfo, cemi_node, cemi_list, p_offset, size, -1, 1, p_error );

  /* 2 bytes Range */
  dissect_range( tvb, pinfo, cemi_node, cemi_list, p_offset, size, *p_pa_flags, p_error );
}

/* Dissect A_PropertyDescription service */
static void dissect_property_description_service( tvbuff_t* tvb, packet_info* pinfo, proto_item* cemi_node, proto_tree* cemi_list,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  /* 1 byte Object Index */
  dissect_ox( tvb, pinfo, cemi_node, cemi_list, p_offset, size, p_error );

  /* 1 byte Property ID */
  {
    uint8_t pa_flags = *p_pa_flags;
    uint8_t pid = dissect_pid( tvb, pinfo, cemi_node, cemi_list, p_offset, size, -1, pa_flags, p_error );

    /* 1 byte Property Index */
    dissect_px( tvb, pinfo, cemi_node, cemi_list, p_offset, size, pa_flags || !pid, p_error );

    if( pa_flags )  /* A_PropertyDescription_Response */
    {
      /* 1 byte PDT, 2 bytes Max Elements, 1 byte Access Levels */
      dissect_prop_descr( tvb, pinfo, cemi_node, cemi_list, p_offset, size, p_error );

      /* No further trailing data */
      *p_pa_flags = 0;
    }
  }
}

/* Dissect A_NetworkParameter or A_GroupPropertyValue service */
static void dissect_network_parameter_service( tvbuff_t* tvb, packet_info* pinfo, proto_item* cemi_node, proto_tree* cemi_list,
  int* p_offset, int size, uint8_t* p_error )
{
  /* 2 bytes Object Type */
  uint16_t ot = dissect_ot( tvb, pinfo, cemi_node, cemi_list, p_offset, size, p_error );

  /* 1 byte Property ID */
  dissect_pid( tvb, pinfo, cemi_node, cemi_list, p_offset, size, ot, 1, p_error );
}

/* Dissect A_IndividualAddressSerialNumber or A_DomainAddressSerialNumber service */
static void dissect_ia_serial_number_service( tvbuff_t* tvb, packet_info* pinfo, proto_item* cemi_node, proto_tree* cemi_list,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node;

  /* 6 bytes Serial Nr */
  if( offset + 6 > size )
  {
    node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Serial Number" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 6 bytes" );
    error = 1;
    offset = size;
  }
  else
  {
    proto_tree_add_data( cemi_list, tvb, offset, 6, cinfo, cemi_node, "Serial Number", " SN=$", ", SerNr=$" );
    offset += 6;
  }

  if( pa_flags )
  {
    if( offset >= size )
    {
      proto_tree_add_expert_format( cemi_list, pinfo, KIP_ERROR, tvb, offset, 0, "? Data: missing" );
      error = 1;
    }
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect A_SystemNetworkParameter service */
static void dissect_system_network_parameter_service( tvbuff_t* tvb, packet_info* pinfo, proto_item* cemi_node, proto_tree* cemi_list,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node;
  const char* name;
  uint16_t ot;
  uint16_t cc;
  uint8_t c;

  /* 2 bytes Object Type */
  if( offset + 1 >= size )
  {
    ot = 0;
    node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Object Type" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
    error = 1;
    offset = size;
  }
  else
  {
    ot = cc = tvb_get_ntohs( tvb, offset );

    if( cc )
    {
      col_append_fstr( cinfo, COL_INFO, " OT=%u", cc );
      proto_item_append_text( cemi_node, ", OT=%u", cc );
    }

    if( cemi_list )
    {
      node = proto_tree_add_item( cemi_list, hf_cemi_ot, tvb, offset, 2, ENC_BIG_ENDIAN );
      name = try_val_to_str( cc, ot_vals );
      if( name )
      {
        proto_item_append_text( node, " = %s", name );
      }
    }

    offset += 2;
  }

  /* 2 bytes Property ID (12 bits) and Reserved (4 bits) */
  if( offset + 1 >= size )
  {
    node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Property ID" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
    error = 1;
    offset = size;
  }
  else
  {
    /* 12 bits Property ID */
    cc = tvb_get_ntohs( tvb, offset );
    c = cc & 0x000F;
    cc >>= 4;

    col_append_fstr( cinfo, COL_INFO, " P=%u", cc );
    proto_item_append_text( cemi_node, ", PID=%u", cc );

    if( cemi_list )
    {
      node = proto_tree_add_item( cemi_list, hf_cemi_snp_pid, tvb, offset, 2, ENC_BIG_ENDIAN );
      name = get_pid_name( ot, cc );
      if( name )
      {
        proto_item_append_text( node, " = %s", name );
      }
    }

    ++offset;

    /* 4 bits Reserved */
    if( c )
    {
      col_append_fstr( cinfo, COL_INFO, " $%X", c );
      proto_item_append_text( cemi_node, ", $%X", c );
      node = proto_tree_add_item( cemi_list, hf_cemi_snp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN );
      expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: zero" );
      error = 1;
    }

    ++offset;
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect A_PropertyExtValue service */
static void dissect_property_ext_value_service( tvbuff_t* tvb, packet_info* pinfo, proto_item* cemi_node, proto_tree* cemi_list,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node;

  /* 2 bytes OT, 12 bits OI, 12 bits PID */
  dissect_pid_ext( tvb, pinfo, cemi_node, cemi_list, &offset, size, &error );

  /* 3 bytes Range (1 byte Count, 2 bytes Index) */
  if( offset + 3 > size )
  {
    node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Range" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 3 bytes" );
    error = 1;
    offset = size;
  }
  else
  {
    /* 1 byte Count */
    uint8_t ne = tvb_get_uint8( tvb, offset );
    if( ne != 1 )
    {
      col_append_fstr( cinfo, COL_INFO, " N=%u", ne );
      proto_item_append_text( cemi_node, ", N=%u", ne );
    }

    /* 2 bytes Index */
    uint16_t sx = tvb_get_ntohs( tvb, offset + 1 );
    if( sx != 1 )
    {
      col_append_fstr( cinfo, COL_INFO, " X=%u", sx );
      proto_item_append_text( cemi_node, ", X=%u", sx );
    }

    if( cemi_list )
    {
      proto_item *range_node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 3, "Range: %u element%s at position %u", ne, (ne == 1) ? "" : "s", sx );
      proto_tree *range_list = proto_item_add_subtree( range_node, ett_cemi_range );
      proto_tree_add_item( range_list, hf_cemi_ext_ne, tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( range_list, hf_cemi_ext_sx, tvb, offset + 1, 2, ENC_BIG_ENDIAN );
    }

    offset += 3;
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect A_PropertyExtDescription service */
static void dissect_property_ext_description_service( tvbuff_t* tvb, packet_info* pinfo, proto_item* cemi_node, proto_tree* cemi_list,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node;
  uint16_t cc;
  uint8_t c;

  /* 2 bytes OT, 12 bits OI, 12 bits PID */
  dissect_pid_ext( tvb, pinfo, cemi_node, cemi_list, &offset, size, &error );

  /* 4 bits Description Type */
  if( offset >= size )
  {
    node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Description Type" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 4 bits" );
    error = 1;
  }
  else
  {
    c = tvb_get_uint8( tvb, offset ) >> 4;
    col_append_fstr( cinfo, COL_INFO, " D=%u", c );
    proto_item_append_text( cemi_node, ", D=%u", c );
    proto_tree_add_item( cemi_list, hf_cemi_ext_dt, tvb, offset, 1, ENC_BIG_ENDIAN );
  }

  /* 12 bits Property Index */
  if( offset + 2 > size )
  {
    node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Property Index" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 12 bits" );
    error = 1;
    offset = size;
  }
  else
  {
    cc = tvb_get_ntohs( tvb, offset ) & 0x0FFF;
    col_append_fstr( cinfo, COL_INFO, " PX=%u", cc );
    proto_item_append_text( cemi_node, ", PX=%u", cc );
    proto_tree_add_item( cemi_list, hf_cemi_ext_px, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;
  }

  if( pa_flags ) /* AX_PropExtDescrResp */
  {
    /* 4 bytes DPT (2 bytes DPT Major, 2 bytes DPT Minor) */
    if( offset + 4 > size )
    {
      node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Data Point Type" );
      expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 4 bytes" );
      error = 1;
      offset = size;
    }
    else
    {
      uint16_t dpt_major = tvb_get_ntohs( tvb, offset );
      uint16_t dpt_minor = tvb_get_ntohs( tvb, offset + 2 );

      if( cemi_list )
      {
        proto_item *dpt_node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 2, "Data Point Type: %u.%u", dpt_major, dpt_minor );
        proto_tree *dpt_list = proto_item_add_subtree( dpt_node, ett_cemi_dpt );
        proto_tree_add_item( dpt_list, hf_cemi_dpt_major, tvb, offset, 2, ENC_BIG_ENDIAN );
        proto_tree_add_item( dpt_list, hf_cemi_dpt_minor, tvb, offset + 2, 2, ENC_BIG_ENDIAN );
      }

      offset += 4;

      if( dpt_major || dpt_minor )
      {
        col_append_fstr( cinfo, COL_INFO, " DPT=%u.%u", dpt_major, dpt_minor );
        proto_item_append_text( cemi_node, ", DPT=%u.%u", dpt_major, dpt_minor );
      }
    }

    /* 1 byte PDT, 2 bytes Max Elements, 1 byte Access Levels */
    dissect_prop_descr( tvb, pinfo, cemi_node, cemi_list, &offset, size, &error );

    /* No further trailing data */
    pa_flags = 0;
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect A_DataSecurity service */
static void dissect_data_security_service( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* cemi_node, proto_tree* cemi_list,
  uint16_t source_addr, proto_item* source_node, uint16_t dest_addr, proto_item* dest_node, uint8_t unicast,
  const char* name, int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  proto_tree* root_tree = tree;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node;
  proto_tree* list;

  // 1 byte SCF, 6 bytes SeqNr, ...
  // and either another SeqNr for sync or Apci+Mac (2+4 bytes) for data.
  if( offset + 13 > size )
  {
    node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? SCF, SeqNr, ..." );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: min 13 bytes" );
    error = 1;
    offset = size;
  }
  else
  {
    /* 1 byte SCF */
    uint8_t scf = tvb_get_uint8( tvb, offset );
    uint8_t is_sync = (scf & 6) == 0x02;
    uint8_t is_sync_req = is_sync && (scf & 1) == 0;
    uint8_t is_sync_res = is_sync && !is_sync_req;
    uint64_t seq_nr;

    name = try_val_to_str( scf, scf_short_vals );
    if( !name ) name = "?";
    col_append_fstr( cinfo, COL_INFO, " %s", name );
    proto_item_append_text( cemi_node, ", %s", name );

    node = proto_tree_add_item( cemi_list, hf_cemi_scf, tvb, offset, 1, ENC_BIG_ENDIAN );
    list = proto_item_add_subtree( node, ett_cemi_scf );
    proto_tree_add_item( list, hf_cemi_scf_t, tvb, offset, 1, ENC_BIG_ENDIAN );
    proto_tree_add_item( list, hf_cemi_scf_sai, tvb, offset, 1, ENC_BIG_ENDIAN );
    proto_tree_add_item( list, hf_cemi_scf_sbc, tvb, offset, 1, ENC_BIG_ENDIAN );
    proto_tree_add_item( list, hf_cemi_scf_svc, tvb, offset, 1, ENC_BIG_ENDIAN );

    ++offset;

    /*  6 bytes SeqNr */
    name = is_sync_req ? "SeqNrLocal" : is_sync_res ? "Challenge" : "SeqNr";
    seq_nr = tvb_get_ntoh48( tvb, offset );
    proto_tree_add_data( cemi_list, tvb, offset, 6, cinfo, cemi_node, name, NULL, is_sync_res ? NULL : ", SeqNrLocal=$" );
    offset += 6;

    if( is_sync )
    {
      /* 6 bytes SyncReq SerNr or SyncRes SeqNrRemote */
      name = is_sync_req ? "SerNr" : "SeqNrRemote";
      proto_tree_add_data( cemi_list, tvb, offset, 6, cinfo, cemi_node, name, NULL, is_sync_res ? ", SeqNrRemote=$" : NULL );
      offset += 6;

      /* 6 bytes SyncReq Challenge or SyncRes SeqNrLocal */
      name = is_sync_req ? "Challenge" : "SeqNrLocal";
      if( offset + 6 > size )
      {
        node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "%s", name );
        proto_item_prepend_text( node, "? " );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 6 bytes" );
        error = 1;
        offset = size;
      }
      else
      {
        proto_tree_add_data( cemi_list, tvb, offset, 6, NULL, NULL, name, NULL, NULL );
        offset += 6;

        if( offset < size )
        {
          /* 4 bytes MAC */
          node = proto_tree_add_data( cemi_list, tvb, offset, size - offset, NULL, NULL, "Message Authentication Code", NULL, NULL );
          if( offset + 4 != size )
          {
            proto_item_prepend_text( node, "? " );
            expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 4 bytes" );
            error = 1;
          }
          offset = size;
        }
      }
    }
    else // Data
    {
      struct data_security_info info;
      struct knx_keyring_ia_seqs* ia_seq;
      const uint8_t* cemi;
      const uint8_t* encrypted;
      int encrypted_size;
      const uint8_t* decrypted;
      proto_item* item;

      info.source = source_addr;
      info.dest = dest_addr;
      info.multicast = !unicast;
      info.seq_nr = seq_nr;
      *info.output_text = '\0';

      if( !unicast )  // multicast or broadcast
      {
        // Check sending IA
        uint8_t ga_found = 0;
        uint8_t ia_ok = 0;
        struct knx_keyring_ga_senders* ga_sender = knx_keyring_ga_senders;
        for( ; ga_sender; ga_sender = ga_sender->next )
        {
          if( ga_sender->ga == dest_addr )
          {
            ga_found = 1;

            if( ga_sender->ia == source_addr )
            {
              ia_ok = 1;
              break;
            }
          }
        }

        if( !ia_ok )
        {
          if( ga_found )
          {
            expert_add_info_format( pinfo, source_node, KIP_ERROR, "Unknown sender" );
            error = 1;
          }
          else
          {
            expert_add_info_format( pinfo, dest_node, KIP_WARNING, "Unknown group address" );
          }
        }
      }

      // Check SeqNr
      for( ia_seq = knx_keyring_ia_seqs; ia_seq; ia_seq = ia_seq->next )
      {
        if( ia_seq->ia == source_addr )
        {
          if( ia_seq->seq > seq_nr )
          {
            expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: min $%012" PRIX64, ia_seq->seq );
            break;
          }
        }
      }

      // Get encrypted data.
      cemi = tvb_get_ptr( tvb, 0, size );
      encrypted = cemi + offset;
      encrypted_size = size - offset;

      // Decrypt.
      decrypted = decrypt_data_security_data( pinfo->pool, encrypted, encrypted_size, cemi, size, &info );

      if( decrypted )
      {
        tvbuff_t* tvb2 = tvb_new_child_real_data( tvb, decrypted, encrypted_size, encrypted_size );
        int size2 = encrypted_size - 4;  // > 0, guaranteed by decrypt_data_security_data
        proto_item_append_text( cemi_node, ", MAC OK" );
        //tvb_set_free_cb(tvb2, wmem_free);
        add_new_data_source( pinfo, tvb2, "Decrypted" );

        item = proto_tree_add_none_format( cemi_list, hf_folder, tvb2, 0, encrypted_size, "Decrypted" );
        tree = proto_item_add_subtree( item, ett_cemi_decrypted );

        if( *info.output_text )
        {
          proto_item_append_text( item, " (%s)", info.output_text );
        }

        proto_tree_add_data( tree, tvb2, 0, size2, NULL, NULL, "Embedded APDU", NULL, NULL );
        proto_tree_add_data( tree, tvb2, size2, 4, NULL, NULL, "Message Authentication Code", NULL, NULL );

        /* Dissect embedded APDU */
        {
          // Hack: To save us from splitting another sub dissector which only
          // dissects the Apci+Apdu
          // we synthesize a telegram from the outer ApciSec telegram fields and the inner
          // decrypted apci+apdu and then we dissect this as a new cEMI frame.
          int innerTelegramSize = size - 13;     // > 0, already checked above
          int additionalInfoLength = cemi[ 1 ];  // cemi size > 13, already checked above
          int offsetToApci = additionalInfoLength + 9;
          if( offsetToApci < size )
          {
            if( offsetToApci + size2 <= innerTelegramSize )
            {
              uint8_t* innerTelegram = (uint8_t*) wmem_alloc( pinfo->pool, innerTelegramSize );

              memcpy( innerTelegram, cemi, offsetToApci );
              memcpy( innerTelegram + offsetToApci, decrypted, size2 );
              innerTelegram[ additionalInfoLength + 8 ] = (uint8_t) (size2 - 1);

              tvbuff_t* tvb3 = tvb_new_child_real_data( tvb, innerTelegram, innerTelegramSize, innerTelegramSize );
              //tvb_set_free_cb(tvb3, wmem_free);
              add_new_data_source( pinfo, tvb3, "Inner Decrypted Telegram" );

              dissector_handle_t cemi_handle = find_dissector( "cemi" );
              if( cemi_handle )
              {
                call_dissector( cemi_handle, tvb3, pinfo, root_tree );
              }
            }
          }
        }
      }
      else
      {
        // Could not be decrypted.
        proto_item_append_text( cemi_node, ", Could not be decrypted" );

        if( *info.output_text )
        {
          proto_item_append_text( cemi_node, " (%s)", info.output_text );
        }
      }

      offset = size;
    }
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect extended AL service (10 bit AL service code)
*/
static void dissect_extended_app_service( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* cemi_node, proto_tree* cemi_list,
  uint16_t source_addr, proto_item* source_node, uint16_t dest_addr, proto_item* dest_node, uint8_t unicast,
  uint16_t ax, const char* name,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node = NULL;
  proto_tree* list = NULL;

  col_append_fstr( cinfo, COL_INFO, " %s", name );

  if( tree )
  {
    proto_item_append_text( cemi_node, ", %s", name );
    node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 2, "APCI: %s", name );
    list = proto_item_add_subtree( node, ett_cemi_apci );
    proto_tree_add_item( list, hf_cemi_ax, tvb, offset, 2, ENC_BIG_ENDIAN );
  }

  offset += 2;

  pa_flags = PA_RESPONSE | PA_DATA;

  switch( ax )
  {
  case AX_UserMemRead:
  case AX_MemExtRead:
  case AX_RoutingTableRead:
  case AX_RouterMemRead:
  case AX_PropValueRead:
  case AX_PropDescrRead:
  case AX_IndAddrSerNumRead:
  case AX_DomAddrSerNumRead:
  case AX_PropExtValueRead:
  case AX_PropExtDescrRead:
    pa_flags = 0;
    break;
  }

  switch( ax )
  {
  case AX_MemExtRead:
  case AX_MemExtReadResp:
  case AX_MemExtWrite:
  case AX_MemExtWriteResp:
    dissect_memory_ext_service( tvb, pinfo, cemi_node, cemi_list, ax, &offset, size, &pa_flags, &error );
    break;

  case AX_UserMemRead:
  case AX_UserMemResp:
  case AX_UserMemWrite:
  case AX_UserMemBitWrite:
    dissect_user_memory_service( tvb, pinfo, tree, cemi_node, cemi_list, &offset, size, &pa_flags, &error );
    break;

  case AX_FuncPropCmd:
  case AX_FuncPropRead:
  case AX_FuncPropResp:
    dissect_function_property_service( tvb, pinfo, cemi_node, cemi_list, &offset, size, &error );
    break;

  case AX_RoutingTableRead:
  case AX_RouterMemRead:
  case AX_RoutingTableResp:
  case AX_RoutingTableWrite:
  case AX_RouterMemResp:
  case AX_RouterMemWrite:
  case AX_MemBitWrite:
    dissect_router_service( tvb, pinfo, tree, cemi_node, cemi_list, &offset, size, &pa_flags, &error );
    break;

  case AX_AuthReq:
  case AX_AuthResp:
  case AX_KeyWrite:
  case AX_KeyResp:
    dissect_authenticate_service( tvb, pinfo, tree, cemi_node, cemi_list, ax, &offset, size, &pa_flags, &error );
    break;

  case AX_PropValueRead:
  case AX_PropValueResp:
  case AX_PropValueWrite:
    dissect_property_value_service( tvb, pinfo, cemi_node, cemi_list, &offset, size, &pa_flags, &error );
    break;

  case AX_PropDescrRead:
  case AX_PropDescrResp:
    dissect_property_description_service( tvb, pinfo, cemi_node, cemi_list, &offset, size, &pa_flags, &error );
    break;

  case AX_NwkParamRead:
  case AX_NwkParamResp:
  case AX_NwkParamWrite:
  case AX_GroupPropValueRead:
  case AX_GroupPropValueResp:
  case AX_GroupPropValueWrite:
  case AX_GroupPropValueInfo:
    dissect_network_parameter_service( tvb, pinfo, cemi_node, cemi_list, &offset, size, &error );
    break;

  case AX_IndAddrSerNumRead:
  case AX_DomAddrSerNumRead:
  case AX_IndAddrSerNumResp:
  case AX_IndAddrSerNumWrite:
  case AX_DomAddrSerNumResp:
  case AX_DomAddrSerNumWrite:
    dissect_ia_serial_number_service( tvb, pinfo, cemi_node, cemi_list, &offset, size, &pa_flags, &error );
    break;

  case AX_SysNwkParamRead:
  case AX_SysNwkParamResp:
  case AX_SysNwkParamWrite:
    dissect_system_network_parameter_service( tvb, pinfo, cemi_node, cemi_list, &offset, size, &pa_flags, &error );
    break;

  case AX_PropExtValueRead:
  case AX_PropExtValueResp:
  case AX_PropExtValueWriteCon:
  case AX_PropExtValueWriteConRes:
  case AX_PropExtValueWriteUnCon:
    dissect_property_ext_value_service( tvb, pinfo, cemi_node, cemi_list, &offset, size, &pa_flags, &error );
    break;

  case AX_PropExtDescrRead:
  case AX_PropExtDescrResp:
    dissect_property_ext_description_service( tvb, pinfo, cemi_node, cemi_list, &offset, size, &pa_flags, &error );
    break;

  case AX_FuncPropExtCmd:
  case AX_FuncPropExtRead:
  case AX_FuncPropExtResp:

    /* 2 bytes OT, 12 bits OI, 12 bits PID */
    dissect_pid_ext( tvb, pinfo, cemi_node, cemi_list, &offset, size, &error );
    break;

  case AX_DataSec:
    dissect_data_security_service( tvb, pinfo, tree, cemi_node, cemi_list, source_addr, source_node, dest_addr, dest_node, unicast,
      name, &offset, size, &pa_flags, &error );
    break;
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect simple AL service (4 bit AL service code)
*/
static void dissect_simple_app_service( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* cemi_node, proto_tree* cemi_list,
  uint8_t ac, uint8_t ad, int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node = NULL;
  proto_tree* list = NULL;

  uint8_t c;
  uint16_t cc;

  const char* name = val_to_str( ac, ac_vals, "AC=%u" );
  col_append_fstr( cinfo, COL_INFO, " %s", name );
  if( tree )
  {
    proto_item_append_text( cemi_node, ", %s", name );
    node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 2, "APCI: %s", name );
    list = proto_item_add_subtree( node, ett_cemi_apci );
    proto_tree_add_item( list, hf_cemi_ac, tvb, offset, 2, ENC_BIG_ENDIAN );
  }

  offset++;

  switch( ac )
  {
  case AC_GroupValueRead:
  case AC_MemRead:
  case AC_AdcRead:
  case AC_DevDescrRead:
    pa_flags = 0;
    break;
  }

  switch( ac )
  {
  case AC_GroupValueRead:
  case AC_GroupValueResp:
  case AC_GroupValueWrite:
  case AC_Restart:
    {
      uint8_t expected = ((pa_flags && offset + 1 >= size) || ac == AC_Restart);

      if( expected || ad != 0 )
      {
        /* Show APCI 6-bit data
        */
        if( !expected )
        {
          error = 1;
        }
        else if( ad != 0 || ac != AC_Restart || offset + 1 < size )
        {
          col_append_fstr( cinfo, COL_INFO, " $%02X", ad );
          proto_item_append_text( cemi_node, " $%02X", ad );
        }

        if( tree )
        {
          node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 1, "Data: %02X", ad );
          list = proto_item_add_subtree( node, ett_cemi_apci );
          proto_tree_add_item( list, hf_cemi_ad, tvb, offset, 1, ENC_BIG_ENDIAN );

          if( !expected )
          {
            proto_item_prepend_text( node, "? " );
            expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 0x00" );
          }
        }
      }
    }
    break;

  case AC_MemRead:
  case AC_MemResp:
  case AC_MemWrite:

    /* 6 bits Memory Length, 2 bytes Memory Address */
    if( offset + 3 > size )
    {
      node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset + 1, size - offset - 1, NULL, "? Memory Address" );
      expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
      error = 1;
      offset = size - 1;
    }
    else
    {
      cc = tvb_get_ntohs( tvb, offset + 1 );
      if( ad != 1 )
        col_append_fstr( cinfo, COL_INFO, " N=%u", ad );
      col_append_fstr( cinfo, COL_INFO, " X=$%04X", cc );
      if( tree )
      {
        if( ad != 1 )
          proto_item_append_text( cemi_node, ", N=%u", ad );
        proto_item_append_text( cemi_node, ", X=$%04X", cc );
        node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 3, "Range: %u byte%s at address $%04X", ad, (ad == 1) ? "" : "s", cc );
        list = proto_item_add_subtree( node, ett_cemi_range );
        proto_tree_add_item( list, hf_cemi_ad_memory_length, tvb, offset, 1, ENC_BIG_ENDIAN );
        proto_tree_add_item( list, hf_cemi_memory_address, tvb, offset + 1, 2, ENC_BIG_ENDIAN );
      }
      offset += 2;
    }
    break;

  case AC_AdcRead:
  case AC_AdcResp:

    /* 6 bits Channel */
    col_append_fstr( cinfo, COL_INFO, " #%u", ad );
    if( tree )
    {
      proto_item_append_text( cemi_node, " #%u", ad );
      node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 1, "Channel: %u", ad );
      list = proto_item_add_subtree( node, ett_cemi_apci );
      proto_tree_add_item( list, hf_cemi_ad_channel, tvb, offset, 1, ENC_BIG_ENDIAN );
    }
    ++offset;

    /* 1 byte Count */
    if( offset >= size )
    {
      proto_tree_add_expert_format( cemi_list, pinfo, KIP_ERROR, tvb, offset, 0, "? Count: expected 1 byte" );
      error = 1;
      --offset;
    }
    else
    {
      c = tvb_get_uint8( tvb, offset );
      if( c != 1 )
      {
        col_append_fstr( cinfo, COL_INFO, " N=%u", c );
        proto_item_append_text( cemi_node, ", N=%u", c );
      }
      proto_tree_add_item( cemi_list, hf_cemi_adc_count, tvb, offset, 1, ENC_BIG_ENDIAN );
    }
    break;

  case AC_DevDescrRead:
  case AC_DevDescrResp:

    /* 6 bits Descriptor Type */
    if( ad != 0 )
      col_append_fstr( cinfo, COL_INFO, " #%u", ad );
    if( tree )
    {
      if( ad != 0 )
        proto_item_append_text( cemi_node, " #%u", ad );
      node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 1, "Descriptor Type: %u", ad );
      list = proto_item_add_subtree( node, ett_cemi_apci );
      proto_tree_add_item( list, hf_cemi_ad_type, tvb, offset, 1, ENC_BIG_ENDIAN );
    }
    break;

  case AC_UserMsg:
  case AC_Escape:

    /* 6 bits Data */
    col_append_fstr( cinfo, COL_INFO, " #%u", ad );
    if( tree )
    {
      proto_item_append_text( cemi_node, " #%u", ad );
      proto_item_append_text( node, " $%02X", ad );
      proto_tree_add_item( list, hf_cemi_ad, tvb, offset, 1, ENC_BIG_ENDIAN );
    }
    break;
  }

  offset++;

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect cEMI Application Layer
*/
static void dissect_cemi_app_layer( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* cemi_node, proto_tree* cemi_list,
  uint16_t source_addr, proto_item* source_node, uint16_t dest_addr, proto_item* dest_node, uint8_t unicast,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  /* 10 bits APCI
  */
  if( offset + 1 >= size )
  {
    proto_item* node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? APCI" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
    error = 1;
    offset = size;
  }
  else
  {
    /* Extract and split AL service code */
    uint8_t tb = tvb_get_uint8( tvb, offset );
    uint8_t ab = tvb_get_uint8( tvb, offset + 1 );

    /* 4 bits simple AL service code */
    uint8_t ac = ((tb & 0x03) << 2) | ((ab & 0xC0) >> 6);

    /* 6 bits data */
    uint8_t ad = ab & 0x3F;

    /* 10 = 4 + 6 bits extended AL service code */
    uint16_t ax = (ac << 6) | ad;

    const char* name = try_val_to_str( ax, ax_vals );

    if( name )  /* Extended AL code (10 bits) */
    {
      dissect_extended_app_service( tvb, pinfo, tree, cemi_node, cemi_list, source_addr, source_node, dest_addr, dest_node, unicast,
        ax, name, &offset, size, &pa_flags, &error );
    }
    else  /* Simple AL code (4 bits) followed by data (6 bits) */
    {
      dissect_simple_app_service( tvb, pinfo, tree, cemi_node, cemi_list, ac, ad, &offset, size, &pa_flags, &error );
    }
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect cEMI Transport Layer
*/
static void dissect_cemi_transport_layer( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* cemi_node, proto_tree* cemi_list,
  uint8_t is_tdata, uint16_t source_addr, proto_item* source_node, uint16_t dest_addr, proto_item* dest_node, uint8_t unicast,
  int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node;
  const char* name;
  char text[ 128 ];
  uint8_t c;

  /* 6 bits TPCI */
  if( offset >= size )
  {
    proto_tree_add_expert_format( cemi_list, pinfo, KIP_ERROR, tvb, offset, 0, "? TPCI: expected 1 byte" );
    error = 1;
  }
  else
  {
    uint8_t tb = tvb_get_uint8( tvb, offset );
    proto_item *tpci_node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 1, "TPCI" );
    proto_tree *tpci_list = proto_item_add_subtree( tpci_node, ett_cemi_tpci );
    uint8_t tpci_error = 0;

    node = proto_tree_add_item( tpci_list, hf_cemi_tpt, tvb, offset, 1, ENC_BIG_ENDIAN );
    if( is_tdata && (tb & 0x80) )
    {
      proto_item_prepend_text( node, "? " );
      expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: zero" );
      tpci_error = 1;
    }

    node = proto_tree_add_item( tpci_list, hf_cemi_tst, tvb, offset, 1, ENC_BIG_ENDIAN );
    if( is_tdata && (tb & 0x40) )
    {
      proto_item_prepend_text( node, "? " );
      expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: zero" );
      tpci_error = 1;
    }

    c = (tb & 0x3C) >> 2;

    if( c || tb & 0x40 )  /* Numbered Packet? */
    {
      node = proto_tree_add_item( tpci_list, hf_cemi_num, tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_item_append_text( tpci_node, ", SeqNum = %u", c );
      if( !(tb & 0x40) )
      {
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: zero" );
        tpci_error = 1;
      }
    }

    if( tb & 0x80 )  /* Control Packet */
    {
      /* 2 bits TPCI Code */
      uint8_t tc = tb & 0x03;
      name = try_val_to_str( tc, tc_vals );
      if( !name )
      {
        snprintf( text, sizeof text, "TC=%u", tc );
        name = text;
      }
      col_append_fstr( cinfo, COL_INFO, " %s", name );
      if( tree )
      {
        proto_item_append_text( cemi_node, ", %s", name );
        proto_item_append_text( tpci_node, ": %s", name );
        proto_tree_add_item( tpci_list, hf_cemi_tc, tvb, offset, 1, ENC_BIG_ENDIAN );
      }
    }

    if( tpci_error )
    {
      proto_item_prepend_text( tpci_node, "? " );
      error = 1;
    }

    if( tb & 0x80 )  /* Control Packet */
    {
      pa_flags = 0;
      offset++;
    }
    else  /* Data Packet */
    {
      /* APCI etc */
      dissect_cemi_app_layer( tvb, pinfo, tree, cemi_node, cemi_list, source_addr, source_node, dest_addr, dest_node, unicast, &offset, size, &pa_flags, &error );
    }
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

/* Dissect cEMI Link Layer
  (typically L_Data or T_Data)
*/
static void dissect_cemi_link_layer( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* cemi_node, proto_tree* cemi_list, uint8_t mc, int* p_offset, int size, uint8_t* p_pa_flags, uint8_t* p_error )
{
  column_info* cinfo = pinfo->cinfo;
  int offset = *p_offset;
  uint8_t pa_flags = *p_pa_flags;
  uint8_t error = *p_error;

  proto_item* node = NULL;
  proto_tree* list = NULL;

  const char* name;
  char text[ 128 ];
  uint8_t c;

  uint8_t is_tdata = 0;
  uint8_t is_ldata = 0;
  uint16_t source_addr = 0;
  uint16_t dest_addr = 0;
  uint8_t unicast = 0;

  proto_item* source_node = NULL;
  proto_item* dest_node = NULL;

  proto_item* ai_node;
  proto_tree* ai_list;

  if( size < 2 )
  {
    ai_list = proto_tree_add_subtree( cemi_list, tvb, offset, 0, ett_cemi_ai, &ai_node, "? Additional Info" );
    proto_tree_add_expert_format( ai_list, pinfo, KIP_ERROR, tvb, offset, 0, "? Length: expected 1 byte" );
    offset = size;
    error = 1;
  }
  else
  {
    /* Additional Information */
    uint8_t ai_len = tvb_get_uint8( tvb, 1 );
    int ai_end = 2 + ai_len;
    int ai_size = ai_len;

    if( ai_end > size )
    {
      error = 2;
      ai_size = size - 2;
      ai_end = size;
    }

    ai_node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, 1, ai_size + 1, "Additional Info (%u bytes)", ai_len );
    ai_list = proto_item_add_subtree( ai_node, ett_cemi_ai );
    node = proto_tree_add_item( ai_list, hf_cemi_ai_length, tvb, 1, 1, ENC_BIG_ENDIAN );

    if( error == 2 )
    {
      proto_item_prepend_text( node, "? " );
      expert_add_info_format( pinfo, node, KIP_ERROR, "Available: %d bytes", ai_size );
    }

    offset = 2;
    while( offset < ai_end )
    {
      /* Additional Information Element */
      uint8_t aie_type = tvb_get_uint8( tvb, offset );
      uint8_t aie_len;
      int aie_size;
      proto_item *aie_node;
      proto_tree *aie_list;

      name = try_val_to_str( aie_type, aiet_vals );

      if( offset + 1 >= ai_end )
      {
        error = 3;
        aie_len = 0;
        aie_size = 1;
      }
      else
      {
        aie_len = tvb_get_uint8( tvb, offset + 1 );
        aie_size = ai_end - offset - 2;
        if( aie_size < aie_len )
        {
          error = 4;
        }
        else
        {
          aie_size = aie_len;
        }
        aie_size += 2;
      }

      aie_node = proto_tree_add_none_format( ai_list, hf_folder, tvb, offset, aie_size, "Additional Info: %s", name ? name : "?" );
      aie_list = proto_item_add_subtree( aie_node, ett_cemi_aie );
      node = proto_tree_add_item( aie_list, hf_cemi_aie_type, tvb, offset, 1, ENC_BIG_ENDIAN );
      if( name ) proto_item_append_text( node, " = %s", name );
      offset++;

      if( error == 3 )
      {
        proto_item_prepend_text( aie_node, "? " );
        proto_tree_add_expert_format( aie_list, pinfo, KIP_ERROR, tvb, offset, 0, "? Length: expected 1 byte" );
        break;
      }

      proto_item_append_text( aie_node, " (%u bytes)", aie_len );
      node = proto_tree_add_item( aie_list, hf_cemi_aie_length, tvb, offset, 1, ENC_BIG_ENDIAN );
      offset++;

      if( error == 4 )
      {
        proto_item_prepend_text( aie_node, "? " );
        proto_item_prepend_text( node, "? " );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Available: %d bytes", aie_size - 2 );
        break;
      }

      if( aie_len > 0 )
      {
        proto_tree_add_data( aie_list, tvb, offset, aie_len, NULL, NULL, "Data", NULL, NULL );
        offset += aie_len;
      }
      else
      {
        proto_item_prepend_text( aie_node, "? " );
        proto_item_append_text( node, " (?)" );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: >= 1 byte(s)" );
        error = 5;
      }
    }

    if( error >= 2 )
    {
      proto_item_prepend_text( ai_node, "? " );
    }

    offset = ai_end;
  }

  switch( mc )
  {
  case CEMI_L_BUSMON_IND:
  case CEMI_L_RAW_IND:
  case CEMI_L_RAW_REQ:
  case CEMI_L_RAW_CON:
    break;

  default:

    switch( mc )
    {
    case CEMI_L_DATA_REQ:
    case CEMI_L_DATA_CON:
    case CEMI_L_DATA_IND:
      is_ldata = 1;
      break;

    case CEMI_T_DATA_INDIVIDUAL_REQ:
    case CEMI_T_DATA_INDIVIDUAL_IND:
    case CEMI_T_DATA_CONNECTED_REQ:
    case CEMI_T_DATA_CONNECTED_IND:
      is_tdata = 1;
      break;
    }

    if( is_tdata )
    {
      int length = (size >= offset + 6) ? 6 : size - offset;
      node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, length, NULL, "Reserved" );
      if( length < 6 )
      {
        proto_item_prepend_text( node, "? " );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 6 bytes" );
        error = 1;
      }
      else
      {
        int pos = 0;
        for( ; pos < 6; pos++ )
        {
          if( tvb_get_uint8( tvb, offset + pos ) != 0 )
          {
            proto_item_prepend_text( node, "? " );
            expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: zero" );
            error = 1;
            break;
          }
        }
      }

      is_tdata = 1;
      offset += length;
    }
    else
    {
      /* 1 byte Control Field 1 */
      if( offset >= size )
      {
        proto_tree_add_expert_format( cemi_list, pinfo, KIP_ERROR, tvb, offset, 0, "? Ctrl1: expected 1 byte" );
        error = 1;
      }
      else
      {
        if( tree )
        {
          c = tvb_get_uint8( tvb, offset );
          proto_item_append_text( cemi_node, ", " );
          node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 1, "Ctrl1: " );
          if( !(c & 0x80) )
          {
            proto_item_append_text( cemi_node, "X " );
            proto_item_append_text( node, "Extended, " );
          }
          if( !(c & 0x20) )
          {
            proto_item_append_text( cemi_node, "R " );
            proto_item_append_text( node, "Repeat On Error, " );
          }
          if( !(c & 0x10) )
          {
            proto_item_append_text( cemi_node, "B " );
            proto_item_append_text( node, "System Broadcast, " );
          }
          if( c & 0x02 )
          {
            proto_item_append_text( cemi_node, "A " );
            proto_item_append_text( node, "Ack Wanted, " );
          }
          if( c & 0x01 )
          {
            proto_item_append_text( cemi_node, "C " );
            proto_item_append_text( node, "Unconfirmed, " );
          }

          name = try_val_to_str( (c & 0x0C) >> 2, prio_vals );
          if( !name )
            name = "?";
          proto_item_append_text( cemi_node, "P=%s", name );
          proto_item_append_text( node, "Prio = %s", name );
          list = proto_item_add_subtree( node, ett_cemi_ctrl1 );
          proto_tree_add_item( list, hf_cemi_ft, tvb, offset, 1, ENC_BIG_ENDIAN );
          proto_tree_add_item( list, hf_cemi_rep, tvb, offset, 1, ENC_BIG_ENDIAN );
          proto_tree_add_item( list, hf_cemi_bt, tvb, offset, 1, ENC_BIG_ENDIAN );
          proto_tree_add_item( list, hf_cemi_prio, tvb, offset, 1, ENC_BIG_ENDIAN );
          proto_tree_add_item( list, hf_cemi_ack, tvb, offset, 1, ENC_BIG_ENDIAN );
          proto_tree_add_item( list, hf_cemi_ce, tvb, offset, 1, ENC_BIG_ENDIAN );
        }

        offset++;
      }

      /* 1 byte Control Field 2 */
      if( offset >= size )
      {
        proto_tree_add_expert_format( cemi_list, pinfo, KIP_ERROR, tvb, offset, 0, "? Ctrl2: expected 1 byte" );
        error = 1;
      }
      else
      {
        c = tvb_get_uint8( tvb, offset );

        unicast = !(c & 0x80);  /* Address Type (IA or GA) */

        if( tree )
        {
          uint8_t hc = (c & 0x70) >> 4;  /* Hop Count */
          uint8_t eff = c & 0x0F;  /* Extended Frame Format (0 = standard) */

          snprintf( text, sizeof text, "%u", (c & 0x70) >> 4 );   /* hop count */
          proto_item_append_text( cemi_node, ", H=%u", hc );
          node = proto_tree_add_none_format( cemi_list, hf_folder, tvb, offset, 1, "Ctrl2: Hops = %u", hc );
          if( eff )
          {
            proto_item_append_text( cemi_node, " F=%u", eff );
            proto_item_append_text( cemi_node, " Frame = %u", eff );
          }
          list = proto_item_add_subtree( node, ett_cemi_ctrl2 );
          proto_tree_add_item( list, hf_cemi_at, tvb, offset, 1, ENC_BIG_ENDIAN );
          proto_tree_add_item( list, hf_cemi_hc, tvb, offset, 1, ENC_BIG_ENDIAN );
          proto_tree_add_item( list, hf_cemi_eff, tvb, offset, 1, ENC_BIG_ENDIAN );
        }

        offset++;
      }

      /* 2 bytes Source Address */
      if( offset + 1 >= size )
      {
        node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Source" );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
        error = 1;
        offset = size;
      }
      else
      {
        source_addr = tvb_get_ntohs( tvb, offset );
        snprintf( text, sizeof text, "%u.%u.%u", (source_addr >> 12) & 0xF, (source_addr >> 8) & 0xF, source_addr & 0xFF );
        col_append_fstr( cinfo, COL_INFO, " %s", text );
        if( tree )
        {
          proto_item_append_text( cemi_node, ", Src=%s", text );
          source_node = proto_tree_add_item( cemi_list, hf_cemi_sa, tvb, offset, 2, ENC_BIG_ENDIAN );
          proto_item_append_text( source_node, " = %s", text );
        }

        offset += 2;
      }

      /* 2 bytes Destination Address */
      if( offset + 1 >= size )
      {
        node = proto_tree_add_bytes_format( cemi_list, hf_bytes, tvb, offset, size - offset, NULL, "? Destination" );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
        error = 1;
        offset = size;
      }
      else
      {
        dest_addr = tvb_get_ntohs( tvb, offset );

        if( unicast )
        {
          /* Individual Address */
          snprintf( text, sizeof text, "%u.%u.%u", (dest_addr >> 12) & 0xF, (dest_addr >> 8) & 0xF, dest_addr & 0xFF );
        }
        else
        {
          /* Group Address */
          snprintf( text, sizeof text, "%u/%u/%u", (dest_addr >> 11) & 0x1F, (dest_addr >> 8) & 0x7, dest_addr & 0xFF );
        }

        col_append_fstr( cinfo, COL_INFO, "->%s", text );

        if( tree )
        {
          proto_item_append_text( cemi_node, ", Dst=%s", text );
          dest_node = proto_tree_add_item( cemi_list, hf_cemi_da, tvb, offset, 2, ENC_BIG_ENDIAN );
          proto_item_append_text( dest_node, " = %s", text );
        }

        offset += 2;
      }
    }

    if( is_ldata || is_tdata )
    {
      /* 1 byte NPDU Length */
      if( offset >= size )
      {
        proto_tree_add_expert_format( cemi_list, pinfo, KIP_ERROR, tvb, offset, 0, "? Length: expected 1 byte" );
        error = 1;
      }
      else
      {
        uint8_t data_len = tvb_get_uint8( tvb, offset );
        node = proto_tree_add_item( cemi_list, hf_cemi_len, tvb, offset, 1, ENC_BIG_ENDIAN );

        if( offset + 2 + data_len != size )
        {
          proto_item_prepend_text( node, "? " );
          expert_add_info_format( pinfo, node, KIP_ERROR, "Available: %d bytes", size - offset - 2 );
          error = 1;
        }

        offset++;
      }

      /* TPCI etc */
      dissect_cemi_transport_layer( tvb, pinfo, tree, cemi_node, cemi_list, is_tdata, source_addr, source_node, dest_addr, dest_node, unicast, &offset, size, &pa_flags, &error );
    }

    break;
  }

  *p_offset = offset;
  *p_pa_flags = pa_flags;
  *p_error = error;
}

static int dissect_cemi( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_ )
{
  int offset = 0;
  int size = tvb_captured_length_remaining( tvb, 0 );
  uint8_t error = 0;
  column_info* cinfo = pinfo->cinfo;

  /* cEMI node in tree view */
  proto_item* cemi_node = proto_tree_add_item( tree, proto_cemi, tvb, 0, size, ENC_BIG_ENDIAN );

  /* Subnodes of cEMI node */
  proto_tree* cemi_list = proto_item_add_subtree( cemi_node, ett_cemi );

  uint8_t pa_flags = PA_DATA;

  /* Only add cEMI information to the info column (not replacing it).
    This means that we do not have to clear that column here, but
    are adding a seperator here.
  */
  col_append_str( cinfo, COL_INFO, " " );

  /* Replace long name "Common External Message Interface" by short name "cEMI" */
  proto_item_set_text( cemi_node, "cEMI" );

  if( size <= 0 )
  {
    expert_add_info_format( pinfo, cemi_node, KIP_ERROR, "Expected: min 1 byte" );
    error = 1;
  }
  else
  {
    /* 1 byte cEMI Message Code */
    uint8_t mc = tvb_get_uint8( tvb, 0 );
    const char* name = try_val_to_str( mc, mc_vals );

    if( !name )
    {
      /* Unknown Message Code */
      col_append_str( cinfo, COL_INFO, "cEMI" );
      pa_flags = 0;
    }
    else
    {
      /* Add cEMI message code to info column */
      col_append_str( cinfo, COL_INFO, name );

      /* Show MC in cEMI node, and more detailed in a subnode */
      proto_item_append_text( cemi_node, " %s", name );
      proto_tree_add_item( cemi_list, hf_cemi_mc, tvb, 0, 1, ENC_BIG_ENDIAN );

      offset = 1;

      if( mc >= 0xF0 )
      {
        /* cEMI Management packet */
        dissect_cemi_mgmt_packet( tvb, pinfo, cemi_node, cemi_list, mc, &offset, size, &pa_flags, &error );
      }
      else
      {
        /* cEMI Link Layer packet */
        dissect_cemi_link_layer( tvb, pinfo, tree, cemi_node, cemi_list, mc, &offset, size, &pa_flags, &error );
      }
    }
  }

  if( offset < size )
  {
    /* Trailing data */
    proto_item* node = proto_tree_add_data( cemi_list, tvb, offset, size - offset, cinfo, cemi_node, "Data", " $", ", $" );

    if( !pa_flags )
    {
      proto_item_prepend_text( node, "? " );
      expert_add_info_format( pinfo, node, KIP_ERROR, "Unexpected" );
      error = 1;
    }

    offset = size;
  }

  if( error )
  {
    /* If not already done */
    if( !knxip_error )
    {
      knxip_error = 1;
      col_prepend_fstr( cinfo, COL_INFO, "? " );
    }

    proto_item_prepend_text( cemi_node, "? " );
  }

  return size;
}

void proto_register_cemi( void )
{
  /* Header fields */
  static hf_register_info hf[] = {
    { &hf_bytes, { "Data", "cemi.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_folder, { "Folder", "cemi.folder", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_cemi_mc, { "Message Code", "cemi.mc", FT_UINT8, BASE_HEX, VALS( mc_vals ), 0, NULL, HFILL } },
    { &hf_cemi_error, { "Error", "cemi.e", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_cemi_ai_length, { "Additional Information Length", "cemi.ai.n", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_aie_type, { "Additional Information Element Type", "cemi.ait.n", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_cemi_aie_length, { "Additional Information Element Length", "cemi.aie.n", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_ot, { "Object Type", "cemi.ot", FT_UINT16, BASE_DEC, VALS( ot_vals ), 0, NULL, HFILL } },
    { &hf_cemi_oi, { "Object Instance", "cemi.oi", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_ox, { "Object Index", "cemi.ox", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_px, { "Property Index", "cemi.px",FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_pid, { "Property ID", "cemi.pid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_ne, { "Count", "cemi.n", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL } },
    { &hf_cemi_sx, { "Index", "cemi.x", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL } },
    { &hf_cemi_ft, { "Frame Type", "cemi.ft", FT_UINT8, BASE_DEC, VALS( ft_vals ), 0x80, NULL, HFILL } },
    { &hf_cemi_rep, { "Repeat On Error", "cemi.rep", FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x20, NULL, HFILL } },
    { &hf_cemi_bt, { "Broadcast Type", "cemi.bt", FT_UINT8, BASE_DEC, VALS( bt_vals ), 0x10, NULL, HFILL } },
    { &hf_cemi_prio, { "Priority", "cemi.prio", FT_UINT8, BASE_DEC, VALS( prio_vals ), 0x0C, NULL, HFILL } },
    { &hf_cemi_ack, { "Ack Wanted", "cemi.ack", FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x02, NULL, HFILL } },
    { &hf_cemi_ce, { "Confirmation Error", "cemi.ce", FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x01, NULL, HFILL } },
    { &hf_cemi_at, { "Address Type", "cemi.at", FT_UINT8, BASE_DEC, VALS( at_vals ), 0x80, NULL, HFILL } },
    { &hf_cemi_hc, { "Hop Count", "cemi.hc", FT_UINT8, BASE_DEC, NULL, 0x70, NULL, HFILL } },
    { &hf_cemi_eff, { "Extended Frame Format", "cemi.eff", FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL } },
    { &hf_cemi_sa, { "Source", "cemi.sa", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_cemi_da, { "Destination", "cemi.da", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_cemi_len, { "Length", "cemi.len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_tpt, { "Packet Type", "cemi.tpt", FT_UINT8, BASE_DEC, VALS( pt_vals ), 0x80, NULL, HFILL } },
    { &hf_cemi_tst, { "Sequence Type", "cemi.st", FT_UINT8, BASE_DEC, VALS( st_vals ), 0x40, NULL, HFILL } },
    { &hf_cemi_num, { "Sequence Number", "cemi.num", FT_UINT8, BASE_DEC, NULL, 0x3C, NULL, HFILL } },
    { &hf_cemi_tc, { "Service", "cemi.tc", FT_UINT8, BASE_HEX, VALS( tc_vals ), 0x03, NULL, HFILL } },
    { &hf_cemi_ac, { "Service", "cemi.ac", FT_UINT16, BASE_HEX, VALS( ac_vals ), 0x03C0, NULL, HFILL } },
    { &hf_cemi_ad, { "Data", "cemi.ad", FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL } },
    { &hf_cemi_ad_memory_length, { "Memory Length", "cemi.ad.ml", FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL } },
    { &hf_cemi_ad_channel, { "Channel", "cemi.ad.ch", FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL } },
    { &hf_cemi_ad_type, { "Data", "cemi.ad.type", FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL } },
    { &hf_cemi_ax, { "Service", "cemi.ax", FT_UINT16, BASE_HEX, VALS( ax_vals ), 0x03FF, NULL, HFILL } },
    { &hf_cemi_pw, { "Writable", "cemi.pw", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
    { &hf_cemi_pdt, { "Property Data Type", "cemi.pdt", FT_UINT8, BASE_HEX, VALS( pdt_vals ), 0x3F, NULL, HFILL } },
    { &hf_cemi_me, { "Max Elements", "cemi.me", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL } },
    { &hf_cemi_ra, { "Read Access", "cemi.ra", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL } },
    { &hf_cemi_wa, { "Write Access", "cemi.wa", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL } },
    { &hf_cemi_ext_oi, { "Object Instance", "cemi.oi", FT_UINT16, BASE_DEC, NULL, 0xFFF0, NULL, HFILL } },
    { &hf_cemi_ext_pid, { "Property ID", "cemi.pid", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL } },
    { &hf_cemi_ext_ne, { "Count", "cemi.n", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_ext_sx, { "Index", "cemi.x", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_ext_dt, { "Description Type", "cemi.dt", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL } },
    { &hf_cemi_ext_px, { "Property Index", "cemi.px", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL } },
    { &hf_cemi_ext_memory_length, { "Memory Length", "cemi.n", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_ext_memory_address, { "Memory Address", "cemi.x", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_cemi_memory_length, { "Memory Length", "cemi.n", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL } },
    { &hf_cemi_memory_address, { "Memory Address", "cemi.x", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_cemi_memory_address_ext, { "Memory Address Extension", "cemi.xx", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL } },
    { &hf_cemi_level, { "Level", "cemi.level", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_snp_pid, { "Property ID", "cemi.pid", FT_UINT16, BASE_DEC, NULL, 0xFFF0, NULL, HFILL } },
    { &hf_cemi_snp_reserved, { "Reserved", "cemi.reserved", FT_UINT16, BASE_DEC, NULL, 0x0F, NULL, HFILL } },
    { &hf_cemi_dpt_major, { "Data Point Type Major", "cemi.pdt.major", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_dpt_minor, { "Data Point Type Minor", "cemi.pdt.minor", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_cemi_scf, { "Security Control Field", "cemi.scf", FT_UINT8, BASE_HEX, VALS( scf_vals ), 0, NULL, HFILL } },
    { &hf_cemi_scf_t, { "Tool Access", "cemi.scf.t", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
    { &hf_cemi_scf_sai, { "Security Algorithm Identifier", "cemi.scf.sai", FT_UINT8, BASE_HEX, VALS( scf_sai_vals ), 0x70, NULL, HFILL } },
    { &hf_cemi_scf_sbc, { "System Broadcast", "cemi.scf.sbc", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
    { &hf_cemi_scf_svc, { "Service", "cemi.scf.svc", FT_UINT8, BASE_HEX, VALS( scf_svc_vals ), 0x07, NULL, HFILL } },
    { &hf_cemi_adc_count, { "Count", "cemi.adc.n", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
  };

  /* Subtrees */
  static int *ett[] = {
    &ett_cemi,
    &ett_cemi_ai,
    &ett_cemi_aie,
    &ett_cemi_ctrl1,
    &ett_cemi_ctrl2,
    &ett_cemi_tpci,
    &ett_cemi_apci,
    &ett_cemi_range,
    &ett_cemi_pd,
    &ett_cemi_dpt,
    &ett_cemi_scf,
    &ett_cemi_decrypted
  };

  proto_cemi = proto_register_protocol( "Common External Message Interface", "cEMI", "cemi" );

  proto_register_field_array( proto_cemi, hf, array_length( hf ) );
  proto_register_subtree_array( ett, array_length( ett ) );

  register_dissector( "cemi", dissect_cemi, proto_cemi );
}

void proto_reg_handoff_cemi( void )
{
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
