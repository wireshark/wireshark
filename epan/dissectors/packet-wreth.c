/* packet-wreth.c
 * Functions for the WSE Remote Ethernet Dissector
 *
 * $Id$
 *
 * Dissector - WSE RemoteEthernet
 * By Clement Marrast <clement.marrast@molex.com>
 * Copyright 2012 Clement Marrast
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 */

#include "config.h"

#include <epan/packet.h>

#define WRETH_PORT 0xAAAA

static void dissect_wreth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gint WrethIdentPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree);
static gint WrethConnectPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree);
static gint WrethDisconnectPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree);
static gint WrethBlinkyPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree);
static gint WrethGetValuePacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree);
static gint WrethSetValuePacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree);
static gint WrethBoostPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree);
static gint WrethAckPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree);
static gint WrethNackPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree);
static gint WrethMailPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree);
static gint WrethMailDissection(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree, guint8 fragmented);
static gint WrethCodefMasterInfoDissection(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethMailboxTree);
static gint WrethCodefEquipmentInfoDissection(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethMailboxTree);

/* Remote ethernet sub packet type */
#define WSE_RETH_SUBTYPE    0x0200

/* Remote ethernet function code */
#define WRETH_IDENT          1
#define WRETH_CONNECT        2
#define WRETH_ACK            3
#define WRETH_NACK           4
#define WRETH_DISCONNECT     5
#define WRETH_MAIL           6
#define WRETH_BLINKY         7
#define WRETH_GET_VALUE      8
#define WRETH_SET_VALUE      9
#define WRETH_BOOST         10

/* Remote ethernet error code */
#define WRETH_BAD_FUNCTION_CODE         1
#define WRETH_ALREADY_CONNECTED         2
#define WRETH_INVALID_PROTOCOL_VERSION  3
#define WRETH_NOT_CONNECTED             4
#define WRETH_INVALID_MAC_ADDRESS       5
#define WRETH_INVALID_FRAME_SIZE        6
#define WRETH_NO_MEMORY_AVAILABLE       7
#define WRETH_BAD_PARAMETER             8
#define WRETH_TASK_REGISTERED           9

/* Initialize the protocol and registered fields */
static gint wreth_proto = -1;

/* static gint wreth_mail_proto = -1; */
static int hf_Wreth_Subtype = -1;
static int hf_Wreth_Size = -1;
static int hf_Wreth_FunctionCode = -1;
static int hf_Wreth_FrameId = -1;
static int hf_Wreth_ErrorCode = -1;
static int hf_Wreth_Fragmented = -1;
static int hf_Wreth_Retry = -1;
static int hf_Wreth_IdentificationBiosVersion = -1;
static int hf_Wreth_IdentificationBoardNumber = -1;
static int hf_Wreth_IdentificationProtocolVersion = -1;
static int hf_Wreth_IdentificationBoardId = -1;
static int hf_Wreth_IdentificationState = -1;
static int hf_Wreth_IdentificationMacAddr = -1;
static int hf_Wreth_ConnectProtocolVersion = -1;
static int hf_Wreth_ConnectTimeout = -1;
static int hf_Wreth_BlinkyPeriod = -1;
static int hf_Wreth_GetValueVal = -1;
static int hf_Wreth_SetValueVal = -1;
static int hf_Wreth_BoostValue = -1;
static int hf_Wreth_MailDestTic = -1;
static int hf_Wreth_MailReserved = -1;
static int hf_Wreth_Mail_Codef = -1;
static int hf_Wreth_Mail_Status = -1;
static int hf_Wreth_Mail_TicUser_Root = -1;
static int hf_Wreth_Mail_PidUser = -1;
static int hf_Wreth_Mail_Mode = -1;
static int hf_Wreth_Mail_Time = -1;
static int hf_Wreth_Mail_Stop = -1;
static int hf_Wreth_Mail_Nfonc = -1;
static int hf_Wreth_Mail_Ncard = -1;
static int hf_Wreth_Mail_Nchan = -1;
static int hf_Wreth_Mail_Nes = -1;
static int hf_Wreth_Mail_Nb = -1;
static int hf_Wreth_Mail_TypVar = -1;
static int hf_Wreth_Mail_Adr = -1;
static int hf_Wreth_Mail_TicUser_DispCyc = -1;
static int hf_Wreth_Mail_Nb_Max_Size_Mail = -1;
static int hf_Wreth_Mail_User_ThreadID = -1;
static int hf_Wreth_Mail_DispCyc_Version = -1;
static int hf_Wreth_Mail_DifUserParam = -1;
static int hf_Wreth_Mail_Filler = -1;
/* static int hf_Wreth_Mail_Data = -1; */
static int hf_Wreth_Mail_Mastinf_Version = -1;
static int hf_Wreth_Mail_Mastinf_Release = -1;
static int hf_Wreth_Mail_Mastinf_Protocol = -1;
static int hf_Wreth_Mail_Mastinf_CyclicFlux = -1;
static int hf_Wreth_Mail_Mastinf_szProtocolName = -1;
static int hf_Wreth_Mail_Mastinf_MaxTypeEquipment = -1;
static int hf_Wreth_Mail_Mastinf_MinEquipmentNumber = -1;
static int hf_Wreth_Mail_Mastinf_MaxEquipmentNumber = -1;
static int hf_Wreth_Mail_Equinf_Version = -1;
static int hf_Wreth_Mail_Equinf_Release = -1;
static int hf_Wreth_Mail_Equinf_Network = -1;
static int hf_Wreth_Mail_Equinf_Protocol = -1;
static int hf_Wreth_Mail_Equinf_Messaging = -1;
static int hf_Wreth_Mail_Equinf_Equipment = -1;
static int hf_Wreth_Mail_Equinf_Flux = -1;
static int hf_Wreth_Mail_Equinf_IncWord = -1;
static int hf_Wreth_Mail_Equinf_IncDWord = -1;
static int hf_Wreth_Mail_Equinf_IncFWord = -1;
static int hf_Wreth_Mail_Mastinf_DllItemName = -1;
static int hf_Wreth_Mail_Mastinf_szEquipmentName = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteBit = -1;
static int hf_Wreth_Mail_Equinf_MaxReadBit = -1;
static int hf_Wreth_Mail_Equinf_BreakBit = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteIBit = -1;
static int hf_Wreth_Mail_Equinf_MaxReadIBit = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteQBit = -1;
static int hf_Wreth_Mail_Equinf_MaxReadQBit = -1;
static int hf_Wreth_Mail_Equinf_BreakQBit = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteByte = -1;
static int hf_Wreth_Mail_Equinf_MaxReadByte = -1;
static int hf_Wreth_Mail_Equinf_BreakByte = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteIByte = -1;
static int hf_Wreth_Mail_Equinf_MaxReadIByte = -1;
static int hf_Wreth_Mail_Equinf_BreakIByte = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteQByte = -1;
static int hf_Wreth_Mail_Equinf_MaxReadQByte = -1;
static int hf_Wreth_Mail_Equinf_BreakQByte = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteWord = -1;
static int hf_Wreth_Mail_Equinf_MaxReadWord = -1;
static int hf_Wreth_Mail_Equinf_BreakWord = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteIWord = -1;
static int hf_Wreth_Mail_Equinf_MaxReadIWord = -1;
static int hf_Wreth_Mail_Equinf_BreakIWord = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteQWord = -1;
static int hf_Wreth_Mail_Equinf_MaxReadQWord = -1;
static int hf_Wreth_Mail_Equinf_BreakQWord = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteDWord = -1;
static int hf_Wreth_Mail_Equinf_MaxReadDWord = -1;
static int hf_Wreth_Mail_Equinf_BreakDWord = -1;
static int hf_Wreth_Mail_Equinf_MaxWriteFWord = -1;
static int hf_Wreth_Mail_Equinf_MaxReadFWord = -1;
static int hf_Wreth_Mail_Equinf_BreakFWord = -1;
static int hf_Wreth_Mail_Equinf_ReadFactorWord = -1;
static int hf_Wreth_Mail_Equinf_ReadFactorIWord = -1;
static int hf_Wreth_Mail_Equinf_ReadFactorQWord = -1;
static int hf_Wreth_Mail_Equinf_ReadFactorDWord = -1;
static int hf_Wreth_Mail_Equinf_ReadFactorFWord = -1;
static int hf_Wreth_Mail_Equinf_WriteFactorWord = -1;
static int hf_Wreth_Mail_Equinf_WriteFactorIWord = -1;
static int hf_Wreth_Mail_Equinf_WriteFactorQWord = -1;
static int hf_Wreth_Mail_Equinf_WriteFactorDWord = -1;
static int hf_Wreth_Mail_Equinf_WriteFactorFWord = -1;
static int hf_Wreth_Mail_Equinf_DataFormat = -1;
static int hf_Wreth_Mail_Equinf_BreakIBit = -1;

/* Initialize the subtree pointers */
static gint ett_wreth = -1;

/* Note: vals are stored as unsigned 32 bit quantities */
static const value_string tabStatus[] = {
    {   0, "stat_ok" },
    {   1, "stat_err_fonc" },
    {   2, "stat_err_addr" },
    {   3, "stat_bad_frame" },
    {   4, "stat_lock_data" },
    {  10, "STAT_QUEUE_OVERFLOW" },

    {  32, "stat_par" },
    {  33, "statjb_timeout" },
    {  34, "statjb_crc" },
    {  35, "stat_cyc_inc" },
    {  36, "stat_escl_inconnu" },

    {  40, "STAT_DIF_MAX_THREAD" },
    {  41, "stat_dif_full" },
    {  42, "stat_dif_empty" },
    {  43, "STAT_NES_UNKNOWN" },
    {  45, "stat_no_soft" },
    {  46, "stat_conf" },
    {  47, "stat_no_board" },
    {  48, "stat_timeout_cts" },
    {  49, "stat_timeout_wait" },
    {  50, "stat_fill" },
    {  51, "stat_sys" },
    {  52, "stat_bug" },
    {  53, "stat_sync" },
    {  54, "stat_nopolling" },
    {  55, "stat_badintpol" },
    {  56, "stat_answer" },
    {  57, "stat_no_statment" },
    {  58, "stat_net_no_ready" },
    {  59, "stat_key" },

    {  60, "stat_no_retmail" },
    {  61, "stat_no_dsr_gt4000" },
    {  62, "stat_no_cts_gt4000" },
    {  63, "stat_timeout_gt4000" },
    {  64, "stat_bcc_gt4000" },
    {  65, "STAT_NOT_CONNECT" },
    {  66, "STAT_RESSOURCE" },
    {  67, "STAT_ERR_PDU" },
    {  68, "STAT_OBJECT_NON_EXISTENT" },
    {  69, "STAT_TYPE_CONFLICT" },
    {  70, "STAT_ABORT_USER" },
    {  71, "STAT_ABORT_FMS" },
    {  72, "STAT_ABORT_LLI" },
    {  73, "STAT_ABORT_LAYER2" },
    {  74, "STAT_MAX_PDU_SIZE" },
    {  75, "STAT_FEATURE_NOT_SUPPORTED" },
    {  76, "STAT_VERSION_INCOMPATIBLE" },
    {  77, "STAT_USER_INITIATE_DENIED" },
    {  78, "STAT_PASSWORD_ERROR" },
    {  79, "STAT_PROFILE_INCOMPATIBLE" },
    {  80, "STAT_ABORT_LLI_CONTEXT" },
    {  81, "STAT_ABORT_LLI_ABT_RC2" },
    {  82, "STAT_ABORT_LLI_ABT_RC3" },
    {  83, "STAT_ERR_CLASS_VFD_STATE" },
    {  84, "STAT_ERR_CLASS_APPLICATION_REF" },
    {  85, "STAT_ERR_CLASS_DEFINITION" },
    {  86, "STAT_ERR_CLASS_RESSOURCE" },
    {  87, "STAT_ERR_CLASS_SERVICE" },
    {  88, "STAT_ERR_CLASS_ACCESS" },
    {  89, "STAT_ERR_CLASS_OD" },
    {  90, "STAT_ERR_CLASS_OTHER" },
    {  91, "STAT_REJECT_PDU" },
    {  92, "STAT_ERR_HARDWARE" },
    {  93, "STAT_DRIVER_ACCESS" },
    {  94, "STAT_DRIVER_BAD_VERSION" },
    {  95, "STAT_FILL_BIG_MAIL" },
    {  96, "STAT_NO_TASK_VERSION" },
    {  97, "STAT_DLL_LOCKED" },
    {  98, "STAT_BOARD_LOCKED" },
    {  99, "STAT_MODEIO_LOCKED" },

    /*---- RESERVED STATUS FOR USER KIT4000 ----*/
    { 100, "STAT_KIT_START" },
    /* ..... */
    { 127, "STAT_KIT_END" },
    /*------------------------------------------*/
    { 128, "STAT_ERR_NO_REMOTE_CONNECTION" },
    { 129, "STAT_CONFIG_OK" },
    { 130, "STAT_CONFIG_NOK" },

    { 131, "STAT_DNS_PENDING" },
    { 132, "STAT_DNS_ERROR" },
    { 133, "STAT_OVERTIME" },

    { 134, "STAT_FRAG_WRITE" },
    { 135, "STAT_FRAG_READ" },

    { 136, "STAT_API_ACCESS" },
    { 137, "STAT_QUEUE_EMPTY" },
    { 138, "STAT_QUEUE_FULL" },

    { 254, "STAT_DEV_INIT" },
    { 255, "STAT_NA" },
    { -11, "index not updated" },
    { -10, "stat_handshake" },
    {  -9, "stat_event_data" },
    {  -8, "stat_timeout_ic_read" },
    {  -7, "stat_timeout_read" },
    {  -6, "stat_cyc_stopped" },
    {  -5, "stat_dif_not_ready" },
    {  -4, "stat_unchanged" },
    {  -3, "stat_nes_broadcast" },
    {  -2, "Unknown Status" },
    {  -1, "stat_writedif_ok" },
    { 0, NULL    }
};
static value_string_ext tabStatus_ext = VALUE_STRING_EXT_INIT(tabStatus);

static const value_string tabCodef[] = {
    /* Code for monitor */
    { 0x0000, "TIC_INVALID_ROOT" },
    { 0x0002, "tic_monitor" },

    /*Loader*/
    { 0x0003, "COD_LOAD_TASK" },
    { 0x0004, "COD_LOAD_TASK" },

    { 0x00ff, "TIC_TASK_NON_INIT" },  /* 255 */

    /* Code for monitor */
    { 0x0106, "COD_MON_INFO" },
    { 0x0109, "COD_GETTIC" },
    { 0x0119, "COD_MON_SETTIME" },
    { 0x0126, "COD_MON_SIZEMAIL" },
    { 0x0127, "COD_MON_SETSYNCHRO" },
    { 0x0128, "COD_MON_GETSYNCHRO" },

    { 0x012A, "COD_MON_FLAG_DEBUG" },
    { 0x012B, "COD_MON_SETSCADA_PT" },
    { 0x012C, "COD_MON_GETSCADA_PT" },

    { 0x0134, "COD_MON_SETGENVAR" },
    { 0x0135, "COD_MON_GETGENVAR" },
    { 0x0200, "COD_MON_READFLASHGT" },
    { 0x0206, "COD_MON_SETCOMSPEED" },
    { 0x020c, "COD_MON_TESTCARDTYPE" },

    /*Loader*/
    { 0x0400, "COD_LOAD_TASK" },
    { 0x0600, "COD_RELOAD_TASK" },

    /* Code for master function */
    { 0x1000, "cod_initmasterline" },
    { 0x1001, "cod_loadmasterconf" },
    { 0x1002, "cod_masterinfo" },
    { 0x1003, "cod_readpackbit" },
    { 0x1004, "cod_readpackibit" },
    { 0x1005, "cod_readword" },
    { 0x1006, "cod_readiword" },
    { 0x1007, "cod_readdword" },
    { 0x1008, "cod_readfword" },
    { 0x1009, "cod_writepackbit" },
    { 0x100A, "cod_writeword" },
    { 0x100B, "cod_writedword" },
    { 0x100C, "cod_writefword" },
    { 0x100D, "cod_readquickbit" },
    { 0x100E, "cod_readdiag" },
    { 0x100F, "cod_readeven" },
    { 0x1010, "cod_readtrace" },
    { 0x1011, "cod_statjbus" },
    { 0x1012, "cod_creatjnet" },
    { 0x1013, "cod_rijnet" },
    { 0x1014, "cod_rcjnet" },
    { 0x1015, "cod_writemes" },
    { 0x1016, "cod_readmes" },
    { 0x1017, "cod_manual" },
    { 0x1018, "cod_automatic" },
    { 0x1019, "cod_connect" },
    { 0x101A, "cod_unconnect" },
    { 0x101B, "cod_iocounter" },
    { 0x101C, "cod_resetiocounter" },
    { 0x101D, "codute_identequipment" },
    { 0x101E, "codute_readbit_SY" },
    { 0x101F, "codute_readbit_IO" },
    { 0x1020, "codute_readword_CW" },
    { 0x1021, "codute_readword_SW" },
    { 0x1022, "codute_readword_COM" },
    { 0x1023, "codute_readtempo" },
    { 0x1024, "codute_readmonost_Mi" },
    { 0x1025, "codute_readcounter_Ci" },
    { 0x1026, "codute_readreg_Ri" },
    { 0x1027, "codute_readsteps_Xi" },
    { 0x1028, "codute_readdword_DW" },
    { 0x1029, "codute_readdword_CDW" },
    { 0x102A, "codute_readone_step" },
    { 0x102B, "codute_writebit_SY" },
    { 0x102C, "codute_writebit_IO" },
    { 0x102D, "codute_writeword_SW" },
    { 0x102E, "codute_writeword_COM" },
    { 0x102F, "codute_writetimer_Ti" },
    { 0x1030, "codute_writemonost_Mi" },
    { 0x1031, "codute_writecounter_Ci" },
    { 0x1032, "codute_writereg_Ri" },
    { 0x1033, "codute_writedword_DW" },
    { 0x1034, "codute_readbit_B" },
    { 0x1035, "codute_readword_W" },
    { 0x1036, "codute_readobjets" },
    { 0x1037, "codute_readstruc_obj" },
    { 0x1038, "codute_writebit_B" },
    { 0x1039, "codute_writeword_W" },
    { 0x103A, "codute_writestruc_obj" },
    { 0x103B, "codute_no_requestdata" },
    { 0x103C, "codute_prot_ver" },
    { 0x103D, "codute_status" },
    { 0x103E, "codute_mirror" },
    { 0x103F, "codute_readerror_count" },
    { 0x1040, "codute_readstation_status" },
    { 0x1041, "codute_razerror_counter" },
    { 0x1042, "codute_write_xgs" },
    { 0x1043, "codute_stop" },
    { 0x1044, "codute_run" },
    { 0x1045, "codute_selftest" },
    { 0x1046, "codute_init" },
    { 0x1047, "codute_reserv" },
    { 0x1048, "codute_unreserv" },
    { 0x1049, "codute_entreserv" },
    { 0x104A, "codute_initloader" },
    { 0x104B, "codute_upload_seg" },
    { 0x104C, "codute_end_upload_seg" },
    { 0x104D, "codute_init_download" },
    { 0x104E, "codute_download_seg" },
    { 0x104F, "codute_end_download" },
    { 0x1050, "codute_writereq_file" },
    { 0x1051, "codute_readanswer_file" },
    { 0x1052, "codute_exereq_file" },
    { 0x1053, "codute_razreq_file" },
    { 0x1054, "codute_stopdrum_DiS" },
    { 0x1055, "codute_incdrum_DiS" },
    { 0x1056, "codute_godrum_DiS" },
    { 0x1057, "codute_readeven_DiS" },
    { 0x1058, "codute_readone_DiS" },
    { 0x1059, "codute_write_objet" },
    { 0x105A, "cod_readpackqbit" },
    { 0x105B, "cod_writepackqbit" },
    { 0x105C, "cod_send_rec_txt" },
    { 0x105D, "cod_iowhite" },
    { 0x105E, "cod_readpackbyte" },
    { 0x105F, "cod_readbyte" },
    { 0x1060, "cod_writepackbyte" },
    { 0x1061, "cod_writebyte" },
    { 0x1062, "cod_readwordbcd" },
    { 0x1063, "cod_writewordbcd" },
    { 0x1064, "cod_writereadmes" },
    { 0x1065, "cod_readqword" },
    { 0x1066, "cod_writeqword" },
    { 0x1067, "cod_writereaddifmes" },
    { 0x1068, "cod_readpackibyte" },
    { 0x1069, "cod_readibyte" },
    { 0x106A, "cod_readpackqbyte" },
    { 0x106B, "cod_readqbyte" },
    { 0x106C, "cod_writepackqbyte" },
    { 0x106D, "cod_writeqbyte" },
    { 0x106E, "cod_readident" },
    { 0x106F, "cod_readpackiqbit" },
    { 0x1070, "cod_writepackiqbit" },
    { 0x1071, "cod_layer2profibus" },
    { 0x1072, "cod_readtimer" },
    { 0x1073, "cod_writetimer" },
    { 0x1074, "cod_readcounter" },
    { 0x1075, "cod_writecounter" },
    { 0x1076, "0x1076COD_FMSGETOD" },
    { 0x1077, "cod_endloadmasterconf" },
    { 0x1078, "COD_FMSSTATUS" },
    { 0x1079, "COD_EQUIPMENTINFO" },
    { 0x107A, "COD_WRITEREADPACKBIT" },
    { 0x107B, "COD_WRITEREADPACKQBIT" },
    { 0x107C, "COD_WRITEREADPACKBYTE" },
    { 0x107D, "COD_WRITEREADBYTE" },
    { 0x107E, "COD_WRITEREADPACKQBYTE" },
    { 0x107F, "COD_WRITEREADQBYTE" },
    { 0x1080, "COD_WRITEREADWORD" },
    { 0x1081, "COD_WRITEREADQWORD" },
    { 0x1082, "COD_WRITEREADDWORD" },
    { 0x1083, "COD_WRITEREADFWORD" },
    { 0x1084, "COD_WRITEREADWORDBCD" },
    { 0x1085, "COD_CLOSECONNECTION" },
    { 0x1086, "COD_GET_SUPPORTED_FUNCTION" },
    { 0x1087, "COD_READOBJECT" },
    { 0x1088, "COD_WRITEFIELDOBJECT" },
    { 0x1089, "COD_EQUINFO_OBJ" },
    { 0x1090, "COD_WRITEREADMSG" },
    { 0x1091, "COD_START_SCANNER" },

    /* Code slave function */
    { 0x2000, "cod_initslave" },
    { 0x2001, "cod_loadslaveconf" },
    { 0x2002, "cod_endloadslaveconf" },

    /* Codes Database*/
    { 0x3000, "cod_getpackbit" },
    { 0x3001, "cod_getbit" },
    { 0x3002, "cod_getword" },
    { 0x3003, "cod_getdword" },
    { 0x3004, "cod_getfword" },
    { 0x3005, "cod_setpackbit" },
    { 0x3006, "cod_setbit" },
    { 0x3007, "cod_setword" },
    { 0x3008, "cod_setdword" },
    { 0x3009, "cod_setfword" },
    { 0x300A, "cod_getdispbit" },
    { 0x300B, "cod_getdispword" },
    { 0x300C, "cod_getdispdword" },
    { 0x300D, "cod_getdispfword" },
    { 0x300E, "cod_setdispbit" },
    { 0x300F, "cod_setdispword" },
    { 0x3010, "cod_setdispdword" },
    { 0x3011, "cod_setdispfword" },
    { 0x3012, "cod_incdispword" },
    { 0x3013, "cod_incdispdword" },
    { 0x3014, "cod_decdispword" },
    { 0x3015, "cod_decdispdword" },
    { 0x3016, "cod_getevent" },
    { 0x3017, "cod_confdb" },
    { 0x3018, "cod_puteventvar" },
    { 0x3019, "cod_getpackbyte" },
    { 0x301A, "cod_setpackbyte" },
    { 0x301B, "cod_fillbit" },
    { 0x301C, "cod_fillbyte" },
    { 0x301D, "cod_fillword" },
    { 0x301E, "cod_filldword" },
    { 0x301F, "cod_fillfword" },
    { 0x3020, "COD_APPGETBIT" },
    { 0x3021, "COD_DBEXECUTED" },
    { 0x3022, "COD_GETRIGHTS" },
    { 0x3023, "COD_WFCYC_COS" },
    { 0x3024, "COD_END_FCYC" },
    { 0x3025, "COD_FCYC_END" },
    { 0x3026, "COD_TAB_FCYC" },
    { 0x3027, "COD_GETFCYCCOS" },
    { 0x3028, "COD_SETIOAREAADDR" },
    { 0x3029, "COD_GETIOAREAADDR" },
    { 0x3030, "COD_SETACTFNTADDR" },
    { 0x3031, "COD_GETACTFNTADDR" },
    { 0x3032, "COD_GETACTFNTBITWORD" },

    /* Code disp_cyc functions */
    { 0x4000, "cod_cycinfo" },
    { 0x4001, "cod_createcyc" },
    { 0x4002, "cod_startcyc" },
    { 0x4003, "cod_stopcyc" },
    { 0x4004, "cod_transcyc" },
    { 0x4005, "cod_actcyc" },
    { 0x4006, "cod_initcyc" },
    { 0x4007, "cod_cycparam" },
    { 0x4008, "cod_stopallcyc" },
    { 0x4009, "cod_stopallcycread" },
    { 0x400A, "cod_stopallcycwrite" },
    { 0x400B, "cod_cyctimebase" },
    { 0x400C, "COD_CYCEXECUTED" },
    { 0x400E, "COD_NEWCREATECYC" },
    { 0x400F, "COD_DISPCYC_DEBUG" },
    { 0x4010, "COD_NEWCREATECYC_ID" },
    { 0x4011, "COD_DESTROYCYC_ID" },
    { 0x4012, "COD_CREATECYC_OBJ" },
    { 0x4013, "COD_TRANSCYC_VERIF" },
    { 0x4014, "COD_CREATECYC_WRMSG" },
    { 0x4015, "COD_NEWCREATECYC_WRMSG" },
    { 0x4016, "COD_NEWCREATECYC_WRMSG_ID" },
    { 0x4017, "COD_CYCEXECUTED_AND_COS" },
    { 0x4018, "COD_STARTCYCONE" },
    { 0x4019, "COD_GETCRESCENDO_USB" },
    { 0x4020, "COD_GETCYCPARAM2" },
    { 0x4021, "COD_FCYCWRITENONCOS" },
    { 0x4022, "COD_RESETCPTACTIVATION" },

    /* Code Root function */
    { 0x5000, "cod_rootinfo" },
    { 0x5001, "cod_initjbus" },
    { 0x5002, "cod_exitjbus" },
    { 0x5003, "cod_transdif" },
    { 0x5004, "cod_testtransdif" },
    { 0x5005, "cod_watchdog" },
    { 0x5006, "cod_accesskey" },
    { 0x5007, "cod_getmodem" },
    { 0x5008, "cod_setmodem" },
    { 0x5009, "COD_GETSTATIONNAME" },
    { 0x500A, "COD_GETSTATIONINFO" },
    { 0x500B, "COD_GETWATCHDOG" },
    { 0x500C, "COD_DIAG_ROOT" },

    /* Code bt100 function */
    { 0x6000, "COD_CREATEBT" },
    { 0x6001, "COD_TIMEBASEBT" },
    { 0x6002, "COD_CREATEBASETIME" },

    /* Code ADMINFL-0 : files */
    { 0x7000, "COD_OPENFILE" },
    { 0x7001, "COD_CLOSEFILE" },
    { 0x7002, "COD_READFILE" },
    { 0x7003, "COD_WRITEFILE" },
    { 0x7004, "COD_DELETEFILE" },
    { 0x7005, "COD_SEEKFILE" },
    { 0x7006, "COD_TEELFILE" },
    { 0x7007, "COD_EOFFILE" },
    { 0x7008, "COD_GETPTRFILE" },
    { 0x7009, "COD_DIRFILE" },

    /* Code MSG USER */
    { 0x7500, "COD_USER_FIRST" },

    { 0x7501, "COD_USER_EXCHANGE" },
    { 0x7502, "COD_USER_STATUSEXCHANGE" },
    { 0x7503, "COD_USER_SENDFRAME" },
    { 0x7504, "COD_USER_STATUSSENDFRAME" },

    { 0x7600, "COD_USER_EQUIPPARAMSREAD" },
    { 0x7601, "COD_USER_EQUIPINFOUPDATE" },
    { 0x7602, "COD_USER_ANALYZESTDREQUEST" },
    { 0x7603, "COD_USER_ANALYZEOBJREQUEST" },
    { 0x7604, "COD_USER_PREPROCESSREQUEST" },
    { 0x7605, "COD_USER_PREPROCESSANSWER" },
    { 0x7606, "COD_USER_EXEFUNCREQUEST" },
    { 0x7607, "COD_USER_EXEFUNCANSWER" },
    { 0x7608, "COD_USER_ABORTFRAME" },

    { 0x7700, "COD_USER_GETFUNCTION" },
    { 0x7701, "COD_USER_EXEFUNCREQ" },
    { 0x7702, "COD_USER_EXEFUNCACK" },

    { 0x7999, "COD_USER_LAST" },

    /* ??? */
    { 0x8000, "COD_INDWRITEMASK" },

    /* Code ADMINMSG-0 : message */
    { 0x9000, "COD_READMSG" },
    { 0x9001, "COD_CLEARMSG" },
    { 0x9002, "COD_DIRMSG" },
    { 0x9003, "COD_ENABLEMSG" },
    { 0x9004, "COD_DISABLEMSG" },
    { 0x9005, "COD_CREATEMSG" },
    { 0x9006, "COD_GETDESCRMSG" },
    { 0x9007, "COD_DIRALLMSG" },
    { 0x9008, "COD_INFOMSG" },
    { 0x9009, "COD_GETFLAGSMSG" },
    { 0x900A, "COD_SETFLAGSMSG" },
    { 0x9100, "COD_MSG_ENABLED" },

    /* First LLI MAIL Codef */
    { 0x9500, "COD_LLI_WHITE" },

    /* system commands */
    { 0x9510, "COD_MANAGE_INIT" },
    { 0x9511, "COD_MANAGE_SAP" },
    { 0x9512, "COD_LLI_DIAG" },
    { 0x9513, "COD_LLI_MANAGE" },
    { 0x9514, "COD_ADD_INSTANCE" },
    { 0x9515, "COD_REM_INSTANCE" },
    { 0x9516, "COD_GET_MESSAGING" },
    { 0x9517, "COD_LLI_CMD" },

    /* protocol commands */
    { 0x9600, "COD_LLI_EXCHANGE" },
    { 0x9602, "COD_LLI_INIT" },
    { 0x9603, "COD_LLI_START" },
    { 0x9604, "COD_LLI_STOP" },
    { 0x9605, "COD_LLI_READ_INPUT" },
    { 0x9606, "COD_LLI_READ_OUTPUT" },
    { 0x9607, "COD_LLI_ABORT" },
    { 0x9608, "COD_LLI_TRACE_ON" },
    { 0x9609, "COD_LLI_TRACE_OFF" },
    { 0x960A, "COD_LLI_WRITE_OUTPUT" },
    { 0x960B, "COD_LLI_READ_ASYNC" },
    { 0x960C, "COD_LLI_WRITE_ASYNC" },
    { 0x960D, "COD_LLI_DP_SERVICE" },
    { 0x960E, "COD_LLI_FDL_SERVICE" },
    { 0x960F, "COD_LLI_SCAN_L2" },
    { 0x9610, "COD_LLI_SCAN_MESSAGING" },
    { 0x9611, "COD_LLI_MPISLAVE_SERVICE" },
    { 0x9612, "COD_LLI_FDL_MESSAGING" },

    /* Last LLI MAIL Codef */
    { 0x96FF, "COD_LLI_LAST" },

    { 0xA001, "COD_REFRESH_INPUT" },
    { 0xA002, "COD_REFRESH_OUTPUT" },

    /* Codef SOCKET */
    { 0xB001, "COD_SOCKET_CREATE" },
    { 0xB002, "COD_SOCKET_BIND" },
    { 0xB003, "COD_SOCKET_CONNECT" },
    { 0xB004, "COD_SOCKET_LISTEN" },
    { 0xB005, "COD_SOCKET_ACCEPT" },
    { 0xB006, "COD_SOCKET_SENDTO" },
    { 0xB007, "COD_SOCKET_RECVFROM" },
    { 0xB008, "COD_SOCKET_SEND" },
    { 0xB009, "COD_SOCKET_RECV" },
    { 0xB010, "COD_SOCKET_CLOSE" },
    { 0xB011, "COD_SOCKET_HOST_INFO" },
    { 0xB012, "COD_SOCKET_PEER_INFO" },
    { 0xB013, "COD_SOCKET_RECV_GET_DATA" },
    { 0xB014, "COD_SOCKET_GET_STAT" },
    { 0xB015, "COD_SOCKET_RESET_STAT" },
    /*New type for the version 2*/
    { 0xB016, "COD_SOCKET_SETSOCKOPT" },
    { 0xB017, "COD_SOCKET_SELECT" },
    { 0xB018, "COD_SOCKET_SHUTDOWN_ALL" },
    { 0xB019, "COD_SOCKET_DIAG_SUMMARY" },
    { 0xB01A, "COD_SOCKET_DIAG_DETAILS" },
    { 0xB01B, "COD_SOCKET_DIAG_SO" },
    { 0xB01C, "COD_SOCKET_EVENT" },

    /* Codef ARP */
    { 0xC000, "COD_ARP_QUERY" },
    { 0xC001, "COD_ARP_FLUSH" },

    { 0xFFEF, "index not updated" },  /* -11 */

    { 0xFFFE, "Unknown Status" },
    { 0, NULL }
};
static value_string_ext tabCodef_ext = VALUE_STRING_EXT_INIT(tabCodef);

static const value_string FunctionCodes[] = {
    { WRETH_IDENT,      "Identification" },
    { WRETH_CONNECT,    "Connection" },
    { WRETH_ACK,        "Acknowledge" },
    { WRETH_NACK,       "Non acknowledge" },
    { WRETH_DISCONNECT, "Disconnection" },
    { WRETH_MAIL,       "Mail" },
    { WRETH_BLINKY,     "Blinky" },
    { WRETH_GET_VALUE,  "Get value" },
    { WRETH_SET_VALUE,  "Set value" },
    { WRETH_BOOST,      "Boost" },
    { 0, NULL }
};
static value_string_ext FunctionCodes_ext = VALUE_STRING_EXT_INIT(FunctionCodes);

static const value_string ErrorCode_vals[] = {
    { 0,                              "No error" },
    { WRETH_BAD_FUNCTION_CODE,        "Bad function code" },
    { WRETH_ALREADY_CONNECTED,        "Already connected" },
    { WRETH_INVALID_PROTOCOL_VERSION, "Invalid protocol version" },
    { WRETH_NOT_CONNECTED,            "Not connected" },
    { WRETH_INVALID_MAC_ADDRESS,      "Invalid MAC address" },
    { WRETH_INVALID_FRAME_SIZE,       "Invalid frame size" },
    { WRETH_NO_MEMORY_AVAILABLE,      "No memory available" },
    { WRETH_BAD_PARAMETER,            "Bad parameter" },
    { WRETH_TASK_REGISTERED,          "Task registered" },
    { 0, NULL }
};
static value_string_ext ErrorCode_vals_ext = VALUE_STRING_EXT_INIT(ErrorCode_vals);

static void dissect_wreth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    guint16     packet_type,functionCode;
    guint8      fragmented;
    proto_item *mi, *ti;
    proto_tree *pWrethTree ;
    guint8      Offset = 0 ;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Wreth");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /*Read the packet type, if not good, exit*/
    packet_type = tvb_get_ntohs(tvb,0);
    if(packet_type != WSE_RETH_SUBTYPE) return;

    mi = proto_tree_add_protocol_format(tree, wreth_proto, tvb, Offset, -1, "WSE remote ethernet");
    pWrethTree = proto_item_add_subtree(mi, ett_wreth);

    functionCode = tvb_get_letohs(tvb,4);
    fragmented   = tvb_get_guint8(tvb,10);

    if(fragmented > 2)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "Invalid fragmented byte");
        return;
    }

    if (tree)
    {
        /*Subtype*/
        proto_tree_add_item(pWrethTree, hf_Wreth_Subtype, tvb, Offset, 2, ENC_LITTLE_ENDIAN);

        /*Size*/
        proto_tree_add_item(pWrethTree, hf_Wreth_Size, tvb, Offset + 2, 2, ENC_LITTLE_ENDIAN);

        /*Function code*/
        proto_tree_add_item(pWrethTree, hf_Wreth_FunctionCode, tvb, Offset + 4, 2, ENC_LITTLE_ENDIAN);

        /*FrameID*/
        proto_tree_add_item(pWrethTree, hf_Wreth_FrameId, tvb, Offset + 6, 2, ENC_LITTLE_ENDIAN);

        /*Error Code*/
        proto_tree_add_item(pWrethTree, hf_Wreth_ErrorCode, tvb, Offset + 8, 2, ENC_LITTLE_ENDIAN);

    }

        /*Fragmented*/
        if(fragmented == 2)
        {
             ti = proto_tree_add_item(pWrethTree, hf_Wreth_Fragmented, tvb, Offset + 10, 1, ENC_LITTLE_ENDIAN);
             proto_item_append_text(ti, ": second fragment");

            /*Retry*/
            proto_tree_add_item(pWrethTree, hf_Wreth_Retry, tvb, Offset + 11, 1, ENC_LITTLE_ENDIAN);

            WrethMailDissection(tvb, Offset + 12, pinfo, pWrethTree, fragmented);
            return;
        }

        ti = proto_tree_add_item(pWrethTree, hf_Wreth_Fragmented, tvb, Offset + 10, 1, ENC_LITTLE_ENDIAN);
        if(fragmented == 1)
        {
            proto_item_append_text(ti, ": first fragment");
        }else
            proto_item_append_text(ti, ": no");

        /*Retry*/
        proto_tree_add_item(pWrethTree, hf_Wreth_Retry, tvb, Offset + 11, 1, ENC_LITTLE_ENDIAN);

        /* Add items to protocol tree specific to Wreth */
        switch(functionCode)
        {
            case WRETH_IDENT:
                WrethIdentPacket(tvb, Offset + 12, pinfo, pWrethTree);
                break;
            case WRETH_CONNECT:
                WrethConnectPacket(tvb, Offset + 12, pinfo, pWrethTree);
                break;
            case WRETH_ACK:
                WrethAckPacket(tvb, Offset + 12, pinfo, pWrethTree);
                break;
            case WRETH_NACK:
                WrethNackPacket(tvb, Offset + 12, pinfo, pWrethTree);
                break;
            case WRETH_DISCONNECT:
                WrethDisconnectPacket(tvb, Offset + 12, pinfo, pWrethTree);
                break;
            case WRETH_MAIL:
                WrethMailPacket(tvb, Offset + 12, pinfo, pWrethTree);
                break;
            case WRETH_BLINKY:
                WrethBlinkyPacket(tvb, Offset + 12, pinfo, pWrethTree);
                break;
            case WRETH_GET_VALUE:
                WrethGetValuePacket(tvb, Offset + 12, pinfo, pWrethTree);
                break;
            case WRETH_SET_VALUE:
                WrethSetValuePacket(tvb, Offset + 12, pinfo, pWrethTree);
                break;
            case WRETH_BOOST:
                WrethBoostPacket(tvb, Offset + 12, pinfo, pWrethTree);
                break;
            default:
                break;
        }

}

/*****************************************************************************/

static const value_string IdentState[] = {
    { 0, "Ready" },
    { 1, "Busy"},
    { 0, NULL }
};

gint WrethIdentPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree)
{
    guint16 Size;

    Size = tvb_get_letohs(tvb, 2);

    if((Size != 0)&&(Size != 19))
    {
        /* Invalid identification frame */
        col_set_str(pInfo->cinfo, COL_INFO, "Invalid identification frame");
        return 0;
    }

    if(Size == 0)
    {
        col_set_str(pInfo->cinfo, COL_INFO, "Identification question");
        return 0;
    }

    /*BiosVersion*/
    proto_tree_add_item(pWrethTree, hf_Wreth_IdentificationBiosVersion, tvb, Offset, 6, ENC_ASCII|ENC_NA);

    /*Board Number*/
    proto_tree_add_item(pWrethTree, hf_Wreth_IdentificationBoardNumber, tvb, Offset + 6, 2, ENC_LITTLE_ENDIAN);

    /*Protocol*/
    proto_tree_add_item(pWrethTree, hf_Wreth_IdentificationProtocolVersion, tvb, Offset + 8, 2, ENC_LITTLE_ENDIAN);

    /*Board Id*/
    proto_tree_add_item(pWrethTree, hf_Wreth_IdentificationBoardId, tvb, Offset + 10, 2, ENC_LITTLE_ENDIAN);

    /*State*/
    proto_tree_add_item(pWrethTree, hf_Wreth_IdentificationState, tvb, Offset + 12, 1, ENC_LITTLE_ENDIAN);

    /*Client MAC address*/
    proto_tree_add_item(pWrethTree, hf_Wreth_IdentificationMacAddr, tvb, Offset + 13, 6, ENC_BIG_ENDIAN);

    col_set_str(pInfo->cinfo, COL_INFO, "Identification response");

    return Offset;
}

/*****************************************************************************/

gint WrethConnectPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree _U_)
{
    guint16    Size;

    Size = tvb_get_letohs(tvb,2);

    if(Size != 4)
    {
        /* Invalid connection frame */
        col_set_str(pInfo->cinfo, COL_INFO, "Invalid connection frame");
        return 0;
    }

    col_set_str(pInfo->cinfo, COL_INFO, "Connection");

    proto_tree_add_item(pWrethTree, hf_Wreth_ConnectProtocolVersion, tvb, Offset, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(pWrethTree, hf_Wreth_ConnectTimeout, tvb, Offset + 2, 2, ENC_LITTLE_ENDIAN);

    return Offset;
}

/*****************************************************************************/

gint WrethDisconnectPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree _U_)
{
    guint16    Size;

    Size = tvb_get_letohs(tvb,2);

    if(Size != 0)
    {
        /* Invalid disconnection frame */
        col_set_str(pInfo->cinfo, COL_INFO, "Invalid disconnection frame");
        return 0;
    }

    col_set_str(pInfo->cinfo, COL_INFO, "Disconnection");

    return Offset;
}

/*****************************************************************************/

gint WrethBlinkyPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree)
{
    guint16    Size;

    Size = tvb_get_letohs(tvb,2);

    if(Size != 2)
    {
        /* Invalid blinky frame */
        col_set_str(pInfo->cinfo, COL_INFO, "Invalid blinky frame");
        return 0;
    }

    col_set_str(pInfo->cinfo, COL_INFO, "Blinky");

    proto_tree_add_item(pWrethTree, hf_Wreth_BlinkyPeriod, tvb, Offset, 2, ENC_LITTLE_ENDIAN);

    return Offset;
}

/*****************************************************************************/

gint WrethGetValuePacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree)
{
    guint16    Size;

    Size = tvb_get_letohs(tvb,2);

    switch(Size)
    {
        case 0:
            col_set_str(pInfo->cinfo, COL_INFO, "Get value question");
            break;
        case 1:
            proto_tree_add_item(pWrethTree, hf_Wreth_GetValueVal, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
            col_set_str(pInfo->cinfo, COL_INFO, "Get value response");
            break;
        default:
            col_set_str(pInfo->cinfo, COL_INFO, "Invalid get value frame");
            break;
    }

    return Offset;
}

/*****************************************************************************/

gint WrethSetValuePacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree)
{
    guint16    Size;

    Size = tvb_get_letohs(tvb,2);

    if(Size != 0)
    {
        col_set_str(pInfo->cinfo, COL_INFO, "Invalid set value frame");
    }

    proto_tree_add_item(pWrethTree, hf_Wreth_SetValueVal, tvb, Offset, 1, ENC_LITTLE_ENDIAN);

    col_set_str(pInfo->cinfo, COL_INFO, "Set value question");

    return Offset;
}

/*****************************************************************************/
static const value_string BoostValue[] = {
    { 0, "disabled" },
    { 1, "enabled"},
    { 0, NULL }
};

gint WrethBoostPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree)
{
    guint16    Size;

    Size = tvb_get_letohs(tvb,2);

    if(Size != 2)
    {
        /* Invalid boost frame */
        col_set_str(pInfo->cinfo, COL_INFO, "Invalid boost frame");
        return 0;
    }

    col_set_str(pInfo->cinfo, COL_INFO, "Boost");

    proto_tree_add_item(pWrethTree, hf_Wreth_BoostValue, tvb, Offset, 2, ENC_LITTLE_ENDIAN);

    return Offset;
}

/*****************************************************************************/

gint WrethAckPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree _U_)
{
    guint16    Size;

    Size = tvb_get_letohs(tvb,2);

    if(Size != 0)
    {
        /* Invalid ack frame */
        col_set_str(pInfo->cinfo, COL_INFO, "Invalid acknowledge frame");
        return 0;
    }

    col_set_str(pInfo->cinfo, COL_INFO, "Acknowledge");

    return Offset;
}

/*****************************************************************************/

gint WrethNackPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree)
{
    guint16 Size;
    guint16 ErrorCode;

    Size      = tvb_get_letohs(tvb,2);
    ErrorCode = tvb_get_letohs(tvb,2);  /* XXX:  what offset should be used  ??  */

    if((Size != 0)&&(Size != 6))
    {
        /* Invalid ack frame */
        col_set_str(pInfo->cinfo, COL_INFO, "Invalid non acknowledge frame");
        return 0;
    }


    col_add_str(pInfo->cinfo, COL_INFO, val_to_str_ext(ErrorCode, &ErrorCode_vals_ext, "Unknown 0x%04x"));

    if(Size == 6)
    {
        proto_tree_add_item(pWrethTree, hf_Wreth_IdentificationMacAddr, tvb, Offset, 6, ENC_BIG_ENDIAN);
    }

    return Offset;
}

/*****************************************************************************/

gint WrethMailPacket(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree)
{

    proto_tree_add_item(pWrethTree, hf_Wreth_MailDestTic, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(pWrethTree, hf_Wreth_MailReserved, tvb, Offset + 2, 4, ENC_LITTLE_ENDIAN);

    col_set_str(pInfo->cinfo, COL_INFO, "Mail");

    /*Frame not fragmented => last argument = 0*/
    WrethMailDissection(tvb, Offset+6, pInfo, pWrethTree,0);

    return Offset;
}

/*****************************************************************************/

gint WrethMailDissection(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo, proto_tree * pWrethTree, guint8 fragmented)
{
    proto_item *mi;
    proto_tree *pWrethMailboxTree;
    gint        Nb    = 0;
    guint16     Codef = 0;

    mi = proto_tree_add_protocol_format(pWrethTree, wreth_proto, tvb, Offset, -1, "MailBox");
    pWrethMailboxTree = proto_item_add_subtree(mi, ett_wreth);

    /*If it's not the last fragment, display the header of the MailBox*/
    if (2 != fragmented)
    {
        guint16 Card, Chan;
        gint Status;

        /*Codef*/
        Codef = tvb_get_letohs(tvb,Offset);
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Codef, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Status*/
        Status = (gint16)tvb_get_letohs(tvb,Offset); /* cast fetched value to signed so sign is extended */
                                                     /*  so that lookup of 32-bit unsigned in tabCodef   */
                                                     /*  value_string array will work properly.          */
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Status, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*TicUser Root*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_TicUser_Root, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail PidUser*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_PidUser, tvb, Offset, 4, ENC_LITTLE_ENDIAN);
        Offset += 4;
        /*Mail Mode*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Mode, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail Time*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Time, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail Stop*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Stop, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail Nfonc*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Nfonc, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail Ncard*/
        Card = tvb_get_letohs(tvb,Offset);
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Ncard, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail Nchan*/
        Chan = tvb_get_letohs(tvb,Offset);
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Nchan, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail Nes*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Nes, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail Nb*/
        Nb = (gint)tvb_get_letohs(tvb,Offset);
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Nb, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail TypVar*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_TypVar, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail Adr*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Adr, tvb, Offset, 4, ENC_LITTLE_ENDIAN);
        Offset += 4;
        /*Mail TicUser*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_TicUser_DispCyc, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail Nb Max Size Mail*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Nb_Max_Size_Mail, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail User ThreadID*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_User_ThreadID, tvb, Offset, 4, ENC_LITTLE_ENDIAN);
        Offset += 4;
        /*Mail DispCyc Version*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_DispCyc_Version, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;
        /*Mail DifUserParam*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_DifUserParam, tvb, Offset, 4, ENC_LITTLE_ENDIAN);
        Offset += 4;
        /*Mail Filler*/
        proto_tree_add_item(pWrethMailboxTree, hf_Wreth_Mail_Filler, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
        Offset += 2;

        col_add_fstr(pInfo->cinfo, COL_INFO, "Mail : Codef = Ox%X (%s), Status = %02d (%s), Card = %d, Chan = %d" ,
                     Codef,
                     val_to_str_ext(Codef, &tabCodef_ext, "Unknown 0x%04x%"),
                     Status,
                     val_to_str_ext(Status, &tabStatus_ext, "Unknown %d"),
                     Card,
                     Chan);
    }
    else
    {
        col_set_str(pInfo->cinfo, COL_INFO, "Mail : Data Second Fragment ");
    }

    if (0 != Nb)
    {
        /*Specific Decode for some Codef*/
        switch(Codef)
        {
            case 0x1002: /*Master Info*/
                WrethCodefMasterInfoDissection(tvb, Offset, pInfo, pWrethMailboxTree);
                break;
            case 0x1079: /*Equipment Info*/
                WrethCodefEquipmentInfoDissection(tvb, Offset, pInfo, pWrethMailboxTree);
                break;
            default:
                proto_tree_add_protocol_format(pWrethMailboxTree, wreth_proto, tvb, Offset, -1, "Data");
                break;
        }
    }

    return Offset;
}

/*****************************************************************************/

gint WrethCodefMasterInfoDissection(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo _U_, proto_tree * pWrethMailboxTree)
{
    proto_item *mi;
    proto_tree *pWrethMailboxDataTree;

    mi = proto_tree_add_protocol_format(pWrethMailboxTree, wreth_proto, tvb, Offset, -1, "Data");
    pWrethMailboxDataTree = proto_item_add_subtree(mi, ett_wreth);

    /*bVersion*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Mastinf_Version, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
    Offset += 1;
    /*bRelease*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Mastinf_Release, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
    Offset += 1;
    /*bProtocol*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Mastinf_Protocol, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
    Offset += 1;
    /*bCyclicFlux*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Mastinf_CyclicFlux, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
    Offset += 1;
    /*szProtocolName*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Mastinf_szProtocolName, tvb, Offset, 16, ENC_ASCII|ENC_NA);
    Offset += 16;
    /*bMaxTypeEquipment*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Mastinf_MaxTypeEquipment, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
    Offset += 1;
    /*wMinEquipmentNumber*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Mastinf_MinEquipmentNumber, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxEquipmentNumber*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Mastinf_MaxEquipmentNumber, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;

    return Offset;
}

/*****************************************************************************/

gint WrethCodefEquipmentInfoDissection(tvbuff_t *tvb, guint8 Offset, packet_info * pInfo _U_, proto_tree * pWrethMailboxTree)
{
    proto_item *mi;
    proto_tree *pWrethMailboxDataTree;

    mi = proto_tree_add_protocol_format(pWrethMailboxTree, wreth_proto, tvb, Offset, -1, "Data");
    pWrethMailboxDataTree = proto_item_add_subtree(mi, ett_wreth);

    /*bVersion*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_Version, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
    Offset += 1;
    /*Free*/
    Offset += 1;
    /*bRelease*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_Release, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
    Offset += 1;
    /*bNetwork*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_Network, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
    Offset += 1;
    /*bProtocol*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_Protocol, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
    Offset += 1;
    /*bMessaging*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_Messaging, tvb, Offset, 1, ENC_LITTLE_ENDIAN);
    Offset += 1;
    /*wEquipment*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_Equipment, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wFlux*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_Flux, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*Free*/
    Offset += 10;
    /*IncWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_IncWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*IncDWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_IncDWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*IncFWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_IncFWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*Free*/
    Offset += 4;
    /*DllItemName*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Mastinf_DllItemName, tvb, Offset, 14, ENC_ASCII|ENC_NA);
    Offset += 14;
    /*szEquipmentName*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Mastinf_szEquipmentName, tvb, Offset, 16, ENC_ASCII|ENC_NA);
    Offset += 16;
    /*Free*/
    Offset += 2;
    /*wMaxWriteBit*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteBit, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadBit*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadBit, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakBit*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakBit, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxWriteIBit*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteIBit, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadIBit*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadIBit, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakIBit*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakIBit, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxWriteQBit*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteQBit, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadQBit*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadQBit, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakQBit*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakQBit, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxWriteByte*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteByte, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadByte*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadByte, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakByte*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakByte, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxWriteIByte*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteIByte, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadIByte*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadIByte, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakIByte*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakIByte, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxWriteQByte*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteQByte, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadQByte*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadQByte, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakQByte*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakQByte, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxWriteWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxWriteIWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteIWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadIWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadIWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakIWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakIWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxWriteQWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteQWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadQWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadQWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakQWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakQWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxWriteDWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteDWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadDWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadDWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakDWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakDWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxWriteFWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxWriteFWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wMaxReadFWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_MaxReadFWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wBreakFWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_BreakFWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wReadFactorWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_ReadFactorWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wReadFactorIWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_ReadFactorIWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wReadFactorQWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_ReadFactorQWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wReadFactorDWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_ReadFactorDWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wReadFactorFWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_ReadFactorFWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wWriteFactorWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_WriteFactorWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wWriteFactorIWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_WriteFactorIWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wWriteFactorQWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_WriteFactorQWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wWriteFactorDWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_WriteFactorDWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wWriteFactorFWord*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_WriteFactorFWord, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;
    /*wDataFormat*/
    proto_tree_add_item(pWrethMailboxDataTree, hf_Wreth_Mail_Equinf_DataFormat, tvb, Offset, 2, ENC_LITTLE_ENDIAN);
    Offset += 2;

    return Offset;
}

void proto_register_wreth(void)
{
    static hf_register_info hf[] =
    {
        /* Wreth header fields */
        { &hf_Wreth_Subtype,
            { "Subtype", "wreth.Subtype",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Size,
            { "Size",        "wreth.Size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "", HFILL }
        },
        { &hf_Wreth_FunctionCode,
            { "Function code","wreth.FunctionCode",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &FunctionCodes_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_FrameId,
            { "FrameId", "wreth.FrameId",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_ErrorCode,
            { "Error code", "wreth.ErrorCode",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &ErrorCode_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Fragmented,
            { "Fragmented", "wreth.Fragmented",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Retry,
            { "Retry", "wreth.Retry",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_IdentificationBiosVersion,
            { "Bios version", "wreth.IdentBiosVersion",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_IdentificationBoardNumber,
            { "Board number", "wreth.IdentBoardNumber",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_IdentificationProtocolVersion,
            { "Protocol version", "wreth.IdentProtocolVersion",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_IdentificationBoardId,
            { "Board Id", "wreth.IdentBoardId",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_IdentificationState,
            { "State", "wreth.IdentState",
            FT_UINT8, BASE_DEC, VALS(IdentState), 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_IdentificationMacAddr,
            { "Client MAC address :", "wreth.IdentClientMacAddr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_ConnectProtocolVersion,
            { "Protocol version", "wreth.ConnectProtocolVersion",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_ConnectTimeout,
            { "Connect timeout", "wreth.ConnectTimeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_BlinkyPeriod,
            { "Period", "wreth.BlinkyPeriod",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_GetValueVal,
            { "Value", "wreth.GetValue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_SetValueVal,
            { "Value", "wreth.SetValue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_BoostValue,
            { "Boost", "wreth.BoostStatus",
            FT_UINT16, BASE_DEC, VALS(BoostValue), 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_MailDestTic,
            { "Dest tic", "wreth.MailDestTic",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_MailReserved,
            { "Reserved", "wreth.MailReserved",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Codef,
            { "Codef", "wreth.Mail.Codef",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &tabCodef_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Status,
            { "Status", "wreth.Mail.Status",
            FT_INT16, BASE_DEC | BASE_EXT_STRING, &tabStatus_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_TicUser_Root,
            { "TicUser Root", "wreth.Mail.TicUserRoot",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_PidUser,
            { "PidUser", "wreth.Mail.PidUser",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Mode,
            { "Mode", "wreth.Mail.Mode",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Time,
            { "Time", "wreth.Mail.Time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Stop,
            { "Stop", "wreth.Mail.Stop",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Nfonc,
            { "Nfonc", "wreth.Mail.Nfonc",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Ncard,
            { "Ncard", "wreth.Mail.Ncard",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Nchan,
            { "Nchan", "wreth.Mail.Nchan",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Nes,
            { "Nes", "wreth.Mail.Nes",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Nb,
            { "Nb", "wreth.Mail.Nb",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_TypVar,
            { "TypVar", "wreth.Mail.TypVar",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Adr,
            { "Adr", "wreth.Mail.Adr",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_TicUser_DispCyc,
            { "TicUser DispCyc", "wreth.Mail.TicUser.DispCyc",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Nb_Max_Size_Mail,
            { "Nb Max Size Mail", "wreth.Mail.TicUser.Nb.Max.Size.Mail",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_User_ThreadID,
            { "User ThreadID", "wreth.Mail.User.ThreadID",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_DispCyc_Version,
            { "DispCyc Version", "wreth.Mail.DispCyc.Version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_DifUserParam,
            { "DifUserParam", "wreth.Mail.DifUserParam",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Filler,
            { "Filler", "wreth.Mail.Filler",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
#if 0
        { &hf_Wreth_Mail_Data,
            { "Data", "wreth.Mail.Data",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
#endif
        { &hf_Wreth_Mail_Mastinf_Version,
            { "Version", "wreth.Mail.Mastinf.Version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Mastinf_Release,
            { "Release", "wreth.Mail.Mastinf.Release",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Mastinf_Protocol,
            { "Protocol", "wreth.Mail.Mastinf.Protocol",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Mastinf_CyclicFlux,
            { "CyclicFlux", "wreth.Mail.Mastinf.CyclicFlux",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Mastinf_szProtocolName,
            { "ProtocolName", "wreth.Mail.Mastinf.ProtocolName",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Mastinf_MaxTypeEquipment,
            { "MaxTypeEquipment", "wreth.Mail.Mastinf.MaxTypeEquipment",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Mastinf_MinEquipmentNumber,
            { "MinEquipmentNumber", "wreth.Mail.Mastinf.MinEquipmentNumber",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Mastinf_MaxEquipmentNumber,
            { "MaxEquipmentNumber", "wreth.Mail.Mastinf.MaxEquipmentNumber",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_Version,
            { "Version", "wreth.Mail.Equinf.Version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_Release,
            { "Release", "wreth.Mail.Equinf.Release",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_Network,
            { "Network", "wreth.Mail.Equinf.Network",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_Protocol,
            { "Protocol", "wreth.Mail.Equinf.Protocol",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_Messaging,
            { "Messaging", "wreth.Mail.Equinf.Messaging",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_Equipment,
            { "Equipment", "wreth.Mail.Equinf.Equipment",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_Flux,
            { "Flux", "wreth.Mail.Equinf.Flux",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_IncWord,
            { "IncWord", "wreth.Mail.Equinf.IncWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_IncDWord,
            { "IncDWord", "wreth.Mail.Equinf.IncDWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_IncFWord,
            { "IncFWord", "wreth.Mail.Equinf.IncFWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Mastinf_DllItemName,
            { "DllItemName", "wreth.Mail.Equinf.DllItemName",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Mastinf_szEquipmentName,
            { "EquipmentName", "wreth.Mail.Equinf.EquipmentName",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteBit,
            { "MaxWriteBit", "wreth.Mail.Equinf.MaxWriteBit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadBit,
            { "MaxReadBit", "wreth.Mail.Equinf.MaxReadBit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_BreakBit,
            { "BreakBit", "wreth.Mail.Equinf.BreakBit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteIBit,
            { "MaxWriteIBit", "wreth.Mail.Equinf.MaxWriteIBit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadIBit,
            { "MaxReadIBit", "wreth.Mail.Equinf.MaxReadIBit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteQBit,
            { "MaxWriteQBit", "wreth.Mail.Equinf.MaxWriteQBit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadQBit,
            { "MaxReadQBit", "wreth.Mail.Equinf.MaxReadQBit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_BreakQBit,
            { "BreakQBit", "wreth.Mail.Equinf.BreakQBit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteByte,
            { "MaxWriteByte", "wreth.Mail.Equinf.MaxWriteByte",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadByte,
            { "MaxReadByte", "wreth.Mail.Equinf.MaxReadByte",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_BreakByte,
            { "BreakByte", "wreth.Mail.Equinf.BreakByte",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteIByte,
            { "MaxWriteIByte", "wreth.Mail.Equinf.MaxWriteIByte",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadIByte,
            { "MaxReadIByte", "wreth.Mail.Equinf.MaxReadIByte",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_BreakIByte,
            { "BreakIByte", "wreth.Mail.Equinf.BreakIByte",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteQByte,
            { "MaxWriteQByte", "wreth.Mail.Equinf.MaxWriteQByte",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadQByte,
            { "MaxReadQByte", "wreth.Mail.Equinf.MaxReadQByte",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        }
        ,
        { &hf_Wreth_Mail_Equinf_BreakQByte ,
            { "BreakQByte", "wreth.Mail.Equinf.BreakQByte",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteWord ,
            { "MaxWriteWord", "wreth.Mail.Equinf.MaxWriteWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadWord ,
            { "MaxReadWord", "wreth.Mail.Equinf.MaxReadWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_BreakWord ,
            { "BreakWord", "wreth.Mail.Equinf.BreakWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteIWord ,
            { "MaxWriteIWord", "wreth.Mail.Equinf.MaxWriteIWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadIWord ,
            { "MaxReadIWord", "wreth.Mail.Equinf.MaxReadIWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_BreakIWord ,
            { "BreakIWord", "wreth.Mail.Equinf.BreakIWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadQWord ,
            { "MaxReadQWord", "wreth.Mail.Equinf.MaxReadQWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteQWord ,
            { "MaxWriteQWord", "wreth.Mail.Equinf.MaxWriteQWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_BreakQWord ,
            { "BreakQWord", "wreth.Mail.Equinf.BreakQWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteDWord ,
            { "MaxWriteDWord", "wreth.Mail.Equinf.MaxWriteDWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadDWord ,
            { "MaxReadDWord", "wreth.Mail.Equinf.MaxReadDWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_BreakDWord ,
            { "BreakDWord", "wreth.Mail.Equinf.BreakDWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxWriteFWord ,
            { "MaxWriteFWord", "wreth.Mail.Equinf.MaxWriteFWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_MaxReadFWord ,
            { "MaxReadFWord", "wreth.Mail.Equinf.MaxReadFWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_BreakFWord ,
            { "BreakFWord", "wreth.Mail.Equinf.BreakFWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_ReadFactorWord ,
            { "ReadFactorWord", "wreth.Mail.Equinf.ReadFactorWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_ReadFactorIWord ,
            { "ReadFactorIWord", "wreth.Mail.Equinf.ReadFactorIWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_ReadFactorQWord ,
            { "ReadFactorQWord", "wreth.Mail.Equinf.ReadFactorQWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_ReadFactorDWord ,
            { "ReadFactorDWord", "wreth.Mail.Equinf.ReadFactorDWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_ReadFactorFWord ,
            { "ReadFactorFWord", "wreth.Mail.Equinf.ReadFactorFWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_WriteFactorWord ,
            { "WriteFactorWord", "wreth.Mail.Equinf.WriteFactorWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_WriteFactorIWord ,
            { "WriteFactorIWord", "wreth.Mail.Equinf.WriteFactorIWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_WriteFactorQWord ,
            { "WriteFactorQWord", "wreth.Mail.Equinf.WriteFactorQWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_WriteFactorDWord ,
            { "WriteFactorDWord", "wreth.Mail.Equinf.WriteFactorDWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_WriteFactorFWord  ,
            { "WriteFactorFWord", "wreth.Mail.Equinf.WriteFactorFWord",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_DataFormat  ,
            { "DataFormat", "wreth.Mail.Equinf.DataFormat",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Wreth_Mail_Equinf_BreakIBit  ,
            { "BreakIBit", "wreth.Mail.Equinf.BreakIBit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_wreth
    };

    wreth_proto = proto_register_protocol (
        "WSE remote ethernet", /* name       */
        "WRETH",               /* short name */
        "wreth"                /* abbrev     */
    );
    proto_register_field_array(wreth_proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_wreth(void)
{
    static dissector_handle_t wreth_handle;

    wreth_handle = create_dissector_handle(dissect_wreth, wreth_proto);
    dissector_add_uint("ethertype", WRETH_PORT, wreth_handle);
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
