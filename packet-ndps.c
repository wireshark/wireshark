/* packet-ndps.c
 * Routines for NetWare's NDPS
 * Greg Morris <gmorris@novell.com>
 *
 * $Id: packet-ndps.c,v 1.2 2002/10/08 19:15:24 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-ipx.h"
#include <epan/resolv.h>
#include "etypes.h"
#include "ppptypes.h"
#include "llcsaps.h"
#include "aftypes.h"
#include "packet-tcp.h"
#include "packet-ndps.h"


#define SPX_HEADER_LEN	12

static int proto_ndps = -1;
static int hf_ndps_record_mark = -1;
static int hf_ndps_length = -1;
static int hf_ndps_xid = -1;
static int hf_ndps_packet_type = -1;
static int hf_ndps_rpc_version = -1;
static int hf_ndps_error = -1;

static int hf_spx_ndps_program = -1;
static int hf_spx_ndps_version = -1;
static int hf_spx_ndps_func_print = -1;
static int hf_spx_ndps_func_registry = -1;
static int hf_spx_ndps_func_notify = -1;
static int hf_spx_ndps_func_resman = -1;
static int hf_spx_ndps_func_delivery = -1;
static int hf_spx_ndps_func_broker = -1;

static gint ett_spx = -1;

static int proto_spx = -1;
static int hf_spx_connection_control = -1;
static int hf_spx_datastream_type = -1;
static int hf_spx_src_id = -1;
static int hf_spx_dst_id = -1;
static int hf_spx_seq_nr = -1;
static int hf_spx_ack_nr = -1;
static int hf_spx_all_nr = -1;

static gint ett_ndps = -1;
static dissector_handle_t ndps_data_handle;


static const value_string spx_ndps_program_vals[] = {
    { 0x00060976, "Print Program " },
    { 0x00060977, "Broker Program " },
    { 0x00060978, "Registry Program " },
    { 0x00060979, "Notify Program " },
    { 0x0006097a, "Resource Manager Program " },
    { 0x0006097b, "Programatic Delivery Program " },
    { 0,          NULL }
};

static const value_string spx_ndps_print_func_vals[] = {
    { 0x00000001, "Bind PSM" },
    { 0x00000002, "Bind PA" },
    { 0x00000003, "Unbind" },
    { 0x00000004, "Print" },
    { 0x00000005, "Modify Job" },
    { 0x00000006, "Cancel Job" },
    { 0x00000007, "List Object Attributes" },
    { 0x00000008, "Promote Job" },
    { 0x00000009, "Interrupt" },
    { 0x0000000a, "Pause" },
    { 0x0000000b, "Resume" },
    { 0x0000000c, "Clean" },
    { 0x0000000d, "Create" },
    { 0x0000000e, "Delete" },
    { 0x0000000f, "Disable PA" },
    { 0x00000010, "Enable PA" },
    { 0x00000011, "Resubmit Jobs" },
    { 0x00000012, "Set" },
    { 0x00000013, "Shutdown PA" },
    { 0x00000014, "Startup PA" },
    { 0x00000015, "Reorder Job" },
    { 0x00000016, "Pause PA" },
    { 0x00000017, "Resume PA" },
    { 0x00000018, "Transfer Data" },
    { 0x00000019, "Device Control" },
    { 0x0000001a, "Add Event Profile" },
    { 0x0000001b, "Remove Event Profile" },
    { 0x0000001c, "Modify Event Profile" },
    { 0x0000001d, "List Event Profiles" },
    { 0x0000001e, "Shutdown PSM" },
    { 0x0000001f, "Cancel PSM Shutdown" },
    { 0x00000020, "Set Printer DS Information" },
    { 0x00000021, "Clean User Jobs" },
    { 0x00000022, "Map GUID to NDS Name" },
    { 0,          NULL }
};

static const value_string spx_ndps_notify_func_vals[] = {
    { 0x00000001, "Notify Bind" },
    { 0x00000002, "Notify Unbind" },
    { 0x00000003, "Register Supplier" },
    { 0x00000004, "Deregister Supplier" },
    { 0x00000005, "Add Profile" },
    { 0x00000006, "Remove Profile" },
    { 0x00000007, "Modify Profile" },
    { 0x00000008, "List Profiles" },
    { 0x00000009, "Report Event" },
    { 0x0000000a, "List Supported Languages" },
    { 0x0000000b, "Report Notification" },
    { 0x0000000c, "Add Delivery Method" },
    { 0x0000000d, "Remove Delivery Method" },
    { 0x0000000e, "List Delivery Methods" },
    { 0x0000000f, "Get Delivery Method Information" },
    { 0x00000010, "Get Notify NDS Object Name" },
    { 0x00000011, "Get Notify Session Information" },
    { 0,          NULL }
};

static const value_string spx_ndps_deliver_func_vals[] = {
    { 0x00000001, "Delivery Bind" },
    { 0x00000002, "Delivery Unbind" },
    { 0x00000003, "Delivery Send" },
    { 0x00000004, "Delivery Send2" },
    { 0,          NULL }
};

static const value_string spx_ndps_registry_func_vals[] = {
    { 0x00000001, "Bind" },
    { 0x00000002, "Unbind" },
    { 0x00000003, "Register Server" },
    { 0x00000004, "Deregister Server" },
    { 0x00000005, "Register Registry" },
    { 0x00000006, "Deregister Registry" },
    { 0x00000007, "Registry Update" },
    { 0x00000008, "List Local Servers" },
    { 0x00000009, "List Servers" },
    { 0x0000000a, "List Known Registries" },
    { 0x0000000b, "Get Registry NDS Object Name" },
    { 0x0000000c, "Get Registry Session Information" },
    { 0,          NULL }
};

static const value_string spx_ndps_resman_func_vals[] = {
    { 0x00000001, "Bind" },
    { 0x00000002, "Unbind" },
    { 0x00000003, "Add Resource File" },
    { 0x00000004, "Delete Resource File" },
    { 0x00000005, "List Resources" },
    { 0x00000006, "Get Resource File" },
    { 0x00000007, "Get Resource File Data" },
    { 0x00000008, "Get Resource Manager NDS Object Name" },
    { 0x00000009, "Get Resource Manager Session Information" },
    { 0,          NULL }
};

static const value_string spx_ndps_broker_func_vals[] = {
    { 0x00000001, "Bind" },
    { 0x00000002, "Unbind" },
    { 0x00000003, "List Services" },
    { 0x00000004, "Enable Service" },
    { 0x00000005, "Disable Service" },
    { 0x00000006, "Down Broker" },
    { 0x00000007, "Get Broker NDS Object Name" },
    { 0x00000008, "Get Broker Session Information" },
    { 0,          NULL }
};

static const value_string ndps_packet_types[] = {
    { 0x00000000, "Request" },
    { 0x00000001, "Reply" },
    { 0,          NULL }
};

static const value_string ndps_error_types[] = {
    { 0xFFFFFC18, "NWDP_OE_BK_OUT_OF_MEMORY" },      /* Broker Errors */
    { 0xFFFFFC17, "NWDP_OE_BK_BAD_NETWARE_VERSION" },
    { 0xFFFFFC16, "NWDP_OE_BK_WRONG_CMD_LINE_ARGS" },
    { 0xFFFFFC15, "NWDP_OE_BK_BROKER_NAME_NOT_GIVN" },
    { 0xFFFFFC14, "NWDP_OE_BK_NOT_BROKER_CLASS" },
    { 0xFFFFFC13, "NWDP_OE_BK_INVALID_BROKER_PWORD" },
    { 0xFFFFFC12, "NWDP_OE_BK_INVALID_BROKER_NAME" },
    { 0xFFFFFC11, "NWDP_OE_BK_FAILED_TO_CRTE_THRED" },
    { 0xFFFFFC10, "NWDP_OE_BK_FAILED_TO_INIT_NUT" },
    { 0xFFFFFC0F, "NWDP_OE_BK_FAILED_TO_GET_MSGS" },
    { 0xFFFFFC0E, "NWDP_OE_BK_FAILED_TO_ALLOC_RES" },
    { 0xFFFFFC0D, "NWDP_OE_BK_SVC_MUST_BE_FULL_DIS" },
    { 0xFFFFFC0C, "NWDP_OE_BK_UNINITIALIZED_MODULE" },
    { 0xFFFFFC0B, "NWDP_OE_BK_DS_VAL_SIZE_TOO_LARG" },
    { 0xFFFFFC0A, "NWDP_OE_BK_NO_ATTRIBUTE_VALUES" },
    { 0xFFFFFC09, "NWDP_OE_BK_UNKNOWN_SESSION" },
    { 0xFFFFFC08, "NWDP_OE_BK_SERVICE_DISABLED" },
    { 0xFFFFFC07, "NWDP_OE_BK_UNKNOWN_MODIFY_OPER" },
    { 0xFFFFFC06, "NWDP_OE_BK_INVALID_ARGUMENTS" },
    { 0xFFFFFC05, "NWDP_OE_BK_DUPLICATE_SESSION_ID" },
    { 0xFFFFFC04, "NWDP_OE_BK_UNKNOWN_SERVICE" },
    { 0xFFFFFC03, "NWDP_OE_BK_SRVC_ALREADY_ENABLED" },
    { 0xFFFFFC02, "NWDP_OE_BK_SRVC_ALREADY_DISABLD" },
    { 0xFFFFFC01, "NWDP_OE_BK_INVALID_CREDENTIAL" },
    { 0xFFFFFC00, "NWDP_OE_BK_UNKNOWN_DESIGNATOR" },
    { 0xFFFFFBFF, "NWDP_OE_BK_FAIL_MAKE_CHG_PERMNT" },
    { 0xFFFFFBFE, "NWDP_OE_BK_NOT_ADMIN_TYPE_SESN" },
    { 0xFFFFFBFD, "NWDP_OE_BK_OPTION_NOT_SUPPORTED" },
    { 0xFFFFFBFC, "NWDP_OE_BK_NO_EFFECTIVE_RIGHTS" },
    { 0xFFFFFBFB, "NWDP_OE_BK_COULD_NOT_FIND_FILE" },
    { 0xFFFFFBFA, "NWDP_OE_BK_ERROR_READING_FILE" },
    { 0xFFFFFBF9, "NWDP_OE_BK_NOT_NLM_FILE_FORMAT" },
    { 0xFFFFFBF8, "NWDP_OE_BK_WRONG_NLM_FILE_VER" },
    { 0xFFFFFBF7, "NWDP_OE_BK_REENTRANT_INIT_FAIL" },
    { 0xFFFFFBF6, "NWDP_OE_BK_ALREADY_IN_PROGRESS" },
    { 0xFFFFFBF5, "NWDP_OE_BK_INITIALIZE_FAILURE" },
    { 0xFFFFFBF4, "NWDP_OE_BK_INCONSISTNT_FILE_FMT" },
    { 0xFFFFFBF3, "NWDP_OE_BK_CANT_LOAD_AT_STARTUP" },
    { 0xFFFFFBF2, "NWDP_OE_BK_AUTO_MODULS_NOT_LOAD" },
    { 0xFFFFFBF1, "NWDP_OE_BK_UNRESOLVED_EXTERNAL" },
    { 0xFFFFFBF0, "NWDP_OE_BK_PUBLIC_ALREADY_DEFND" },
    { 0xFFFFFBEF, "NWDP_OE_BK_OTHER_BRKR_USING_OBJ" },
    { 0xFFFFFBEE, "NWDP_OE_BK_SRVC_FAILED_TO_INIT" },
    { 0xFFFFFBB4, "NWDP_OE_RG_OUT_OF_MEMORY" },       /* SRS Errors */
    { 0xFFFFFBB3, "NWDP_OE_RG_BAD_NETWARE_VERSION" },
    { 0xFFFFFBB2, "NWDP_OE_RG_FAIL_CREATE_CONTEXT" },
    { 0xFFFFFBB1, "NWDP_OE_RG_FAIL_LOGIN" },
    { 0xFFFFFBB0, "NWDP_OE_RG_FAIL_CREATE_THREAD" },
    { 0xFFFFFBAF, "NWDP_OE_RG_FAIL_GET_MSGS" },
    { 0xFFFFFBAE, "NWDP_OE_RG_SVC_MUST_BE_FULL_DIS" },
    { 0xFFFFFBAD, "NWDP_OE_RG_DS_VAL_SIZE_TOO_LARG" },
    { 0xFFFFFBAC, "NWDP_OE_RG_NO_ATTRIBUTE_VALUES" },
    { 0xFFFFFBAB, "NWDP_OE_RG_UNKNOWN_SESSION" },
    { 0xFFFFFBAA, "NWDP_OE_RG_SERVICE_DISABLED" },
    { 0xFFFFFBA9, "NWDP_OE_RG_UNKNOWN_MODIFY_OPER" },
    { 0xFFFFFBA8, "NWDP_OE_RG_CANT_START_ADVERTISE" },
    { 0xFFFFFBA7, "NWDP_OE_RG_DUP_SERVER_ENTRY" },
    { 0xFFFFFBA6, "NWDP_OE_RG_CANT_BIND_2_REGISTRY" },
    { 0xFFFFFBA5, "NWDP_OE_RG_CANT_CREATE_CLIENT" },
    { 0xFFFFFBA4, "NWDP_OE_RG_INVALID_ARGUMENTS" },
    { 0xFFFFFBA3, "NWDP_OE_RG_DUPLICATE_SESSION_ID" },
    { 0xFFFFFBA2, "NWDP_OE_RG_UNKNOWN_SERVER_ENTRY" },
    { 0xFFFFFBA1, "NWDP_OE_RG_INVALID_CREDENTIAL" },
    { 0xFFFFFBA0, "NWDP_OE_RG_REGIST_TYPE_SESN" },
    { 0xFFFFFB9F, "NWDP_OE_RG_SERVER_TYPE_SESN" },
    { 0xFFFFFB9E, "NWDP_OE_RG_NOT_SERVER_TYPE_SESN" },
    { 0xFFFFFB9D, "NWDP_OE_RG_NOT_REGIST_TYPE_SESN" },
    { 0xFFFFFB9C, "NWDP_OE_RG_UNKNOWN_DESIGNATOR" },
    { 0xFFFFFB9B, "NWDP_OE_RG_OPTION_NOT_SUPPORTED" },
    { 0xFFFFFB9A, "NWDP_OE_RG_NOT_IN_LST_ITERATION" },
    { 0xFFFFFB99, "NWDP_OE_RG_INVLD_CONTNUATN_HNDL" },
    { 0xFFFFFB50, "NWDP_OE_NF_OUT_OF_MEMORY" },        /* Notification Service Errors */
    { 0xFFFFFB4F, "NWDP_OE_NF_BAD_NETWARE_VERSION" },
    { 0xFFFFFB4E, "NWDP_OE_NF_FAIL_CREATE_THREAD" },
    { 0xFFFFFB4D, "NWDP_OE_NF_FAIL_GET_MSGS" },
    { 0xFFFFFB4C, "NWDP_OE_NF_FAIL_CREATE_CONTEXT" },
    { 0xFFFFFB4B, "NWDP_OE_NF_FAIL_LOGIN" },
    { 0xFFFFFB4A, "NWDP_OE_NF_SVC_MUST_BE_FULL_DIS" },
    { 0xFFFFFB49, "NWDP_OE_NF_DS_VAL_SIZE_TOO_LARG" },
    { 0xFFFFFB48, "NWDP_OE_NF_NO_ATTRIBUTE_VALUES" },
    { 0xFFFFFB47, "NWDP_OE_NF_UNKNOWN_SESSION" },
    { 0xFFFFFB46, "NWDP_OE_NF_UNKNOWN_NOTIFY_PROF" },
    { 0xFFFFFB45, "NWDP_OE_NF_ERROR_READING_FILE" },
    { 0xFFFFFB44, "NWDP_OE_NF_ERROR_WRITING_FILE" },
    { 0xFFFFFB43, "NWDP_OE_NF_WRONG_NOTIFY_DB_VERS" },
    { 0xFFFFFB42, "NWDP_OE_NF_CORRUPTED_NOTIFY_DB" },
    { 0xFFFFFB41, "NWDP_OE_NF_UNKNOWN_EVENT_OID" },
    { 0xFFFFFB40, "NWDP_OE_NF_METHOD_ALREADY_INST" },
    { 0xFFFFFB3F, "NWDP_OE_NF_UNKNOWN_METHOD" },
    { 0xFFFFFB3E, "NWDP_OE_NF_SERVICE_DISABLED" },
    { 0xFFFFFB3D, "NWDP_OE_NF_UNKNOWN_MODIFY_OP" },
    { 0xFFFFFB3C, "NWDP_OE_NF_OUT_OF_NOTIFY_ENTRYS" },
    { 0xFFFFFB3B, "NWDP_OE_NF_UNKNOWN_LANGUAGE_ID" },
    { 0xFFFFFB3A, "NWDP_OE_NF_NOTIFY_QUEUE_EMPTY" },
    { 0xFFFFFB39, "NWDP_OE_NF_CANT_LOAD_DELVR_METH" },
    { 0xFFFFFB38, "NWDP_OE_NF_INVALID_ARGUMENTS" },
    { 0xFFFFFB37, "NWDP_OE_NF_DUPLICATE_SESSION_ID" },
    { 0xFFFFFB36, "NWDP_OE_NF_INVALID_CREDENTIAL" },
    { 0xFFFFFB35, "NWDP_OE_NF_UNKNOWN_CHOICE" },
    { 0xFFFFFB34, "NWDP_OE_NF_UNKNOWN_ATTR_VALUE" },
    { 0xFFFFFB33, "NWDP_OE_NF_ERROR_WRITING_DB" },
    { 0xFFFFFB32, "NWDP_OE_NF_UNKNOWN_OBJECT_ID" },
    { 0xFFFFFB31, "NWDP_OE_NF_UNKNOWN_DESIGNATOR" },
    { 0xFFFFFB30, "NWDP_OE_NF_FAIL_MAKE_CHG_PERMNT" },
    { 0xFFFFFB2F, "NWDP_OE_NF_UI_NOT_SUPPORTED" },
    { 0xFFFFFB2E, "NWDP_OE_NF_NOT_SUPPLY_TYPE_SESN" },
    { 0xFFFFFB2D, "NWDP_OE_NF_NOT_ADMIN_TYPE_SESN" },
    { 0xFFFFFB2C, "NWDP_OE_NF_NO_SRVC_REGIST_AVAIL" },
    { 0xFFFFFB2B, "NWDP_OE_NF_FAIL_TO_REG_W_ANY_SR" },
    { 0xFFFFFB2A, "NWDP_OE_NF_EMPTY_EVENT_OBJ_SET" },
    { 0xFFFFFB29, "NWDP_OE_NF_UNKNOWN_NTFY_HANDLE" },
    { 0xFFFFFB28, "NWDP_OE_NF_OPTION_NOT_SUPPORTED" },
    { 0xFFFFFB27, "NWDP_OE_NF_UNKNOWN_RPC_SESSION" },
    { 0xFFFFFB26, "NWDP_OE_NF_INITIALIZATION_ERROR" },
    { 0xFFFFFB25, "NWDP_OE_NF_NO_EFFECTIVE_RIGHTS" },
    { 0xFFFFFB24, "NWDP_OE_NF_NO_PERSISTENT_STORAG" },
    { 0xFFFFFB23, "NWDP_OE_NF_BAD_METHOD_FILENAME" },
    { 0xFFFFFB22, "NWDP_OE_NF_UNKNOWN_CONT_HANDLE" },
    { 0xFFFFFB21, "NWDP_OE_NF_INVALID_CONT_HANDLE" },
    { 0xFFFFFB20, "NWDP_OE_NF_COULD_NOT_FIND_FILE" },
    { 0xFFFFFB1F, "NWDP_OE_NF_L_ERROR_READING_FILE" },
    { 0xFFFFFB1E, "NWDP_OE_NF_NOT_NLM_FILE_FORMAT" },
    { 0xFFFFFB1D, "NWDP_OE_NF_WRONG_NLM_FILE_VER" },
    { 0xFFFFFB1C, "NWDP_OE_NF_REENTRANT_INIT_FAIL" },
    { 0xFFFFFB1B, "NWDP_OE_NF_ALREADY_IN_PROGRESS" },
    { 0xFFFFFB1A, "NWDP_OE_NF_INITIALIZE_FAILURE" },
    { 0xFFFFFB19, "NWDP_OE_NF_INCONSISTNT_FILE_FMT" },
    { 0xFFFFFB18, "NWDP_OE_NF_CANT_LOAD_AT_STARTUP" },
    { 0xFFFFFB17, "NWDP_OE_NF_AUTO_MODULS_NOT_LOAD" },
    { 0xFFFFFB16, "NWDP_OE_NF_UNRESOLVED_EXTERNAL" },
    { 0xFFFFFB15, "NWDP_OE_NF_PUBLIC_ALREADY_DEFND" },
    { 0xFFFFFB14, "NWDP_OE_NF_USING_UNKNOWN_METHDS" },
    { 0xFFFFFB13, "NWDP_OE_NF_SRVC_NOT_FULL_ENABLD" },
    { 0xFFFFFB12, "NWDP_OE_NF_FOREIGN_NDS_TREE_NAM" },
    { 0xFFFFFB11, "NWDP_OE_NF_DLVYMETH_REJCTD_ADDR" },
    { 0xFFFFFB10, "NWDP_OE_NF_UNSUPRT_DLVYADDRTYPE" },
    { 0xFFFFFB0F, "NWDP_OE_NF_USR_OBJ_NO_DEFLTSERV" },
    { 0xFFFFFB0E, "NWDP_OE_NF_FAILED_TO_SEND_NOTIF" },
    { 0xFFFFFB0D, "NWDP_OE_NF_BAD_VOLUME_IN_ADDR" },
    { 0xFFFFFB0C, "NWDP_OE_NF_BROKER_NO_FILE_RIGHT" },
    { 0xFFFFFB0B, "NWDP_OE_NF_MAX_METHDS_SUPPORTED" },
    { 0xFFFFFB0A, "NWDP_OE_NF_NO_FILTER_PROVIDED" },
    { 0xFFFFFB09, "NE_IPX_NOT_SUPPORTED_BY_METHOD" },
    { 0xFFFFFB08, "NE_IP_NOT_SUPPORTED_BY_METHOD" },
    { 0xFFFFFB07, "NE_FAILED_TO_STARTUP_WINSOCK" },
    { 0xFFFFFB06, "NE_NO_PROTOCOLS_AVAILABLE" },
    { 0xFFFFFB05, "NE_FAILED_TO_LAUNCH_RPC_SERVER" },
    { 0xFFFFFB04, "NE_INVALID_SLP_ATTR_FORMAT" },
    { 0xFFFFFB03, "NE_INVALID_SLP_URL_FORMAT" },
    { 0xFFFFFB02, "NE_UNKNOWN_ATTRIBUTE_OID" },
    { 0xFFFFFB01, "NE_DUPLICATE_SESSION_ID" },
    { 0xFFFFFB00, "NE_FAILED_TO_AUTHENTICATE" },
    { 0xFFFFFAFF, "NE_FAILED_TO_AUTH_PROTOCOL_MISMATCH" },
    { 0xFFFFFAFE, "NE_FAILED_TO_AUTH_INTERNAL_ERROR" },
    { 0xFFFFFAFD, "NE_FAILED_TO_AUTH_CONNECTION_ERROR" },
    { 0xFFFFFC7C, "NWDP_OE_RM_OUT_OF_MEMORY" },  /* ResMan Errors */
    { 0xFFFFFC7B, "NWDP_OE_RM_BAD_NETWARE_VERSION" },
    { 0xFFFFFC7A, "NWDP_OE_RM_WRONG_CMD_LINE_ARGS" },
    { 0xFFFFFC79, "NWDP_OE_RM_BROKER_NAME_NOT_GIVN" },
    { 0xFFFFFC78, "NWDP_OE_RM_INVALID_BROKER_PWORD" },
    { 0xFFFFFC77, "NWDP_OE_RM_INVALID_BROKER_NAME" },
    { 0xFFFFFC76, "NWDP_OE_RM_FAILED_TO_CRTE_THRED" },
    { 0xFFFFFC75, "NWDP_OE_RM_SVC_MUST_BE_FULL_DIS" },
    { 0xFFFFFC74, "NWDP_OE_RM_DS_VAL_SIZE_TOO_LARG" },
    { 0xFFFFFC73, "NWDP_OE_RM_NO_ATTRIBUTE_VALUES" },
    { 0xFFFFFC72, "NWDP_OE_RM_UNKNOWN_SESSION" },
    { 0xFFFFFC71, "NWDP_OE_RM_ERROR_READING_FILE" },
    { 0xFFFFFC70, "NWDP_OE_RM_ERROR_WRITING_FILE" },
    { 0xFFFFFC6F, "NWDP_OE_RM_SERVICE_DISABLED" },
    { 0xFFFFFC6E, "NWDP_OE_RM_UNKNOWN_MODIFY_OPER" },
    { 0xFFFFFC6D, "NWDP_OE_RM_DUPLICATE_SESSION_ID" },
    { 0xFFFFFC6C, "NWDP_OE_RM_INVALID_CREDENTIAL" },
    { 0xFFFFFC6B, "NWDP_OE_RM_NO_SRVC_REGIST_AVAIL" },
    { 0xFFFFFC6A, "NWDP_OE_RM_FAIL_TO_REG_W_ANY_SR" },
    { 0xFFFFFC69, "NWDP_OE_RM_FAIL_TO_GET_MSGS" },
    { 0xFFFFFC68, "NWDP_OE_RM_FAIL_TO_CRTE_CONTEXT" },
    { 0xFFFFFC67, "NWDP_OE_RM_FAIL_TO_LOGIN" },
    { 0xFFFFFC66, "NWDP_OE_RM_NPD_FILE_GEN_ERR" },
    { 0xFFFFFC65, "NWDP_OE_RM_INF_FILE_FORMAT_ERR" },
    { 0xFFFFFC64, "NWDP_OE_RM_NO_PRT_TYPE_IN_INF" },
    { 0xFFFFFC63, "NWDP_OE_RM_NO_INF_FILES_PRESENT" },
    { 0xFFFFFC62, "NWDP_OE_RM_FILE_OPEN_ERROR" },
    { 0xFFFFFC61, "NWDP_OE_RM_READ_FILE_ERROR" },
    { 0xFFFFFC60, "NWDP_OE_RM_WRITE_FILE_ERROR" },
    { 0xFFFFFC5F, "NWDP_OE_RM_RESRC_TYPE_INVALID" },
    { 0xFFFFFC5E, "NWDP_OE_RM_NO_SUCH_FILENAME" },
    { 0xFFFFFC5D, "NWDP_OE_RM_BANR_TYPE_INVALID" },
    { 0xFFFFFC5C, "NWDP_OE_RM_LIST_TYPE_UNKNOWN" },
    { 0xFFFFFC5B, "NWDP_OE_RM_OS_NOT_SUPPORTED" },
    { 0xFFFFFC5A, "NWDP_OE_RM_NO_BANR_FILES_PRESNT" },
    { 0xFFFFFC59, "NWDP_OE_RM_PRN_DEF_TYPE_UNKNOWN" },
    { 0xFFFFFC58, "NWDP_OE_RM_NO_PRN_TYPES_IN_LIST" },
    { 0xFFFFFC57, "NWDP_OE_RM_OPTION_NOT_SUPPORTED" },
    { 0xFFFFFC56, "NWDP_OE_RM_UNICODE_CONV_ERR" },
    { 0xFFFFFC55, "NWDP_OE_RM_INVALID_ARGUMENTS" },
    { 0xFFFFFC54, "NWDP_OE_RM_INITIALIZATION_ERROR" },
    { 0xFFFFFC53, "NWDP_OE_RM_NO_SRV_REG_AVAILABLE" },
    { 0xFFFFFC52, "NWDP_OE_RM_FAIL_RGSTR_TO_ANY_SR" },
    { 0xFFFFFC51, "NWDP_OE_RM_UNKNOWN_DESIGNATOR" },
    { 0xFFFFFC50, "NWDP_OE_RM_NOT_ADMIN_SESSION" },
    { 0xFFFFFC4F, "NWDP_OE_RM_NO_EFFECTIVE_RIGHTS" },
    { 0xFFFFFC4E, "NWDP_OE_RM_BAD_FILE_ATTRIBUTE" },
    { 0xFFFFFC4D, "NWDP_OE_RM_DID_FORMAT_ERROR" },
    { 0xFFFFFC4C, "NWDP_OE_RM_UNKNOWN_RPC_SESSION" },
    { 0xFFFFFC4B, "NWDP_OE_RM_SESSN_BEING_REMOVED" },
    { 0xFFFFFC49, "NWDP_OE_RM_FMGR_IO_ERROR" },
    { 0xFFFFFC48, "NWDP_OE_RM_FMGR_REENTRANCY" },
    { 0xFFFFFC47, "NWDP_OE_RM_FMGR_SEQ_ERROR" },
    { 0xFFFFFC46, "NWDP_OE_RM_FMGR_CRPT_INDEX_FILE" },
    { 0xFFFFFC45, "NWDP_OE_RM_FMGR_NO_SUCH_FONT" },
    { 0xFFFFFC44, "NWDP_OE_RM_FMGR_NOT_INITIALIZED" },
    { 0xFFFFFC43, "NWDP_OE_RM_FMGR_SYSTEM_ERROR" },
    { 0xFFFFFC42, "NWDP_OE_RM_FMGR_BAD_PARM" },
    { 0xFFFFFC41, "NWDP_OE_RM_FMGR_PATH_TOO_LONG" },
    { 0xFFFFFC40, "NWDP_OE_RM_FMGR_FAILURE" },
    { 0xFFFFFC3F, "NWDP_OE_RM_DUP_TIRPC_SESSION" },
    { 0xFFFFFC3E, "NWDP_OE_RM_CONN_LOST_RMS_DATA" },
    { 0xFFFFFC3D, "NWDP_OE_RM_FAIL_START_WINSOCK" },
    { 0xFFFFFC3C, "NWDP_OE_RM_NO_PROTOCOLS_AVAIL" },
    { 0xFFFFFC3B, "NWDP_OE_RM_FAIL_LNCH_RPC_SRVR" },
    { 0xFFFFFC3A, "NWDP_OE_RM_INVALID_SLP_ATTR_FMT" },
    { 0xFFFFFC39, "NWDP_OE_RM_INVALID_SLP_URL_FMT" },
    { 0xFFFFFC38, "NWDP_OE_RM_UNRESOLVED_EXTERNAL" },
    { 0xFFFFFC37, "NWDP_OE_RM_FAILED_TO_AUTHENT" },
    { 0xFFFFFC36, "NWDP_OE_RM_FAIL_AUTH_PROT_MISMA" },
    { 0xFFFFFC35, "NWDP_OE_RM_FAIL_AUTH_INT_ERR" },
    { 0xFFFFFC34, "NWDP_OE_RM_FAIL_AUTH_CONN_ERR" },
    { 0xFFFFFC33, "NWDP_OE_RM_NO_RIGHTS_REM_RESDIR" },
    { 0xFFFFFC32, "NWDP_OE_RM_CANT_INIT_NDPS_LIB" },
    { 0xFFFFFC31, "NWDP_OE_RM_CANT_CREAT_RESREF" },
    { 0xFFFFFC30, "NWDP_OE_RM_FILE_ZERO_LENGTH" },
    { 0xFFFFFC2F, "NWDP_OE_RM_FAIL_WRI_INF_IN_ADD" },
    { 0xFFFFFCDF, "NDPS_E_NO_MEMORY" },               /* NDPSM Errors */
    { 0xFFFFFCDE, "NDPS_E_MEMORY_NOT_FOUND" },
    { 0xFFFFFCDD, "NDPS_E_JOB_STORAGE_LIMIT" },
    { 0xFFFFFCDC, "NDPS_E_JOB_RETENTION_LIMIT" },
    { 0xFFFFFCDB, "NDPS_E_UNSUPPORTED_TYPE" },
    { 0xFFFFFCDA, "NDPS_E_UNDEFINED_TYPE" },
    { 0xFFFFFCD9, "NDPS_E_UNSUPPORTED_OP" },
    { 0xFFFFFCD8, "NDPS_E_ACCESSING_DB" },
    { 0xFFFFFCD7, "NDPS_E_NO_PDS" },
    { 0xFFFFFCD6, "NDPS_E_INVALID_CLASS" },
    { 0xFFFFFCD5, "NDPS_E_BAD_PARAMETER" },
    { 0xFFFFFCD4, "NDPS_E_OBJECT_NOT_FOUND" },
    { 0xFFFFFCD3, "NDPS_E_ATTRIBUTE_NOT_FOUND" },
    { 0xFFFFFCD2, "NDPS_E_VALUE_NOT_FOUND" },
    { 0xFFFFFCD1, "NDPS_E_VALUES_NOT_COMPARABLE" },
    { 0xFFFFFCD0, "NDPS_E_INVALID_VALUE_SYNTAX" },
    { 0xFFFFFCCF, "NDPS_E_JOB_NOT_FOUND" },
    { 0xFFFFFCCE, "NDPS_E_COMMUNICATION" },
    { 0xFFFFFCCD, "NDPS_E_PA_INITIALIZING" },
    { 0xFFFFFCCC, "NDPS_E_PA_GOING_DOWN" },
    { 0xFFFFFCCB, "NDPS_E_PA_DISABLED" },
    { 0xFFFFFCCA, "NDPS_E_PA_PAUSED" },
    { 0xFFFFFCC9, "NDPS_E_BAD_PA_HANDLE" },
    { 0xFFFFFCC8, "NDPS_E_OBJECT_NOT_LOCKED" },
    { 0xFFFFFCC7, "NDPS_E_VERSION_INCOMPATIBLE" },
    { 0xFFFFFCC6, "NDPS_E_PSM_INITIALIZING" },
    { 0xFFFFFCC5, "NDPS_E_PSM_GOING_DOWN" },
    { 0xFFFFFCC4, "NDPS_E_NOTIF_SVC_ERROR" },
    { 0xFFFFFCC3, "NDPS_E_MEDIUM_NEEDS_MOUNTED" },
    { 0xFFFFFCC2, "NDPS_E_PDS_NOT_RESPONDING" },
    { 0xFFFFFCC1, "NDPS_E_SESSION_NOT_FOUND" },
    { 0xFFFFFCC0, "NDPS_E_RPC_FAILURE" },
    { 0xFFFFFCBF, "NDPS_E_DUPLICATE_VALUE" },
    { 0xFFFFFCBE, "NDPS_E_PDS_REFUSES_RENAME" },
    { 0xFFFFFCBD, "NDPS_E_NO_MANDATORY_ATTR" },
    { 0xFFFFFCBC, "NDPS_E_ALREADY_ATTACHED" },
    { 0xFFFFFCBB, "NDPS_E_CANT_ATTACH" },
    { 0xFFFFFCBA, "NDPS_E_TOO_MANY_NW_SERVERS" },
    { 0xFFFFFCB9, "NDPS_E_CANT_CREATE_DOC_FILE" },
    { 0xFFFFFCB8, "NDPS_E_CANT_DELETE_DOC_FILE" },
    { 0xFFFFFCB7, "NDPS_E_CANT_OPEN_DOC_FILE" },
    { 0xFFFFFCB6, "NDPS_E_CANT_WRITE_DOC_FILE" },
    { 0xFFFFFCB5, "NDPS_E_JOB_IS_ACTIVE" },
    { 0xFFFFFCB4, "NDPS_E_NO_SCHEDULER" },
    { 0xFFFFFCB3, "NDPS_E_CHANGING_CONNECTION" },
    { 0xFFFFFCB2, "NDPS_E_COULD_NOT_CREATE_ACC_REF" },
    { 0xFFFFFCB1, "NDPS_E_ACCTG_SVC_ERROR" },
    { 0xFFFFFCB0, "NDPS_E_RMS_SVC_ERROR" },
    { 0xFFFFFCAF, "NDPS_E_FAILED_VALIDATION" },
    { 0xFFFFFCAE, "NDPS_E_BROKER_SRVR_CONNECTING" },
    { 0xFFFFFCAD, "NDPS_E_SRS_SVC_ERROR" },
    { 0xFFFFFD44, "JPM_W_EXECUTE_REQUEST_LATER" },
    { 0xFFFFFD43, "JPM_E_FAILED_TO_OPEN_DOC" },
    { 0xFFFFFD42, "JPM_E_FAILED_READ_DOC_FILE" },
    { 0xFFFFFD41, "JPM_E_BAD_PA_HANDLE" },
    { 0xFFFFFD40, "JPM_E_BAD_JOB_HANDLE" },
    { 0xFFFFFD3F, "JPM_E_BAD_DOC_HANDLE" },
    { 0xFFFFFD3E, "JPM_E_UNSUPPORTED_OP" },
    { 0xFFFFFD3D, "JPM_E_REQUEST_QUEUE_FULL" },
    { 0xFFFFFD3C, "JPM_E_PA_NOT_FOUND" },
    { 0xFFFFFD3B, "JPM_E_INVALID_REQUEST" },
    { 0xFFFFFD3A, "JPM_E_NOT_ACCEPTING_REQ" },
    { 0xFFFFFD39, "JPM_E_PA_ALREADY_SERVICED_BY_PDS" },
    { 0xFFFFFD38, "JPM_E_NO_JOB" },
    { 0xFFFFFD37, "JPM_E_JOB_NOT_FOUND" },
    { 0xFFFFFD36, "JPM_E_COULD_NOT_ACCESS_DATA_BASE" },
    { 0xFFFFFD35, "JPM_E_BAD_OBJ_TYPE" },
    { 0xFFFFFD34, "JPM_E_JOB_ALREADY_CLOSED" },
    { 0xFFFFFD33, "JPM_E_DOC_ALREADY_CLOSED" },
    { 0xFFFFFD32, "JPM_E_PH_NOT_REGISTERED" },
    { 0xFFFFFD31, "JPM_E_VERSION_INCOMPATIBLE" },
    { 0xFFFFFD30, "JPM_E_PA_PAUSED" },
    { 0xFFFFFD2F, "JPM_E_PA_SHUTDOWN" },
    { 0xFFFFFD2E, "JPM_E_NO_CLIB_CONTEXT" },
    { 0xFFFFFD2D, "JPM_E_ACCOUNTING_ALREADY_SERVICE" },
    { 0xFFFFFC7B, "DB_E_CANT_CREATE_FILE" },
    { 0xFFFFFC7A, "DB_E_CANT_FIND_DATA_FILE" },
    { 0xFFFFFC79, "DB_E_CANT_OPEN_DATA_FILE" },
    { 0xFFFFFC78, "DB_E_CANT_OPEN_INDEX_FILE" },
    { 0xFFFFFC77, "DB_E_INDEX_FILE_NOT_OPEN" },
    { 0xFFFFFC76, "DB_E_CANT_RENAME_FILE" },
    { 0xFFFFFC75, "DB_E_CANT_READ_DATA_FILE" },
    { 0xFFFFFC74, "DB_E_CANT_READ_INDEX_FILE" },
    { 0xFFFFFC73, "DB_E_CANT_WRITE_DATA_FILE" },
    { 0xFFFFFC72, "DB_E_CANT_WRITE_INDEX_FILE" },
    { 0xFFFFFC71, "DB_E_CANT_DELETE_PA_DIR" },
    { 0xFFFFFC70, "DB_E_ALREADY_DELETED" },
    { 0xFFFFFC6F, "DB_E_OBJECT_EXISTS" },
    { 0xFFFFFC6E, "DB_E_DESCRIPTOR_IN_USE" },
    { 0xFFFFFC6D, "DB_E_DESCRIPTOR_BEING_DELETED" },
    { 0,          NULL }
};

/* ================================================================= */
/* SPX                                                               */
/* ================================================================= */
static const char*
spx_conn_ctrl(guint8 ctrl)
{
	const char *p;

	static const value_string conn_vals[] = {
		{ 0x10, "End-of-Message" },
		{ 0x20, "Attention" },
		{ 0x40, "Acknowledgment Required"},
        { 0x50, "Send Ack: End Message"},
        { 0x80, "System Packet"},
        { 0xc0, "System Packet: Send Ack"},
		{ 0x00, NULL }
	};

	p = match_strval((ctrl & 0xf0), conn_vals);

	if (p) {
		return p;
	}
	else {
		return "Unknown";
	}
}

static const char*
spx_datastream(guint8 type)
{
	switch (type) {
		case 0xfe:
			return "End-of-Connection";
		case 0xff:
			return "End-of-Connection Acknowledgment";
		default:
			return "Client-Defined";
	}
}

/* ================================================================= */
/* NDPS                                                               */
/* ================================================================= */

static void
dissect_ndps_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_spx)
{
    proto_tree	*ndps_tree;
    proto_item	*ti;
    proto_tree	*spx_tree;
    proto_item	*spxti;
    tvbuff_t	*next_tvb;
	
    guint8	conn_ctrl;
    guint8	datastream_type;

    guint16     record_mark;
    guint16     ndps_length;
    guint32     ndps_xid;
    guint32     ndps_prog;
    guint32     ndps_version;
    guint32     ndps_packet_type;
    guint32     ndps_rpc_version;
    guint32     foffset;
    guint32     ndps_hfname;
    guint32     ndps_func;
    guint32     ndps_err;
    guint32     ndps_err_dec;
    const char  *ndps_program_string='\0';
    const char  *ndps_func_string='\0';
    char        *ndps_err_string='\0';
    const char  *ndps_error_val = '\0';

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDPS");

    if (check_col(pinfo->cinfo, COL_INFO))
	col_set_str(pinfo->cinfo, COL_INFO, "NDPS ");
	
    if (tree) {
        foffset = 0;
        if(is_spx)
        {
            spxti = proto_tree_add_item(tree, proto_spx, tvb, 0, SPX_HEADER_LEN, FALSE);
            spx_tree = proto_item_add_subtree(spxti, ett_spx);

            conn_ctrl = tvb_get_guint8(tvb, 0);
            
            proto_tree_add_uint_format(spx_tree, hf_spx_connection_control, tvb,
                           0, 1, conn_ctrl,
                           "Connection Control: %s (0x%02X)",
                           spx_conn_ctrl(conn_ctrl), conn_ctrl);

            datastream_type = tvb_get_guint8(tvb, 1);
            proto_tree_add_uint_format(spx_tree, hf_spx_datastream_type, tvb,
                           1, 1, datastream_type,
                           "Datastream Type: %s (0x%02X)",
                           spx_datastream(datastream_type), datastream_type);

            proto_tree_add_item(spx_tree, hf_spx_src_id, tvb,  2, 2, FALSE);
            proto_tree_add_item(spx_tree, hf_spx_dst_id, tvb,  4, 2, FALSE);
            proto_tree_add_item(spx_tree, hf_spx_seq_nr, tvb,  6, 2, FALSE);
            proto_tree_add_item(spx_tree, hf_spx_ack_nr, tvb,  8, 2, FALSE);
            proto_tree_add_item(spx_tree, hf_spx_all_nr, tvb, 10, 2, FALSE);
            foffset = 12;
            ti = proto_tree_add_item(tree, proto_ndps, tvb, foffset, -1, FALSE);
            ndps_tree = proto_item_add_subtree(ti, ett_ndps);
        }
        else
        {
	    ti = proto_tree_add_item(tree, proto_ndps, tvb, foffset, -1, FALSE);
	    ndps_tree = proto_item_add_subtree(ti, ett_ndps);
        }
        if (tvb_length_remaining(tvb, foffset) > 28)
        {
            record_mark = tvb_get_ntohs(tvb, foffset);
    	    proto_tree_add_item(ndps_tree, hf_ndps_record_mark, tvb,
    					   foffset, 2, record_mark);
            foffset += 2;
    	    ndps_length = tvb_get_ntohs(tvb, foffset);
    	    proto_tree_add_uint_format(ndps_tree, hf_ndps_length, tvb,
    				       foffset, 2, ndps_length,
    				       "Length of NDPS Packet: %d", ndps_length);
            foffset += 2;
 	    ndps_xid = tvb_get_ntohl(tvb, foffset);
    	    proto_tree_add_uint(ndps_tree, hf_ndps_xid, tvb, foffset, 4, ndps_xid);
    	    foffset += 4;
    	    ndps_packet_type = tvb_get_ntohl(tvb, foffset);
    	    proto_tree_add_item(ndps_tree, hf_ndps_packet_type, tvb, foffset, 4, FALSE);
            if(ndps_packet_type == 0x00000001)
            {
                ndps_err_string = "NDPS Reply - Ok";
                ndps_err = tvb_get_ntohl(tvb, (tvb_length_remaining(tvb, foffset)+foffset) -4 );
                if((ndps_err & 0xffff0000) == 0xffff0000)
                {
                        ndps_error_val = match_strval(ndps_err, ndps_error_types);
                        if(ndps_error_val == NULL)
                            ndps_error_val = "No Error Message Found";
                        ndps_err_dec = -ndps_err;
                        ndps_err_string = "NDPS Error - (0x%08x), (-%d), %s";
                        if (check_col(pinfo->cinfo, COL_INFO))
                            col_add_fstr(pinfo->cinfo, COL_INFO, ndps_err_string, ndps_err, ndps_err_dec, ndps_error_val);
                        proto_tree_add_uint_format(ndps_tree, hf_ndps_error, tvb, (tvb_length_remaining(tvb, foffset)+foffset) -4, 4, ndps_err,
                                                   ndps_err_string, ndps_err, ndps_err_dec, ndps_error_val );
                }
                else
                {
                    if (check_col(pinfo->cinfo, COL_INFO))
                        col_add_fstr(pinfo->cinfo, COL_INFO, ndps_err_string);
                }
            }
            foffset += 4;
    	    ndps_rpc_version = tvb_get_ntohl(tvb, foffset);
    	    proto_tree_add_uint(ndps_tree, hf_ndps_rpc_version, tvb, foffset, 4, ndps_rpc_version);
    
            foffset += 4;
            ndps_prog = tvb_get_ntohl(tvb, foffset);
            ndps_program_string = match_strval(ndps_prog, spx_ndps_program_vals);
            if( ndps_program_string != NULL)
            {
                proto_tree_add_item(ndps_tree, hf_spx_ndps_program, tvb, foffset, 4, FALSE);
                foffset += 4;
                if (check_col(pinfo->cinfo, COL_INFO))
                {
                    col_append_str(pinfo->cinfo, COL_INFO, (gchar*) ndps_program_string);
                    col_append_str(pinfo->cinfo, COL_INFO, ", ");
                }
                ndps_version = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_item(ndps_tree, hf_spx_ndps_version, tvb, foffset, 4, FALSE);
                foffset += 4;
                ndps_func = tvb_get_ntohl(tvb, foffset);
                switch(ndps_prog)
                    {
                    case 0x060976:
                        ndps_hfname = hf_spx_ndps_func_print;
                        ndps_func_string = match_strval(ndps_func, spx_ndps_print_func_vals);
                        break;
                    case 0x060977:
                        ndps_hfname = hf_spx_ndps_func_broker;
                        ndps_func_string = match_strval(ndps_func, spx_ndps_broker_func_vals);
                        break;
                    case 0x060978:
                        ndps_hfname = hf_spx_ndps_func_registry;
                        ndps_func_string = match_strval(ndps_func, spx_ndps_registry_func_vals);
                        break;
                    case 0x060979:
                        ndps_hfname = hf_spx_ndps_func_notify;
                        ndps_func_string = match_strval(ndps_func, spx_ndps_notify_func_vals);
                        break;
                    case 0x06097a:
                        ndps_hfname = hf_spx_ndps_func_resman;
                        ndps_func_string = match_strval(ndps_func, spx_ndps_resman_func_vals);
                        break;
                    case 0x06097b:
                        ndps_hfname = hf_spx_ndps_func_delivery;
                        ndps_func_string = match_strval(ndps_func, spx_ndps_deliver_func_vals);
                        break;
                    default:
                        ndps_hfname = 0;
                        break;
                }
                if(ndps_hfname != 0)
                {
                    proto_tree_add_item(ndps_tree, ndps_hfname, tvb, foffset, 4, FALSE);
                    if (ndps_func_string != NULL) 
                    {
                        if (check_col(pinfo->cinfo, COL_INFO))
                            col_append_str(pinfo->cinfo, COL_INFO, (gchar*) ndps_func_string);
                    }
                }
            }
            next_tvb = tvb_new_subset(tvb, foffset, -1, -1);
            call_dissector(ndps_data_handle,next_tvb, pinfo, tree);
    	}
        else
        {
            if (is_spx)
            {
                if (check_col(pinfo->cinfo, COL_INFO))
                    col_append_str(pinfo->cinfo, COL_INFO, (gchar*) spx_conn_ctrl(conn_ctrl));
            }
        }
    }
}


static void
dissect_ndps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_ndps_common(tvb, pinfo, tree, TRUE);
}

static void
dissect_ndps_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_ndps_common(tvb, pinfo, tree, FALSE);
}

void
proto_register_ndps(void)
{
	static hf_register_info hf_ndps[] = {
		{ &hf_ndps_record_mark,
		{ "Record Mark",		"ndps.record_mark", FT_BOOLEAN, BASE_HEX, NULL, 0x80,
			"", HFILL }},

        { &hf_ndps_packet_type,
        { "Packet Type",    "ndps.packet_type",
          FT_UINT32,    BASE_HEX,   VALS(ndps_packet_types),   0x0,
          "Packet Type", HFILL }},

        { &hf_ndps_length,
        { "Record Length",    "ndps.record_length",
           FT_UINT16,    BASE_HEX,   NULL,   0x0,
           "Record Length", HFILL }},
        
        { &hf_ndps_xid,
        { "Exhange ID",    "ndps.xid",
           FT_UINT32,    BASE_HEX,   NULL,   0x0,
           "Exchange ID", HFILL }},

        { &hf_ndps_rpc_version,
        { "RPC Version",    "ndps.rpc_version",
           FT_UINT32,    BASE_HEX,   NULL,   0x0,
           "RPC Version", HFILL }},

        { &hf_spx_ndps_program,
        { "NDPS Program Number",    "spx.ndps_program",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_program_vals),   0x0,
          "NDPS Program Number", HFILL }},
	
        { &hf_spx_ndps_version,
        { "Program Version",    "spx.ndps_version",
          FT_UINT32,    BASE_DEC,   NULL,   0x0,
          "Program Version", HFILL }}, 
    
        { &hf_ndps_error,
        { "NDPS Error",    "spx.ndps_error",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "NDPS Error", HFILL }}, 
        
        { &hf_spx_ndps_func_print,
        { "Print Program",    "spx.ndps_func_print",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_print_func_vals),   0x0,
          "Print Program", HFILL }},
        
        { &hf_spx_ndps_func_notify,
        { "Notify Program",    "spx.ndps_func_notify",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_notify_func_vals),   0x0,
          "Notify Program", HFILL }},
        
        { &hf_spx_ndps_func_delivery,
        { "Delivery Program",    "spx.ndps_func_delivery",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_deliver_func_vals),   0x0,
          "Delivery Program", HFILL }},
        
        { &hf_spx_ndps_func_registry,
        { "Registry Program",    "spx.ndps_func_registry",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_registry_func_vals),   0x0,
          "Registry Program", HFILL }},
        
        { &hf_spx_ndps_func_resman,
        { "ResMan Program",    "spx.ndps_func_resman",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_resman_func_vals),   0x0,
          "ResMan Program", HFILL }},
        
        { &hf_spx_ndps_func_broker,
        { "Broker Program",    "spx.ndps_func_broker",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_broker_func_vals),   0x0,
          "Broker Program", HFILL }}
    };

	static hf_register_info hf_spx[] = {
		{ &hf_spx_connection_control,
		{ "Connection Control",		"spx.ctl",
		  FT_UINT8,	BASE_HEX,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_datastream_type,
		{ "Datastream type",	       	"spx.type",
		  FT_UINT8,	BASE_HEX,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_src_id,
		{ "Source Connection ID",	"spx.src",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_dst_id,
		{ "Destination Connection ID",	"spx.dst",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_seq_nr,
		{ "Sequence Number",		"spx.seq",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_ack_nr,
		{ "Acknowledgment Number",	"spx.ack",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_all_nr,
		{ "Allocation Number",		"spx.alloc",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "", HFILL }}    };

	static gint *ett[] = {
		&ett_ndps,
		&ett_spx,
	};
	
    proto_spx = proto_register_protocol("Sequenced Packet eXchange",
	    "SPX", "spx");
	proto_register_field_array(proto_spx, hf_spx, array_length(hf_spx));

	proto_ndps = proto_register_protocol("Novell Distributed Print System",
	    "NDPS", "ndps");
	proto_register_field_array(proto_ndps, hf_ndps, array_length(hf_ndps));

	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ndps(void)
{
	dissector_handle_t ndps_handle, ndps_tcp_handle, spx_handle;

	ndps_handle = create_dissector_handle(dissect_ndps, proto_ndps);
	ndps_tcp_handle = create_dissector_handle(dissect_ndps_tcp, proto_ndps);
	
	/*spx_handle = create_dissector_handle(dissect_ndps, proto_spx);
	dissector_add("ipx.packet_type", IPX_PACKET_TYPE_SPX, spx_handle);*/
	dissector_add("ipx.socket", SPX_SOCKET_PA, ndps_handle);
	dissector_add("ipx.socket", SPX_SOCKET_BROKER, ndps_handle);
	dissector_add("ipx.socket", SPX_SOCKET_SRS, ndps_handle);
	dissector_add("ipx.socket", SPX_SOCKET_ENS, ndps_handle);
	dissector_add("ipx.socket", SPX_SOCKET_RMS, ndps_handle);
	dissector_add("ipx.socket", SPX_SOCKET_NOTIFY_LISTENER, ndps_handle);
	dissector_add("tcp.port", TCP_PORT_PA, ndps_tcp_handle);
	dissector_add("tcp.port", TCP_PORT_BROKER, ndps_tcp_handle);
	dissector_add("tcp.port", TCP_PORT_SRS, ndps_tcp_handle);
	dissector_add("tcp.port", TCP_PORT_ENS, ndps_tcp_handle);
	dissector_add("tcp.port", TCP_PORT_RMS, ndps_tcp_handle);
	dissector_add("tcp.port", TCP_PORT_NOTIFY_LISTENER, ndps_tcp_handle);
	ndps_data_handle = find_dissector("data");
}
