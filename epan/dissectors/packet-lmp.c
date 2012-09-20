/* packet-lmp.c
 * Routines for LMP packet disassembly
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
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

/*
 * Code for dissecting the Link Management Protocol (LMP). The latest LMP
 * specification is in draft-ieft-ccamp-lmp-10.txt. This version also includes
 * support for dissecting LMP service discovery extensions defined in the
 * UNI 1.0 specification.
 *
 * Support for LMP service discovery extensions added by Manu Pathak
 * (mapathak@cisco.com), June 2005.
 *
 * Support for RFC4207 (SONET/SDH encoding for LMP test messages) added
 * by Roberto Morro (roberto.morro [AT] tilab.com), August 2007
 *
 * Support for (provisional) oif-p0040.010.006 added by Roberto Morro,
 * August 2007
 */

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <prefs.h>
#include <epan/in_cksum.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>

#include "packet-ip.h"
#include "packet-rsvp.h"
#include "packet-frame.h"

static int proto_lmp = -1;

#define UDP_PORT_LMP_DEFAULT 701
static guint lmp_udp_port = UDP_PORT_LMP_DEFAULT;
static guint lmp_udp_port_config = UDP_PORT_LMP_DEFAULT;

static gboolean lmp_checksum_config = FALSE;

static dissector_handle_t lmp_handle;

/*----------------------------------------------------------------------
 * LMP message types
 */
typedef enum {
    LMP_MSG_CONFIG=1,
    LMP_MSG_CONFIG_ACK,
    LMP_MSG_CONFIG_NACK,
    LMP_MSG_HELLO,
    LMP_MSG_BEGIN_VERIFY,
    LMP_MSG_BEGIN_VERIFY_ACK,
    LMP_MSG_BEGIN_VERIFY_NACK,
    LMP_MSG_END_VERIFY,
    LMP_MSG_END_VERIFY_ACK,
    LMP_MSG_TEST,
    LMP_MSG_TEST_STATUS_SUCCESS,
    LMP_MSG_TEST_STATUS_FAILURE,
    LMP_MSG_TEST_STATUS_ACK,
    LMP_MSG_LINK_SUMMARY,
    LMP_MSG_LINK_SUMMARY_ACK,
    LMP_MSG_LINK_SUMMARY_NACK,
    LMP_MSG_CHANNEL_STATUS,
    LMP_MSG_CHANNEL_STATUS_ACK,
    LMP_MSG_CHANNEL_STATUS_REQ,
    LMP_MSG_CHANNEL_STATUS_RESP,
    LMP_MSG_TRACE_MONITOR,
    LMP_MSG_TRACE_MONITOR_ACK,
    LMP_MSG_TRACE_MONITOR_NACK,
    LMP_MSG_TRACE_MISMATCH,
    LMP_MSG_TRACE_MISMATCH_ACK,
    LMP_MSG_TRACE_REQUEST,
    LMP_MSG_TRACE_REPORT,
    LMP_MSG_TRACE_REQUEST_NACK,
    LMP_MSG_INSERT_TRACE,
    LMP_MSG_INSERT_TRACE_ACK,
    LMP_MSG_INSERT_TRACE_NACK,
    LMP_MSG_SERVICE_CONFIG=50,
    LMP_MSG_SERVICE_CONFIG_ACK,
    LMP_MSG_SERVICE_CONFIG_NACK,
    LMP_MSG_DISCOVERY_RESP=241,
    LMP_MSG_DISCOVERY_RESP_ACK,
    LMP_MSG_DISCOVERY_RESP_NACK
} lmp_message_types;

static const value_string message_type_vals[] = {
    {LMP_MSG_CONFIG,              "Config Message. "},
    {LMP_MSG_CONFIG_ACK,          "ConfigAck Message. "},
    {LMP_MSG_CONFIG_NACK,         "ConfigNack Message. "},
    {LMP_MSG_HELLO,               "Hello Message. "},
    {LMP_MSG_BEGIN_VERIFY,        "BeginVerify Message. "},
    {LMP_MSG_BEGIN_VERIFY_ACK,    "BeginVerifyAck Message. "},
    {LMP_MSG_BEGIN_VERIFY_NACK,   "BeginVerifyNack Message. "},
    {LMP_MSG_END_VERIFY,          "EndVerify Message. "},
    {LMP_MSG_END_VERIFY_ACK,      "EndVerifyAck Message. "},
    {LMP_MSG_TEST,                "Test Message. "},
    {LMP_MSG_TEST_STATUS_SUCCESS, "TestStatusSuccess Message. "},
    {LMP_MSG_TEST_STATUS_FAILURE, "TestStatusFailure Message. "},
    {LMP_MSG_TEST_STATUS_ACK,     "TestStatusAck Message. "},
    {LMP_MSG_LINK_SUMMARY,        "LinkSummary Message. "},
    {LMP_MSG_LINK_SUMMARY_ACK,    "LinkSummaryAck Message. "},
    {LMP_MSG_LINK_SUMMARY_NACK,   "LinkSummaryNack Message. "},
    {LMP_MSG_CHANNEL_STATUS,      "ChannelStatus Message. "},
    {LMP_MSG_CHANNEL_STATUS_ACK,  "ChannelStatusAck Message. "},
    {LMP_MSG_CHANNEL_STATUS_REQ,  "ChannelStatusRequest Message. "},
    {LMP_MSG_CHANNEL_STATUS_RESP, "ChannelStatusResponse Message. "},
    {LMP_MSG_TRACE_MONITOR,       "TraceMonitor Message. "},
    {LMP_MSG_TRACE_MONITOR_ACK,   "TraceMonitorAck Message. "},
    {LMP_MSG_TRACE_MONITOR_NACK,  "TraceMonitorNack Message. "},
    {LMP_MSG_TRACE_MISMATCH,      "TraceMismatch Message. "},
    {LMP_MSG_TRACE_MISMATCH_ACK,  "TraceMismatchAck Message. "},
    {LMP_MSG_TRACE_REQUEST,       "TraceRequest Message. "},
    {LMP_MSG_TRACE_REPORT,        "TraceReport Message. "},
    {LMP_MSG_TRACE_REQUEST_NACK,  "TraceReportNack Message. "},
    {LMP_MSG_INSERT_TRACE,        "InsertTrace Message. "},
    {LMP_MSG_INSERT_TRACE_ACK,    "InsertTraceAck Message. "},
    {LMP_MSG_INSERT_TRACE_NACK,   "InsertTraceNack Message. "},
    {LMP_MSG_SERVICE_CONFIG,      "ServiceConfig Message. "},
    {LMP_MSG_SERVICE_CONFIG_ACK,  "ServiceConfigAck Message. "},
    {LMP_MSG_SERVICE_CONFIG_NACK, "ServiceConfigNack Message. "},
    {LMP_MSG_DISCOVERY_RESP,      "DiscoveryResponse Message. "},
    {LMP_MSG_DISCOVERY_RESP_ACK,  "DiscoveryResponseAck Message. "},
    {LMP_MSG_DISCOVERY_RESP_NACK, "DiscoveryResponseNack Message. "},
    {0, NULL}
};

/*------------------------------------------------------------------------------
 * LMP object classes
 */
#define LMP_CLASS_NULL				0

#define	LMP_CLASS_CCID                          1
#define	LMP_CLASS_NODE_ID                       2
#define	LMP_CLASS_LINK_ID                       3
#define	LMP_CLASS_INTERFACE_ID                  4
#define	LMP_CLASS_MESSAGE_ID                    5
#define	LMP_CLASS_CONFIG                        6
#define	LMP_CLASS_HELLO                         7
#define	LMP_CLASS_BEGIN_VERIFY                  8
#define	LMP_CLASS_BEGIN_VERIFY_ACK              9
#define	LMP_CLASS_VERIFY_ID                     10
#define	LMP_CLASS_TE_LINK                       11
#define	LMP_CLASS_DATA_LINK                     12
#define	LMP_CLASS_CHANNEL_STATUS                13
#define	LMP_CLASS_CHANNEL_STATUS_REQUEST        14
#define LMP_LAST_CONTIGUOUS_CLASS              	LMP_CLASS_CHANNEL_STATUS_REQUEST
#define	LMP_CLASS_ERROR                         20
#define LMP_CLASS_TRACE                         21
#define LMP_CLASS_TRACE_REQ                     22
#define LMP_CLASS_SERVICE_CONFIG                51
#define LMP_CLASS_DA_DCN_ADDRESS               248
#define LMP_CLASS_LOCAL_LAD_INFO               249
#define	LMP_CLASS_MAX                          250

static const value_string lmp_class_vals[] = {

    {LMP_CLASS_CCID, "CCID"},
    {LMP_CLASS_NODE_ID, "NODE_ID"},
    {LMP_CLASS_LINK_ID, "LINK_ID"},
    {LMP_CLASS_INTERFACE_ID, "INTERFACE_ID"},
    {LMP_CLASS_MESSAGE_ID, "MESSAGE_ID"},
    {LMP_CLASS_CONFIG, "CONFIG"},
    {LMP_CLASS_HELLO, "HELLO"},
    {LMP_CLASS_BEGIN_VERIFY, "BEGIN_VERIFY"},
    {LMP_CLASS_BEGIN_VERIFY_ACK, "BEGIN_VERIFY_ACK"},
    {LMP_CLASS_VERIFY_ID, "VERIFY_ID"},
    {LMP_CLASS_TE_LINK, "TE_LINK"},
    {LMP_CLASS_DATA_LINK, "DATA_LINK"},
    {LMP_CLASS_CHANNEL_STATUS, "CHANNEL_STATUS"},
    {LMP_CLASS_CHANNEL_STATUS_REQUEST, "CHANNEL_STATUS_REQUEST"},
    {LMP_CLASS_ERROR, "ERROR"},
    {LMP_CLASS_TRACE, "TRACE"},
    {LMP_CLASS_TRACE_REQ, "TRACE_REQ"},
    {LMP_CLASS_SERVICE_CONFIG, "SERVICE_CONFIG"},
    {LMP_CLASS_DA_DCN_ADDRESS, "DA_DCN_ADDRESS"},
    {LMP_CLASS_LOCAL_LAD_INFO, "LOCAL_LAD_INFO"},
    {0, NULL}
};


/*------------------------------------------------------------------------------
 * Other constants & stuff
 */

/* Channel Status */
static const value_string channel_status_str[] = {
    {1, "Signal Okay (OK)"},
    {2, "Signal Degraded (SD)"},
    {3, "Signal Failed (SF)"},
    {0, NULL}
};
static const value_string channel_status_short_str[] = {
    {1, "OK"},
    {2, "SD"},
    {3, "SF"},
    {0, NULL}
};

/* Service Discovery Client ServiceConfig object (defined in UNI 1.0) */

/* Client Port-Level Service Attribute Object */

/* Link Type */
static const value_string service_attribute_link_type_str[] = {
    {5, "SDH ITU-T G.707"},
    {6, "SONET ANSI T1.105"},
    {0, NULL}
};

/* Signal Types for SDH */
static const value_string service_attribute_signal_types_sdh_str[] = {
    {5,  "VC-3"},
    {6,  "VC-4"},
    {7,  "STM-0"},
    {8,  "STM-1"},
    {9,  "STM-4"},
    {10, "STM-16"},
    {11, "STM-64"},
    {12, "STM-256"},
    {0, NULL}
};

/* Signal Types for SONET */
static const value_string service_attribute_signal_types_sonet_str[] = {
    {5,  "STS-1 SPE"},
    {6,  "STS-3c SPE"},
    {7,  "STS-1"},
    {8,  "STS-3"},
    {9,  "STS-12"},
    {10, "STS-48"},
    {11, "STS-192"},
    {12, "STS-768"},
    {0, NULL}
};

/* Trace type */
static const value_string lmp_trace_type_str[] = {
    { 1, "SONET Section Trace (J0 Byte)"},
    { 2, "SONET Path Trace (J1 Byte)"},
    { 3, "SONET Path Trace (J2 Byte)"},
    { 4, "SDH Section Trace (J0 Byte)"},
    { 5, "SDH Path Trace (J1 Byte)"},
    { 6, "SDH Path Trace (J2 Byte)"},
    { 0, NULL}
};

/*
 * These values are used by the code that handles the Service Discovery
 * Client Port-Level Service Attributes Object.
 */
#define LMP_CLASS_SERVICE_CONFIG_CPSA_SIGNAL_TYPES_SDH 5
#define LMP_CLASS_SERVICE_CONFIG_CPSA_SIGNAL_TYPES_SONET 6

/*------------------------------------------------------------------------------
 * LMP Filter values
 */

enum hf_lmp_filter_keys {

  /* Message types ---------------- */
  LMPF_MSG,

  LMPF_MSG_CONFIG,
  LMPF_MSG_CONFIG_ACK,
  LMPF_MSG_CONFIG_NACK,
  LMPF_MSG_HELLO,
  LMPF_MSG_BEGIN_VERIFY,
  LMPF_MSG_BEGIN_VERIFY_ACK,
  LMPF_MSG_BEGIN_VERIFY_NACK,
  LMPF_MSG_END_VERIFY,
  LMPF_MSG_END_VERIFY_ACK,
  LMPF_MSG_TEST,
  LMPF_MSG_TEST_STATUS_SUCCESS,
  LMPF_MSG_TEST_STATUS_FAILURE,
  LMPF_MSG_TEST_STATUS_ACK,
  LMPF_MSG_LINK_SUMMARY,
  LMPF_MSG_LINK_SUMMARY_ACK,
  LMPF_MSG_LINK_SUMMARY_NACK,
  LMPF_MSG_CHANNEL_STATUS,
  LMPF_MSG_CHANNEL_STATUS_ACK,
  LMPF_MSG_CHANNEL_STATUS_REQ,
  LMPF_MSG_CHANNEL_STATUS_RESP,
  LMPF_MSG_TRACE_MONITOR,
  LMPF_MSG_TRACE_MONITOR_ACK,
  LMPF_MSG_TRACE_MONITOR_NACK,
  LMPF_MSG_TRACE_MISMATCH,
  LMPF_MSG_TRACE_MISMATCH_ACK,
  LMPF_MSG_TRACE_REQUEST,
  LMPF_MSG_TRACE_REPORT,
  LMPF_MSG_TRACE_REQUEST_NACK,
  LMPF_MSG_INSERT_TRACE,
  LMPF_MSG_INSERT_TRACE_ACK,
  LMPF_MSG_INSERT_TRACE_NACK,
  LMPF_MSG_SERVICE_CONFIG,
  LMPF_MSG_SERVICE_CONFIG_ACK,
  LMPF_MSG_SERVICE_CONFIG_NACK,
  LMPF_MSG_DISCOVERY_RESP,
  LMPF_MSG_DISCOVERY_RESP_ACK,
  LMPF_MSG_DISCOVERY_RESP_NACK,

  LMPF_MSG_MAX,

  /* LMP Message Header Fields ------------------ */
  LMPF_HDR_FLAGS,
  LMPF_HDR_FLAGS_CC_DOWN,
  LMPF_HDR_FLAGS_REBOOT,

  /* LMP Object Class Filters -------------------- */
  LMPF_OBJECT,

  LMPF_CLASS_CCID,
  LMPF_CLASS_NODE_ID,
  LMPF_CLASS_LINK_ID,
  LMPF_CLASS_INTERFACE_ID,
  LMPF_CLASS_MESSAGE_ID,
  LMPF_CLASS_CONFIG,
  LMPF_CLASS_HELLO,
  LMPF_CLASS_BEGIN_VERIFY,
  LMPF_CLASS_BEGIN_VERIFY_ACK,
  LMPF_CLASS_VERIFY_ID,
  LMPF_CLASS_TE_LINK,
  LMPF_CLASS_DATA_LINK,
  LMPF_CLASS_CHANNEL_STATUS,
  LMPF_CLASS_CHANNEL_STATUS_REQUEST,
  LMPF_CLASS_ERROR,
  LMPF_CLASS_TRACE,
  LMPF_CLASS_TRACE_REQ,
  LMPF_CLASS_SERVICE_CONFIG,
  LMPF_CLASS_DA_DCN_ADDRESS,
  LMPF_CLASS_LOCAL_LAD_INFO,

  LMPF_VAL_CTYPE,
  LMPF_VAL_LOCAL_CCID,
  LMPF_VAL_REMOTE_CCID,
  LMPF_VAL_LOCAL_NODE_ID,
  LMPF_VAL_REMOTE_NODE_ID,
  LMPF_VAL_LOCAL_LINK_ID_IPV4,
  LMPF_VAL_LOCAL_LINK_ID_IPV6,
  LMPF_VAL_LOCAL_LINK_ID_UNNUM,
  LMPF_VAL_REMOTE_LINK_ID_IPV4,
  LMPF_VAL_REMOTE_LINK_ID_IPV6,
  LMPF_VAL_REMOTE_LINK_ID_UNNUM,
  LMPF_VAL_LOCAL_INTERFACE_ID_IPV4,
  LMPF_VAL_LOCAL_INTERFACE_ID_IPV6,
  LMPF_VAL_LOCAL_INTERFACE_ID_UNNUM,
  LMPF_VAL_REMOTE_INTERFACE_ID_IPV4,
  LMPF_VAL_REMOTE_INTERFACE_ID_IPV6,
  LMPF_VAL_REMOTE_INTERFACE_ID_UNNUM,
  LMPF_VAL_MESSAGE_ID,
  LMPF_VAL_MESSAGE_ID_ACK,
  LMPF_VAL_CONFIG_HELLO,
  LMPF_VAL_CONFIG_HELLO_DEAD,
  LMPF_VAL_HELLO_TXSEQ,
  LMPF_VAL_HELLO_RXSEQ,

  LMPF_VAL_BEGIN_VERIFY_FLAGS,
  LMPF_VAL_BEGIN_VERIFY_FLAGS_ALL_LINKS,
  LMPF_VAL_BEGIN_VERIFY_FLAGS_LINK_TYPE,
  LMPF_VAL_BEGIN_VERIFY_INTERVAL,
  LMPF_VAL_BEGIN_VERIFY_ENCTYPE,
  LMPF_VAL_BEGIN_VERIFY_TRANSPORT,
  LMPF_VAL_BEGIN_VERIFY_TRANSMISSION_RATE,
  LMPF_VAL_BEGIN_VERIFY_WAVELENGTH,
  LMPF_VAL_VERIFY_ID,

  LMPF_VAL_TE_LINK_FLAGS,
  LMPF_VAL_TE_LINK_FLAGS_FAULT_MGMT,
  LMPF_VAL_TE_LINK_FLAGS_LINK_VERIFY,
  LMPF_VAL_TE_LINK_LOCAL_IPV4,
  LMPF_VAL_TE_LINK_LOCAL_UNNUM,
  LMPF_VAL_TE_LINK_REMOTE_IPV4,
  LMPF_VAL_TE_LINK_REMOTE_UNNUM,

  LMPF_VAL_DATA_LINK_FLAGS,
  LMPF_VAL_DATA_LINK_FLAGS_PORT,
  LMPF_VAL_DATA_LINK_FLAGS_ALLOCATED,
  LMPF_VAL_DATA_LINK_LOCAL_IPV4,
  LMPF_VAL_DATA_LINK_LOCAL_UNNUM,
  LMPF_VAL_DATA_LINK_REMOTE_IPV4,
  LMPF_VAL_DATA_LINK_REMOTE_UNNUM,
  LMPF_VAL_DATA_LINK_SUBOBJ,
  LMPF_VAL_DATA_LINK_SUBOBJ_SWITCHING_TYPE,
  LMPF_VAL_DATA_LINK_SUBOBJ_LSP_ENCODING,

  LMPF_VAL_ERROR,
  LMPF_VAL_ERROR_VERIFY_UNSUPPORTED_LINK,
  LMPF_VAL_ERROR_VERIFY_UNWILLING,
  LMPF_VAL_ERROR_VERIFY_TRANSPORT,
  LMPF_VAL_ERROR_VERIFY_TE_LINK_ID,
  LMPF_VAL_ERROR_VERIFY_UNKNOWN_CTYPE,
  LMPF_VAL_ERROR_SUMMARY_BAD_PARAMETERS,
  LMPF_VAL_ERROR_SUMMARY_RENEGOTIATE,
  LMPF_VAL_ERROR_SUMMARY_BAD_TE_LINK,
  LMPF_VAL_ERROR_SUMMARY_BAD_DATA_LINK,
  LMPF_VAL_ERROR_SUMMARY_UNKNOWN_TEL_CTYPE,
  LMPF_VAL_ERROR_SUMMARY_UNKNOWN_DL_CTYPE,
  LMPF_VAL_ERROR_SUMMARY_BAD_REMOTE_LINK_ID,
  LMPF_VAL_ERROR_CONFIG_BAD_PARAMETERS,
  LMPF_VAL_ERROR_CONFIG_RENEGOTIATE,
  LMPF_VAL_ERROR_CONFIG_BAD_CCID,
  LMPF_VAL_ERROR_TRACE_UNSUPPORTED_TYPE,
  LMPF_VAL_ERROR_TRACE_INVALID_MSG,
  LMPF_VAL_ERROR_TRACE_UNKNOWN_CTYPE,
  LMPF_VAL_ERROR_LAD_AREA_ID_MISMATCH,
  LMPF_VAL_ERROR_LAD_TCP_ID_MISMATCH,
  LMPF_VAL_ERROR_LAD_DA_DCN_MISMATCH,
  LMPF_VAL_ERROR_LAD_CAPABILITY_MISMATCH,
  LMPF_VAL_ERROR_LAD_UNKNOWN_CTYPE,

  LMPF_VAL_TRACE_LOCAL_TYPE,
  LMPF_VAL_TRACE_LOCAL_LEN,
  LMPF_VAL_TRACE_LOCAL_MSG,
  LMPF_VAL_TRACE_REMOTE_TYPE,
  LMPF_VAL_TRACE_REMOTE_LEN,
  LMPF_VAL_TRACE_REMOTE_MSG,

  LMPF_VAL_TRACE_REQ_TYPE,

  LMPF_VAL_SERVICE_CONFIG_SP_FLAGS,
  LMPF_VAL_SERVICE_CONFIG_SP_FLAGS_RSVP,
  LMPF_VAL_SERVICE_CONFIG_SP_FLAGS_LDP,
  LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS,
  LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS_PATH_OVERHEAD,
  LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS_LINE_OVERHEAD,
  LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS_SECTION_OVERHEAD,
  LMPF_VAL_SERVICE_CONFIG_CPSA_CCT_FLAGS,
  LMPF_VAL_SERVICE_CONFIG_CPSA_CCT_FLAGS_CC_SUPPORTED,
  LMPF_VAL_SERVICE_CONFIG_CPSA_MIN_NCC,
  LMPF_VAL_SERVICE_CONFIG_CPSA_MAX_NCC,
  LMPF_VAL_SERVICE_CONFIG_CPSA_MIN_NVC,
  LMPF_VAL_SERVICE_CONFIG_CPSA_MAX_NVC,
  LMPF_VAL_SERVICE_CONFIG_CPSA_INTERFACE_ID,
  LMPF_VAL_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS,
  LMPF_VAL_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS_SOH,
  LMPF_VAL_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS_LOH,
  LMPF_VAL_SERVICE_CONFIG_NSA_TCM_FLAGS,
  LMPF_VAL_SERVICE_CONFIG_NSA_TCM_FLAGS_TCM_SUPPORTED,
  LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS,
  LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS_NODE,
  LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS_LINK,
  LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS_SRLG,

  LMPF_VAL_LOCAL_DA_DCN_ADDR,
  LMPF_VAL_REMOTE_DA_DCN_ADDR,

  LMPF_VAL_LOCAL_LAD_INFO_NODE_ID,
  LMPF_VAL_LOCAL_LAD_INFO_AREA_ID,
  LMPF_VAL_LOCAL_LAD_INFO_TE_LINK_ID,
  LMPF_VAL_LOCAL_LAD_INFO_COMPONENT_ID,
  LMPF_VAL_LOCAL_LAD_INFO_SC_PC_ID,
  LMPF_VAL_LOCAL_LAD_INFO_SC_PC_ADDR,

  LMPF_VAL_LAD_INFO_SUBOBJ,
  LMPF_VAL_LAD_INFO_SUBOBJ_PRI_AREA_ID,
  LMPF_VAL_LAD_INFO_SUBOBJ_PRI_RC_PC_ID,
  LMPF_VAL_LAD_INFO_SUBOBJ_PRI_RC_PC_ADDR,
  LMPF_VAL_LAD_INFO_SUBOBJ_SEC_AREA_ID,
  LMPF_VAL_LAD_INFO_SUBOBJ_SEC_RC_PC_ID,
  LMPF_VAL_LAD_INFO_SUBOBJ_SEC_RC_PC_ADDR,
  LMPF_VAL_LAD_INFO_SUBOBJ_SWITCHING_TYPE,
  LMPF_VAL_LAD_INFO_SUBOBJ_LSP_ENCODING,

  LMPF_MAX
};

static int hf_lmp_filter[LMPF_MAX];

static int
lmp_valid_class(int class)
{
    /* Contiguous classes */
    if (class > LMP_CLASS_NULL && class <= LMP_LAST_CONTIGUOUS_CLASS)
	return 1;

    /* Noncontiguous classes */
    if (class == LMP_CLASS_ERROR ||
        class == LMP_CLASS_TRACE ||
        class == LMP_CLASS_TRACE_REQ ||
	class == LMP_CLASS_SERVICE_CONFIG ||
        class == LMP_CLASS_DA_DCN_ADDRESS ||
        class == LMP_CLASS_LOCAL_LAD_INFO)
	return 1;

    return 0;
}

static int
lmp_msg_to_filter_num(int msg_type)
{
  if (msg_type <= LMP_MSG_INSERT_TRACE_NACK)
    return LMPF_MSG + msg_type;

  switch (msg_type) {
    case LMP_MSG_SERVICE_CONFIG:
      return LMPF_MSG_SERVICE_CONFIG;

    case LMP_MSG_SERVICE_CONFIG_ACK:
      return LMPF_MSG_SERVICE_CONFIG_ACK;

    case LMP_MSG_SERVICE_CONFIG_NACK:
      return LMPF_MSG_SERVICE_CONFIG_NACK;

    case LMP_MSG_DISCOVERY_RESP:
      return LMPF_MSG_DISCOVERY_RESP;

    case LMP_MSG_DISCOVERY_RESP_ACK:
      return LMPF_MSG_DISCOVERY_RESP_ACK;

    case LMP_MSG_DISCOVERY_RESP_NACK:
      return LMPF_MSG_DISCOVERY_RESP_NACK;

    default:
	return -1;
    }
}


static int
lmp_class_to_filter_num(int class)
{

    /*
     * The contiguous values can all be handled in the same way. The ERROR and
     * Service Config objects, whose C-Type values are not contiguously assigned,
     * must be handled separately.
     */
    switch (class) {

    case LMP_CLASS_CCID:
    case LMP_CLASS_NODE_ID:
    case LMP_CLASS_LINK_ID:
    case LMP_CLASS_INTERFACE_ID:
    case LMP_CLASS_MESSAGE_ID:
    case LMP_CLASS_CONFIG:
    case LMP_CLASS_HELLO:
    case LMP_CLASS_BEGIN_VERIFY:
    case LMP_CLASS_BEGIN_VERIFY_ACK:
    case LMP_CLASS_VERIFY_ID:
    case LMP_CLASS_TE_LINK:
    case LMP_CLASS_DATA_LINK:
    case LMP_CLASS_CHANNEL_STATUS:
    case LMP_CLASS_CHANNEL_STATUS_REQUEST:
	return LMPF_OBJECT + class;

    case LMP_CLASS_ERROR:
	return LMPF_CLASS_ERROR;

    case LMP_CLASS_TRACE:
	return LMPF_CLASS_TRACE;

    case LMP_CLASS_TRACE_REQ:
	return LMPF_CLASS_TRACE_REQ;

    case LMP_CLASS_SERVICE_CONFIG:
	return LMPF_CLASS_SERVICE_CONFIG;

    case LMP_CLASS_DA_DCN_ADDRESS:
	return LMPF_CLASS_DA_DCN_ADDRESS;

    case LMP_CLASS_LOCAL_LAD_INFO:
	return LMPF_CLASS_LOCAL_LAD_INFO;

    default:
	return -1;
    }
}


/*------------------------------------------------------------------------------
 * LMP Subtrees
 *
 * We have two types of subtrees - a statically defined, constant set and
 * a class set - one for each class. The static ones are before all the class ones
 */
enum {
    LMP_TREE_MAIN,
    LMP_TREE_HEADER,
    LMP_TREE_HEADER_FLAGS,
    LMP_TREE_OBJECT_HEADER,
    LMP_TREE_ERROR_FLAGS,
    LMP_TREE_BEGIN_VERIFY_FLAGS,
    LMP_TREE_BEGIN_VERIFY_TRANSPORT_FLAGS,
    LMP_TREE_TE_LINK_FLAGS,
    LMP_TREE_DATA_LINK_FLAGS,
    LMP_TREE_DATA_LINK_SUBOBJ,
    LMP_TREE_CHANNEL_STATUS_ID,
    LMP_TREE_SERVICE_CONFIG_SP_FLAGS,
    LMP_TREE_SERVICE_CONFIG_CPSA_TP_FLAGS,
    LMP_TREE_SERVICE_CONFIG_CPSA_CCT_FLAGS,
    LMP_TREE_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS,
    LMP_TREE_SERVICE_CONFIG_NSA_TCM_FLAGS,
    LMP_TREE_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS,
    LMP_TREE_LAD_INFO_SUBOBJ,

    LMP_TREE_CLASS_START
};

#define NUM_LMP_SUBTREES (LMP_TREE_CLASS_START + LMP_CLASS_MAX)

static gint lmp_subtree[NUM_LMP_SUBTREES];

static int lmp_class_to_subtree(int class)
{
    if (lmp_valid_class(class)) {
	if (class == LMP_CLASS_SERVICE_CONFIG) {
	    return lmp_subtree[LMP_TREE_CLASS_START + LMP_CLASS_SERVICE_CONFIG];
	}
	if (class == LMP_CLASS_DA_DCN_ADDRESS) {
	    return lmp_subtree[LMP_TREE_CLASS_START + LMP_CLASS_DA_DCN_ADDRESS];
	}
	if (class == LMP_CLASS_LOCAL_LAD_INFO) {
	    return lmp_subtree[LMP_TREE_CLASS_START + LMP_CLASS_LOCAL_LAD_INFO];
	}

	return lmp_subtree[LMP_TREE_CLASS_START + class];
    }
    return -1;
}

/*------------------------------------------------------------------------------
 * Da code
 */

static int
dissect_lmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    proto_tree *lmp_tree = NULL, *ti, *ti2;
    proto_tree *lmp_header_tree;
    proto_tree *lmp_header_flags_tree;
    proto_tree *lmp_object_tree;
    proto_tree *lmp_object_header_tree;
    proto_tree *lmp_flags_tree;
    proto_tree *lmp_subobj_tree;
    proto_item *hidden_item;

    guint8 version;
    guint8 flags;
    guint8 message_type;
    guint16 cksum, computed_cksum;
    vec_t cksum_vec[1];
    int j, k, l, len;
    int msg_length;
    int obj_length;
    int mylen;
    int offset2;
    int proto;

    proto = pinfo->ipproto;

    /* Only process UDP packets */
    if (proto != IP_PROTO_UDP) {
	    return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LMP");
    col_clear(pinfo->cinfo, COL_INFO);

    version = (tvb_get_guint8(tvb, offset+0)) >> 4;
    flags = tvb_get_guint8(tvb, offset+2);
    message_type = tvb_get_guint8(tvb, offset+3);
    col_add_str(pinfo->cinfo, COL_INFO,
         val_to_str(message_type, message_type_vals, "Unknown (%u). "));

    if (tree) {
	msg_length = tvb_get_ntohs(tvb, offset+4);
	ti = proto_tree_add_item(tree, proto_lmp, tvb, offset, msg_length,
	    ENC_NA);
	lmp_tree = proto_item_add_subtree(ti, lmp_subtree[LMP_TREE_MAIN]);
	ti = proto_tree_add_text(lmp_tree, tvb, offset, 12, "LMP Header. %s",
				 val_to_str(message_type, message_type_vals,
					    "Unknown Message (%u). "));
	lmp_header_tree = proto_item_add_subtree(ti, lmp_subtree[LMP_TREE_HEADER]);
        proto_tree_add_text(lmp_header_tree, tvb, offset, 1, "LMP Version: %u",
			    version);
	ti = proto_tree_add_text(lmp_header_tree, tvb, offset+2, 1, "Flags: %02x",
				 flags);
	lmp_header_flags_tree = proto_item_add_subtree(ti, lmp_subtree[LMP_TREE_HEADER_FLAGS]);
	proto_tree_add_boolean(lmp_header_flags_tree, hf_lmp_filter[LMPF_HDR_FLAGS_CC_DOWN],
			       tvb, offset+2, 1, flags);
	proto_tree_add_boolean(lmp_header_flags_tree, hf_lmp_filter[LMPF_HDR_FLAGS_REBOOT],
			       tvb, offset+2, 1, flags);
	proto_tree_add_uint(lmp_header_tree, hf_lmp_filter[LMPF_MSG], tvb,
			    offset+3, 1, message_type);
	proto_tree_add_text(lmp_header_tree, tvb, offset+4, 2, "Length: %d bytes",
			    msg_length);
/*	if (LMPF_MSG + message_type < LMPF_MSG_MAX && message_type > 0) {*/
    /* this "if" is still a hack, but compared to the former one at least correct */
    if ((message_type >= LMP_MSG_CONFIG && message_type <= LMP_MSG_CHANNEL_STATUS_RESP) ||
        (message_type >= LMP_MSG_SERVICE_CONFIG && message_type <= LMP_MSG_SERVICE_CONFIG_NACK) ||
        (message_type >= LMP_MSG_DISCOVERY_RESP && message_type <= LMP_MSG_DISCOVERY_RESP_NACK) ) {
	    hidden_item = proto_tree_add_boolean(lmp_header_tree,
                                          hf_lmp_filter[lmp_msg_to_filter_num(message_type)],
                                          tvb, offset+3, 1, 1);
	    PROTO_ITEM_SET_HIDDEN(hidden_item);
	} else {
	    proto_tree_add_protocol_format(lmp_header_tree, proto_malformed, tvb, offset+3, 1,
					   "Invalid message type: %u", message_type);
		return tvb_length(tvb);
	}

	if (lmp_checksum_config) {
		cksum = tvb_get_ntohs(tvb, offset+6);
		if (!pinfo->fragmented && (int) tvb_length(tvb) >= msg_length) {
		    /* The packet isn't part of a fragmented datagram and isn't
		       truncated, so we can checksum it. */
		    cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, msg_length);
		    cksum_vec[0].len = msg_length;
		    computed_cksum = in_cksum(&cksum_vec[0], 1);

		    if (computed_cksum == 0) {
			proto_tree_add_text(lmp_header_tree, tvb, offset+6, 2,
					    "Message Checksum: 0x%04x [correct]",
					    cksum);
		    } else {
			proto_tree_add_text(lmp_header_tree, tvb, offset+6, 2,
					    "Message Checksum: 0x%04x [incorrect, should be 0x%04x]",
					    cksum,
					    in_cksum_shouldbe(cksum, computed_cksum));
		    }
		} else {
		    proto_tree_add_text(lmp_header_tree, tvb, offset+6, 2,
					"Message Checksum: 0x%04x",
					cksum);
		}
	} else {
		proto_tree_add_text(lmp_header_tree, tvb, offset+6, 2, "No checksum");
	}

	offset += 8;
	len = 8;
	while (len < msg_length) {
	  guint8 class;
	  guint8 type;
	  guint8 negotiable;
	  const char *object_type;

	  obj_length = tvb_get_ntohs(tvb, offset+2);
	  class = tvb_get_guint8(tvb, offset+1);
	  type = tvb_get_guint8(tvb, offset);
	  negotiable = (type >> 7); type &= 0x7f;
	  object_type = val_to_str_const(class, lmp_class_vals, "Unknown");
	  hidden_item = proto_tree_add_uint(lmp_tree, hf_lmp_filter[LMPF_OBJECT], tvb,
				     offset, 1, class);
	  PROTO_ITEM_SET_HIDDEN(hidden_item);
	  if (lmp_valid_class(class)) {

	      ti = proto_tree_add_item(lmp_tree,
				       hf_lmp_filter[lmp_class_to_filter_num(class)],
				       tvb, offset, obj_length, ENC_NA);  /* all possibilities are FT_NONE */
	  } else {
	      proto_tree_add_protocol_format(lmp_tree, proto_malformed, tvb,
					     offset+1, 1,
					     "Invalid class: %u", class);
	      return tvb_length(tvb);
	  }
	  lmp_object_tree = proto_item_add_subtree(ti, lmp_class_to_subtree(class));

	  ti2 = proto_tree_add_text(lmp_object_tree, tvb, offset, 4,
				    "Header. Class %d, C-Type %d, Length %d, %s",
				    class, type, obj_length,
				    negotiable ? "Negotiable" : "Not Negotiable");

	  lmp_object_header_tree =
	      proto_item_add_subtree(ti2, lmp_subtree[LMP_TREE_OBJECT_HEADER]);

	  proto_tree_add_text(lmp_object_header_tree, tvb, offset, 1,
			      negotiable ? "Negotiable" : "Not Negotiable");
	  proto_tree_add_text(lmp_object_header_tree, tvb, offset+2, 2,
			      "Length: %u", obj_length);
	  proto_tree_add_text(lmp_object_header_tree, tvb, offset+1, 1,
			      "Object Class: %u - %s",
			      class, object_type);
	  proto_tree_add_uint(lmp_object_header_tree, hf_lmp_filter[LMPF_VAL_CTYPE],
			      tvb, offset, 1, type);
	  offset2 = offset+4;
	  mylen = obj_length - 4;

	  switch (class) {

	  case LMP_CLASS_NULL:
	      break;

	  case LMP_CLASS_CCID:
	      switch(type) {

	      case 1:
		  l = LMPF_VAL_LOCAL_CCID;
		  proto_item_append_text(ti, ": %d", tvb_get_ntohl(tvb, offset2));
		  proto_tree_add_uint(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, tvb_get_ntohl(tvb, offset2));
		  break;

	      case 2:
		  l = LMPF_VAL_REMOTE_CCID;
		  proto_item_append_text(ti, ": %d", tvb_get_ntohl(tvb, offset2));
		  proto_tree_add_uint(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, tvb_get_ntohl(tvb, offset2));
		  break;
	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_NODE_ID:
	      switch(type) {

	      case 1:
		  l = LMPF_VAL_LOCAL_NODE_ID;
		  proto_item_append_text(ti, ": %s", tvb_ip_to_str(tvb, offset2));
		  proto_tree_add_item(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, ENC_BIG_ENDIAN);
		  break;

	      case 2:
		  l = LMPF_VAL_REMOTE_NODE_ID;
		  proto_item_append_text(ti, ": %s", tvb_ip_to_str(tvb, offset2));
		  proto_tree_add_item(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, ENC_BIG_ENDIAN);
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_LINK_ID:

	      switch(type) {

	      case 1:
	      case 2:
		  l = (type == 1)? LMPF_VAL_LOCAL_LINK_ID_IPV4:
		      LMPF_VAL_REMOTE_LINK_ID_IPV4;
		  proto_item_append_text(ti, ": IPv4 %s", tvb_ip_to_str(tvb, offset2));
		  proto_tree_add_item(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, ENC_BIG_ENDIAN);
		  break;

	      case 3:
	      case 4:
		  l = (type == 3)? LMPF_VAL_LOCAL_LINK_ID_IPV6:
		      LMPF_VAL_REMOTE_LINK_ID_IPV6;
		  proto_item_append_text(ti, ": IPv6 %s", tvb_ip6_to_str(tvb, offset2));
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, 16, "IPv6: %s",
				      tvb_ip6_to_str(tvb, offset2));
		  break;
	      case 5:
	      case 6:
		  l = (type == 5)? LMPF_VAL_LOCAL_LINK_ID_UNNUM:
		      LMPF_VAL_REMOTE_LINK_ID_UNNUM;
		  proto_item_append_text(ti, ": Unnumbered %d",
					 tvb_get_ntohl(tvb, offset2));
		  proto_tree_add_item(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, ENC_BIG_ENDIAN);
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_INTERFACE_ID:

	      switch(type) {

	      case 1:
	      case 2:
		  l = (type == 1)? LMPF_VAL_LOCAL_INTERFACE_ID_IPV4:
		      LMPF_VAL_REMOTE_INTERFACE_ID_IPV4;
		  proto_item_append_text(ti, ": IPv4 %s", tvb_ip_to_str(tvb, offset2));
		  proto_tree_add_item(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, ENC_BIG_ENDIAN);
		  break;

	      case 3:
	      case 4:
		  l = (type == 3)? LMPF_VAL_LOCAL_INTERFACE_ID_IPV6:
		      LMPF_VAL_REMOTE_INTERFACE_ID_IPV6;
		  proto_item_append_text(ti, ": IPv6 %s", tvb_ip6_to_str(tvb, offset2));
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, 16, "IPv6: %s",
				      tvb_ip6_to_str(tvb, offset2));
		  break;

	      case 5:
	      case 6:
		  l = (type == 5)? LMPF_VAL_LOCAL_INTERFACE_ID_UNNUM:
		      LMPF_VAL_REMOTE_INTERFACE_ID_UNNUM;
		  proto_item_append_text(ti, ": Unnumbered %d",
					 tvb_get_ntohl(tvb, offset2));
		  proto_tree_add_item(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, ENC_BIG_ENDIAN);
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_MESSAGE_ID:

	      switch(type) {

	      case 1:

		  l = LMPF_VAL_MESSAGE_ID;
		  proto_item_append_text(ti, ": %d", tvb_get_ntohl(tvb, offset2));
		  proto_tree_add_uint(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, tvb_get_ntohl(tvb, offset2));
		  break;

	      case 2:
		  l = LMPF_VAL_MESSAGE_ID_ACK;
		  proto_item_append_text(ti, ": %d", tvb_get_ntohl(tvb, offset2));
		  proto_tree_add_uint(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, tvb_get_ntohl(tvb, offset2));
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_CONFIG:

	      switch(type) {

	      case 1:
		  proto_item_append_text(ti, ": HelloInterval: %d, HelloDeadInterval: %d",
					 tvb_get_ntohs(tvb, offset2),
					 tvb_get_ntohs(tvb, offset2+2));
		  proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_CONFIG_HELLO],
				      tvb, offset2, 2, tvb_get_ntohs(tvb, offset2));
		  proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_CONFIG_HELLO_DEAD],
				      tvb, offset2+2, 2,
				      tvb_get_ntohs(tvb, offset2+2));
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_HELLO:

	      switch(type) {

	      case 1:
		  proto_item_append_text(ti, ": TxSeq %d, RxSeq: %d",
					 tvb_get_ntohl(tvb, offset2),
					 tvb_get_ntohl(tvb, offset2+4));
		  proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_HELLO_TXSEQ],
				      tvb, offset2, 4,
				      tvb_get_ntohl(tvb, offset2));
		  proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_HELLO_RXSEQ],
				      tvb, offset2+4, 4,
				      tvb_get_ntohl(tvb, offset2+4));
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_BEGIN_VERIFY:

	      switch(type) {

	      case 1:
		  l = tvb_get_ntohs(tvb, offset2);
		  ti2 = proto_tree_add_item(lmp_object_tree,
					    hf_lmp_filter[LMPF_VAL_BEGIN_VERIFY_FLAGS],
					    tvb, offset2, 2, ENC_BIG_ENDIAN);

		  lmp_flags_tree = proto_item_add_subtree(ti2,
							  lmp_subtree[LMP_TREE_BEGIN_VERIFY_FLAGS]);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_BEGIN_VERIFY_FLAGS_ALL_LINKS],
					 tvb, offset2, 2, l);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_BEGIN_VERIFY_FLAGS_LINK_TYPE],
					 tvb, offset2, 2, l);
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+2, 2,
				      "Verify Interval: %d ms",
				      tvb_get_ntohs(tvb, offset2+2));
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+4, 4,
				      "Number of Data Links: %d",
				      tvb_get_ntohl(tvb, offset2+4));
		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_BEGIN_VERIFY_ENCTYPE],
				      tvb, offset2+8, 1, ENC_BIG_ENDIAN);
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+10, 2,
				      "Verify Transport Mechanism: 0x%0x",
				      tvb_get_ntohs(tvb, offset2+10));
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+12, 4,
				      "Transmission Rate: %.3f Mbps",
				      tvb_get_ntohieee_float(tvb, offset2+12)*8/1000000);
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+16, 4,
				      "Wavelength: %d",
				      tvb_get_ntohl(tvb, offset2+16));
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_BEGIN_VERIFY_ACK:

	      switch(type) {

	      case 1:
		  proto_item_append_text(ti, ": VerifyDeadInterval: %d, TransportResponse: 0x%0x",
					 tvb_get_ntohs(tvb, offset2),
					 tvb_get_ntohs(tvb, offset2+2));
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, 2,
				      "VerifyDeadInterval: %d ms",
				      tvb_get_ntohs(tvb, offset2));
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+2, 2,
				      "Verify Transport Response: 0x%0x",
				      tvb_get_ntohs(tvb, offset2+2));
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_VERIFY_ID:

	      switch(type) {

	      case 1:
		  proto_item_append_text(ti, ": %d",
					 tvb_get_ntohl(tvb, offset2));
		  proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_VERIFY_ID],
				      tvb, offset2, 4,
				      tvb_get_ntohl(tvb, offset2));
		  break;
	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_TE_LINK:
	      l = tvb_get_guint8(tvb, offset2);
	      ti2 = proto_tree_add_uint(lmp_object_tree,
					hf_lmp_filter[LMPF_VAL_TE_LINK_FLAGS],
					tvb, offset2, 1, l);

	      proto_item_append_text(ti2, ": %s%s",
				     (l&0x01) ? "Fault-Mgmt-Supported " : "",
				     (l&0x02) ? "Link-Verification-Supported " : "");

	      lmp_flags_tree = proto_item_add_subtree(ti2,
						      lmp_subtree[LMP_TREE_TE_LINK_FLAGS]);
	      proto_tree_add_boolean(lmp_flags_tree,
				     hf_lmp_filter[LMPF_VAL_TE_LINK_FLAGS_FAULT_MGMT],
				     tvb, offset2, 1, l);
	      proto_tree_add_boolean(lmp_flags_tree,
				     hf_lmp_filter[LMPF_VAL_TE_LINK_FLAGS_LINK_VERIFY],
				     tvb, offset2, 1, l);
	      switch(type) {

	      case 1:
		  proto_item_append_text(ti, ": IPv4: Local %s, Remote %s",
					 tvb_ip_to_str(tvb, offset2+4),
					 tvb_ip_to_str(tvb, offset2+8));
		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_TE_LINK_LOCAL_IPV4],
				      tvb, offset2+4, 4, ENC_BIG_ENDIAN);
		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_TE_LINK_REMOTE_IPV4],
				      tvb, offset2+8, 4, ENC_BIG_ENDIAN);
		  break;

	      case 2:
		  proto_item_append_text(ti, ": IPv6: Local %s, Remote %s",
					 tvb_ip6_to_str(tvb, offset2+4),
					 tvb_ip6_to_str(tvb, offset2+8));
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+4, 16,
				      "TE-Link Local ID - IPv6: %s",
				      tvb_ip6_to_str(tvb, offset2));
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+20,16,
				      "TE-Link Remote ID - IPv6: %s",
				      tvb_ip6_to_str(tvb, offset2+4));
		  break;

	      case 3:
		  proto_item_append_text(ti, ": Unnumbered: Local %d, Remote %d",
					 tvb_get_ntohl(tvb, offset2+4),
					 tvb_get_ntohl(tvb, offset2+8));

		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_TE_LINK_LOCAL_UNNUM],
				      tvb, offset2+4, 4, ENC_BIG_ENDIAN);

		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_TE_LINK_REMOTE_UNNUM],
				      tvb, offset2+8, 4, ENC_BIG_ENDIAN);
		  break;
	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_DATA_LINK:

	      l = tvb_get_guint8(tvb, offset2);
	      ti2 = proto_tree_add_uint(lmp_object_tree,
					hf_lmp_filter[LMPF_VAL_DATA_LINK_FLAGS],
					tvb, offset2, 1, l);
	      proto_item_append_text(ti2, ": %s%s",
				     (l&0x01) ? "Interface-Type-Port " : "Interface-Type-Component-Link ",
				     (l&0x02) ? "Allocated " : "Unallocated ");

	      lmp_flags_tree = proto_item_add_subtree(ti2,
						      lmp_subtree[LMP_TREE_DATA_LINK_FLAGS]);
	      proto_tree_add_boolean(lmp_flags_tree,
				     hf_lmp_filter[LMPF_VAL_DATA_LINK_FLAGS_PORT],
				     tvb, offset2, 1, l);
	      proto_tree_add_boolean(lmp_flags_tree,
				     hf_lmp_filter[LMPF_VAL_DATA_LINK_FLAGS_ALLOCATED],
				     tvb, offset2, 1, l);
	      switch(type) {

	      case 1:
		  proto_item_append_text(ti, ": IPv4: Local %s, Remote %s",
					 tvb_ip_to_str(tvb, offset2+4),
					 tvb_ip_to_str(tvb, offset2+8));

		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_DATA_LINK_LOCAL_IPV4],
				      tvb, offset2+4, 4, ENC_BIG_ENDIAN);

		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_DATA_LINK_REMOTE_IPV4],
				      tvb, offset2+8, 4, ENC_BIG_ENDIAN);
		  l = 12;
		  break;

	      case 2:
		  proto_item_append_text(ti, ": IPv6: Local %s, Remote %s",
					 tvb_ip6_to_str(tvb, offset2+4),
					 tvb_ip6_to_str(tvb, offset2+8));
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+4, 16,
				      "Data-Link Local ID - IPv6: %s",
				      tvb_ip6_to_str(tvb, offset2));
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+20,16,
				      "Data-Link Remote ID - IPv6: %s",
				      tvb_ip6_to_str(tvb, offset2+4));
		  l = 36;
		  break;

	      case 3:
		  proto_item_append_text(ti, ": Unnumbered: Local %d, Remote %d",
					 tvb_get_ntohl(tvb, offset2+4),
					 tvb_get_ntohl(tvb, offset2+8));
		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_DATA_LINK_LOCAL_UNNUM],
				      tvb, offset2+4, 4, ENC_BIG_ENDIAN);
		  proto_tree_add_item(lmp_object_tree, hf_lmp_filter[LMPF_VAL_DATA_LINK_REMOTE_UNNUM],
				      tvb, offset2+8, 4, ENC_BIG_ENDIAN);
		  l = 12;
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }

	      while (l < obj_length - 4) {
		  mylen = tvb_get_guint8(tvb, offset2+l+1);
		  ti2 = proto_tree_add_item(lmp_object_tree,
					    hf_lmp_filter[LMPF_VAL_DATA_LINK_SUBOBJ],
					    tvb, offset2+l, mylen, ENC_NA);
		  lmp_subobj_tree = proto_item_add_subtree(ti2,
							   lmp_subtree[LMP_TREE_DATA_LINK_SUBOBJ]);
		  proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l, 1,
				      "Subobject Type: %d",
				      tvb_get_guint8(tvb, offset2+l));

		  proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l+1, 1,
				      "Subobject Length: %d", mylen);
		  switch(tvb_get_guint8(tvb, offset2+l)) {

		  case 1:

		      proto_item_set_text(ti2, "Interface Switching Capability: "
					  "Switching Cap: %s, Encoding Type: %s, "
					  "Min BW: %.3f Mbps, Max BW: %.3f Mbps",
					  rval_to_str(tvb_get_guint8(tvb, offset2+l+2),
						     gmpls_switching_type_rvals, "Unknown (%d)"),
					  rval_to_str(tvb_get_guint8(tvb, offset2+l+3),
						     gmpls_lsp_enc_rvals, "Unknown (%d)"),
					  tvb_get_ntohieee_float(tvb, offset2+l+4)*8/1000000,
					  tvb_get_ntohieee_float(tvb, offset2+l+8)*8/1000000);
		      proto_tree_add_item(lmp_subobj_tree,
					  hf_lmp_filter[LMPF_VAL_DATA_LINK_SUBOBJ_SWITCHING_TYPE],
					  tvb, offset2+l+2, 1, ENC_BIG_ENDIAN);
		      proto_tree_add_item(lmp_subobj_tree,
					  hf_lmp_filter[LMPF_VAL_DATA_LINK_SUBOBJ_LSP_ENCODING],
					  tvb, offset2+l+3, 1, ENC_BIG_ENDIAN);
		      proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l+4, 4,
					  "Minimum Reservable Bandwidth: %.3f Mbps",
					  tvb_get_ntohieee_float(tvb, offset2+l+4)*8/1000000);
		      proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l+8, 4,
					  "Maximum Reservable Bandwidth: %.3f Mbps",
					  tvb_get_ntohieee_float(tvb, offset2+l+8)*8/1000000);
		      break;

		  case 2:
		      proto_item_set_text(ti2, "Wavelength: %d",
					  tvb_get_ntohl(tvb, offset2+l+2));
		      proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l+4, 4,
					  "Wavelength: %d",
					  tvb_get_ntohl(tvb, offset2+l+4));
		      break;

		  default:
		      proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l,
					  tvb_get_guint8(tvb, offset2+l+1),
					  "Data (%d bytes)", tvb_get_guint8(tvb, offset2+l+1));
		      break;
		  }
		  if (tvb_get_guint8(tvb, offset2+l+1) < 1)
		      THROW(ReportedBoundsError);
		  l += tvb_get_guint8(tvb, offset2+l+1);
	      }

	      break;

	  case LMP_CLASS_CHANNEL_STATUS:

	      k = 0; j = 0;

	      switch(type) {

	      case 1:
	      case 3:
		  k = 8; break;

	      case 2:
		  k = 20; break;
	      }

	      if (!k)
		  break;

	      for (l=0; l<obj_length - 4; ) {

		  ti2 = proto_tree_add_text(lmp_object_tree, tvb, offset2+l, k,
					    "Interface-Id");
		  lmp_subobj_tree = proto_item_add_subtree(ti2,
							   lmp_subtree[LMP_TREE_CHANNEL_STATUS_ID]);
		  switch(type) {

		  case 1:
		      if (j < 4)
			  proto_item_append_text(ti, ": [IPv4-%s",
						 tvb_ip_to_str(tvb, offset2+l));
		      proto_item_append_text(ti2, ": IPv4 %s",
					     tvb_ip_to_str(tvb, offset2+l));
		      proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l, 4,
					  "Interface ID: IPv4: %s",
					  tvb_ip_to_str(tvb, offset2+l));
		      l += 4;
		      break;

		  case 2:
		      if (j < 4)
			  proto_item_append_text(ti, ": [IPv6-%s", tvb_ip6_to_str(tvb, offset2+l));
		      proto_item_append_text(ti2, ": IPv6 %s", tvb_ip6_to_str(tvb, offset2+l));
		      proto_tree_add_text(lmp_subobj_tree, tvb, offset2, 16, "Interface ID: IPv6: %s",
					  tvb_ip6_to_str(tvb, offset2+l));
		      l += 16;
		      break;

		  case 3:
		      if (j < 4)
			  proto_item_append_text(ti, ": [Unnum-%d",
						 tvb_get_ntohl(tvb, offset2+l));
		      proto_item_append_text(ti, ": Unnumbered %d",
					     tvb_get_ntohl(tvb, offset2+l));
		      proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l, 4,
					  "Interface ID: Unnumbered: %d",
					  tvb_get_ntohl(tvb, offset2+l));
		      l += 4;
		      break;

		  default:
		      proto_tree_add_text(lmp_object_tree, tvb, offset2+l, obj_length-4-l,
					  "Data (%d bytes)", obj_length-4-l);
		      l = obj_length - 4;
		      break;
		  }
		  if (l == obj_length - 4) break;

		  proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l, 1,
				      tvb_get_guint8(tvb, offset2+l) & 0x80 ?
				      "Link Allocated - Active Monitoring" :
				      "Link Not Allocated");
		  if (j < 4)
		      proto_item_append_text(ti, "-%s,%s], ",
					     tvb_get_guint8(tvb, offset2+l) & 0x80 ? "Act" : "NA",
					     val_to_str(tvb_get_ntohl(tvb, offset2+l) & 0x7fffffff,
							channel_status_short_str, "UNK (%u)."));
		  proto_item_append_text(ti2, ": %s, ",
					 tvb_get_guint8(tvb, offset2+l) & 0x80 ? "Active" : "Not Active");
		  proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l, 4,
				      "Channel Status: %s",
				      val_to_str(tvb_get_ntohl(tvb, offset2+l) & 0x7fffffff,
						 channel_status_str, "Unknown (%u). "));
		  proto_item_append_text(ti2, "%s", val_to_str(tvb_get_ntohl(tvb, offset2+l) & 0x7fffffff,
							 channel_status_str, "Unknown (%u). "));
		  j++;
		  l += 4;
		  if (j==4 && l < obj_length - 4)
		      proto_item_append_text(ti, " ...");
	      }
	      break;

	  case LMP_CLASS_CHANNEL_STATUS_REQUEST:
	      for (l=0; l<obj_length - 4; ) {
		  switch(type) {
		  case 1:
		      proto_tree_add_text(lmp_object_tree, tvb, offset2+l, 4,
					  "Interface ID: IPv4: %s",
					  tvb_ip_to_str(tvb, offset2+l));
		      l += 4;
		      break;

		  case 2:
		      proto_tree_add_text(lmp_object_tree, tvb, offset2+l, 16, "Interface ID: IPv6: %s",
					  tvb_ip6_to_str(tvb, offset2+l));
		      l += 16;
		      break;

		  case 3:
		      proto_tree_add_text(lmp_object_tree, tvb, offset2+l, 4,
					  "Interface ID: Unnumbered: %d",
					  tvb_get_ntohl(tvb, offset2+l));
		      l += 4;
		      break;

		  default:
		      proto_tree_add_text(lmp_object_tree, tvb, offset2+l,
					  obj_length-4-l,
					  "Data (%d bytes)", obj_length-4-l);
		      l = obj_length - 4;
		      break;
		  }
	      }
	      break;

	  case LMP_CLASS_ERROR:
	      l = tvb_get_ntohl(tvb, offset2);
	      ti2 = proto_tree_add_uint(lmp_object_tree, hf_lmp_filter[LMPF_VAL_ERROR],
					tvb, offset2, 4, l);

	      switch(type) {

	      case 1:
		  proto_item_append_text(ti, ": BEGIN_VERIFY_ERROR: %s%s%s%s",
					 (l&0x01) ? "Unsupported-Link " : "",
					 (l&0x02) ? "Unwilling" : "",
					 (l&0x04) ? "Unsupported-Transport" : "",
					 (l&0x08) ? "TE-Link-ID" : "");
		  lmp_flags_tree = proto_item_add_subtree(ti2,
							  lmp_subtree[LMP_TREE_ERROR_FLAGS]);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_VERIFY_UNSUPPORTED_LINK],
					 tvb, offset, 4, l);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_VERIFY_UNWILLING],
					 tvb, offset, 4, l);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_VERIFY_TRANSPORT],
					 tvb, offset, 4, l);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_VERIFY_TE_LINK_ID],
					 tvb, offset, 4, l);
		  break;

		case 2:
		    proto_item_append_text(ti, ": LINK_SUMMARY_ERROR: %s%s%s%s%s%s",
					   (l&0x01) ? "Unacceptable-Params " : "",
					   (l&0x02) ? "Renegotiate" : "",
					   (l&0x04) ? "Bad-TE-Link" : "",
					   (l&0x08) ? "Bad-Data-Link" : "",
					   (l&0x10) ? "Bad-TE-Link-CType" : "",
					   (l&0x20) ? "Bad-Data-Link-CType" : "");
		    lmp_flags_tree = proto_item_add_subtree(ti2,
							    lmp_subtree[LMP_TREE_ERROR_FLAGS]);
		    proto_tree_add_boolean(lmp_flags_tree,
					   hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_BAD_PARAMETERS],
					   tvb, offset, 4, l);
		    proto_tree_add_boolean(lmp_flags_tree,
					   hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_RENEGOTIATE],
					   tvb, offset, 4, l);
		    proto_tree_add_boolean(lmp_flags_tree,
					   hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_BAD_TE_LINK],
					   tvb, offset, 4, l);
		    proto_tree_add_boolean(lmp_flags_tree,
					   hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_BAD_DATA_LINK],
					   tvb, offset, 4, l);
		    proto_tree_add_boolean(lmp_flags_tree,
					   hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_UNKNOWN_TEL_CTYPE],
					   tvb, offset, 4, l);
		    proto_tree_add_boolean(lmp_flags_tree,
					   hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_UNKNOWN_DL_CTYPE],
					   tvb, offset, 4, l);
		    break;

	      case 3:
		  proto_item_append_text(ti, ": TRACE_ERROR: %s%s%s",
					 (l&0x01) ? "Unsupported Trace Type " : "",
					 (l&0x02) ? "Invalid Trace Message" : "",
					 (l&0x10) ? "Unknown Object C-Type" : "");
		  lmp_flags_tree = proto_item_add_subtree(ti2,
							  lmp_subtree[LMP_TREE_ERROR_FLAGS]);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_TRACE_UNSUPPORTED_TYPE],
					 tvb, offset, 4, l);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_TRACE_INVALID_MSG],
					 tvb, offset, 4, l);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_TRACE_UNKNOWN_CTYPE],
					 tvb, offset, 4, l);
		  break;

	      case 4:
		  proto_item_append_text(ti, ": LAD_ERROR: %s%s%s%s%s",
					 (l&0x01) ? "Domain Routing Area ID mismatch" : "",
					 (l&0x02) ? "TCP ID mismatch" : "",
					 (l&0x04) ? "DA DCN mismatch" : "",
					 (l&0x08) ? "Capability mismatch" : "",
					 (l&0x10) ? "Unknown Object C-Type" : "");
		  lmp_flags_tree = proto_item_add_subtree(ti2,
							  lmp_subtree[LMP_TREE_ERROR_FLAGS]);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_LAD_AREA_ID_MISMATCH],
					 tvb, offset, 4, l);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_LAD_TCP_ID_MISMATCH],
					 tvb, offset, 4, l);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_LAD_DA_DCN_MISMATCH],
					 tvb, offset, 4, l);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_LAD_CAPABILITY_MISMATCH],
					 tvb, offset, 4, l);
		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_ERROR_LAD_UNKNOWN_CTYPE],
					 tvb, offset, 4, l);
		  break;

	      default:
		  proto_item_append_text(ti, ": UNKNOWN_ERROR (%d): 0x%04x", type, l);
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

          case LMP_CLASS_TRACE:
	      switch (type) {
	      case 1:
	          l = tvb_get_ntohs(tvb, offset2);
	          proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_TRACE_LOCAL_TYPE],
				      tvb, offset2, 2, l);
		  proto_item_append_text(lmp_object_tree, ": %s",
					 val_to_str(l, lmp_trace_type_str, "Unknown (%d)"));

	          l = tvb_get_ntohs(tvb, offset2+2);
	          proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_TRACE_LOCAL_LEN],
				      tvb, offset2+2, 2, l);
		  if (l && l <= obj_length - 8) {
		    proto_item_append_text(lmp_object_tree, " = %s",
					   tvb_format_text(tvb, offset2+4, l));
		    proto_tree_add_string(lmp_object_tree,
					  hf_lmp_filter[LMPF_VAL_TRACE_LOCAL_MSG],
					  tvb, offset2+4, l, tvb_format_text(tvb,
									     offset2+4,l));
		  }
		  else
		    proto_tree_add_text(lmp_object_tree, tvb, offset2+4, 1,
					"[Invalid Trace Length]");
		  break;

	      case 2:
	          l = tvb_get_ntohs(tvb, offset2);
	          proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_TRACE_REMOTE_TYPE],
				      tvb, offset2, 2, l);
		  proto_item_append_text(lmp_object_tree, ": %s",
					 val_to_str(l, lmp_trace_type_str, "Unknown (%d)"));

	          l = tvb_get_ntohs(tvb, offset2+2);
	          proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_TRACE_REMOTE_LEN],
				      tvb, offset2+2, 2, l);
		  proto_item_append_text(lmp_object_tree, " = %s",
			                 tvb_format_text(tvb, offset2+4, l));
	          proto_tree_add_string(lmp_object_tree,
				        hf_lmp_filter[LMPF_VAL_TRACE_REMOTE_MSG],
				        tvb, offset2+4, l, tvb_format_text(tvb, offset2+4,l));
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;

	      }
	      break;

          case LMP_CLASS_TRACE_REQ:
	      switch (type) {
	      case 1:
	          l = tvb_get_ntohs(tvb, offset2);
	          proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_TRACE_REQ_TYPE],
				      tvb, offset2, 2, l);
		  proto_item_append_text(lmp_object_tree, ": %s",
					 val_to_str(l, lmp_trace_type_str, "Unknown (%d)"));
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;

	      }
	      break;

	  case LMP_CLASS_SERVICE_CONFIG:

	      /* Support for the ServiceConfig object defined in the UNI 1.0 spec */
	      switch (type) {

	      case 1:
		  /* Supported Signaling Protocols Object */

		  /* Signaling Protocols */
		  l = tvb_get_guint8(tvb, offset2);

		  ti2 = proto_tree_add_uint(lmp_object_tree,
					    hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_SP_FLAGS],
					    tvb, offset2, 1, l);
		  proto_item_append_text(ti2, ": %s %s",
					 (l & 0x01) ? "RSVP-based UNI signaling supported " : "",
					 (l & 0x02) ? "LDP-based UNI signaling supported " : "");

		  lmp_flags_tree = proto_item_add_subtree(ti2,
							  lmp_subtree[LMP_TREE_SERVICE_CONFIG_SP_FLAGS]);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_SP_FLAGS_RSVP],
					 tvb, offset2, 1, l);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_SP_FLAGS_LDP],
					 tvb, offset2, 1, l);

		  /* UNI version */
		  proto_tree_add_text(lmp_object_tree, tvb, offset2+1, 1,
				      "UNI Version: %u",
				      tvb_get_guint8(tvb, offset2+1));
		  break;

	      case 2:
		  /* Client Port-Level Service Attributes Object */

		  /* Link Type */
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, 1,
				      "Link Type: %s",
				      val_to_str(tvb_get_guint8(tvb, offset2),
						 service_attribute_link_type_str,
						 "UNK (%u). "));

		  proto_item_append_text(lmp_object_tree, "%s",
					 val_to_str(tvb_get_guint8(tvb, offset2),
						    service_attribute_link_type_str,
						    "Unknown (%u). "));

		  l = tvb_get_guint8(tvb, offset2+1);
		  /* Signal type for SDH */
		  if (l == LMP_CLASS_SERVICE_CONFIG_CPSA_SIGNAL_TYPES_SDH) {
		      /* Signal types for an SDH link */
		      proto_tree_add_text(lmp_object_tree, tvb, offset2+1, 1,
					  "Signal Types: %s",
					  val_to_str(tvb_get_guint8(tvb, offset2+1),
						     service_attribute_signal_types_sdh_str,
						     "Unknown (%u).  "));

		      proto_item_append_text(lmp_object_tree, "%s",
					     val_to_str(tvb_get_guint8(tvb, offset2+1),
							service_attribute_signal_types_sdh_str,
							"Unknown (%u).   "));
		  }

		  if (l == LMP_CLASS_SERVICE_CONFIG_CPSA_SIGNAL_TYPES_SONET) {
		      /* Signal types for a SONET link */
		      proto_tree_add_text(lmp_object_tree, tvb, offset2+1, 1,
					  "Signal Types: %s",
					  val_to_str(tvb_get_guint8(tvb, offset2+1),
						     service_attribute_signal_types_sonet_str,
						     "Unknown (%u).  "));

		      proto_item_append_text(lmp_object_tree, "%s",
					     val_to_str(tvb_get_guint8(tvb, offset2+1),
							service_attribute_signal_types_sonet_str,
							"Unknown (%u).   "));
		  }

		  /* TP Transparency */
		  l = tvb_get_guint8(tvb, offset2+2);
		  ti2 = proto_tree_add_uint(lmp_object_tree,
					    hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS],
					    tvb, offset2+2, 1, l);

		  proto_item_append_text(ti2, ": %s%s%s",
					 (l & 0x01) ? "Path/VC Overhead Transparency " : "",
					 (l & 0x02) ? "Line/MS Overhead Transparency " : "",
					 (l & 0x04) ? "Section/RS Overhead Transparency " : "");

		  lmp_flags_tree = proto_item_add_subtree(ti2,
							  lmp_subtree[LMP_TREE_SERVICE_CONFIG_CPSA_TP_FLAGS]);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS_PATH_OVERHEAD],
					 tvb, offset2+2, 1, l);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS_LINE_OVERHEAD],
					 tvb, offset2+2, 1, l);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS_SECTION_OVERHEAD],
					 tvb, offset2+2, 1, l);

		  /* Contiguous Concatentation Types */
		  l = tvb_get_guint8(tvb, offset2+3);
		  ti2 = proto_tree_add_uint(lmp_object_tree,
					    hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_CCT_FLAGS],
					    tvb, offset2+3, 1, l);

		  lmp_flags_tree = proto_item_add_subtree(ti2,
							  lmp_subtree[LMP_TREE_SERVICE_CONFIG_CPSA_CCT_FLAGS]);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_CCT_FLAGS_CC_SUPPORTED],
					 tvb, offset2+3, 1, l);

		  /* Min and Max NCC */
		  proto_item_append_text(ti, ": Minimum NCC: %d, Maximum NCC: %d",
					 tvb_get_ntohs(tvb, offset2+4),
					 tvb_get_ntohs(tvb, offset2+6));

		  proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_MIN_NCC],
				      tvb, offset2+4, 2,
				      tvb_get_ntohs(tvb, offset2+4));

		  proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_MAX_NCC],
				      tvb, offset2+6, 2,
				      tvb_get_ntohs(tvb, offset2+6));

		  /* Min and Max NVC */
		  proto_item_append_text(ti, ": Minimum NVC: %d, Maximum NVC: %d",
					 tvb_get_ntohs(tvb, offset2+8),
					 tvb_get_ntohs(tvb, offset2+10));

		  proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_MIN_NVC],
				      tvb, offset2+8, 2,
				      tvb_get_ntohs(tvb, offset2+8));

		  proto_tree_add_uint(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_MAX_NVC],
				      tvb, offset2+10, 2,
				      tvb_get_ntohs(tvb, offset2+10));

		  /* Local interface ID */
		  proto_item_append_text(ti, ": Local Interface ID %s",
					 tvb_ip_to_str(tvb, offset2+12));

		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_INTERFACE_ID],
				      tvb, offset2+12, 4, ENC_BIG_ENDIAN);

		  break;

	      case 3:

		  /* Network Transparency Support and TCM Monitoring Object */

		  /* Transparency */
		  l = tvb_get_ntohl(tvb, offset2);
		  ti2 = proto_tree_add_uint(lmp_object_tree,
					    hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS],
					    tvb, offset2, 4, l);

		  proto_item_append_text(ti2, ": %s %s",
					 (l & 0x01) ? "Standard SOH/RSOH transparency supported " : "",
					 (l & 0x02) ? "Standard LOH/MSOH transparency supported " : "");

		  lmp_flags_tree = proto_item_add_subtree(ti2,
							  lmp_subtree[LMP_TREE_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS]);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS_SOH],
					 tvb, offset2, 4, l);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS_LOH],
					 tvb, offset2, 4, l);

		  /* TCM Monitoring */
		  l = tvb_get_guint8(tvb, offset2+7);

		  ti2 = proto_tree_add_uint(lmp_object_tree,
					    hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_TCM_FLAGS],
					    tvb, offset2+7, 1, l);

		  proto_item_append_text(ti2, ": %s",
					 (l & 0x01) ? "Transparent Support of TCM available " :  "");

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_TCM_FLAGS_TCM_SUPPORTED],
					 tvb, offset2+7, 1, l);

		  break;

	      case 4:

		  /* Network Diversity Object */
		  l = tvb_get_guint8(tvb,offset2+3);

		  ti2 = proto_tree_add_uint(lmp_object_tree,
					    hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS],
					    tvb, offset2+3, 1, l);

		  proto_item_append_text(ti2, ": %s%s%s",
					 (l & 0x01) ? "Node Diversity is supported " :  "",
					 (l & 0x02) ? "Link Diversity is supported " : "",
					 (l & 0x04) ? "SRLG Diversity is supported " : "");


		  lmp_flags_tree = proto_item_add_subtree(ti2,
							  lmp_subtree[LMP_TREE_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS]);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS_NODE],
					 tvb, offset2+3, 1, l);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS_LINK],
					 tvb, offset2+3, 1, l);

		  proto_tree_add_boolean(lmp_flags_tree,
					 hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS_SRLG],
					 tvb, offset2+3, 1, l);
		  break;

	      default:
		  /* Unknown type in Service Config object */
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;

	  case LMP_CLASS_DA_DCN_ADDRESS:
	      switch(type) {

	      case 1:
		  l = LMPF_VAL_LOCAL_DA_DCN_ADDR;
		  proto_item_append_text(ti, ": %s", tvb_ip_to_str(tvb, offset2));
		  proto_tree_add_item(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, ENC_BIG_ENDIAN);
		  break;

	      case 2:
		  l = LMPF_VAL_REMOTE_DA_DCN_ADDR;
		  proto_item_append_text(ti, ": %s", tvb_ip_to_str(tvb, offset2));
		  proto_tree_add_item(lmp_object_tree, hf_lmp_filter[l], tvb,
				      offset2, 4, ENC_BIG_ENDIAN);
		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;


	  case LMP_CLASS_LOCAL_LAD_INFO:
	      switch(type) {
	        case 1:
		  proto_item_append_text(ti, ": IPv4");
		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_NODE_ID],
				      tvb, offset2, 4, ENC_BIG_ENDIAN);
		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_AREA_ID],
				      tvb, offset2+4, 4, ENC_BIG_ENDIAN);
		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_TE_LINK_ID],
				      tvb, offset2+8, 4, ENC_BIG_ENDIAN);
		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_COMPONENT_ID],
				      tvb, offset2+12, 4, ENC_BIG_ENDIAN);
		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_SC_PC_ID],
				      tvb, offset2+16, 4, ENC_BIG_ENDIAN);
		  proto_tree_add_item(lmp_object_tree,
				      hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_SC_PC_ADDR],
				      tvb, offset2+20, 4, ENC_BIG_ENDIAN);
		  l = 24;
		  while (l < obj_length - 4) {
		    mylen = tvb_get_guint8(tvb, offset2+l+1);
		    ti2 = proto_tree_add_item(lmp_object_tree,
					    hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ],
					    tvb, offset2+l, mylen, ENC_NA);
		    lmp_subobj_tree = proto_item_add_subtree(ti2,
							     lmp_subtree[LMP_TREE_LAD_INFO_SUBOBJ]);
		    proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l, 1,
					"Subobject Type: %d", tvb_get_guint8(tvb, offset2+l));

		    if (mylen == 0 || l + mylen > obj_length - 4) {
	    		proto_tree_add_text(lmp_object_tree, tvb, offset2+l+1, 1,
					    "Subobject Length: %d (Invalid)", mylen);
			break;
		    }
		    else
			proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l+1, 1,
					    "Subobject Length: %d", mylen);

		    switch(tvb_get_guint8(tvb, offset2+l)) {

		      case 250:
			proto_item_set_text(ti2, "Primary Routing Controller: "
					    "Area ID: %s, RC PC ID: %s, "
					    "RC PC Addr: %s",
					    tvb_ip_to_str(tvb, offset2+l+4),
					    tvb_ip_to_str(tvb, offset2+l+8),
					    tvb_ip_to_str(tvb, offset2+l+12));
			proto_tree_add_item(lmp_subobj_tree,
					    hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_PRI_AREA_ID],
					    tvb, offset2+l+4, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(lmp_subobj_tree,
					    hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_PRI_RC_PC_ID],
					    tvb, offset2+l+8, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(lmp_subobj_tree,
					    hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_PRI_RC_PC_ADDR],
					    tvb, offset2+l+12, 4, ENC_BIG_ENDIAN);
			break;

		      case 251:
			proto_item_set_text(ti2, "Secondary Routing Controller: "
					    "Area ID: %s, RC PC ID: %s, "
					    "RC PC Addr: %s",
					    tvb_ip_to_str(tvb, offset2+l+4),
					    tvb_ip_to_str(tvb, offset2+l+8),
					    tvb_ip_to_str(tvb, offset2+l+12));
			proto_tree_add_item(lmp_subobj_tree,
					    hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_SEC_AREA_ID],
					    tvb, offset2+l+4, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(lmp_subobj_tree,
					    hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_SEC_RC_PC_ID],
					    tvb, offset2+l+8, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(lmp_subobj_tree,
					    hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_SEC_RC_PC_ADDR],
					    tvb, offset2+l+12, 4, ENC_BIG_ENDIAN);
			break;

		      case 252:
			proto_item_set_text(ti2, "SONET/SDH Layer Capability: "
					    "Switching Cap: %s, Encoding Type: %s",
					    rval_to_str(tvb_get_guint8(tvb, offset2+l+4),
						       gmpls_switching_type_rvals, "Unknown (%d)"),
					    rval_to_str(tvb_get_guint8(tvb, offset2+l+5),
						       gmpls_lsp_enc_rvals, "Unknown (%d)"));
			proto_tree_add_item(lmp_subobj_tree,
					    hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_SWITCHING_TYPE],
					    tvb, offset2+l+4, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(lmp_subobj_tree,
					    hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_LSP_ENCODING],
					    tvb, offset2+l+5, 1, ENC_BIG_ENDIAN);

			for (j = 0; j < (mylen - 8) / 4; j++) {
			  proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l+8+(j*4), 4,
					      "%s: %d free timeslots",
                                              val_to_str_ext(tvb_get_guint8(tvb, offset2+l+8+(j*4)),
                                                         &gmpls_sonet_signal_type_str_ext,
                                                         "Unknown Signal Type (%d)"),
					      tvb_get_ntoh24(tvb, offset2+l+9+(j*4)));
		    	}
			break;

		      default:
		        proto_tree_add_text(lmp_subobj_tree, tvb, offset2+l,
					    tvb_get_guint8(tvb, offset2+l+1),
					    "Data (%d bytes)", tvb_get_guint8(tvb,
									      offset2+l+1));
		        break;
		  }
		  if (tvb_get_guint8(tvb, offset2+l+1) < 1)
		      THROW(ReportedBoundsError);
		  l += tvb_get_guint8(tvb, offset2+l+1);
	      }

		  break;

	      default:
		  proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				      "Data (%d bytes)", mylen);
		  break;
	      }
	      break;



	  default:
	      proto_tree_add_text(lmp_object_tree, tvb, offset2, mylen,
				  "Data (%d bytes)", mylen);
	      break;
	  }

	  if (obj_length < 1)
	      THROW(ReportedBoundsError);
	  offset += obj_length;
	  len += obj_length;

	} /* while */
    } /* tree */

    return tvb_length(tvb);
}
static void
lmp_prefs_applied (void)
{
    if (lmp_udp_port != lmp_udp_port_config) {
	dissector_delete_uint("udp.port", lmp_udp_port, lmp_handle);
	lmp_udp_port = lmp_udp_port_config;
	dissector_add_uint("udp.port", lmp_udp_port, lmp_handle);
    }
}

static void
register_lmp_prefs (void)
{
    module_t *lmp_module;

    lmp_module = prefs_register_protocol(proto_lmp, lmp_prefs_applied);

    prefs_register_uint_preference(
	lmp_module, "udp_port", "LMP UDP Port",
	"UDP port number to use for LMP", 10, &lmp_udp_port_config);
    prefs_register_bool_preference(
	lmp_module, "checksum", "LMP checksum field",
	"Whether LMP contains a checksum which can be checked", &lmp_checksum_config);
    prefs_register_obsolete_preference(
        lmp_module, "version");
}

void
proto_register_lmp(void)
{
    static gint *ett[NUM_LMP_SUBTREES];
    int i;

	static hf_register_info lmpf_info[] = {

	   /* Message type number */
	   {&hf_lmp_filter[LMPF_MSG],
		{ "Message Type", "lmp.msg", FT_UINT8, BASE_DEC, VALS(message_type_vals), 0x0,
			NULL, HFILL }},

	   /* Message type shorthands */
	   {&hf_lmp_filter[LMPF_MSG_CONFIG],
		{ "Config Message", "lmp.msg.config", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_CONFIG_ACK],
		{ "ConfigAck Message", "lmp.msg.configack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_CONFIG_NACK],
		{ "ConfigNack Message", "lmp.msg.confignack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_HELLO],
		{ "HELLO Message", "lmp.msg.hello", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_BEGIN_VERIFY],
		{ "BeginVerify Message", "lmp.msg.beginverify", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_BEGIN_VERIFY_ACK],
		{ "BeginVerifyAck Message", "lmp.msg.beginverifyack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_BEGIN_VERIFY_NACK],
		{ "BeginVerifyNack Message", "lmp.msg.beginverifynack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_END_VERIFY],
		{ "EndVerify Message", "lmp.msg.endverify", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_END_VERIFY_ACK],
		{ "EndVerifyAck Message", "lmp.msg.endverifyack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TEST],
		{ "Test Message", "lmp.msg.test", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TEST_STATUS_SUCCESS],
		{ "TestStatusSuccess Message", "lmp.msg.teststatussuccess", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TEST_STATUS_FAILURE],
		{ "TestStatusFailure Message", "lmp.msg.teststatusfailure", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TEST_STATUS_ACK],
		{ "TestStatusAck Message", "lmp.msg.teststatusack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_LINK_SUMMARY],
		{ "LinkSummary Message", "lmp.msg.linksummary", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_LINK_SUMMARY_ACK],
		{ "LinkSummaryAck Message", "lmp.msg.linksummaryack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_LINK_SUMMARY_NACK],
		{ "LinkSummaryNack Message", "lmp.msg.linksummarynack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_CHANNEL_STATUS],
		{ "ChannelStatus Message", "lmp.msg.channelstatus", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_CHANNEL_STATUS_ACK],
		{ "ChannelStatusAck Message", "lmp.msg.channelstatusack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_CHANNEL_STATUS_REQ],
		{ "ChannelStatusRequest Message", "lmp.msg.channelstatusrequest", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_CHANNEL_STATUS_RESP],
		{ "ChannelStatusResponse Message", "lmp.msg.channelstatusresponse", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TRACE_MONITOR],
		{ "TraceMonitor Message", "lmp.msg.tracemonitor", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TRACE_MONITOR_ACK],
		{ "TraceMonitorAck Message", "lmp.msg.tracemonitorack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TRACE_MONITOR_NACK],
		{ "TraceMonitorNack Message", "lmp.msg.tracemonitornack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TRACE_MISMATCH],
		{ "TraceMismatch Message", "lmp.msg.tracemismatch", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TRACE_MISMATCH_ACK],
		{ "TraceMismatchAck Message", "lmp.msg.tracemismatchack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TRACE_REQUEST],
		{ "TraceRequest Message", "lmp.msg.tracerequest", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TRACE_REPORT],
		{ "TraceReport Message", "lmp.msg.tracereport", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_TRACE_REQUEST_NACK],
		{ "TraceRequestNack Message", "lmp.msg.tracerequestnack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_INSERT_TRACE],
		{ "InsertTrace Message", "lmp.msg.inserttrace", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_INSERT_TRACE_ACK],
		{ "InsertTraceAck Message", "lmp.msg.inserttraceack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_INSERT_TRACE_NACK],
		{ "InsertTraceNack Message", "lmp.msg.inserttracenack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_SERVICE_CONFIG],
		{ "ServiceConfig Message", "lmp.msg.serviceconfig", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_SERVICE_CONFIG_ACK],
		{ "ServiceConfigAck Message", "lmp.msg.serviceconfigack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_SERVICE_CONFIG_NACK],
		{ "ServiceConfigNack Message", "lmp.msg.serviceconfignack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_DISCOVERY_RESP],
		{ "DiscoveryResponse Message", "lmp.msg.discoveryresp", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_DISCOVERY_RESP_ACK],
		{ "DiscoveryResponseAck Message", "lmp.msg.discoveryrespack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_MSG_DISCOVERY_RESP_NACK],
		{ "DiscoveryResponseNack Message", "lmp.msg.discoveryrespnack", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   /* LMP Message Header Fields ------------------- */

	   {&hf_lmp_filter[LMPF_HDR_FLAGS],
		{ "LMP Header - Flags", "lmp.hdr.flags", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_HDR_FLAGS_CC_DOWN],
		{ "ControlChannelDown", "lmp.hdr.ccdown", FT_BOOLEAN, 8, NULL, 0x01,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_HDR_FLAGS_REBOOT],
		{ "Reboot", "lmp.hdr.reboot", FT_BOOLEAN, 8, NULL, 0x02,
			NULL, HFILL }},

	   /* LMP object class filters ------------------------------- */

	   {&hf_lmp_filter[LMPF_OBJECT],
		{ "LOCAL_CCID", "lmp.object", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_CLASS_CCID],
		{ "CCID", "lmp.obj.ccid", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_CLASS_NODE_ID],
		{ "NODE_ID", "lmp.obj.Nodeid", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_CLASS_LINK_ID],
		{ "LINK_ID", "lmp.obj.linkid", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_CLASS_INTERFACE_ID],
		{ "INTERFACE_ID", "lmp.obj.interfaceid", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_CLASS_MESSAGE_ID],
		{ "MESSAGE_ID", "lmp.obj.messageid", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_CLASS_CONFIG],
		{ "CONFIG", "lmp.obj.config", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_CLASS_HELLO],
		{ "HELLO", "lmp.obj.hello", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_CLASS_BEGIN_VERIFY],
		{ "BEGIN_VERIFY", "lmp.obj.begin_verify", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_CLASS_BEGIN_VERIFY_ACK],
		{ "BEGIN_VERIFY_ACK", "lmp.obj.begin_verify_ack", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_CLASS_VERIFY_ID],
		{ "VERIFY_ID", "lmp.obj.verifyid", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_CLASS_TE_LINK],
		{ "TE_LINK", "lmp.obj.te_link", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_CLASS_DATA_LINK],
		{ "DATA_LINK", "lmp.obj.data_link", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_CLASS_CHANNEL_STATUS],
		{ "CHANNEL_STATUS", "lmp.obj.channel_status", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_CLASS_CHANNEL_STATUS_REQUEST],
		{ "CHANNEL_STATUS_REQUEST", "lmp.obj.channel_status_request", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_CLASS_ERROR],
		{ "ERROR", "lmp.obj.error", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_CLASS_TRACE],
		{ "TRACE", "lmp.obj.trace", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_CLASS_TRACE_REQ],
		{ "TRACE REQ", "lmp.obj.trace_req", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_CLASS_SERVICE_CONFIG],
		{ "SERVICE_CONFIG", "lmp.obj.serviceconfig", FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_CLASS_DA_DCN_ADDRESS],
		{ "DA_DCN_ADDRESS", "lmp.obj.dadcnaddr", FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_CLASS_LOCAL_LAD_INFO],
		{ "LOCAL_LAD_INFO", "lmp.obj.localladinfo", FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},

	   /* Other LMP Value Filters ------------------------------ */

	   {&hf_lmp_filter[LMPF_VAL_CTYPE],
		{ "Object C-Type", "lmp.obj.ctype", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_LOCAL_CCID],
		{ "Local CCID Value", "lmp.local_ccid", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_REMOTE_CCID],
		{ "Remote CCID Value", "lmp.remote_ccid", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_LOCAL_NODE_ID],
		{ "Local Node ID Value", "lmp.local_nodeid", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_REMOTE_NODE_ID],
		{ "Remote Node ID Value", "lmp.remote_nodeid", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_LOCAL_LINK_ID_IPV4],
		{ "Local Link ID - IPv4", "lmp.local_linkid_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LOCAL_LINK_ID_UNNUM],
		{ "Local Link ID - Unnumbered", "lmp.local_linkid_unnum", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_REMOTE_LINK_ID_IPV4],
		{ "Remote Link ID - IPv4", "lmp.remote_linkid_ipv4", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_REMOTE_LINK_ID_UNNUM],
		{ "Remote Link ID - Unnumbered", "lmp.remote_linkid_unnum", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_LOCAL_INTERFACE_ID_IPV4],
		{ "Local Interface ID - IPv4", "lmp.local_interfaceid_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LOCAL_INTERFACE_ID_UNNUM],
		{ "Local Interface ID - Unnumbered", "lmp.local_interfaceid_unnum", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_REMOTE_INTERFACE_ID_IPV4],
		{ "Remote Interface ID - IPv4", "lmp.remote_interfaceid_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_REMOTE_INTERFACE_ID_UNNUM],
		{ "Remote Interface ID - Unnumbered", "lmp.remote_interfaceid_unnum", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_MESSAGE_ID],
		{ "Message-ID Value", "lmp.messageid", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_MESSAGE_ID_ACK],
		{ "Message-ID Ack Value", "lmp.messageid_ack", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_CONFIG_HELLO],
		{ "HelloInterval", "lmp.hellointerval", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_CONFIG_HELLO_DEAD],
		{ "HelloDeadInterval", "lmp.hellodeadinterval", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_HELLO_TXSEQ],
		{ "TxSeqNum", "lmp.txseqnum", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_HELLO_RXSEQ],
		{ "RxSeqNum", "lmp.rxseqnum", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_BEGIN_VERIFY_FLAGS],
		{ "Flags", "lmp.begin_verify.flags", FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_BEGIN_VERIFY_FLAGS_ALL_LINKS],
		{ "Verify All Links", "lmp.begin_verify.all_links",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_BEGIN_VERIFY_FLAGS_LINK_TYPE],
		{ "Data Link Type", "lmp.begin_verify.link_type",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_BEGIN_VERIFY_ENCTYPE],
		{ "Encoding Type", "lmp.begin_verify.enctype",
		  FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_lsp_enc_rvals), 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_VERIFY_ID],
		{ "Verify-ID", "lmp.verifyid", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_TE_LINK_FLAGS],
		{ "TE-Link Flags", "lmp.te_link_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TE_LINK_FLAGS_FAULT_MGMT],
		{ "Fault Management Supported", "lmp.te_link.fault_mgmt",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TE_LINK_FLAGS_LINK_VERIFY],
		{ "Link Verification Supported", "lmp.te_link.link_verify",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TE_LINK_LOCAL_IPV4],
		{ "TE-Link Local ID - IPv4", "lmp.te_link.local_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TE_LINK_LOCAL_UNNUM],
		{ "TE-Link Local ID - Unnumbered", "lmp.te_link.local_unnum", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TE_LINK_REMOTE_IPV4],
		{ "TE-Link Remote ID - IPv4", "lmp.te_link.remote_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TE_LINK_REMOTE_UNNUM],
		{ "TE-Link Remote ID - Unnumbered", "lmp.te_link.remote_unnum", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_DATA_LINK_FLAGS],
		{ "Data-Link Flags", "lmp.data_link_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_DATA_LINK_FLAGS_PORT],
		{ "Data-Link is Individual Port", "lmp.data_link.port",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_DATA_LINK_FLAGS_ALLOCATED],
		{ "Data-Link is Allocated", "lmp.data_link.link_verify",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_DATA_LINK_LOCAL_IPV4],
		{ "Data-Link Local ID - IPv4", "lmp.data_link.local_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_DATA_LINK_LOCAL_UNNUM],
		{ "Data-Link Local ID - Unnumbered", "lmp.data_link.local_unnum", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_DATA_LINK_REMOTE_IPV4],
		{ "Data-Link Remote ID - IPv4", "lmp.data_link.remote_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_DATA_LINK_REMOTE_UNNUM],
		{ "Data-Link Remote ID - Unnumbered", "lmp.data_link.remote_unnum", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_DATA_LINK_SUBOBJ],
		{ "Subobject", "lmp.data_link_subobj", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_DATA_LINK_SUBOBJ_SWITCHING_TYPE],
		{ "Interface Switching Capability", "lmp.data_link_switching", FT_UINT8, BASE_DEC|BASE_RANGE_STRING,
		  RVALS(gmpls_switching_type_rvals), 0x0, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_DATA_LINK_SUBOBJ_LSP_ENCODING],
		{ "LSP Encoding Type", "lmp.data_link_encoding", FT_UINT8, BASE_DEC|BASE_RANGE_STRING,
		  RVALS(gmpls_lsp_enc_rvals), 0x0, NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_ERROR],
		{ "Error Code", "lmp.error", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_ERROR_VERIFY_UNSUPPORTED_LINK],
		{ "Verification - Unsupported for this TE-Link", "lmp.error.verify_unsupported_link",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_VERIFY_UNWILLING],
		{ "Verification - Unwilling to Verify at this time", "lmp.error.verify_unwilling",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_VERIFY_TRANSPORT],
		{ "Verification - Transport Unsupported", "lmp.error.verify_unsupported_transport",
		  FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_VERIFY_TE_LINK_ID],
		{ "Verification - TE Link ID Configuration Error", "lmp.error.verify_te_link_id",
		  FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_ERROR_VERIFY_UNKNOWN_CTYPE],
		{ "Verification - Unknown Object C-Type", "lmp.error.verify_unknown_ctype",
		  FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_BAD_PARAMETERS],
		{ "Summary - Unacceptable non-negotiable parameters", "lmp.error.summary_bad_params",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_RENEGOTIATE],
		{ "Summary - Renegotiate Parametere", "lmp.error.summary_renegotiate",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_BAD_TE_LINK],
		{ "Summary - Bad TE Link Object", "lmp.error.summary_bad_te_link",
		  FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_BAD_DATA_LINK],
		{ "Summary - Bad Data Link Object", "lmp.error.summary_bad_data_link",
		  FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_UNKNOWN_TEL_CTYPE],
		{ "Summary - Bad TE Link C-Type", "lmp.error.summary_unknown_tel_ctype",
		  FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_UNKNOWN_DL_CTYPE],
		{ "Summary - Bad Data Link C-Type", "lmp.error.summary_unknown_dl_ctype",
		  FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_SUMMARY_BAD_REMOTE_LINK_ID],
		{ "Summary - Bad Remote Link ID", "lmp.error.summary_bad_remote_link_id",
		  FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_CONFIG_BAD_PARAMETERS],
		{ "Config - Unacceptable non-negotiable parameters", "lmp.error.config_bad_params",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_CONFIG_RENEGOTIATE],
		{ "Config - Renegotiate Parameter", "lmp.error.config_renegotiate",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_CONFIG_BAD_CCID],
		{ "Config - Bad CC ID", "lmp.error.config_bad_ccid",
		  FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_TRACE_UNSUPPORTED_TYPE],
		{ "Trace - Unsupported trace type", "lmp.error.trace_unsupported_type",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_TRACE_INVALID_MSG],
		{ "Trace - Invalid Trace Message", "lmp.error.trace_invalid_msg",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_TRACE_UNKNOWN_CTYPE],
		{ "Trace - Unknown Object C-Type", "lmp.error.trace_unknown_ctype",
		  FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_LAD_AREA_ID_MISMATCH],
		{ "LAD - Domain Routing Area ID Mismatch detected", "lmp.error.lad_area_id_mismatch",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_LAD_TCP_ID_MISMATCH],
		{ "LAD - TCP ID Mismatch detected", "lmp.error.lad_tcp_id_mismatch",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_LAD_DA_DCN_MISMATCH],
		{ "LAD - DA DCN Mismatch detected", "lmp.error.lad_da_dcn_mismatch",
		  FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_LAD_CAPABILITY_MISMATCH],
		{ "LAD - Capability Mismatch detected", "lmp.error.lad_capability_mismatch",
		  FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_ERROR_LAD_UNKNOWN_CTYPE],
		{ "LAD - Unknown Object C-Type", "lmp.error.lad_unknown_ctype",
		  FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_TRACE_LOCAL_TYPE],
		{ "Local Trace Type", "lmp.trace.local_type", FT_UINT16, BASE_DEC,
		  VALS(lmp_trace_type_str), 0x0, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TRACE_LOCAL_LEN],
		{ "Local Trace Length", "lmp.trace.local_length", FT_UINT16, BASE_DEC,
		  NULL, 0x0, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TRACE_LOCAL_MSG],
		{ "Local Trace Message", "lmp.trace.local_msg", FT_STRING, BASE_NONE,
		  NULL, 0x0, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TRACE_REMOTE_TYPE],
		{ "Remote Trace Type", "lmp.trace.remote_type", FT_UINT16, BASE_DEC,
		  VALS(lmp_trace_type_str), 0x0, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TRACE_REMOTE_LEN],
		{ "Remote Trace Length", "lmp.trace.remote_length", FT_UINT16, BASE_DEC,
		  NULL, 0x0, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_TRACE_REMOTE_MSG],
		{ "Remote Trace Message", "lmp.trace.remote_msg", FT_STRING, BASE_NONE,
		  NULL, 0x0, NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_TRACE_REQ_TYPE],
		{ "Trace Type", "lmp.trace_req.type", FT_UINT16, BASE_DEC,
		  VALS(lmp_trace_type_str), 0x0, NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_SP_FLAGS],
		{ "Service Config - Supported Signalling Protocols",
		"lmp.service_config.sp", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_SP_FLAGS_RSVP],
	   { "RSVP is supported", "lmp.service_config.sp.rsvp",
		 FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_SP_FLAGS_LDP],
		{ "LDP is supported", "lmp.service_config.sp.ldp",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS],
		{ "Client Port Service Attributes", "lmp.service_config.cpsa",
		  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS_PATH_OVERHEAD],
		{ "Path/VC Overhead Transparency Supported",
		  "lmp.service_config.cpsa.path_overhead",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS_LINE_OVERHEAD],
		{ "Line/MS Overhead Transparency Supported",
		  "lmp.service_config.cpsa.line_overhead",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_TP_FLAGS_SECTION_OVERHEAD],
		{ "Section/RS Overhead Transparency Supported",
		  "lmp.service_config.cpsa.section_overhead",
		  FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_CCT_FLAGS],
		{ "Contiguous Concatenation Types", "lmp.service_config.cct",
		  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_CCT_FLAGS_CC_SUPPORTED],
		{ "Contiguous Concatenation Types Supported",
		  "lmp.service_config.cpsa.line_overhead",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_MIN_NCC],
		{ "Minimum Number of Contiguously Concatenated Components",
		  "lmp.service_config.cpsa.min_ncc",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_MAX_NCC],
		{ "Maximum Number of Contiguously Concatenated Components",
		  "lmp.service_config.cpsa.max_ncc",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_MIN_NVC],
		{ "Maximum Number of Contiguously Concatenated Components",
		  "lmp.service_config.cpsa.min_nvc",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_MAX_NVC],
		{ "Minimum Number of Virtually Concatenated Components",
		  "lmp.service_config.cpsa.max_nvc",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_CPSA_INTERFACE_ID],
		{ "Local interface id of the client interface referred to",
		  "lmp.service_config.cpsa.local_ifid",
		  FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS],
		{ "Network Transparency Flags",
		  "lmp.service_config.nsa.transparency",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS_SOH],
		{ "Standard SOH/RSOH transparency supported",
		  "lmp.service_config.nsa.transparency.soh",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_TRANSPARENCY_FLAGS_LOH],
		{ "Standard LOH/MSOH transparency supported",
		  "lmp.service_config.nsa.transparency.loh",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_TCM_FLAGS],
		{ "TCM Monitoring",
		"lmp.service_config.nsa.tcm",
		  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_TCM_FLAGS_TCM_SUPPORTED],
		{ "TCM Monitoring Supported",
		  "lmp.service_config.nsa.transparency.tcm",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS],
		{ "Network Diversity Flags",
		"lmp.service_config.nsa.diversity",
		  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS_NODE],
		{ "Node diversity supported",
		  "lmp.service_config.nsa.diversity.node",
		  FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS_LINK],
		{ "Link diversity supported",
		  "lmp.service_config.nsa.diversity.link",
		  FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_SERVICE_CONFIG_NSA_NETWORK_DIVERSITY_FLAGS_SRLG],
		{ "SRLG diversity supported",
		  "lmp.service_config.nsa.diversity.srlg",
		  FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}},

	   {&hf_lmp_filter[LMPF_VAL_LOCAL_DA_DCN_ADDR],
		{ "Local DA DCN Address", "lmp.local_da_dcn_addr", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_REMOTE_DA_DCN_ADDR],
		{ "Remote DA DCN Address", "lmp.remote_da_dcn_addr", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

	   {&hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_NODE_ID],
		{ "Node ID", "lmp.local_lad_node_id", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_AREA_ID],
		{ "Area ID", "lmp.local_lad_area_id", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_TE_LINK_ID],
		{ "TE Link ID", "lmp.local_lad_telink_id", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_COMPONENT_ID],
		{ "Component Link ID", "lmp.local_lad_comp_id", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_SC_PC_ID],
		{ "SC PC ID", "lmp.local_lad_sc_pc_id", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LOCAL_LAD_INFO_SC_PC_ADDR],
		{ "SC PC Address", "lmp.local_lad_sc_pc_addr", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ],
		{ "Subobject", "lmp.lad_info_subobj", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_PRI_AREA_ID],
		{ "SC PC Address", "lmp.lad_pri_area_id", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_PRI_RC_PC_ID],
		{ "SC PC Address", "lmp.lad_pri_rc_pc_id", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_PRI_RC_PC_ADDR],
		{ "SC PC Address", "lmp.lad_pri_rc_pc_addr", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_SEC_AREA_ID],
		{ "SC PC Address", "lmp.lad_sec_area_id", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_SEC_RC_PC_ID],
		{ "SC PC Address", "lmp.lad_sec_rc_pc_id", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_SEC_RC_PC_ADDR],
		{ "SC PC Address", "lmp.lad_sec_rc_pc_addr", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_SWITCHING_TYPE],
		{ "Interface Switching Capability", "lmp.lad_switching", FT_UINT8, BASE_DEC|BASE_RANGE_STRING,
		  RVALS(gmpls_switching_type_rvals), 0x0, NULL, HFILL }},
	   {&hf_lmp_filter[LMPF_VAL_LAD_INFO_SUBOBJ_LSP_ENCODING],
		{ "LSP Encoding Type", "lmp.lad_encoding", FT_UINT8, BASE_DEC|BASE_RANGE_STRING,
		  RVALS(gmpls_lsp_enc_rvals), 0x0, NULL, HFILL }},
	};

    for (i=0; i<NUM_LMP_SUBTREES; i++) {
	lmp_subtree[i] = -1;
	ett[i] = &lmp_subtree[i];
    }

    proto_lmp = proto_register_protocol("Link Management Protocol (LMP)",
					"LMP", "lmp");
    proto_register_field_array(proto_lmp, lmpf_info, array_length(lmpf_info));
    proto_register_subtree_array(ett, array_length(ett));

    register_lmp_prefs();
}

void
proto_reg_handoff_lmp(void)
{
    lmp_handle = new_create_dissector_handle(dissect_lmp, proto_lmp);
    dissector_add_uint("udp.port", lmp_udp_port, lmp_handle);
}
