/* packet-dcerpc.c
 * Routines for DCERPC packet disassembly
 * Copyright 2001, Todd Sabin <tas[AT]webspan.net>
 * Copyright 2003, Tim Potter <tpot[AT]samba.org>
 * Copyright 2010, Julien Kerihuel <j.kerihuel[AT]openchange.org>
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

/* The DCE RPC specification can be found at:
 * http://www.opengroup.org/dce/
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>
#include <epan/show_exception.h>
#include <epan/decode_as.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/dissectors/packet-dcerpc-nt.h>

void proto_register_dcerpc(void);
void proto_reg_handoff_dcerpc(void);

static int dcerpc_tap = -1;

/* 32bit Network Data Representation, see DCE/RPC Appendix I */
static e_uuid_t uuid_data_repr_proto        = { 0x8a885d04, 0x1ceb, 0x11c9,
                                                { 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 } };

/* 64bit Network Data Representation, introduced in Windows Server 2008 */
static e_uuid_t uuid_ndr64                  = { 0x71710533, 0xbeba, 0x4937,
                                                { 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36 } };

/* Bind Time Feature Negotiation, see [MS-RPCE] 3.3.1.5.3 */
static e_uuid_t uuid_bind_time_feature_nego_00 = { 0x6cb71c2c, 0x9812, 0x4540, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
static e_uuid_t uuid_bind_time_feature_nego_01 = { 0x6cb71c2c, 0x9812, 0x4540, { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
static e_uuid_t uuid_bind_time_feature_nego_02 = { 0x6cb71c2c, 0x9812, 0x4540, { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
static e_uuid_t uuid_bind_time_feature_nego_03 = { 0x6cb71c2c, 0x9812, 0x4540, { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

/* see [MS-OXRPC] Appendix A: Full IDL, http://msdn.microsoft.com/en-us/library/ee217991%28v=exchg.80%29.aspx */
static e_uuid_t uuid_asyncemsmdb            = { 0x5261574a, 0x4572, 0x206e,
                                                { 0xb2, 0x68, 0x6b, 0x19, 0x92, 0x13, 0xb4, 0xe4 } };

static const value_string pckt_vals[] = {
    { PDU_REQ,        "Request"},
    { PDU_PING,       "Ping"},
    { PDU_RESP,       "Response"},
    { PDU_FAULT,      "Fault"},
    { PDU_WORKING,    "Working"},
    { PDU_NOCALL,     "Nocall"},
    { PDU_REJECT,     "Reject"},
    { PDU_ACK,        "Ack"},
    { PDU_CL_CANCEL,  "Cl_cancel"},
    { PDU_FACK,       "Fack"},
    { PDU_CANCEL_ACK, "Cancel_ack"},
    { PDU_BIND,       "Bind"},
    { PDU_BIND_ACK,   "Bind_ack"},
    { PDU_BIND_NAK,   "Bind_nak"},
    { PDU_ALTER,      "Alter_context"},
    { PDU_ALTER_ACK,  "Alter_context_resp"},
    { PDU_AUTH3,      "AUTH3"},
    { PDU_SHUTDOWN,   "Shutdown"},
    { PDU_CO_CANCEL,  "Co_cancel"},
    { PDU_ORPHANED,   "Orphaned"},
    { PDU_RTS,        "RPC-over-HTTP RTS"},
    { 0,              NULL }
};

static const value_string drep_byteorder_vals[] = {
    { 0, "Big-endian" },
    { 1, "Little-endian" },
    { 0,  NULL }
};

static const value_string drep_character_vals[] = {
    { 0, "ASCII" },
    { 1, "EBCDIC" },
    { 0,  NULL }
};

#define DCE_RPC_DREP_FP_IEEE 0
#define DCE_RPC_DREP_FP_VAX  1
#define DCE_RPC_DREP_FP_CRAY 2
#define DCE_RPC_DREP_FP_IBM  3

static const value_string drep_fp_vals[] = {
    { DCE_RPC_DREP_FP_IEEE, "IEEE" },
    { DCE_RPC_DREP_FP_VAX,  "VAX"  },
    { DCE_RPC_DREP_FP_CRAY, "Cray" },
    { DCE_RPC_DREP_FP_IBM,  "IBM"  },
    { 0,  NULL }
};

/*
 * Authentication services.
 */
static const value_string authn_protocol_vals[] = {
    { DCE_C_RPC_AUTHN_PROTOCOL_NONE,         "None" },
    { DCE_C_RPC_AUTHN_PROTOCOL_KRB5,         "Kerberos 5" },
    { DCE_C_RPC_AUTHN_PROTOCOL_SPNEGO,       "SPNEGO" },
    { DCE_C_RPC_AUTHN_PROTOCOL_NTLMSSP,      "NTLMSSP" },
    { DCE_C_RPC_AUTHN_PROTOCOL_GSS_SCHANNEL, "SCHANNEL SSP" },
    { DCE_C_RPC_AUTHN_PROTOCOL_GSS_KERBEROS, "Kerberos SSP" },
    { DCE_C_RPC_AUTHN_PROTOCOL_DPA,
      "Distributed Password Authentication SSP"},
    { DCE_C_RPC_AUTHN_PROTOCOL_MSN,          "MSN SSP"},
    { DCE_C_RPC_AUTHN_PROTOCOL_DIGEST,       "Digest SSP"},
    { DCE_C_RPC_AUTHN_PROTOCOL_SEC_CHAN,     "NETLOGON Secure Channel" },
    { DCE_C_RPC_AUTHN_PROTOCOL_MQ,           "MSMQ SSP"},
    { 0, NULL }
};

/*
 * Protection levels.
 */
static const value_string authn_level_vals[] = {
    { DCE_C_AUTHN_LEVEL_NONE,          "None" },
    { DCE_C_AUTHN_LEVEL_CONNECT,       "Connect" },
    { DCE_C_AUTHN_LEVEL_CALL,          "Call" },
    { DCE_C_AUTHN_LEVEL_PKT,           "Packet" },
    { DCE_C_AUTHN_LEVEL_PKT_INTEGRITY, "Packet integrity" },
    { DCE_C_AUTHN_LEVEL_PKT_PRIVACY,   "Packet privacy" },
    { 0,                               NULL }
};

/*
 * Flag bits in first flag field in connectionless PDU header.
 */
#define PFCL1_RESERVED_01       0x01    /* Reserved for use by implementations */
#define PFCL1_LASTFRAG          0x02    /* If set, the PDU is the last
                                         * fragment of a multi-PDU
                                         * transmission */
#define PFCL1_FRAG              0x04    /* If set, the PDU is a fragment of
                                           a multi-PDU transmission */
#define PFCL1_NOFACK            0x08    /* If set, the receiver is not
                                         * requested to send a `fack' PDU
                                         * for the fragment */
#define PFCL1_MAYBE             0x10    /* If set, the PDU is for a `maybe'
                                         * request */
#define PFCL1_IDEMPOTENT        0x20    /* If set, the PDU is for an idempotent
                                         * request */
#define PFCL1_BROADCAST         0x40    /* If set, the PDU is for a broadcast
                                         * request */
#define PFCL1_RESERVED_80       0x80    /* Reserved for use by implementations */

/*
 * Flag bits in second flag field in connectionless PDU header.
 */
#define PFCL2_RESERVED_01       0x01    /* Reserved for use by implementations */
#define PFCL2_CANCEL_PENDING    0x02    /* Cancel pending at the call end */
#define PFCL2_RESERVED_04       0x04    /* Reserved for future use */
#define PFCL2_RESERVED_08       0x08    /* Reserved for future use */
#define PFCL2_RESERVED_10       0x10    /* Reserved for future use */
#define PFCL2_RESERVED_20       0x20    /* Reserved for future use */
#define PFCL2_RESERVED_40       0x40    /* Reserved for future use */
#define PFCL2_RESERVED_80       0x80    /* Reserved for future use */

/*
 * Flag bits in connection-oriented PDU header.
 */
#define PFC_FIRST_FRAG          0x01    /* First fragment */
#define PFC_LAST_FRAG           0x02    /* Last fragment */
#define PFC_PENDING_CANCEL      0x04    /* Cancel was pending at sender */
#define PFC_RESERVED_1          0x08
#define PFC_CONC_MPX            0x10    /* supports concurrent multiplexing
                                         * of a single connection. */
#define PFC_DID_NOT_EXECUTE     0x20    /* only meaningful on `fault' packet;
                                         * if true, guaranteed call did not
                                         * execute. */
#define PFC_MAYBE               0x40    /* `maybe' call semantics requested */
#define PFC_OBJECT_UUID         0x80    /* if true, a non-nil object UUID
                                         * was specified in the handle, and
                                         * is present in the optional object
                                         * field. If false, the object field
                                         * is omitted. */

/*
 * Tests whether a connection-oriented PDU is fragmented; returns TRUE if
 * it's not fragmented (i.e., this is both the first *and* last fragment),
 * and FALSE otherwise.
 */
#define PFC_NOT_FRAGMENTED(hdr)                                         \
    ((hdr->flags&(PFC_FIRST_FRAG|PFC_LAST_FRAG)) == (PFC_FIRST_FRAG|PFC_LAST_FRAG))

/*
 * Presentation context negotiation result.
 */
static const value_string p_cont_result_vals[] = {
    { 0, "Acceptance" },
    { 1, "User rejection" },
    { 2, "Provider rejection" },
    { 3, "Negotiate ACK" }, /* [MS-RPCE] 2.2.2.4 */
    { 0, NULL }
};

/*
 * Presentation context negotiation rejection reasons.
 */
static const value_string p_provider_reason_vals[] = {
    { 0, "Reason not specified" },
    { 1, "Abstract syntax not supported" },
    { 2, "Proposed transfer syntaxes not supported" },
    { 3, "Local limit exceeded" },
    { 0, NULL }
};

/*
 * Reject reasons.
 */
#define REASON_NOT_SPECIFIED            0
#define TEMPORARY_CONGESTION            1
#define LOCAL_LIMIT_EXCEEDED            2
#define CALLED_PADDR_UNKNOWN            3 /* not used */
#define PROTOCOL_VERSION_NOT_SUPPORTED  4
#define DEFAULT_CONTEXT_NOT_SUPPORTED   5 /* not used */
#define USER_DATA_NOT_READABLE          6 /* not used */
#define NO_PSAP_AVAILABLE               7 /* not used */
#define AUTH_TYPE_NOT_RECOGNIZED        8 /* [MS-RPCE] 2.2.2.5 */
#define INVALID_CHECKSUM                9 /* [MS-RPCE] 2.2.2.5 */

static const value_string reject_reason_vals[] = {
    { REASON_NOT_SPECIFIED,           "Reason not specified" },
    { TEMPORARY_CONGESTION,           "Temporary congestion" },
    { LOCAL_LIMIT_EXCEEDED,           "Local limit exceeded" },
    { CALLED_PADDR_UNKNOWN,           "Called paddr unknown" },
    { PROTOCOL_VERSION_NOT_SUPPORTED, "Protocol version not supported" },
    { DEFAULT_CONTEXT_NOT_SUPPORTED,  "Default context not supported" },
    { USER_DATA_NOT_READABLE,         "User data not readable" },
    { NO_PSAP_AVAILABLE,              "No PSAP available" },
    { AUTH_TYPE_NOT_RECOGNIZED,       "Authentication type not recognized" },
    { INVALID_CHECKSUM,               "Invalid checksum" },
    { 0,                              NULL }
};

/*
 * Reject status codes.
 */
static const value_string reject_status_vals[] = {
    { 0,          "Stub-defined exception" },
    { 0x00000001, "nca_s_fault_other" },
    { 0x00000005, "nca_s_fault_access_denied" },
    { 0x000006f7, "nca_s_fault_ndr" },
    { 0x000006d8, "nca_s_fault_cant_perform" },
    { 0x1c000001, "nca_s_fault_int_div_by_zero" },
    { 0x1c000002, "nca_s_fault_addr_error" },
    { 0x1c000003, "nca_s_fault_fp_div_zero" },
    { 0x1c000004, "nca_s_fault_fp_underflow" },
    { 0x1c000005, "nca_s_fault_fp_overflow" },
    { 0x1c000006, "nca_s_fault_invalid_tag" },
    { 0x1c000007, "nca_s_fault_invalid_bound" },
    { 0x1c000008, "nca_rpc_version_mismatch" },
    { 0x1c000009, "nca_unspec_reject" },
    { 0x1c00000a, "nca_s_bad_actid" },
    { 0x1c00000b, "nca_who_are_you_failed" },
    { 0x1c00000c, "nca_manager_not_entered" },
    { 0x1c00000d, "nca_s_fault_cancel" },
    { 0x1c00000e, "nca_s_fault_ill_inst" },
    { 0x1c00000f, "nca_s_fault_fp_error" },
    { 0x1c000010, "nca_s_fault_int_overflow" },
    { 0x1c000014, "nca_s_fault_pipe_empty" },
    { 0x1c000015, "nca_s_fault_pipe_closed" },
    { 0x1c000016, "nca_s_fault_pipe_order" },
    { 0x1c000017, "nca_s_fault_pipe_discipline" },
    { 0x1c000018, "nca_s_fault_pipe_comm_error" },
    { 0x1c000019, "nca_s_fault_pipe_memory" },
    { 0x1c00001a, "nca_s_fault_context_mismatch" },
    { 0x1c00001b, "nca_s_fault_remote_no_memory" },
    { 0x1c00001c, "nca_invalid_pres_context_id" },
    { 0x1c00001d, "nca_unsupported_authn_level" },
    { 0x1c00001f, "nca_invalid_checksum" },
    { 0x1c000020, "nca_invalid_crc" },
    { 0x1c000021, "ncs_s_fault_user_defined" },
    { 0x1c000022, "nca_s_fault_tx_open_failed" },
    { 0x1c000023, "nca_s_fault_codeset_conv_error" },
    { 0x1c000024, "nca_s_fault_object_not_found" },
    { 0x1c000025, "nca_s_fault_no_client_stub" },
    { 0x1c010002, "nca_op_rng_error" },
    { 0x1c010003, "nca_unk_if"},
    { 0x1c010006, "nca_wrong_boot_time" },
    { 0x1c010009, "nca_s_you_crashed" },
    { 0x1c01000b, "nca_proto_error" },
    { 0x1c010013, "nca_out_args_too_big" },
    { 0x1c010014, "nca_server_too_busy" },
    { 0x1c010017, "nca_unsupported_type" },
    /* MS Windows specific values
     * see: http://msdn.microsoft.com/library/default.asp?url=/library/en-us/debug/base/system_error_codes__1700-3999_.asp
     * and: http://msdn.microsoft.com/library/default.asp?url=/library/en-us/seccrypto/security/common_hresult_values.asp
     * and: http://www.megos.ch/support/doserrors.txt
     *
     * XXX - we might need a way to dynamically add entries here, as higher layer protocols use these values too,
     * at least MS protocols (like DCOM) do it that way ... */
    { 0x80004001, "E_NOTIMPL" },
    { 0x80004003, "E_POINTER" },
    { 0x80004004, "E_ABORT" },
    { 0x8000FFFF, "E_UNEXPECTED" },
    { 0x80010105, "RPC_E_SERVERFAULT" },
    { 0x80010108, "RPC_E_DISCONNECTED" },
    { 0x80010113, "RPC_E_INVALID_IPID" },
    { 0x8001011F, "RPC_E_TIMEOUT" },
    { 0x80020003, "DISP_E_MEMBERNOTFOUND" },
    { 0x80020006, "DISP_E_UNKNOWNNAME" },
    { 0x8002000E, "DISP_E_BADPARAMCOUNT" },
    { 0x8004CB00, "CBA_E_MALFORMED" },
    { 0x8004CB01, "CBA_E_UNKNOWNOBJECT" },
    { 0x8004CB05, "CBA_E_INVALIDID" },
    { 0x8004CB09, "CBA_E_INVALIDCOOKIE" },
    { 0x8004CB0B, "CBA_E_QOSTYPEUNSUPPORTED" },
    { 0x8004CB0C, "CBA_E_QOSVALUEUNSUPPORTED" },
    { 0x8004CB0F, "CBA_E_NOTAPPLICABLE" },
    { 0x8004CB12, "CBA_E_LIMITVIOLATION" },
    { 0x8004CB13, "CBA_E_QOSTYPENOTAPPLICABLE" },
    { 0x8004CB18, "CBA_E_OUTOFPARTNERACCOS" },
    { 0x8004CB1C, "CBA_E_FLAGUNSUPPORTED" },
    { 0x8004CB23, "CBA_E_FRAMECOUNTUNSUPPORTED" },
    { 0x8004CB25, "CBA_E_MODECHANGE" },
    { 0x8007000E, "E_OUTOFMEMORY" },
    { 0x80070057, "E_INVALIDARG" },
    { 0x800706d1, "RPC_S_PROCNUM_OUT_OF_RANGE" },
    { 0x80070776, "OR_INVALID_OXID" },
    { 0,          NULL }
};


/*
 * RTS Flags
 */
#define RTS_FLAG_NONE             0x0000
#define RTS_FLAG_PING             0x0001
#define RTS_FLAG_OTHER_CMD        0x0002
#define RTS_FLAG_RECYCLE_CHANNEL  0x0004
#define RTS_FLAG_IN_CHANNEL       0x0008
#define RTS_FLAG_OUT_CHANNEL      0x0010
#define RTS_FLAG_EOF              0x0020
#define RTS_FLAG_ECHO             0x0040

/*
 * RTS Commands
 */

#define RTS_CMD_RECEIVEWINDOWSIZE     0x0
#define RTS_CMD_FLOWCONTROLACK        0x1
#define RTS_CMD_CONNECTIONTIMEOUT     0x2
#define RTS_CMD_COOKIE                0x3
#define RTS_CMD_CHANNELLIFETIME       0x4
#define RTS_CMD_CLIENTKEEPALIVE       0x5
#define RTS_CMD_VERSION               0x6
#define RTS_CMD_EMPTY                 0x7
#define RTS_CMD_PADDING               0x8
#define RTS_CMD_NEGATIVEANCE          0x9
#define RTS_CMD_ANCE                  0xA
#define RTS_CMD_CLIENTADDRESS         0xB
#define RTS_CMD_ASSOCIATIONGROUPID    0xC
#define RTS_CMD_DESTINATION           0xD
#define RTS_CMD_PINGTRAFFICSENTNOTIFY 0xE

static const value_string rts_command_vals[] = {
     { RTS_CMD_RECEIVEWINDOWSIZE,     "ReceiveWindowSize" },
     { RTS_CMD_FLOWCONTROLACK,        "FlowControlAck" },
     { RTS_CMD_CONNECTIONTIMEOUT,     "ConnectionTimeOut" },
     { RTS_CMD_COOKIE,                "Cookie" },
     { RTS_CMD_CHANNELLIFETIME,       "ChannelLifetime" },
     { RTS_CMD_CLIENTKEEPALIVE,       "ClientKeepalive" },
     { RTS_CMD_VERSION,               "Version" },
     { RTS_CMD_EMPTY,                 "Empty" },
     { RTS_CMD_PADDING,               "Padding" },
     { RTS_CMD_NEGATIVEANCE,          "NegativeANCE" },
     { RTS_CMD_ANCE,                  "ANCE" },
     { RTS_CMD_CLIENTADDRESS,         "ClientAddress" },
     { RTS_CMD_ASSOCIATIONGROUPID,    "AssociationGroupId" },
     { RTS_CMD_DESTINATION,           "Destination" },
     { RTS_CMD_PINGTRAFFICSENTNOTIFY, "PingTrafficSentNotify" },
     { 0x0, NULL }
};

/*
 * RTS client address type
 */
#define RTS_IPV4 0
#define RTS_IPV6 1

static const value_string rts_addresstype_vals[] = {
     { RTS_IPV4, "IPV4" },
     { RTS_IPV6, "IPV6" },
     { 0x0, NULL }
};

/*
 * RTS Forward destination
 */

static const value_string rts_forward_destination_vals[] = {
     { 0x0, "FDClient" },
     { 0x1, "FDInProxy" },
     { 0x2, "FDServer" },
     { 0x3, "FDOutProxy" },
     { 0x0, NULL }
};

/* we need to keep track of what transport were used, ie what handle we came
 * in through so we know what kind of pinfo->dce_smb_fid was passed to us.
 */
/* Value of -1 is reserved for "not DCE packet" in packet_info.dcetransporttype. */
#define DCE_TRANSPORT_UNKNOWN           0
#define DCE_CN_TRANSPORT_SMBPIPE        1


static int proto_dcerpc = -1;

/* field defines */
static int hf_dcerpc_request_in = -1;
static int hf_dcerpc_time = -1;
static int hf_dcerpc_response_in = -1;
static int hf_dcerpc_ver = -1;
static int hf_dcerpc_ver_minor = -1;
static int hf_dcerpc_packet_type = -1;
static int hf_dcerpc_cn_flags = -1;
static int hf_dcerpc_cn_flags_first_frag = -1;
static int hf_dcerpc_cn_flags_last_frag = -1;
static int hf_dcerpc_cn_flags_cancel_pending = -1;
static int hf_dcerpc_cn_flags_reserved = -1;
static int hf_dcerpc_cn_flags_mpx = -1;
static int hf_dcerpc_cn_flags_dne = -1;
static int hf_dcerpc_cn_flags_maybe = -1;
static int hf_dcerpc_cn_flags_object = -1;
static int hf_dcerpc_drep = -1;
       int hf_dcerpc_drep_byteorder = -1;
static int hf_dcerpc_drep_character = -1;
static int hf_dcerpc_drep_fp = -1;
static int hf_dcerpc_cn_frag_len = -1;
static int hf_dcerpc_cn_auth_len = -1;
static int hf_dcerpc_cn_call_id = -1;
static int hf_dcerpc_cn_max_xmit = -1;
static int hf_dcerpc_cn_max_recv = -1;
static int hf_dcerpc_cn_assoc_group = -1;
static int hf_dcerpc_cn_num_ctx_items = -1;
static int hf_dcerpc_cn_ctx_item = -1;
static int hf_dcerpc_cn_ctx_id = -1;
static int hf_dcerpc_cn_num_trans_items = -1;
static int hf_dcerpc_cn_bind_abstract_syntax = -1;
static int hf_dcerpc_cn_bind_if_id = -1;
static int hf_dcerpc_cn_bind_if_ver = -1;
static int hf_dcerpc_cn_bind_if_ver_minor = -1;
static int hf_dcerpc_cn_bind_trans_syntax = -1;
static int hf_dcerpc_cn_bind_trans_id = -1;
static int hf_dcerpc_cn_bind_trans_ver = -1;
static int hf_dcerpc_cn_bind_trans_btfn_01 = -1;
static int hf_dcerpc_cn_bind_trans_btfn_02 = -1;
static int hf_dcerpc_cn_alloc_hint = -1;
static int hf_dcerpc_cn_sec_addr_len = -1;
static int hf_dcerpc_cn_sec_addr = -1;
static int hf_dcerpc_cn_num_results = -1;
static int hf_dcerpc_cn_ack_result = -1;
static int hf_dcerpc_cn_ack_reason = -1;
static int hf_dcerpc_cn_ack_trans_id = -1;
static int hf_dcerpc_cn_ack_trans_ver = -1;
static int hf_dcerpc_cn_ack_btfn = -1;
static int hf_dcerpc_cn_reject_reason = -1;
static int hf_dcerpc_cn_num_protocols = -1;
static int hf_dcerpc_cn_protocol_ver_major = -1;
static int hf_dcerpc_cn_protocol_ver_minor = -1;
static int hf_dcerpc_cn_cancel_count = -1;
static int hf_dcerpc_cn_status = -1;
static int hf_dcerpc_cn_deseg_req = -1;
static int hf_dcerpc_cn_rts_flags = -1;
static int hf_dcerpc_cn_rts_flags_none = -1;
static int hf_dcerpc_cn_rts_flags_ping = -1;
static int hf_dcerpc_cn_rts_flags_other_cmd = -1;
static int hf_dcerpc_cn_rts_flags_recycle_channel = -1;
static int hf_dcerpc_cn_rts_flags_in_channel = -1;
static int hf_dcerpc_cn_rts_flags_out_channel = -1;
static int hf_dcerpc_cn_rts_flags_eof = -1;
static int hf_dcerpc_cn_rts_commands_nb = -1;
static int hf_dcerpc_cn_rts_command = -1;
static int hf_dcerpc_cn_rts_command_receivewindowsize = -1;
static int hf_dcerpc_cn_rts_command_fack_bytesreceived = -1;
static int hf_dcerpc_cn_rts_command_fack_availablewindow = -1;
static int hf_dcerpc_cn_rts_command_fack_channelcookie = -1;
static int hf_dcerpc_cn_rts_command_connectiontimeout = -1;
static int hf_dcerpc_cn_rts_command_cookie = -1;
static int hf_dcerpc_cn_rts_command_channellifetime = -1;
static int hf_dcerpc_cn_rts_command_clientkeepalive = -1;
static int hf_dcerpc_cn_rts_command_version = -1;
static int hf_dcerpc_cn_rts_command_conformancecount = -1;
static int hf_dcerpc_cn_rts_command_padding = -1;
static int hf_dcerpc_cn_rts_command_addrtype = -1;
static int hf_dcerpc_cn_rts_command_associationgroupid = -1;
static int hf_dcerpc_cn_rts_command_forwarddestination = -1;
static int hf_dcerpc_cn_rts_command_pingtrafficsentnotify = -1;
static int hf_dcerpc_auth_type = -1;
static int hf_dcerpc_auth_level = -1;
static int hf_dcerpc_auth_pad_len = -1;
static int hf_dcerpc_auth_rsrvd = -1;
static int hf_dcerpc_auth_ctx_id = -1;
static int hf_dcerpc_dg_flags1 = -1;
static int hf_dcerpc_dg_flags1_rsrvd_01 = -1;
static int hf_dcerpc_dg_flags1_last_frag = -1;
static int hf_dcerpc_dg_flags1_frag = -1;
static int hf_dcerpc_dg_flags1_nofack = -1;
static int hf_dcerpc_dg_flags1_maybe = -1;
static int hf_dcerpc_dg_flags1_idempotent = -1;
static int hf_dcerpc_dg_flags1_broadcast = -1;
static int hf_dcerpc_dg_flags1_rsrvd_80 = -1;
static int hf_dcerpc_dg_flags2 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_01 = -1;
static int hf_dcerpc_dg_flags2_cancel_pending = -1;
static int hf_dcerpc_dg_flags2_rsrvd_04 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_08 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_10 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_20 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_40 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_80 = -1;
static int hf_dcerpc_dg_serial_hi = -1;
static int hf_dcerpc_obj_id = -1;
static int hf_dcerpc_dg_if_id = -1;
static int hf_dcerpc_dg_act_id = -1;
static int hf_dcerpc_dg_serial_lo = -1;
static int hf_dcerpc_dg_ahint = -1;
static int hf_dcerpc_dg_ihint = -1;
static int hf_dcerpc_dg_frag_len = -1;
static int hf_dcerpc_dg_frag_num = -1;
static int hf_dcerpc_dg_auth_proto = -1;
static int hf_dcerpc_opnum = -1;
static int hf_dcerpc_dg_seqnum = -1;
static int hf_dcerpc_dg_server_boot = -1;
static int hf_dcerpc_dg_if_ver = -1;
static int hf_dcerpc_krb5_av_prot_level = -1;
static int hf_dcerpc_krb5_av_key_vers_num = -1;
static int hf_dcerpc_krb5_av_key_auth_verifier = -1;
static int hf_dcerpc_dg_cancel_vers = -1;
static int hf_dcerpc_dg_cancel_id = -1;
static int hf_dcerpc_dg_server_accepting_cancels = -1;
static int hf_dcerpc_dg_fack_vers = -1;
static int hf_dcerpc_dg_fack_window_size = -1;
static int hf_dcerpc_dg_fack_max_tsdu = -1;
static int hf_dcerpc_dg_fack_max_frag_size = -1;
static int hf_dcerpc_dg_fack_serial_num = -1;
static int hf_dcerpc_dg_fack_selack_len = -1;
static int hf_dcerpc_dg_fack_selack = -1;
static int hf_dcerpc_dg_status = -1;
static int hf_dcerpc_array_max_count = -1;
static int hf_dcerpc_array_offset = -1;
static int hf_dcerpc_array_actual_count = -1;
static int hf_dcerpc_op = -1;
static int hf_dcerpc_referent_id = -1;
static int hf_dcerpc_fragments = -1;
static int hf_dcerpc_fragment = -1;
static int hf_dcerpc_fragment_overlap = -1;
static int hf_dcerpc_fragment_overlap_conflict = -1;
static int hf_dcerpc_fragment_multiple_tails = -1;
static int hf_dcerpc_fragment_too_long_fragment = -1;
static int hf_dcerpc_fragment_error = -1;
static int hf_dcerpc_fragment_count = -1;
static int hf_dcerpc_reassembled_in = -1;
static int hf_dcerpc_reassembled_length = -1;
static int hf_dcerpc_unknown_if_id = -1;

static gint ett_dcerpc = -1;
static gint ett_dcerpc_cn_flags = -1;
static gint ett_dcerpc_cn_ctx = -1;
static gint ett_dcerpc_cn_iface = -1;
static gint ett_dcerpc_cn_trans_syntax = -1;
static gint ett_dcerpc_cn_trans_btfn = -1;
static gint ett_dcerpc_cn_rts_flags = -1;
static gint ett_dcerpc_cn_rts_command = -1;
static gint ett_dcerpc_cn_rts_pdu = -1;
static gint ett_dcerpc_drep = -1;
static gint ett_dcerpc_dg_flags1 = -1;
static gint ett_dcerpc_dg_flags2 = -1;
static gint ett_dcerpc_pointer_data = -1;
static gint ett_dcerpc_string = -1;
static gint ett_dcerpc_fragments = -1;
static gint ett_dcerpc_fragment = -1;
static gint ett_dcerpc_krb5_auth_verf = -1;

static expert_field ei_dcerpc_fragment_multiple = EI_INIT;
static expert_field ei_dcerpc_cn_status = EI_INIT;
static expert_field ei_dcerpc_fragment_reassembled = EI_INIT;
static expert_field ei_dcerpc_fragment = EI_INIT;
static expert_field ei_dcerpc_no_request_found = EI_INIT;
static expert_field ei_dcerpc_context_change = EI_INIT;
static expert_field ei_dcerpc_cn_ctx_id_no_bind = EI_INIT;
static expert_field ei_dcerpc_bind_not_acknowledged = EI_INIT;


static GSList *decode_dcerpc_bindings = NULL;
/*
 * To keep track of ctx_id mappings.
 *
 * Every time we see a bind call we update this table.
 * Note that we always specify a SMB FID. For non-SMB transports this
 * value is 0.
 */
static GHashTable *dcerpc_binds = NULL;

typedef struct _dcerpc_bind_key {
    conversation_t *conv;
    guint16         ctx_id;
    guint16         smb_fid;
} dcerpc_bind_key;

typedef struct _dcerpc_bind_value {
    e_uuid_t uuid;
    guint16  ver;
    e_uuid_t transport;
} dcerpc_bind_value;

/* Extra data for DCERPC handling and tracking of context ids */
typedef struct _dcerpc_decode_as_data {
    guint16 dcectxid;             /**< Context ID (DCERPC-specific) */
    int     dcetransporttype;     /**< Transport type
                                    * Value -1 means "not a DCERPC packet"
                                    */
    guint16 dcetransportsalt;     /**< fid: if transporttype==DCE_CN_TRANSPORT_SMBPIPE */
} dcerpc_decode_as_data;

static dcerpc_decode_as_data*
dcerpc_get_decode_data(packet_info* pinfo)
{
    dcerpc_decode_as_data* data = (dcerpc_decode_as_data*)p_get_proto_data(pinfo->pool, pinfo, proto_dcerpc, 0);
    if (data == NULL)
    {
        data = wmem_new0(pinfo->pool, dcerpc_decode_as_data);
        data->dcetransporttype = -1;
        p_add_proto_data(pinfo->pool, pinfo, proto_dcerpc, 0, data);
    }

    return data;
}

/**
 *  Registers a conversation/UUID binding association, so that
 *  we can invoke the proper sub-dissector for a given DCERPC
 *  conversation.
 *
 *  @param binding all values needed to create and bind a new conversation
 *
 *  @return Pointer to newly-added UUID/conversation binding.
 */
static struct _dcerpc_bind_value *
dcerpc_add_conv_to_bind_table(decode_dcerpc_bind_values_t *binding)
{
    dcerpc_bind_value *bind_value;
    dcerpc_bind_key   *key;
    conversation_t    *conv;

    conv = find_conversation(
        0,
        &binding->addr_a,
        &binding->addr_b,
        binding->ptype,
        binding->port_a,
        binding->port_b,
        0);

    if (!conv) {
        conv = conversation_new(
            0,
            &binding->addr_a,
            &binding->addr_b,
            binding->ptype,
            binding->port_a,
            binding->port_b,
            0);
    }

    bind_value = (dcerpc_bind_value *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_bind_value));
    bind_value->uuid = binding->uuid;
    bind_value->ver = binding->ver;
    /* For now, assume all DCE/RPC we pick from "decode as" is using
       standard ndr and not ndr64.
       We should make this selectable from the dialog in the future
    */
    bind_value->transport = uuid_data_repr_proto;

    key = (dcerpc_bind_key *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_bind_key));
    key->conv = conv;
    key->ctx_id = binding->ctx_id;
    key->smb_fid = binding->smb_fid;

    /* add this entry to the bind table */
    g_hash_table_insert(dcerpc_binds, key, bind_value);

    return bind_value;

}

/* inject one of our bindings into the dcerpc binding table */
static void
decode_dcerpc_inject_binding(gpointer data, gpointer user_data _U_)
{
    dcerpc_add_conv_to_bind_table((decode_dcerpc_bind_values_t *) data);
}

/* inject all of our bindings into the dcerpc binding table */
static void
decode_dcerpc_inject_bindings(void) {
    g_slist_foreach(decode_dcerpc_bindings, decode_dcerpc_inject_binding, NULL /* user_data */);
}

/* free a binding */
static void
decode_dcerpc_binding_free(void *binding_in)
{
    decode_dcerpc_bind_values_t *binding = (decode_dcerpc_bind_values_t *)binding_in;

    g_free((void *) binding->addr_a.data);
    g_free((void *) binding->addr_b.data);
    if (binding->ifname)
        g_string_free(binding->ifname, TRUE);
    g_free(binding);
}

static void
dcerpc_decode_as_free(gpointer value)
{
    decode_dcerpc_bind_values_t *binding = (decode_dcerpc_bind_values_t *)value;
    if (binding != NULL)
        decode_dcerpc_binding_free(binding);
}

/* removes all bindings */
void
decode_dcerpc_reset_all(void)
{
    decode_dcerpc_bind_values_t *binding;

    while (decode_dcerpc_bindings) {
        binding = (decode_dcerpc_bind_values_t *)decode_dcerpc_bindings->data;

        decode_dcerpc_binding_free(binding);
        decode_dcerpc_bindings = g_slist_remove(
            decode_dcerpc_bindings,
            decode_dcerpc_bindings->data);
    }
}


void
decode_dcerpc_add_show_list(decode_add_show_list_func func, gpointer user_data)
{
    g_slist_foreach(decode_dcerpc_bindings, func, user_data);
}

static void
dcerpc_prompt(packet_info *pinfo, gchar* result)
{
    GString *str = g_string_new("Replace binding between:\r\n"),
            *address_str = g_string_new("");
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    switch (pinfo->ptype) {
    case(PT_TCP):
        g_string_append(address_str, "Address: ToBeDone TCP port");
        break;
    case(PT_UDP):
        g_string_append(address_str, "Address: ToBeDone UDP port");
        break;
    default:
        g_string_append(address_str, "Address: ToBeDone Unknown port type");
    }

    g_string_append_printf(str, "%s: %u\r\n", address_str->str, pinfo->srcport);
    g_string_append(str, "&\r\n");
    g_string_append_printf(str, "%s: %u\r\n", address_str->str, pinfo->destport);
    g_string_append_printf(str, "&\r\nContext ID: %u\r\n", decode_data->dcectxid);
    g_string_append_printf(str, "&\r\nSMB FID: %u\r\n", dcerpc_get_transport_salt(pinfo));
    g_string_append(str, "with:\r\n");

    g_strlcpy(result, str->str, MAX_DECODE_AS_PROMPT_LEN);
    g_string_free(str, TRUE);
    g_string_free(address_str, TRUE);
}

static gpointer
dcerpc_value(packet_info *pinfo)
{
    decode_dcerpc_bind_values_t *binding;
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    /* clone binding */
    binding = g_new(decode_dcerpc_bind_values_t,1);
    COPY_ADDRESS(&binding->addr_a, &pinfo->src);
    COPY_ADDRESS(&binding->addr_b, &pinfo->dst);
    binding->ptype = pinfo->ptype;
    binding->port_a = pinfo->srcport;
    binding->port_b = pinfo->destport;
    binding->ctx_id = decode_data->dcectxid;
    binding->smb_fid = dcerpc_get_transport_salt(pinfo);
    binding->ifname = NULL;
    /*binding->uuid = NULL;*/
    binding->ver = 0;

    return binding;
}

struct dcerpc_decode_as_populate
{
    decode_as_add_to_list_func add_to_list;
    gpointer ui_element;
};

static void
decode_dcerpc_add_to_list(gpointer key, gpointer value, gpointer user_data)
{
    struct dcerpc_decode_as_populate* populate = (struct dcerpc_decode_as_populate*)user_data;

    /*dcerpc_uuid_key *k = key;*/
    dcerpc_uuid_value *v = (dcerpc_uuid_value *)value;

    if (strcmp(v->name, "(none)"))
        populate->add_to_list("DCE-RPC", v->name, key, populate->ui_element);
}

static void
dcerpc_populate_list(const gchar *table_name _U_, decode_as_add_to_list_func add_to_list, gpointer ui_element)
{
    struct dcerpc_decode_as_populate populate;

    populate.add_to_list = add_to_list;
    populate.ui_element = ui_element;

    g_hash_table_foreach(dcerpc_uuids, decode_dcerpc_add_to_list, &populate);
}

/* compare two bindings (except the interface related things, e.g. uuid) */
static gint
decode_dcerpc_binding_cmp(gconstpointer a, gconstpointer b)
{
    const decode_dcerpc_bind_values_t *binding_a = (const decode_dcerpc_bind_values_t *)a;
    const decode_dcerpc_bind_values_t *binding_b = (const decode_dcerpc_bind_values_t *)b;


    /* don't compare uuid and ver! */
    if (
        ADDRESSES_EQUAL(&binding_a->addr_a, &binding_b->addr_a) &&
        ADDRESSES_EQUAL(&binding_a->addr_b, &binding_b->addr_b) &&
        binding_a->ptype == binding_b->ptype &&
        binding_a->port_a == binding_b->port_a &&
        binding_a->port_b == binding_b->port_b &&
        binding_a->ctx_id == binding_b->ctx_id &&
        binding_a->smb_fid == binding_b->smb_fid)
    {
        /* equal */
        return 0;
    }

    /* unequal */
    return 1;
}

/* remove a binding (looking the same way as the given one) */
static gboolean
decode_dcerpc_binding_reset(const char *name _U_, const gpointer pattern)
{
    decode_dcerpc_bind_values_t *binding = (decode_dcerpc_bind_values_t*)pattern;
    GSList *le;
    decode_dcerpc_bind_values_t *old_binding;

    /* find the old binding (if it exists) */
    le = g_slist_find_custom(decode_dcerpc_bindings,
                                             binding,
                                             decode_dcerpc_binding_cmp);
    if (le == NULL)
        return FALSE;

    old_binding = (decode_dcerpc_bind_values_t *)le->data;

    decode_dcerpc_bindings = g_slist_remove(decode_dcerpc_bindings, le->data);

    g_free((void *) old_binding->addr_a.data);
    g_free((void *) old_binding->addr_b.data);
    g_string_free(old_binding->ifname, TRUE);
    g_free(old_binding);
    return FALSE;
}

static gboolean
dcerpc_decode_as_change(const char *name, const gpointer pattern, gpointer handle, gchar* list_name)
{
    decode_dcerpc_bind_values_t *binding = (decode_dcerpc_bind_values_t*)pattern;
    decode_dcerpc_bind_values_t *stored_binding;
    dcerpc_uuid_key     *key = *((dcerpc_uuid_key**)handle);


    binding->ifname = g_string_new(list_name);
    binding->uuid = key->uuid;
    binding->ver = key->ver;

    /* remove a probably existing old binding */
    decode_dcerpc_binding_reset(name, binding);

    /* clone the new binding and append it to the list */
    stored_binding = g_new(decode_dcerpc_bind_values_t,1);
    *stored_binding = *binding;
    COPY_ADDRESS(&stored_binding->addr_a, &binding->addr_a);
    COPY_ADDRESS(&stored_binding->addr_b, &binding->addr_b);
    stored_binding->ifname = g_string_new(binding->ifname->str);

    decode_dcerpc_bindings = g_slist_append (decode_dcerpc_bindings, stored_binding);

    return FALSE;
}

static const fragment_items dcerpc_frag_items = {
    &ett_dcerpc_fragments,
    &ett_dcerpc_fragment,

    &hf_dcerpc_fragments,
    &hf_dcerpc_fragment,
    &hf_dcerpc_fragment_overlap,
    &hf_dcerpc_fragment_overlap_conflict,
    &hf_dcerpc_fragment_multiple_tails,
    &hf_dcerpc_fragment_too_long_fragment,
    &hf_dcerpc_fragment_error,
    &hf_dcerpc_fragment_count,
    NULL,
    &hf_dcerpc_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

/* list of hooks to be called when init_protocols is done */
GHookList dcerpc_hooks_init_protos;

static dcerpc_info *
get_next_di(void)
{
    static dcerpc_info di[20];
    static int         di_counter = 0;

    di_counter++;
    if (di_counter >= 20) {
        di_counter = 0;
    }

    memset(&di[di_counter], 0, sizeof(dcerpc_info));
    di[di_counter].dcerpc_procedure_name = "";

    return &di[di_counter];
}

/* try to desegment big DCE/RPC packets over TCP? */
static gboolean dcerpc_cn_desegment = TRUE;

/* reassemble DCE/RPC fragments */
/* reassembly of cl dcerpc fragments will not work for the case where ONE frame
   might contain multiple dcerpc fragments for different PDUs.
   this case would be so unusual/weird so if you got captures like that:
   too bad

   reassembly of co dcerpc fragments will not work for the case where TCP/SMB frames
   are coming in out of sequence, but that will hurt in a lot of other places as well.
*/
static gboolean dcerpc_reassemble = TRUE;
static reassembly_table dcerpc_co_reassembly_table;
static reassembly_table dcerpc_cl_reassembly_table;

typedef struct _dcerpc_fragment_key {
    address src;
    address dst;
    guint32 id;
    e_uuid_t act_id;
} dcerpc_fragment_key;

static guint
dcerpc_fragment_hash(gconstpointer k)
{
    const dcerpc_fragment_key* key = (const dcerpc_fragment_key*) k;
    guint hash_val;

    hash_val = 0;

    hash_val += key->id;
    hash_val += key->act_id.Data1;
    hash_val += key->act_id.Data2 << 16;
    hash_val += key->act_id.Data3;

    return hash_val;
}

static gint
dcerpc_fragment_equal(gconstpointer k1, gconstpointer k2)
{
    const dcerpc_fragment_key* key1 = (const dcerpc_fragment_key*) k1;
    const dcerpc_fragment_key* key2 = (const dcerpc_fragment_key*) k2;

    /*key.id is the first item to compare since item is most
      likely to differ between sessions, thus shortcircuiting
      the comparison of addresses.
    */
    return (((key1->id == key2->id)
             && (ADDRESSES_EQUAL(&key1->src, &key2->src))
             && (ADDRESSES_EQUAL(&key1->dst, &key2->dst))
             && (memcmp (&key1->act_id, &key2->act_id, sizeof (e_uuid_t)) == 0))
            ? TRUE : FALSE);
}

/* allocate a persistent dcerpc fragment key to insert in the hash */
static void *
dcerpc_fragment_temporary_key(const packet_info *pinfo, const guint32 id,
                              const void *data)
{
    dcerpc_fragment_key *key = g_slice_new(dcerpc_fragment_key);
    e_dce_dg_common_hdr_t *hdr = (e_dce_dg_common_hdr_t *)data;

    key->src = pinfo->src;
    key->dst = pinfo->dst;
    key->id = id;
    key->act_id = hdr->act_id;

    return key;
}

/* allocate a persistent dcerpc fragment key to insert in the hash */
static void *
dcerpc_fragment_persistent_key(const packet_info *pinfo, const guint32 id,
                               const void *data)
{
    dcerpc_fragment_key *key = g_slice_new(dcerpc_fragment_key);
    e_dce_dg_common_hdr_t *hdr = (e_dce_dg_common_hdr_t *)data;

    COPY_ADDRESS(&key->src, &pinfo->src);
    COPY_ADDRESS(&key->dst, &pinfo->dst);
    key->id = id;
    key->act_id = hdr->act_id;

    return key;
}

static void
dcerpc_fragment_free_temporary_key(gpointer ptr)
{
    dcerpc_fragment_key *key = (dcerpc_fragment_key *)ptr;

    if (key)
        g_slice_free(dcerpc_fragment_key, key);
}

static void
dcerpc_fragment_free_persistent_key(gpointer ptr)
{
    dcerpc_fragment_key *key = (dcerpc_fragment_key *)ptr;

    if (key) {
        /*
         * Free up the copies of the addresses from the old key.
         */
        g_free((gpointer)key->src.data);
        g_free((gpointer)key->dst.data);

        g_slice_free(dcerpc_fragment_key, key);
    }
}

static const reassembly_table_functions dcerpc_cl_reassembly_table_functions = {
    dcerpc_fragment_hash,
    dcerpc_fragment_equal,
    dcerpc_fragment_temporary_key,
    dcerpc_fragment_persistent_key,
    dcerpc_fragment_free_temporary_key,
    dcerpc_fragment_free_persistent_key
};

static void
dcerpc_reassemble_init(void)
{
    /*
     * XXX - addresses_ports_reassembly_table_functions?
     * Or can a single connection-oriented DCE RPC session persist
     * over multiple transport layer connections?
     */
    reassembly_table_init(&dcerpc_co_reassembly_table,
                          &addresses_reassembly_table_functions);
    reassembly_table_init(&dcerpc_cl_reassembly_table,
                          &dcerpc_cl_reassembly_table_functions);
}

/*
 * Authentication subdissectors.  Used to dissect authentication blobs in
 * DCERPC binds, requests and responses.
 */

typedef struct _dcerpc_auth_subdissector {
    guint8 auth_level;
    guint8 auth_type;
    dcerpc_auth_subdissector_fns auth_fns;
} dcerpc_auth_subdissector;

static GSList *dcerpc_auth_subdissector_list;

static dcerpc_auth_subdissector_fns *get_auth_subdissector_fns(
    guint8 auth_level, guint8 auth_type)
{
    gpointer data;
    int      i;

    for (i = 0; (data = g_slist_nth_data(dcerpc_auth_subdissector_list, i)); i++) {
        dcerpc_auth_subdissector *asd = (dcerpc_auth_subdissector *)data;

        if ((asd->auth_level == auth_level) &&
            (asd->auth_type == auth_type))
            return &asd->auth_fns;
    }

    return NULL;
}

void register_dcerpc_auth_subdissector(guint8 auth_level, guint8 auth_type,
                                       dcerpc_auth_subdissector_fns *fns)
{
    dcerpc_auth_subdissector *d;

    if (get_auth_subdissector_fns(auth_level, auth_type))
        return;

    d = (dcerpc_auth_subdissector *)g_malloc(sizeof(dcerpc_auth_subdissector));

    d->auth_level = auth_level;
    d->auth_type = auth_type;
    memcpy(&d->auth_fns, fns, sizeof(dcerpc_auth_subdissector_fns));

    dcerpc_auth_subdissector_list = g_slist_append(dcerpc_auth_subdissector_list, d);
}

/* Hand off verifier data to a registered dissector */

static void dissect_auth_verf(tvbuff_t *auth_tvb, packet_info *pinfo,
                              proto_tree *tree,
                              dcerpc_auth_subdissector_fns *auth_fns,
                              e_dce_cn_common_hdr_t *hdr,
                              dcerpc_auth_info *auth_info)
{
    dcerpc_dissect_fnct_t *volatile fn = NULL;
    /* XXX - "stub" a fake DCERPC INFO STRUCTURE
       If a dcerpc_info is really needed, update
       the call stacks to include it
     */
    FAKE_DCERPC_INFO_STRUCTURE

    switch (hdr->ptype) {
    case PDU_BIND:
    case PDU_ALTER:
        fn = auth_fns->bind_fn;
        break;
    case PDU_BIND_ACK:
    case PDU_ALTER_ACK:
        fn = auth_fns->bind_ack_fn;
        break;
    case PDU_AUTH3:
        fn = auth_fns->auth3_fn;
        break;
    case PDU_REQ:
        fn = auth_fns->req_verf_fn;
        break;
    case PDU_RESP:
        fn = auth_fns->resp_verf_fn;
        break;

        /* Don't know how to handle authentication data in this
           pdu type. */

    default:
        g_warning("attempt to dissect %s pdu authentication data",
                  val_to_str(hdr->ptype, pckt_vals, "Unknown (%u)"));
        break;
    }

    if (fn)
        fn(auth_tvb, 0, pinfo, tree, &di, hdr->drep);
    else {
        tvb_ensure_bytes_exist(auth_tvb, 0, hdr->auth_len);
        proto_tree_add_text(tree, auth_tvb, 0, hdr->auth_len,
                            "%s Verifier",
                            val_to_str(auth_info->auth_type,
                                       authn_protocol_vals,
                                       "Unknown (%u)"));
    }
}

/* Hand off payload data to a registered dissector */

static tvbuff_t *decode_encrypted_data(tvbuff_t *data_tvb,
                                       tvbuff_t *auth_tvb,
                                       packet_info *pinfo,
                                       dcerpc_auth_subdissector_fns *auth_fns,
                                       gboolean is_request,
                                       dcerpc_auth_info *auth_info)
{
    dcerpc_decode_data_fnct_t *fn;

    if (is_request)
        fn = auth_fns->req_data_fn;
    else
        fn = auth_fns->resp_data_fn;

    if (fn)
        return fn(data_tvb, auth_tvb, 0, pinfo, auth_info);

    return NULL;
}

/*
 * Subdissectors
 */

/* the registered subdissectors */
GHashTable *dcerpc_uuids = NULL;

static gint
dcerpc_uuid_equal(gconstpointer k1, gconstpointer k2)
{
    const dcerpc_uuid_key *key1 = (const dcerpc_uuid_key *)k1;
    const dcerpc_uuid_key *key2 = (const dcerpc_uuid_key *)k2;
    return ((memcmp(&key1->uuid, &key2->uuid, sizeof (e_uuid_t)) == 0)
            && (key1->ver == key2->ver));
}

static guint
dcerpc_uuid_hash(gconstpointer k)
{
    const dcerpc_uuid_key *key = (const dcerpc_uuid_key *)k;
    /* This isn't perfect, but the Data1 part of these is almost always
       unique. */
    return key->uuid.Data1;
}

void
dcerpc_init_uuid(int proto, int ett, e_uuid_t *uuid, guint16 ver,
                 dcerpc_sub_dissector *procs, int opnum_hf)
{
    dcerpc_uuid_key   *key         = (dcerpc_uuid_key *)g_malloc(sizeof (*key));
    dcerpc_uuid_value *value       = (dcerpc_uuid_value *)g_malloc(sizeof (*value));
    header_field_info *hf_info;
    module_t          *samr_module;
    const char        *filter_name = proto_get_protocol_filter_name(proto);

    key->uuid = *uuid;
    key->ver = ver;

    value->proto    = find_protocol_by_id(proto);
    value->proto_id = proto;
    value->ett      = ett;
    value->name     = proto_get_protocol_short_name(value->proto);
    value->procs    = procs;
    value->opnum_hf = opnum_hf;

    g_hash_table_insert(dcerpc_uuids, key, value);

    hf_info = proto_registrar_get_nth(opnum_hf);
    hf_info->strings = value_string_from_subdissectors(procs);

    /* add this GUID to the global name resolving */
    guids_add_uuid(uuid, proto_get_protocol_short_name(value->proto));

    /* Register the samr.nt_password preference as obsolete */
    /* This should be in packet-dcerpc-samr.c */
    if (strcmp(filter_name, "samr") == 0) {
        samr_module = prefs_register_protocol(proto, NULL);
        prefs_register_obsolete_preference(samr_module, "nt_password");
    }
}

/* Function to find the name of a registered protocol
 * or NULL if the protocol/version is not known to wireshark.
 */
const char *
dcerpc_get_proto_name(e_uuid_t *uuid, guint16 ver)
{
    dcerpc_uuid_key    key;
    dcerpc_uuid_value *sub_proto;

    key.uuid = *uuid;
    key.ver = ver;
    if (!(sub_proto = (dcerpc_uuid_value *)g_hash_table_lookup(dcerpc_uuids, &key))) {
        return NULL;
    }
    return sub_proto->name;
}

/* Function to find the opnum hf-field of a registered protocol
 * or -1 if the protocol/version is not known to wireshark.
 */
int
dcerpc_get_proto_hf_opnum(e_uuid_t *uuid, guint16 ver)
{
    dcerpc_uuid_key    key;
    dcerpc_uuid_value *sub_proto;

    key.uuid = *uuid;
    key.ver = ver;
    if (!(sub_proto = (dcerpc_uuid_value *)g_hash_table_lookup(dcerpc_uuids, &key))) {
        return -1;
    }
    return sub_proto->opnum_hf;
}

/* Create a value_string consisting of DCERPC opnum and name from a
   subdissector array. */

value_string *value_string_from_subdissectors(dcerpc_sub_dissector *sd)
{
    value_string *vs     = NULL;
    int           i;
    int           num_sd = 0;

again:
    for (i = 0; sd[i].name; i++) {
        if (vs) {
            vs[i].value = sd[i].num;
            vs[i].strptr = sd[i].name;
        } else
            num_sd++;
    }

    if (!vs) {
        vs = (value_string *)wmem_alloc(wmem_epan_scope(), (num_sd + 1) * sizeof(value_string));
        goto again;
    }

    vs[num_sd].value = 0;
    vs[num_sd].strptr = NULL;

    return vs;
}

/* Function to find the subdissector table of a registered protocol
 * or NULL if the protocol/version is not known to wireshark.
 */
dcerpc_sub_dissector *
dcerpc_get_proto_sub_dissector(e_uuid_t *uuid, guint16 ver)
{
    dcerpc_uuid_key    key;
    dcerpc_uuid_value *sub_proto;

    key.uuid = *uuid;
    key.ver = ver;
    if (!(sub_proto = (dcerpc_uuid_value *)g_hash_table_lookup(dcerpc_uuids, &key))) {
        return NULL;
    }
    return sub_proto->procs;
}



static gint
dcerpc_bind_equal(gconstpointer k1, gconstpointer k2)
{
    const dcerpc_bind_key *key1 = (const dcerpc_bind_key *)k1;
    const dcerpc_bind_key *key2 = (const dcerpc_bind_key *)k2;
    return ((key1->conv == key2->conv)
            && (key1->ctx_id == key2->ctx_id)
            && (key1->smb_fid == key2->smb_fid));
}

static guint
dcerpc_bind_hash(gconstpointer k)
{
    const dcerpc_bind_key *key = (const dcerpc_bind_key *)k;
    guint hash;

    hash = GPOINTER_TO_UINT(key->conv) + key->ctx_id + key->smb_fid;
    return hash;

}

/*
 * To keep track of callid mappings.  Should really use some generic
 * conversation support instead.
 */
static GHashTable *dcerpc_cn_calls = NULL;
static GHashTable *dcerpc_dg_calls = NULL;

typedef struct _dcerpc_cn_call_key {
    conversation_t *conv;
    guint32 call_id;
    guint16 smb_fid;
} dcerpc_cn_call_key;

typedef struct _dcerpc_dg_call_key {
    conversation_t *conv;
    guint32         seqnum;
    e_uuid_t        act_id ;
} dcerpc_dg_call_key;


static gint
dcerpc_cn_call_equal(gconstpointer k1, gconstpointer k2)
{
    const dcerpc_cn_call_key *key1 = (const dcerpc_cn_call_key *)k1;
    const dcerpc_cn_call_key *key2 = (const dcerpc_cn_call_key *)k2;
    return ((key1->conv == key2->conv)
            && (key1->call_id == key2->call_id)
            && (key1->smb_fid == key2->smb_fid));
}

static gint
dcerpc_dg_call_equal(gconstpointer k1, gconstpointer k2)
{
    const dcerpc_dg_call_key *key1 = (const dcerpc_dg_call_key *)k1;
    const dcerpc_dg_call_key *key2 = (const dcerpc_dg_call_key *)k2;
    return ((key1->conv == key2->conv)
            && (key1->seqnum == key2->seqnum)
            && ((memcmp(&key1->act_id, &key2->act_id, sizeof (e_uuid_t)) == 0)));
}

static guint
dcerpc_cn_call_hash(gconstpointer k)
{
    const dcerpc_cn_call_key *key = (const dcerpc_cn_call_key *)k;
    return GPOINTER_TO_UINT(key->conv) + key->call_id + key->smb_fid;
}

static guint
dcerpc_dg_call_hash(gconstpointer k)
{
    const dcerpc_dg_call_key *key = (const dcerpc_dg_call_key *)k;
    return (GPOINTER_TO_UINT(key->conv) + key->seqnum + key->act_id.Data1
            + (key->act_id.Data2 << 16)    + key->act_id.Data3
            + (key->act_id.Data4[0] << 24) + (key->act_id.Data4[1] << 16)
            + (key->act_id.Data4[2] << 8)  + (key->act_id.Data4[3] << 0)
            + (key->act_id.Data4[4] << 24) + (key->act_id.Data4[5] << 16)
            + (key->act_id.Data4[6] << 8)  + (key->act_id.Data4[7] << 0));
}

/* to keep track of matched calls/responses
   this one uses the same value struct as calls, but the key is the frame id
   and call id; there can be more than one call in a frame.

   XXX - why not just use the same keys as are used for calls?
*/

static GHashTable *dcerpc_matched = NULL;

typedef struct _dcerpc_matched_key {
    guint32 frame;
    guint32 call_id;
} dcerpc_matched_key;

static gint
dcerpc_matched_equal(gconstpointer k1, gconstpointer k2)
{
    const dcerpc_matched_key *key1 = (const dcerpc_matched_key *)k1;
    const dcerpc_matched_key *key2 = (const dcerpc_matched_key *)k2;
    return ((key1->frame == key2->frame)
            && (key1->call_id == key2->call_id));
}

static guint
dcerpc_matched_hash(gconstpointer k)
{
    const dcerpc_matched_key *key = (const dcerpc_matched_key *)k;
    return key->frame;
}



/*
 * Utility functions.  Modeled after packet-rpc.c
 */

int
dissect_dcerpc_uint8(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                     proto_tree *tree, guint8 *drep,
                     int hfindex, guint8 *pdata)
{
    guint8 data;

    data = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 1, DREP_ENC_INTEGER(drep));
    }
    if (pdata)
        *pdata = data;
    return offset + 1;
}

int
dissect_dcerpc_uint16(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, guint8 *drep,
                      int hfindex, guint16 *pdata)
{
    guint16 data;

    data = ((drep[0] & DREP_LITTLE_ENDIAN)
            ? tvb_get_letohs(tvb, offset)
            : tvb_get_ntohs(tvb, offset));

    if (tree) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 2, DREP_ENC_INTEGER(drep));
    }
    if (pdata)
        *pdata = data;
    return offset + 2;
}

int
dissect_dcerpc_uint32(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, guint8 *drep,
                      int hfindex, guint32 *pdata)
{
    guint32 data;

    data = ((drep[0] & DREP_LITTLE_ENDIAN)
            ? tvb_get_letohl(tvb, offset)
            : tvb_get_ntohl(tvb, offset));

    if (tree) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 4, DREP_ENC_INTEGER(drep));
    }
    if (pdata)
        *pdata = data;
    return offset+4;
}

/* handles 32 bit unix time_t */
int
dissect_dcerpc_time_t(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, guint8 *drep,
                      int hfindex, guint32 *pdata)
{
    guint32 data;
    nstime_t tv;

    data = ((drep[0] & DREP_LITTLE_ENDIAN)
            ? tvb_get_letohl(tvb, offset)
            : tvb_get_ntohl(tvb, offset));

    tv.secs = data;
    tv.nsecs = 0;
    if (tree) {
        if (data == 0xffffffff) {
            /* special case,   no time specified */
            proto_tree_add_time_format_value(tree, hfindex, tvb, offset, 4, &tv, "No time specified");
        } else {
            proto_tree_add_time(tree, hfindex, tvb, offset, 4, &tv);
        }
    }
    if (pdata)
        *pdata = data;

    return offset+4;
}

int
dissect_dcerpc_uint64(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, guint8 *drep,
                      int hfindex, guint64 *pdata)
{
    guint64 data;

    data = ((drep[0] & DREP_LITTLE_ENDIAN)
            ? tvb_get_letoh64(tvb, offset)
            : tvb_get_ntoh64(tvb, offset));

    if (tree) {
        header_field_info *hfinfo;

        /* This might be a field that is either 32bit, in NDR or
           64 bits in NDR64. So we must be careful and call the right
           helper here
        */
        hfinfo = proto_registrar_get_nth(hfindex);

        switch (hfinfo->type) {
        case FT_UINT64:
            proto_tree_add_uint64(tree, hfindex, tvb, offset, 8, data);
            break;
        case FT_INT64:
            proto_tree_add_int64(tree, hfindex, tvb, offset, 8, data);
            break;
        default:
            DISSECTOR_ASSERT(data <= G_MAXUINT32);
            proto_tree_add_uint(tree, hfindex, tvb, offset, 8, (guint32)data);
        }
    }
    if (pdata)
        *pdata = data;
    return offset+8;
}


int
dissect_dcerpc_float(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                     proto_tree *tree, guint8 *drep,
                     int hfindex, gfloat *pdata)
{
    gfloat data;


    switch (drep[1]) {
    case(DCE_RPC_DREP_FP_IEEE):
        data = ((drep[0] & DREP_LITTLE_ENDIAN)
                ? tvb_get_letohieee_float(tvb, offset)
                : tvb_get_ntohieee_float(tvb, offset));
        if (tree) {
            proto_tree_add_float(tree, hfindex, tvb, offset, 4, data);
        }
        break;
    case(DCE_RPC_DREP_FP_VAX):  /* (fall trough) */
    case(DCE_RPC_DREP_FP_CRAY): /* (fall trough) */
    case(DCE_RPC_DREP_FP_IBM):  /* (fall trough) */
    default:
        /* ToBeDone: non IEEE floating formats */
        /* Set data to a negative infinity value */
        data = -G_MAXFLOAT;
        if (tree) {
            proto_tree_add_debug_text(tree, "DCE RPC: dissection of non IEEE floating formats currently not implemented (drep=%u)!", drep[1]);
        }
    }
    if (pdata)
        *pdata = data;
    return offset + 4;
}


int
dissect_dcerpc_double(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, guint8 *drep,
                      int hfindex, gdouble *pdata)
{
    gdouble data;


    switch (drep[1]) {
    case(DCE_RPC_DREP_FP_IEEE):
        data = ((drep[0] & DREP_LITTLE_ENDIAN)
                ? tvb_get_letohieee_double(tvb, offset)
                : tvb_get_ntohieee_double(tvb, offset));
        if (tree) {
            proto_tree_add_double(tree, hfindex, tvb, offset, 8, data);
        }
        break;
    case(DCE_RPC_DREP_FP_VAX):  /* (fall trough) */
    case(DCE_RPC_DREP_FP_CRAY): /* (fall trough) */
    case(DCE_RPC_DREP_FP_IBM):  /* (fall trough) */
    default:
        /* ToBeDone: non IEEE double formats */
        /* Set data to a negative infinity value */
        data = -G_MAXDOUBLE;
        if (tree) {
            proto_tree_add_debug_text(tree, "DCE RPC: dissection of non IEEE double formats currently not implemented (drep=%u)!", drep[1]);
        }
    }
    if (pdata)
        *pdata = data;
    return offset + 8;
}


int
dissect_dcerpc_uuid_t(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, guint8 *drep,
                      int hfindex, e_uuid_t *pdata)
{
    e_uuid_t uuid;


    if (drep[0] & DREP_LITTLE_ENDIAN) {
        tvb_get_letohguid(tvb, offset, (e_guid_t *) &uuid);
    } else {
        tvb_get_ntohguid(tvb, offset, (e_guid_t *) &uuid);
    }
    if (tree) {
        proto_tree_add_guid(tree, hfindex, tvb, offset, 16, (e_guid_t *) &uuid);
    }
    if (pdata) {
        *pdata = uuid;
    }
    return offset + 16;
}


/*
 * a couple simpler things
 */
guint16
dcerpc_tvb_get_ntohs(tvbuff_t *tvb, gint offset, guint8 *drep)
{
    if (drep[0] & DREP_LITTLE_ENDIAN) {
        return tvb_get_letohs(tvb, offset);
    } else {
        return tvb_get_ntohs(tvb, offset);
    }
}

guint32
dcerpc_tvb_get_ntohl(tvbuff_t *tvb, gint offset, guint8 *drep)
{
    if (drep[0] & DREP_LITTLE_ENDIAN) {
        return tvb_get_letohl(tvb, offset);
    } else {
        return tvb_get_ntohl(tvb, offset);
    }
}

void
dcerpc_tvb_get_uuid(tvbuff_t *tvb, gint offset, guint8 *drep, e_uuid_t *uuid)
{
    if (drep[0] & DREP_LITTLE_ENDIAN) {
        tvb_get_letohguid(tvb, offset, (e_guid_t *) uuid);
    } else {
        tvb_get_ntohguid(tvb, offset, (e_guid_t *) uuid);
    }
}


/* NDR arrays */
/* function to dissect a unidimensional conformant array */
int
dissect_ndr_ucarray(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                    proto_tree *tree, dcerpc_info *di, guint8 *drep,
                    dcerpc_dissect_fnct_t *fnct)
{
    guint32      i;
    int          old_offset;
    int          conformance_size = 4;

    if (di->call_data->flags & DCERPC_IS_NDR64) {
        conformance_size = 8;
    }

    if (di->conformant_run) {
        guint64 val;

        /* conformant run, just dissect the max_count header */
        old_offset = offset;
        di->conformant_run = 0;
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep,
                                       hf_dcerpc_array_max_count, &val);
        di->array_max_count = (gint32)val;
        di->array_max_count_offset = offset-conformance_size;
        di->conformant_run = 1;
        di->conformant_eaten = offset-old_offset;
    } else {
        /* we don't remember where in the bytestream this field was */
        proto_tree_add_uint(tree, hf_dcerpc_array_max_count, tvb, di->array_max_count_offset, conformance_size, di->array_max_count);

        /* real run, dissect the elements */
        for (i=0; i<di->array_max_count; i++) {
            offset = (*fnct)(tvb, offset, pinfo, tree, di, drep);
        }
    }

    return offset;
}

/* function to dissect a unidimensional conformant and varying array
 * depending on the dissection function passed as a parameter,
 * content of the array will be dissected as a block or byte by byte
 */
static int
dissect_ndr_ucvarray_core(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                     proto_tree *tree, dcerpc_info *di, guint8 *drep,
                     dcerpc_dissect_fnct_t *fnct_bytes,
                     dcerpc_dissect_fnct_blk_t *fnct_block)
{
    guint32      i;
    int          old_offset;
    int          conformance_size = 4;

    if (di->call_data->flags & DCERPC_IS_NDR64) {
        conformance_size = 8;
    }

    if (di->conformant_run) {
        guint64 val;

        /* conformant run, just dissect the max_count header */
        old_offset = offset;
        di->conformant_run = 0;
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep,
                                       hf_dcerpc_array_max_count, &val);
        DISSECTOR_ASSERT(val <= G_MAXUINT32);
        di->array_max_count = (guint32)val;
        di->array_max_count_offset = offset-conformance_size;
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep,
                                       hf_dcerpc_array_offset, &val);
        DISSECTOR_ASSERT(val <= G_MAXUINT32);
        di->array_offset = (guint32)val;
        di->array_offset_offset = offset-conformance_size;
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep,
                                       hf_dcerpc_array_actual_count, &val);
        DISSECTOR_ASSERT(val <= G_MAXUINT32);
        di->array_actual_count = (guint32)val;
        di->array_actual_count_offset = offset-conformance_size;
        di->conformant_run = 1;
        di->conformant_eaten = offset-old_offset;
    } else {
        /* we don't remember where in the bytestream these fields were */
        proto_tree_add_uint(tree, hf_dcerpc_array_max_count, tvb, di->array_max_count_offset, conformance_size, di->array_max_count);
        proto_tree_add_uint(tree, hf_dcerpc_array_offset, tvb, di->array_offset_offset, conformance_size, di->array_offset);
        proto_tree_add_uint(tree, hf_dcerpc_array_actual_count, tvb, di->array_actual_count_offset, conformance_size, di->array_actual_count);

        /* real run, dissect the elements */
        if (fnct_block) {
                offset = (*fnct_block)(tvb, offset, di->array_actual_count, pinfo, tree, drep);
        } else {
            for (i=0 ;i<di->array_actual_count; i++) {
                old_offset = offset;
                offset = (*fnct_bytes)(tvb, offset, pinfo, tree, di, drep);
                if (offset <= old_offset)
                    THROW(ReportedBoundsError);
            }
        }
    }

    return offset;
}

int
dissect_ndr_ucvarray_block(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                     proto_tree *tree, dcerpc_info *di, guint8 *drep,
                     dcerpc_dissect_fnct_blk_t *fnct)
{
    return dissect_ndr_ucvarray_core(tvb, offset, pinfo, tree, di, drep, NULL, fnct);
}

int
dissect_ndr_ucvarray(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                     proto_tree *tree, dcerpc_info *di, guint8 *drep,
                     dcerpc_dissect_fnct_t *fnct)
{
    return dissect_ndr_ucvarray_core(tvb, offset, pinfo, tree, di, drep, fnct, NULL);
}
/* function to dissect a unidimensional varying array */
int
dissect_ndr_uvarray(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                    proto_tree *tree, dcerpc_info *di, guint8 *drep,
                    dcerpc_dissect_fnct_t *fnct)
{
    guint32      i;
    int          old_offset;
    int          conformance_size = 4;

    if (di->call_data->flags & DCERPC_IS_NDR64) {
        conformance_size = 8;
    }

    if (di->conformant_run) {
        guint64 val;

        /* conformant run, just dissect the max_count header */
        old_offset = offset;
        di->conformant_run = 0;
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep,
                                       hf_dcerpc_array_offset, &val);
        DISSECTOR_ASSERT(val <= G_MAXUINT32);
        di->array_offset = (guint32)val;
        di->array_offset_offset = offset-conformance_size;
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep,
                                       hf_dcerpc_array_actual_count, &val);
        DISSECTOR_ASSERT(val <= G_MAXUINT32);
        di->array_actual_count = (guint32)val;
        di->array_actual_count_offset = offset-conformance_size;
        di->conformant_run = 1;
        di->conformant_eaten = offset-old_offset;
    } else {
        /* we don't remember where in the bytestream these fields were */
        proto_tree_add_uint(tree, hf_dcerpc_array_offset, tvb, di->array_offset_offset, conformance_size, di->array_offset);
        proto_tree_add_uint(tree, hf_dcerpc_array_actual_count, tvb, di->array_actual_count_offset, conformance_size, di->array_actual_count);

        /* real run, dissect the elements */
        for (i=0; i<di->array_actual_count; i++) {
            offset = (*fnct)(tvb, offset, pinfo, tree, di, drep);
        }
    }

    return offset;
}

/* Dissect an string of bytes.  This corresponds to
   IDL of the form '[string] byte *foo'.

   It can also be used for a conformant varying array of bytes if
   the contents of the array should be shown as a big blob, rather
   than showing each byte as an individual element.

   XXX - which of those is really the IDL type for, for example,
   the encrypted data in some MAPI packets?  (Microsoft hasn't
   released that IDL.)

   XXX - does this need to do all the conformant array stuff that
   "dissect_ndr_ucvarray()" does?  These are presumably for strings
   that are conformant and varying - they're stored like conformant
   varying arrays of bytes.  */
int
dissect_ndr_byte_array(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    guint64      len;

    if (di->conformant_run) {
        /* just a run to handle conformant arrays, no scalars to dissect */
        return offset;
    }

    /* NDR array header */

    offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep,
                                  hf_dcerpc_array_max_count, NULL);

    offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep,
                                  hf_dcerpc_array_offset, NULL);

    offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep,
                                  hf_dcerpc_array_actual_count, &len);

    DISSECTOR_ASSERT(len <= G_MAXUINT32);
    if (tree && len) {
        tvb_ensure_bytes_exist(tvb, offset, (guint32)len);
        proto_tree_add_item(tree, di->hf_index, tvb, offset, (guint32)len,
                            ENC_NA);
    }

    offset += (guint32)len;

    return offset;
}

/* For dissecting arrays that are to be interpreted as strings.  */

/* Dissect an NDR conformant varying string of elements.
   The length of each element is given by the 'size_is' parameter;
   the elements are assumed to be characters or wide characters.

   XXX - does this need to do all the conformant array stuff that
   "dissect_ndr_ucvarray()" does?  */
int
dissect_ndr_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                     proto_tree *tree, dcerpc_info *di, guint8 *drep, int size_is,
                     int hfindex, gboolean add_subtree, char **data)
{
    header_field_info *hfinfo;
    proto_item        *string_item;
    proto_tree        *string_tree;
    guint64            len;
    guint32            buffer_len;
    char              *s;

    /* Make sure this really is a string field. */
    hfinfo = proto_registrar_get_nth(hfindex);
    DISSECTOR_ASSERT(hfinfo->type == FT_STRING);

    if (di->conformant_run) {
        /* just a run to handle conformant arrays, no scalars to dissect */
        return offset;
    }

    if (add_subtree) {
        string_item = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                                          proto_registrar_get_name(hfindex));
        string_tree = proto_item_add_subtree(string_item, ett_dcerpc_string);
    } else {
        string_item = NULL;
        string_tree = tree;
    }

    /* NDR array header */

    offset = dissect_ndr_uint3264(tvb, offset, pinfo, string_tree, di, drep,
                                  hf_dcerpc_array_max_count, NULL);

    offset = dissect_ndr_uint3264(tvb, offset, pinfo, string_tree, di, drep,
                                  hf_dcerpc_array_offset, NULL);

    offset = dissect_ndr_uint3264(tvb, offset, pinfo, string_tree, di, drep,
                                  hf_dcerpc_array_actual_count, &len);

    DISSECTOR_ASSERT(len <= G_MAXUINT32);
    buffer_len = size_is * (guint32)len;

    /* Adjust offset */
    if (!di->no_align && (offset % size_is))
        offset += size_is - (offset % size_is);

    /*
     * "tvb_get_string_enc()" throws an exception if the entire string
     * isn't in the tvbuff.  If the length is bogus, this should
     * keep us from trying to allocate an immensely large buffer.
     * (It won't help if the length is *valid* but immensely large,
     * but that's another matter; in any case, that would happen only
     * if we had an immensely large tvbuff....)
     *
     * XXX - so why are we doing tvb_ensure_bytes_exist()?
     */
    tvb_ensure_bytes_exist(tvb, offset, buffer_len);
    if (size_is == sizeof(guint16)) {
        /*
         * Assume little-endian UTF-16.
         *
         * XXX - is this always little-endian?
         */
        s = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, buffer_len,
                               ENC_UTF_16|ENC_LITTLE_ENDIAN);
    } else {
        /*
         * XXX - what if size_is is neither 1 nor 2?
         */
        s = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, buffer_len,
                               DREP_ENC_CHAR(drep));
    }
    if (tree && buffer_len)
        proto_tree_add_string(string_tree, hfindex, tvb, offset,
                              buffer_len, s);

    if (string_item != NULL)
        proto_item_append_text(string_item, ": %s", s);

    if (data)
        *data = s;

    offset += buffer_len;

    proto_item_set_end(string_item, tvb, offset);

    return offset;
}

int
dissect_ndr_cstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, dcerpc_info *di, guint8 *drep, int size_is,
                    int hfindex, gboolean add_subtree, char **data)
{
    return dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep, size_is, hfindex, add_subtree, data);
}

/* Dissect an conformant varying string of chars.
   This corresponds to IDL of the form '[string] char *foo'.

   XXX - at least according to the DCE RPC 1.1 spec, a string has
   a null terminator, which isn't necessary as a terminator for
   the transfer language (as there's a length), but is presumably
   there for the benefit of null-terminated-string languages
   such as C.  Is this ever used for purely counted strings?
   (Not that it matters if it is.) */
int
dissect_ndr_char_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                          proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    return dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep,
                                sizeof(guint8), di->hf_index,
                                FALSE, NULL);
}

/* Dissect a conformant varying string of wchars (wide characters).
   This corresponds to IDL of the form '[string] wchar *foo'

   XXX - at least according to the DCE RPC 1.1 spec, a string has
   a null terminator, which isn't necessary as a terminator for
   the transfer language (as there's a length), but is presumably
   there for the benefit of null-terminated-string languages
   such as C.  Is this ever used for purely counted strings?
   (Not that it matters if it is.) */
int
dissect_ndr_wchar_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    return dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep,
                                sizeof(guint16), di->hf_index,
                                FALSE, NULL);
}

/* This function is aimed for PIDL usage and dissects a UNIQUE pointer to
 * unicode string.
 */
int
PIDL_dissect_cvstring(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int chsize, int hfindex, guint32 param)
{
    char        *s      = NULL;
    gint         levels = CB_STR_ITEM_LEVELS(param);

    offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep,
                                  chsize, hfindex,
                                  FALSE, &s);

    if (!di->conformant_run) {
        /* Append string to COL_INFO */
        if (param & PIDL_SET_COL_INFO) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", s);
        }
        /* Save string to dcv->private_data */
        if ((param & PIDL_STR_SAVE)
           && (!pinfo->fd->flags.visited)) {
            dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
            dcv->private_data = wmem_strdup(wmem_file_scope(), s);
        }
        /* Append string to upper-level proto_items */
        if ((levels > 0) && tree && s && s[0]) {
            proto_item_append_text(tree, ": %s", s);
            tree = tree->parent;
            levels--;
            if (levels > 0) {
                proto_item_append_text(tree, ": %s", s);
                tree = tree->parent;
                levels--;
                while (levels > 0) {
                    proto_item_append_text(tree, " %s", s);
                    tree = tree->parent;
                    levels--;
                }
            }
        }

    }

    return offset;
}

/* Dissect an NDR varying string of elements.
   The length of each element is given by the 'size_is' parameter;
   the elements are assumed to be characters or wide characters.
*/
int
dissect_ndr_vstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, dcerpc_info *di, guint8 *drep, int size_is,
                    int hfindex, gboolean add_subtree, char **data)
{
    header_field_info *hfinfo;
    proto_item        *string_item;
    proto_tree        *string_tree;
    guint64            len;
    guint32            buffer_len;
    char              *s;

    /* Make sure this really is a string field. */
    hfinfo = proto_registrar_get_nth(hfindex);
    DISSECTOR_ASSERT(hfinfo->type == FT_STRING);

    if (di->conformant_run) {
        /* just a run to handle conformant arrays, no scalars to dissect */
        return offset;
    }

    if (add_subtree) {
        string_item = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                                          proto_registrar_get_name(hfindex));
        string_tree = proto_item_add_subtree(string_item, ett_dcerpc_string);
    } else {
        string_item = NULL;
        string_tree = tree;
    }

    /* NDR array header */
    offset = dissect_ndr_uint3264(tvb, offset, pinfo, string_tree, di, drep,
                                  hf_dcerpc_array_offset, NULL);

    offset = dissect_ndr_uint3264(tvb, offset, pinfo, string_tree, di, drep,
                                  hf_dcerpc_array_actual_count, &len);

    DISSECTOR_ASSERT(len <= G_MAXUINT32);
    buffer_len = size_is * (guint32)len;

    /* Adjust offset */
    if (!di->no_align && (offset % size_is))
        offset += size_is - (offset % size_is);

    /*
     * "tvb_get_string_enc()" throws an exception if the entire string
     * isn't in the tvbuff.  If the length is bogus, this should
     * keep us from trying to allocate an immensely large buffer.
     * (It won't help if the length is *valid* but immensely large,
     * but that's another matter; in any case, that would happen only
     * if we had an immensely large tvbuff....)
     *
     * XXX - so why are we doing tvb_ensure_bytes_exist()?
     */
    tvb_ensure_bytes_exist(tvb, offset, buffer_len);
    if (size_is == sizeof(guint16)) {
        /*
         * Assume little-endian UTF-16.
         *
         * XXX - is this always little-endian?
         */
        s = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, buffer_len,
                               ENC_UTF_16|ENC_LITTLE_ENDIAN);
    } else {
        /*
         * XXX - what if size_is is neither 1 nor 2?
         */
        s = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, buffer_len,
                               DREP_ENC_CHAR(drep));
    }
    if (tree && buffer_len)
        proto_tree_add_string(string_tree, hfindex, tvb, offset,
                              buffer_len, s);

    if (string_item != NULL)
        proto_item_append_text(string_item, ": %s", s);

    if (data)
        *data = s;

    offset += buffer_len;

    proto_item_set_end(string_item, tvb, offset);

    return offset;
}

/* Dissect an varying string of chars.
   This corresponds to IDL of the form '[string] char *foo'.

   XXX - at least according to the DCE RPC 1.1 spec, a string has
   a null terminator, which isn't necessary as a terminator for
   the transfer language (as there's a length), but is presumably
   there for the benefit of null-terminated-string languages
   such as C.  Is this ever used for purely counted strings?
   (Not that it matters if it is.) */
int
dissect_ndr_char_vstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                         proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    return dissect_ndr_vstring(tvb, offset, pinfo, tree, di, drep,
                               sizeof(guint8), di->hf_index,
                               FALSE, NULL);
}

/* Dissect a varying string of wchars (wide characters).
   This corresponds to IDL of the form '[string] wchar *foo'

   XXX - at least according to the DCE RPC 1.1 spec, a string has
   a null terminator, which isn't necessary as a terminator for
   the transfer language (as there's a length), but is presumably
   there for the benefit of null-terminated-string languages
   such as C.  Is this ever used for purely counted strings?
   (Not that it matters if it is.) */
int
dissect_ndr_wchar_vstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
                          proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    return dissect_ndr_vstring(tvb, offset, pinfo, tree, di, drep,
                               sizeof(guint16), di->hf_index,
                               FALSE, NULL);
}


/* ndr pointer handling */
/* list of pointers encountered so far */
static GSList *ndr_pointer_list = NULL;

/* position where in the list to insert newly encountered pointers */
static int ndr_pointer_list_pos = 0;

/* Boolean controlling whether pointers are top-level or embedded */
static gboolean pointers_are_top_level = TRUE;

/* as a kludge, we represent all embedded reference pointers as id == -1
   hoping that his will not collide with any non-ref pointers */
typedef struct ndr_pointer_data {
    guint32                 id;
    proto_item             *item; /* proto_item for pointer */
    proto_tree             *tree; /* subtree of above item */
    dcerpc_dissect_fnct_t  *fnct; /*if non-NULL, we have not called it yet*/
    int                     hf_index;
    dcerpc_callback_fnct_t *callback;
    void                   *callback_args;
} ndr_pointer_data_t;

void
init_ndr_pointer_list(dcerpc_info *di)
{
    di->conformant_run = 0;

    while (ndr_pointer_list) {
        ndr_pointer_data_t *npd = (ndr_pointer_data_t *)g_slist_nth_data(ndr_pointer_list, 0);
        ndr_pointer_list = g_slist_remove(ndr_pointer_list, npd);
        g_free(npd);
    }

    ndr_pointer_list = NULL;
    ndr_pointer_list_pos = 0;
    pointers_are_top_level = TRUE;
}

int
dissect_deferred_pointers(packet_info *pinfo, tvbuff_t *tvb, int offset, dcerpc_info *di, guint8 *drep)
{
    int          found_new_pointer;
    int          old_offset;
    int          next_pointer;

    next_pointer = 0;

    do{
        int i, len;

        found_new_pointer = 0;
        len = g_slist_length(ndr_pointer_list);
        for (i=next_pointer; i<len; i++) {
            ndr_pointer_data_t *tnpd = (ndr_pointer_data_t *)g_slist_nth_data(ndr_pointer_list, i);
            if (tnpd->fnct) {
                dcerpc_dissect_fnct_t *fnct;

                next_pointer = i+1;
                found_new_pointer = 1;
                fnct = tnpd->fnct;
                tnpd->fnct = NULL;
                ndr_pointer_list_pos = i+1;
                di->hf_index = tnpd->hf_index;
                /* first a run to handle any conformant
                   array headers */
                di->conformant_run = 1;
                di->conformant_eaten = 0;
                old_offset = offset;
                offset = (*(fnct))(tvb, offset, pinfo, NULL, di, drep);

                DISSECTOR_ASSERT((offset-old_offset) == di->conformant_eaten);
                /* This is to check for any bugs in the dissectors.
                 *
                 * Basically, the NDR representation will store all
                 * arrays in two blocks, one block with the dimension
                 * description, like size, number of elements and such,
                 * and another block that contains the actual data stored
                 * in the array.
                 * If the array is embedded directly inside another,
                 * encapsulating aggregate type, like a union or struct,
                 * then these two blocks will be stored at different places
                 * in the bytestream, with other data between the blocks.
                 *
                 * For this reason, all pointers to types (both aggregate
                 * and scalar, for simplicity no distinction is made)
                 * will have its dissector called twice.
                 * The dissector will first be called with conformant_run == 1
                 * in which mode the dissector MUST NOT consume any data from
                 * the tvbuff (i.e. may not dissect anything) except the
                 * initial control block for arrays.
                 * The second time the dissector is called, with
                 * conformant_run == 0, all other data for the type will be
                 * dissected.
                 *
                 * All dissect_ndr_<type> dissectors are already prepared
                 * for this and knows when it should eat data from the tvb
                 * and when not to, so implementors of dissectors will
                 * normally not need to worry about this or even know about
                 * it. However, if a dissector for an aggregate type calls
                 * a subdissector from outside packet-dcerpc.c, such as
                 * the dissector in packet-smb.c for NT Security Descriptors
                 * as an example, then it is VERY important to encapsulate
                 * this call to an external subdissector with the appropriate
                 * test for conformant_run, i.e. it will need something like
                 *
                 *      dcerpc_info *di (received as function parameter)
                 *
                 *      if (di->conformant_run) {
                 *              return offset;
                 *      }
                 *
                 * to make sure it makes the right thing.
                 * This assert will signal when someone has forgotten to
                 * make the dissector aware of this requirement.
                 */

                /* now we dissect the actual pointer */
                di->conformant_run = 0;
                old_offset = offset;
                offset = (*(fnct))(tvb, offset, pinfo, tnpd->tree, di, drep);
                if (tnpd->callback)
                    tnpd->callback(pinfo, tnpd->tree, tnpd->item, di, tvb, old_offset, offset, tnpd->callback_args);
                proto_item_set_len(tnpd->item, offset - old_offset);
                break;
            }
        }
    } while (found_new_pointer);

    return offset;
}


static void
add_pointer_to_list(packet_info *pinfo, proto_tree *tree, proto_item *item,
                    dcerpc_info *di, dcerpc_dissect_fnct_t *fnct, guint32 id, int hf_index,
                    dcerpc_callback_fnct_t *callback, void *callback_args)
{
    ndr_pointer_data_t *npd;

    /* check if this pointer is valid */
    if (id != 0xffffffff) {
        dcerpc_call_value *value;

        value = di->call_data;

        if (di->ptype == PDU_REQ) {
            if (!(pinfo->fd->flags.visited)) {
                if (id > value->max_ptr) {
                    value->max_ptr = id;
                }
            }
        } else {
            /* if we haven't seen the request bail out since we cant
               know whether this is the first non-NULL instance
               or not */
            if (value->req_frame == 0) {
                /* XXX THROW EXCEPTION */
            }

            /* We saw this one in the request frame, nothing to
               dissect later */
            if (id <= value->max_ptr) {
                return;
            }
        }
    }

    npd = (ndr_pointer_data_t *)g_malloc(sizeof(ndr_pointer_data_t));
    npd->id   = id;
    npd->tree = tree;
    npd->item = item;
    npd->fnct = fnct;
    npd->hf_index = hf_index;
    npd->callback = callback;
    npd->callback_args = callback_args;
    ndr_pointer_list = g_slist_insert(ndr_pointer_list, npd,
                                      ndr_pointer_list_pos);
    ndr_pointer_list_pos++;
}


static int
find_pointer_index(guint32 id)
{
    ndr_pointer_data_t *npd;
    int                 i,len;

    len = g_slist_length(ndr_pointer_list);
    for (i=0; i<len; i++) {
        npd = (ndr_pointer_data_t *)g_slist_nth_data(ndr_pointer_list, i);
        if (npd) {
            if (npd->id == id) {
                return i;
            }
        }
    }

    return -1;
}

/* This function dissects an NDR pointer and stores the callback for later
 * deferred dissection.
 *
 *   fnct is the callback function for when we have reached this object in
 *   the bytestream.
 *
 *   type is what type of pointer.
 *
 *   this is text is what text we should put in any created tree node.
 *
 *   hf_index is what hf value we want to pass to the callback function when
 *   it is called, the callback can later pick this one up from di->hf_index.
 *
 *   callback is executed after the pointer has been dereferenced.
 *
 *   callback_args is passed as an argument to the callback function
 *
 * See packet-dcerpc-samr.c for examples
 */
int
dissect_ndr_pointer_cb(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, dcerpc_dissect_fnct_t *fnct,
                       int type, const char *text, int hf_index,
                       dcerpc_callback_fnct_t *callback, void *callback_args)
{
    proto_tree  *tr           = NULL;
    gint         start_offset = offset;
    int          pointer_size = 4;

    if (di->conformant_run) {
        /* this call was only for dissecting the header for any
           embedded conformant array. we will not parse any
           pointers in this mode.
        */
        return offset;
    }
    if (di->call_data->flags & DCERPC_IS_NDR64) {
        pointer_size = 8;
    }


    /*TOP LEVEL REFERENCE POINTER*/
    if ( pointers_are_top_level
        && (type == NDR_POINTER_REF) ) {
        proto_item *item;

        /* we must find out a nice way to do the length here */
        item = proto_tree_add_text(tree, tvb, offset, 0,
                                   "%s", text);
        tr = proto_item_add_subtree(item,ett_dcerpc_pointer_data);

        add_pointer_to_list(pinfo, tr, item, di, fnct, 0xffffffff,
                            hf_index, callback, callback_args);
        goto after_ref_id;
    }

    /*TOP LEVEL FULL POINTER*/
    if ( pointers_are_top_level
        && (type == NDR_POINTER_PTR) ) {
        int idx;
        guint64 id;
        proto_item *item;

        /* get the referent id */
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, NULL, di, drep, -1, &id);

        tvb_ensure_bytes_exist(tvb, offset-pointer_size, pointer_size);
        /* we got a NULL pointer */
        if (id == 0) {
            proto_tree_add_text(tree, tvb, offset-pointer_size,
                                pointer_size,
                                "(NULL pointer) %s",text);
            goto after_ref_id;
        }

        /* see if we have seen this pointer before */
        DISSECTOR_ASSERT(id <= G_MAXUINT32);
        idx = find_pointer_index((guint32)id);

        /* we have seen this pointer before */
        if (idx >= 0) {
            proto_tree_add_text(tree, tvb, offset-pointer_size,
                                pointer_size,
                                "(duplicate PTR) %s",text);
            goto after_ref_id;
        }

        /* new pointer */
        item = proto_tree_add_text(tree, tvb, offset-pointer_size,
                                   pointer_size,
                                   "%s", text);
        tr = proto_item_add_subtree(item,ett_dcerpc_pointer_data);
        proto_tree_add_uint(tr, hf_dcerpc_referent_id, tvb,
                            offset-pointer_size, pointer_size, (guint32)id);
        add_pointer_to_list(pinfo, tr, item, di, fnct, (guint32)id, hf_index,
                            callback, callback_args);
        goto after_ref_id;
    }
    /*TOP LEVEL UNIQUE POINTER*/
    if ( pointers_are_top_level
        && (type == NDR_POINTER_UNIQUE) ) {
        guint64 id;
        proto_item *item;

        /* get the referent id */
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, NULL, di, drep, -1, &id);

        tvb_ensure_bytes_exist(tvb, offset-pointer_size, pointer_size);
        /* we got a NULL pointer */
        if (id == 0) {
            proto_tree_add_text(tree, tvb, offset-pointer_size,
                                pointer_size,
                                "(NULL pointer) %s",text);
            goto after_ref_id;
        }

        /* new pointer */
        DISSECTOR_ASSERT(id <= G_MAXUINT32);
        item = proto_tree_add_text(tree, tvb, offset-pointer_size,
                                   pointer_size,
                                   "%s", text);
        tr = proto_item_add_subtree(item,ett_dcerpc_pointer_data);
        proto_tree_add_uint(tr, hf_dcerpc_referent_id, tvb,
                            offset-pointer_size, pointer_size, (guint32)id);
        add_pointer_to_list(pinfo, tr, item, di, fnct, 0xffffffff,
                            hf_index, callback, callback_args);
        goto after_ref_id;
    }

    /*EMBEDDED REFERENCE POINTER*/
    if ( (!pointers_are_top_level)
        && (type == NDR_POINTER_REF) ) {
        guint64 id;
        proto_item *item;

        /* get the referent id */
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, NULL, di, drep, -1, &id);

        tvb_ensure_bytes_exist(tvb, offset-pointer_size, pointer_size);
        /* new pointer */
        item = proto_tree_add_text(tree, tvb, offset-pointer_size,
                                 pointer_size,
                                 "%s",text);
        tr = proto_item_add_subtree(item,ett_dcerpc_pointer_data);
        DISSECTOR_ASSERT(id <= G_MAXUINT32);
        proto_tree_add_uint(tr, hf_dcerpc_referent_id, tvb,
                            offset-pointer_size, pointer_size, (guint32)id);
        add_pointer_to_list(pinfo, tr, item, di, fnct, 0xffffffff,
                            hf_index, callback, callback_args);
        goto after_ref_id;
    }

    /*EMBEDDED UNIQUE POINTER*/
    if ( (!pointers_are_top_level)
        && (type == NDR_POINTER_UNIQUE) ) {
        guint64 id;
        proto_item *item;

        /* get the referent id */
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, NULL, di, drep, -1, &id);

        tvb_ensure_bytes_exist(tvb, offset-pointer_size, pointer_size);
        /* we got a NULL pointer */
        if (id == 0) {
            proto_tree_add_text(tree, tvb, offset-pointer_size,
                                pointer_size,
                                "(NULL pointer) %s", text);
            goto after_ref_id;
        }

        /* new pointer */
        item = proto_tree_add_text(tree, tvb, offset-pointer_size,
                                   pointer_size,
                                   "%s",text);
        tr = proto_item_add_subtree(item,ett_dcerpc_pointer_data);
        DISSECTOR_ASSERT(id <= G_MAXUINT32);
        proto_tree_add_uint(tr, hf_dcerpc_referent_id, tvb,
                            offset-pointer_size, pointer_size, (guint32)id);
        add_pointer_to_list(pinfo, tr, item, di, fnct, 0xffffffff,
                            hf_index, callback, callback_args);
        goto after_ref_id;
    }

    /*EMBEDDED FULL POINTER*/
    if ( (!pointers_are_top_level)
        && (type == NDR_POINTER_PTR) ) {
        int idx;
        guint64 id;
        proto_item *item;

        /* get the referent id */
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, NULL, di, drep, -1, &id);

        tvb_ensure_bytes_exist(tvb, offset-pointer_size, pointer_size);
        /* we got a NULL pointer */
        if (id == 0) {
            proto_tree_add_text(tree, tvb, offset-pointer_size,
                                pointer_size,
                                "(NULL pointer) %s",text);
            goto after_ref_id;
        }

        /* see if we have seen this pointer before */
        DISSECTOR_ASSERT(id <= G_MAXUINT32);
        idx = find_pointer_index((guint32)id);

        /* we have seen this pointer before */
        if (idx >= 0) {
            proto_tree_add_text(tree, tvb, offset-pointer_size,
                                pointer_size,
                                "(duplicate PTR) %s",text);
            goto after_ref_id;
        }

        /* new pointer */
        item = proto_tree_add_text(tree, tvb, offset-pointer_size,
                                   pointer_size,
                                   "%s", text);
        tr = proto_item_add_subtree(item,ett_dcerpc_pointer_data);
        proto_tree_add_uint(tr, hf_dcerpc_referent_id, tvb,
                            offset-pointer_size, pointer_size, (guint32)id);
        add_pointer_to_list(pinfo, tr, item, di, fnct, (guint32)id, hf_index,
                            callback, callback_args);
        goto after_ref_id;
    }


after_ref_id:
    /* After each top level pointer we have dissected we have to
       dissect all deferrals before we move on to the next top level
       argument */
    if (pointers_are_top_level == TRUE) {
        pointers_are_top_level = FALSE;
        offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
        pointers_are_top_level = TRUE;
    }

    /* Set the length for the new subtree */
    if (tr) {
        proto_item_set_len(tr, offset-start_offset);
    }
    return offset;
}

int
dissect_ndr_pointer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                    proto_tree *tree, dcerpc_info *di, guint8 *drep, dcerpc_dissect_fnct_t *fnct,
                    int type, const char *text, int hf_index)
{
    return dissect_ndr_pointer_cb(
        tvb, offset, pinfo, tree, di, drep, fnct, type, text, hf_index,
        NULL, NULL);
}
int
dissect_ndr_toplevel_pointer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                             proto_tree *tree, dcerpc_info *di, guint8 *drep, dcerpc_dissect_fnct_t *fnct,
                             int type, const char *text, int hf_index)
{
    int ret;

    pointers_are_top_level = TRUE;
    ret = dissect_ndr_pointer_cb(
        tvb, offset, pinfo, tree, di, drep, fnct, type, text, hf_index,
        NULL, NULL);
    return ret;
}
int
dissect_ndr_embedded_pointer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                             proto_tree *tree, dcerpc_info *di, guint8 *drep, dcerpc_dissect_fnct_t *fnct,
                             int type, const char *text, int hf_index)
{
    int ret;

    pointers_are_top_level = FALSE;
    ret = dissect_ndr_pointer_cb(
        tvb, offset, pinfo, tree, di, drep, fnct, type, text, hf_index,
        NULL, NULL);
    return ret;
}

static void
show_stub_data(tvbuff_t *tvb, gint offset, proto_tree *dcerpc_tree,
               dcerpc_auth_info *auth_info, gboolean is_encrypted)
{
    int   length, plain_length, auth_pad_len;
    guint auth_pad_offset;

    /*
     * We don't show stub data unless we have some in the tvbuff;
     * however, in the protocol tree, we show, as the number of
     * bytes, the reported number of bytes, not the number of bytes
     * that happen to be in the tvbuff.
     */
    if (tvb_length_remaining(tvb, offset) > 0) {
        auth_pad_len = auth_info?auth_info->auth_pad_len:0;
        length = tvb_reported_length_remaining(tvb, offset);

        /* if auth_pad_len is larger than length then we ignore auth_pad_len totally */
        plain_length = length - auth_pad_len;
        if (plain_length < 1) {
            plain_length = length;
            auth_pad_len = 0;
        }
        auth_pad_offset = offset + plain_length;

        if ((auth_info != NULL) &&
            (auth_info->auth_level == DCE_C_AUTHN_LEVEL_PKT_PRIVACY)) {
            if (is_encrypted) {
                tvb_ensure_bytes_exist(tvb, offset, length);
                proto_tree_add_text(dcerpc_tree, tvb, offset, length,
                                    "Encrypted stub data (%d byte%s)",
                                    length, plurality(length, "", "s"));
                /* is the padding is still inside the encrypted blob, don't display it explicit */
                auth_pad_len = 0;
            } else {
                tvb_ensure_bytes_exist(tvb, offset, plain_length);
                proto_tree_add_text(dcerpc_tree, tvb, offset, plain_length,
                                    "Decrypted stub data (%d byte%s)",
                                    plain_length, plurality(plain_length, "", "s"));
            }
        } else {
            tvb_ensure_bytes_exist(tvb, offset, plain_length);
            proto_tree_add_text(dcerpc_tree, tvb, offset, plain_length,
                                "Stub data (%d byte%s)", plain_length,
                                plurality(plain_length, "", "s"));
        }
        /* If there is auth padding at the end of the stub, display it */
        if (auth_pad_len != 0) {
            tvb_ensure_bytes_exist(tvb, auth_pad_offset, auth_pad_len);
            proto_tree_add_text(dcerpc_tree, tvb, auth_pad_offset,
                                auth_pad_len,
                                "Auth Padding (%u byte%s)",
                                auth_pad_len,
                                plurality(auth_pad_len, "", "s"));
        }
    }
}

static int
dcerpc_try_handoff(packet_info *pinfo, proto_tree *tree,
                   proto_tree *dcerpc_tree,
                   tvbuff_t *volatile tvb, tvbuff_t *decrypted_tvb,
                   guint8 *drep, dcerpc_info *info,
                   dcerpc_auth_info *auth_info)
{
    volatile gint         offset   = 0;
    dcerpc_uuid_key       key;
    dcerpc_uuid_value    *sub_proto;
    proto_tree *volatile  sub_tree = NULL;
    dcerpc_sub_dissector *proc;
    const gchar          *name     = NULL;
    const char *volatile  saved_proto;
    guint                 length   = 0, reported_length = 0;
    tvbuff_t *volatile    stub_tvb;
    volatile guint        auth_pad_len;
    volatile int          auth_pad_offset;
    proto_item           *sub_item = NULL;
    proto_item           *pi, *hidden_item;

    dcerpc_dissect_fnct_t *volatile sub_dissect;

    key.uuid = info->call_data->uuid;
    key.ver = info->call_data->ver;

    if ((sub_proto = (dcerpc_uuid_value *)g_hash_table_lookup(dcerpc_uuids, &key)) == NULL
        || !proto_is_protocol_enabled(sub_proto->proto)) {
        /*
         * We don't have a dissector for this UUID, or the protocol
         * for that UUID is disabled.
         */

        hidden_item = proto_tree_add_boolean(dcerpc_tree, hf_dcerpc_unknown_if_id,
                                             tvb, offset, 0, TRUE);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s V%u",
        guids_resolve_uuid_to_str(&info->call_data->uuid), info->call_data->ver);

        if (decrypted_tvb != NULL) {
            show_stub_data(decrypted_tvb, 0, dcerpc_tree, auth_info,
                           FALSE);
        } else
            show_stub_data(tvb, 0, dcerpc_tree, auth_info, TRUE);
        return -1;
    }

    for (proc = sub_proto->procs; proc->name; proc++) {
        if (proc->num == info->call_data->opnum) {
            name = proc->name;
            break;
        }
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, sub_proto->name);

    if (!name)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown operation %u %s",
                     info->call_data->opnum,
                     (info->ptype == PDU_REQ) ? "request" : "response");
    else
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                     name, (info->ptype == PDU_REQ) ? "request" : "response");

    sub_dissect = (info->ptype == PDU_REQ) ?
        proc->dissect_rqst : proc->dissect_resp;

    if (tree) {
        sub_item = proto_tree_add_item(tree, sub_proto->proto_id,
                                       (decrypted_tvb != NULL)?decrypted_tvb:tvb,
                                       0, -1, ENC_NA);

        if (sub_item) {
            sub_tree = proto_item_add_subtree(sub_item, sub_proto->ett);
            if (!name)
                proto_item_append_text(sub_item, ", unknown operation %u",
                                       info->call_data->opnum);
            else
                proto_item_append_text(sub_item, ", %s", name);
        }

        /*
         * Put the operation number into the tree along with
         * the operation's name.
         */
        if (sub_proto->opnum_hf != -1)
            proto_tree_add_uint_format(sub_tree, sub_proto->opnum_hf,
                                       tvb, 0, 0, info->call_data->opnum,
                                       "Operation: %s (%u)",
                                       name ? name : "Unknown operation",
                                       info->call_data->opnum);
        else
            proto_tree_add_uint_format_value(sub_tree, hf_dcerpc_op, tvb,
                                       0, 0, info->call_data->opnum,
                                       "%s (%u)",
                                       name ? name : "Unknown operation",
                                       info->call_data->opnum);

        if ((info->ptype == PDU_REQ) && (info->call_data->rep_frame != 0)) {
            pi = proto_tree_add_uint(sub_tree, hf_dcerpc_response_in,
                                     tvb, 0, 0, info->call_data->rep_frame);
            PROTO_ITEM_SET_GENERATED(pi);
        }
        if ((info->ptype == PDU_RESP) && (info->call_data->req_frame != 0)) {
            pi = proto_tree_add_uint(sub_tree, hf_dcerpc_request_in,
                                     tvb, 0, 0, info->call_data->req_frame);
            PROTO_ITEM_SET_GENERATED(pi);
        }
    } /* tree */

    if (decrypted_tvb != NULL) {
        /* Either there was no encryption or we successfully decrypted
           the encrypted payload. */
        if (sub_dissect) {
            /* We have a subdissector - call it. */
            saved_proto          = pinfo->current_proto;
            pinfo->current_proto = sub_proto->name;

            init_ndr_pointer_list(info);

            length = tvb_length(decrypted_tvb);
            reported_length = tvb_reported_length(decrypted_tvb);

            /*
             * Remove the authentication padding from the stub data.
             */
            if ((auth_info != NULL) && (auth_info->auth_pad_len != 0)) {
                if (reported_length >= auth_info->auth_pad_len) {
                    /*
                     * OK, the padding length isn't so big that it
                     * exceeds the stub length.  Trim the reported
                     * length of the tvbuff.
                     */
                    reported_length -= auth_info->auth_pad_len;

                    /*
                     * If that exceeds the actual amount of data in
                     * the tvbuff (which means we have at least one
                     * byte of authentication padding in the tvbuff),
                     * trim the actual amount.
                     */
                    if (length > reported_length)
                        length = reported_length;

                    stub_tvb = tvb_new_subset(decrypted_tvb, 0, length, reported_length);
                    auth_pad_len = auth_info->auth_pad_len;
                    auth_pad_offset = reported_length;
                } else {
                    /*
                     * The padding length exceeds the stub length.
                     * Don't bother dissecting the stub, trim the padding
                     * length to what's in the stub data, and show the
                     * entire stub as authentication padding.
                     */
                    stub_tvb = NULL;
                    auth_pad_len = reported_length;
                    auth_pad_offset = 0;
                    length = 0;
                }
            } else {
                /*
                 * No authentication padding.
                 */
                stub_tvb = decrypted_tvb;
                auth_pad_len = 0;
                auth_pad_offset = 0;
            }

            if (sub_item) {
                proto_item_set_len(sub_item, length);
            }

            if (stub_tvb != NULL) {
                /*
                 * Catch all exceptions other than BoundsError, so that even
                 * if the stub data is bad, we still show the authentication
                 * padding, if any.
                 *
                 * If we get BoundsError, it means the frame was cut short
                 * by a snapshot length, so there's nothing more to
                 * dissect; just re-throw that exception.
                 */
                TRY {
                    int remaining;

                    offset = sub_dissect(stub_tvb, 0, pinfo, sub_tree,
                                          info, drep);

                    /* If we have a subdissector and it didn't dissect all
                       data in the tvb, make a note of it. */
                    remaining = tvb_reported_length_remaining(stub_tvb, offset);
                    if (remaining > 0) {
                        proto_tree_add_text(sub_tree, stub_tvb, offset,
                                            remaining,
                                            "[Long frame (%d byte%s)]",
                                            remaining,
                                            plurality(remaining, "", "s"));
                        col_append_fstr(pinfo->cinfo, COL_INFO,
                                            "[Long frame (%d byte%s)]",
                                            remaining,
                                            plurality(remaining, "", "s"));

                    }
                } CATCH_NONFATAL_ERRORS {
                    /*
                     * Somebody threw an exception that means that there
                     * was a problem dissecting the payload; that means
                     * that a dissector was found, so we don't need to
                     * dissect the payload as data or update the protocol
                     * or info columns.
                     *
                     * Just show the exception and then drive on to show
                     * the authentication padding.
                     */
                    show_exception(stub_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
                } ENDTRY;
            }

            /* If there is auth padding at the end of the stub, display it */
            if (auth_pad_len != 0) {
                tvb_ensure_bytes_exist(tvb, auth_pad_offset, auth_pad_len);
                proto_tree_add_text(sub_tree, decrypted_tvb, auth_pad_offset,
                                    auth_pad_len,
                                    "Auth Padding (%u byte%s)",
                                    auth_pad_len,
                                    plurality(auth_pad_len, "", "s"));
            }

            pinfo->current_proto = saved_proto;
        } else {
            /* No subdissector - show it as stub data. */
            if (decrypted_tvb) {
                show_stub_data(decrypted_tvb, 0, sub_tree, auth_info, FALSE);
            } else {
                show_stub_data(tvb, 0, sub_tree, auth_info, TRUE);
            }
        }
    } else
        show_stub_data(tvb, 0, sub_tree, auth_info, TRUE);

    tap_queue_packet(dcerpc_tap, pinfo, info);
    return 0;
}

static int
dissect_dcerpc_verifier(tvbuff_t *tvb, packet_info *pinfo,
                        proto_tree *dcerpc_tree, e_dce_cn_common_hdr_t *hdr,
                        dcerpc_auth_info *auth_info)
{
    int auth_offset;

    auth_info->auth_data = NULL;

    if (auth_info->auth_size != 0) {
        dcerpc_auth_subdissector_fns *auth_fns;
        tvbuff_t *auth_tvb;

        auth_offset = hdr->frag_len - hdr->auth_len;

        auth_tvb = tvb_new_subset(tvb, auth_offset, hdr->auth_len,
                                  hdr->auth_len);

        auth_info->auth_data = auth_tvb;

        if ((auth_fns = get_auth_subdissector_fns(auth_info->auth_level,
                                                  auth_info->auth_type))) {
            /*
             * Catch all bounds-error exceptions, so that even if the
             * verifier is bad or we don't have all of it, we still
             * show the stub data.
             */
            TRY {
                dissect_auth_verf(auth_tvb, pinfo, dcerpc_tree, auth_fns,
                                  hdr, auth_info);
            } CATCH_BOUNDS_ERRORS {
                show_exception(auth_tvb, pinfo, dcerpc_tree, EXCEPT_CODE, GET_MESSAGE);
            } ENDTRY;
        } else {
            tvb_ensure_bytes_exist(tvb, 0, hdr->auth_len);
            proto_tree_add_text(dcerpc_tree, auth_tvb, 0, hdr->auth_len,
                                "Auth Verifier");
        }
    }

    return hdr->auth_len;
}

static void
dissect_dcerpc_cn_auth(tvbuff_t *tvb, int stub_offset, packet_info *pinfo,
                       proto_tree *dcerpc_tree, e_dce_cn_common_hdr_t *hdr,
                       gboolean are_credentials, dcerpc_auth_info *auth_info)
{
    volatile int offset;

    /*
     * Initially set auth_level and auth_type to zero to indicate that we
     * haven't yet seen any authentication level information.
     */
    auth_info->auth_level   = 0;
    auth_info->auth_type    = 0;
    auth_info->auth_size    = 0;
    auth_info->auth_pad_len = 0;

    /*
     * The authentication information is at the *end* of the PDU; in
     * request and response PDUs, the request and response stub data
     * come before it.
     *
     * Is there any authentication data (i.e., is the authentication length
     * non-zero), and is the authentication length valid (i.e., is it, plus
     * 8 bytes for the type/level/pad length/reserved/context id, less than
     * or equal to the fragment length minus the starting offset of the
     * stub data?)
     */

    if (hdr->auth_len
        && ((hdr->auth_len + 8) <= (hdr->frag_len - stub_offset))) {

        /*
         * Yes, there is authentication data, and the length is valid.
         * Do we have all the bytes of stub data?
         * (If not, we'd throw an exception dissecting *that*, so don't
         * bother trying to dissect the authentication information and
         * throwing another exception there.)
         */
        offset = hdr->frag_len - (hdr->auth_len + 8);
        if (offset == 0 || tvb_offset_exists(tvb, offset - 1)) {
            /*
             * Either there's no stub data, or the last byte of the stub
             * data is present in the captured data, so we shouldn't
             * get a BoundsError dissecting the stub data.
             *
             * Try dissecting the authentication data.
             * Catch all exceptions, so that even if the auth info is bad
             * or we don't have all of it, we still show the stuff we
             * dissect after this, such as stub data.
             */
            TRY {
                offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                              hf_dcerpc_auth_type,
                                              &auth_info->auth_type);
                offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                              hf_dcerpc_auth_level,
                                              &auth_info->auth_level);

                offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                              hf_dcerpc_auth_pad_len,
                                              &auth_info->auth_pad_len);
                offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                              hf_dcerpc_auth_rsrvd, NULL);
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                               hf_dcerpc_auth_ctx_id, NULL);

                /*
                 * Dissect the authentication data.
                 */
                if (are_credentials) {
                    tvbuff_t *auth_tvb;
                    dcerpc_auth_subdissector_fns *auth_fns;

                    auth_tvb = tvb_new_subset(tvb, offset,
                                              MIN(hdr->auth_len,tvb_length_remaining(tvb, offset)),
                                              hdr->auth_len);

                    if ((auth_fns = get_auth_subdissector_fns(auth_info->auth_level,
                                                              auth_info->auth_type)))
                        dissect_auth_verf(auth_tvb, pinfo, dcerpc_tree, auth_fns,
                                          hdr, auth_info);
                    else
                        proto_tree_add_text(dcerpc_tree, tvb, offset, hdr->auth_len,
                                             "Auth Credentials");
                }

                /* Compute the size of the auth block.  Note that this should not
                   include auth padding, since when NTLMSSP encryption is used, the
                   padding is actually inside the encrypted stub */
                auth_info->auth_size = hdr->auth_len + 8;
            } CATCH_BOUNDS_ERRORS {
                show_exception(tvb, pinfo, dcerpc_tree, EXCEPT_CODE, GET_MESSAGE);
            } ENDTRY;
        }
    }
}


/* We need to hash in the SMB fid number to generate a unique hash table
 * key as DCERPC over SMB allows several pipes over the same TCP/IP
 * socket.
 * We pass this function the transport type here to make sure we only look
 * at this function if it came across an SMB pipe.
 * Other transports might need to mix in their own extra multiplexing data
 * as well in the future.
 */

guint16 dcerpc_get_transport_salt(packet_info *pinfo)
{
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    switch (decode_data->dcetransporttype) {
    case DCE_CN_TRANSPORT_SMBPIPE:
        /* DCERPC over smb */
        return decode_data->dcetransportsalt;
    }

    /* Some other transport... */
    return 0;
}

void dcerpc_set_transport_salt(guint16 dcetransportsalt, packet_info *pinfo)
{
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    decode_data->dcetransportsalt = dcetransportsalt;
}

/*
 * Connection oriented packet types
 */

static void
dissect_dcerpc_cn_bind(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *dcerpc_tree, e_dce_cn_common_hdr_t *hdr)
{
    conversation_t   *conv          = find_or_create_conversation(pinfo);
    guint8            num_ctx_items = 0;
    guint             i;
    guint16           ctx_id;
    guint8            num_trans_items;
    guint             j;
    e_uuid_t          if_id;
    e_uuid_t          trans_id;
    guint32           trans_ver;
    guint16           if_ver, if_ver_minor;
    dcerpc_auth_info  auth_info;
    char             *uuid_str;
    const char       *uuid_name     = NULL;
    proto_item       *iface_item    = NULL;
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_max_xmit, NULL);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_max_recv, NULL);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_assoc_group, NULL);

    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                  hf_dcerpc_cn_num_ctx_items, &num_ctx_items);

    /* padding */
    offset += 3;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %u context items:", num_ctx_items);

    for (i = 0; i < num_ctx_items; i++) {
        proto_item *ctx_item = NULL;
        proto_tree *ctx_tree = NULL, *iface_tree = NULL;
        gint ctx_offset = offset;

        dissect_dcerpc_uint16(tvb, offset, pinfo, NULL, hdr->drep,
                              hf_dcerpc_cn_ctx_id, &ctx_id);

        /* save context ID for use with dcerpc_add_conv_to_bind_table() */
        /* (if we have multiple contexts, this might cause "decode as"
         *  to behave unpredictably) */
        decode_data->dcectxid = ctx_id;

        if (dcerpc_tree) {
            ctx_item = proto_tree_add_item(dcerpc_tree, hf_dcerpc_cn_ctx_item,
                                           tvb, offset, 0,
                                           ENC_NA);
            ctx_tree = proto_item_add_subtree(ctx_item, ett_dcerpc_cn_ctx);
        }

        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ctx_tree, hdr->drep,
                                       hf_dcerpc_cn_ctx_id, &ctx_id);
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, ctx_tree, hdr->drep,
                                      hf_dcerpc_cn_num_trans_items, &num_trans_items);

        if (dcerpc_tree) {
            proto_item_append_text(ctx_item, "[%u]: Context ID:%u", i+1, ctx_id);
        }

        /* padding */
        offset += 1;

        dcerpc_tvb_get_uuid(tvb, offset, hdr->drep, &if_id);
        if (ctx_tree) {

            iface_item = proto_tree_add_item(ctx_tree, hf_dcerpc_cn_bind_abstract_syntax, tvb, offset, 0, ENC_NA);
            iface_tree = proto_item_add_subtree(iface_item, ett_dcerpc_cn_iface);

            uuid_str = guid_to_ep_str((e_guid_t*)&if_id);
            uuid_name = guids_get_uuid_name(&if_id);
            if (uuid_name) {
                proto_tree_add_guid_format(iface_tree, hf_dcerpc_cn_bind_if_id, tvb,
                                           offset, 16, (e_guid_t *) &if_id, "Interface: %s UUID: %s", uuid_name, uuid_str);
                proto_item_append_text(iface_item, ": %s", uuid_name);
                proto_item_append_text(ctx_item, ", %s", uuid_name);
            } else {
                proto_tree_add_guid_format(iface_tree, hf_dcerpc_cn_bind_if_id, tvb,
                                           offset, 16, (e_guid_t *) &if_id, "Interface UUID: %s", uuid_str);
                proto_item_append_text(iface_item, ": %s", uuid_str);
                proto_item_append_text(ctx_item, ", %s", uuid_str);
            }
        }
        offset += 16;

        if (hdr->drep[0] & DREP_LITTLE_ENDIAN) {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iface_tree, hdr->drep,
                                           hf_dcerpc_cn_bind_if_ver, &if_ver);
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iface_tree, hdr->drep,
                                           hf_dcerpc_cn_bind_if_ver_minor, &if_ver_minor);
        } else {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iface_tree, hdr->drep,
                                           hf_dcerpc_cn_bind_if_ver_minor, &if_ver_minor);
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iface_tree, hdr->drep,
                                           hf_dcerpc_cn_bind_if_ver, &if_ver);
        }

        if (ctx_tree) {
            proto_item_append_text(iface_item, " V%u.%u", if_ver, if_ver_minor);
            proto_item_set_len(iface_item, 20);
        }

        memset(&trans_id, 0, sizeof(trans_id));
        for (j = 0; j < num_trans_items; j++) {
            proto_tree *trans_tree = NULL;
            proto_item *trans_item = NULL;
            proto_item *uuid_item = NULL;

            dcerpc_tvb_get_uuid(tvb, offset, hdr->drep, &trans_id);
            if (ctx_tree) {

                trans_item = proto_tree_add_item(ctx_tree, hf_dcerpc_cn_bind_trans_syntax, tvb, offset, 0, ENC_NA);
                trans_tree = proto_item_add_subtree(trans_item, ett_dcerpc_cn_trans_syntax);

                uuid_str = guid_to_ep_str((e_guid_t *) &trans_id);
                uuid_name = guids_get_uuid_name(&trans_id);

                if (uuid_name) {
                    uuid_item = proto_tree_add_guid_format(trans_tree, hf_dcerpc_cn_bind_trans_id, tvb, offset, 16, (e_guid_t *) &trans_id, "Transfer Syntax: %s UUID:%s", uuid_name, uuid_str);
                    proto_item_append_text(trans_item, "[%u]: %s", j+1, uuid_name);
                    proto_item_append_text(ctx_item, ", %s", uuid_name);
                } else {
                    uuid_item = proto_tree_add_guid_format(trans_tree, hf_dcerpc_cn_bind_trans_id, tvb, offset, 16, (e_guid_t *) &trans_id, "Transfer Syntax: %s", uuid_str);
                    proto_item_append_text(trans_item, "[%u]: %s", j+1, uuid_str);
                    proto_item_append_text(ctx_item, ", %s", uuid_str);
                }

                /* check for [MS-RPCE] 3.3.1.5.3 Bind Time Feature Negotiation */
                if (trans_id.Data1 == 0x6cb71c2c && trans_id.Data2 == 0x9812 && trans_id.Data3 == 0x4540) {
                    proto_tree *uuid_tree = proto_item_add_subtree(uuid_item, ett_dcerpc_cn_trans_btfn);
                    proto_tree_add_boolean(uuid_tree, hf_dcerpc_cn_bind_trans_btfn_01, tvb, offset+8, 1, trans_id.Data4[0]);
                    proto_tree_add_boolean(uuid_tree, hf_dcerpc_cn_bind_trans_btfn_02, tvb, offset+8, 1, trans_id.Data4[0]);
                }
            }
            offset += 16;

            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, trans_tree, hdr->drep,
                                           hf_dcerpc_cn_bind_trans_ver, &trans_ver);
            if (ctx_tree) {
                proto_item_set_len(trans_item, 20);
                proto_item_append_text(trans_item, " V%u", trans_ver);
            }
        }

        /* if this is the first time we've seen this packet, we need to
           update the dcerpc_binds table so that any later calls can
           match to the interface.
           XXX We assume that BINDs will NEVER be fragmented.
        */
        if (!(pinfo->fd->flags.visited)) {
            dcerpc_bind_key   *key;
            dcerpc_bind_value *value;

            key = (dcerpc_bind_key *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_bind_key));
            key->conv = conv;
            key->ctx_id = ctx_id;
            key->smb_fid = dcerpc_get_transport_salt(pinfo);

            value = (dcerpc_bind_value *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_bind_value));
            value->uuid = if_id;
            value->ver = if_ver;
            value->transport = trans_id;

            /* add this entry to the bind table */
            g_hash_table_insert(dcerpc_binds, key, value);
        }

        if (i > 0)
            col_append_fstr(pinfo->cinfo, COL_INFO, ",");
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s V%u.%u (%s)",
                        guids_resolve_uuid_to_str(&if_id), if_ver, if_ver_minor,
                        guids_resolve_uuid_to_str(&trans_id));

        if (ctx_tree) {
            proto_item_set_len(ctx_item, offset - ctx_offset);
        }
    }

    /*
     * XXX - we should save the authentication type *if* we have
     * an authentication header, and associate it with an authentication
     * context, so subsequent PDUs can use that context.
     */
    dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, TRUE, &auth_info);
}

static void
dissect_dcerpc_cn_bind_ack(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *dcerpc_tree, e_dce_cn_common_hdr_t *hdr)
{
    guint16           max_xmit, max_recv;
    guint16           sec_addr_len;
    guint8            num_results;
    guint             i;
    guint16           result    = 0;
    guint16           reason    = 0;
    e_uuid_t          trans_id;
    guint32           trans_ver;
    dcerpc_auth_info  auth_info;
    const char       *uuid_name = NULL;
    const char       *result_str = NULL;

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_max_xmit, &max_xmit);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_max_recv, &max_recv);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_assoc_group, NULL);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_sec_addr_len, &sec_addr_len);
    if (sec_addr_len != 0) {
        tvb_ensure_bytes_exist(tvb, offset, sec_addr_len);
        proto_tree_add_item(dcerpc_tree, hf_dcerpc_cn_sec_addr, tvb, offset,
                            sec_addr_len, ENC_ASCII|ENC_NA);
        offset += sec_addr_len;
    }

    if (offset % 4) {
        offset += 4 - offset % 4;
    }

    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                  hf_dcerpc_cn_num_results, &num_results);

    /* padding */
    offset += 3;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", max_xmit: %u max_recv: %u, %u results:",
                    max_xmit, max_recv, num_results);

    for (i = 0; i < num_results; i++) {
        proto_tree *ctx_tree = NULL;
        proto_item *ctx_item = NULL;

        if (dcerpc_tree) {
            ctx_item = proto_tree_add_text(dcerpc_tree, tvb, offset, 24, "Ctx Item[%u]:", i+1);
            ctx_tree = proto_item_add_subtree(ctx_item, ett_dcerpc_cn_ctx);
        }

        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ctx_tree,
                                       hdr->drep, hf_dcerpc_cn_ack_result,
                                       &result);

        /* [MS-RPCE] 3.3.1.5.3 check if this Ctx Item is the response to a Bind Time Feature Negotiation request */
        if (result == 3) {
            const int old_offset = offset;
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ctx_tree, hdr->drep, hf_dcerpc_cn_ack_btfn, &reason);
            proto_tree_add_boolean(ctx_tree, hf_dcerpc_cn_bind_trans_btfn_01, tvb, old_offset, 1, reason);
            proto_tree_add_boolean(ctx_tree, hf_dcerpc_cn_bind_trans_btfn_02, tvb, old_offset, 1, reason);
        } else if (result != 0) {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ctx_tree,
                                           hdr->drep, hf_dcerpc_cn_ack_reason,
                                           &reason);
        } else {
            /*
             * The reason for rejection isn't meaningful, and often isn't
             * set, when the syntax was accepted.
             */
            offset += 2;
        }

        result_str = val_to_str(result, p_cont_result_vals, "Unknown result (%u)");

        if (ctx_tree) {
            dcerpc_tvb_get_uuid(tvb, offset, hdr->drep, &trans_id);
            uuid_name = guids_get_uuid_name(&trans_id);
            if (! uuid_name) {
                uuid_name = guid_to_ep_str((e_guid_t *) &trans_id);
            }
            proto_tree_add_guid_format(ctx_tree, hf_dcerpc_cn_ack_trans_id, tvb,
                                       offset, 16, (e_guid_t *) &trans_id, "Transfer Syntax: %s",
                                       uuid_name);
            proto_item_append_text(ctx_item, " %s, %s", result_str, uuid_name);
        }
        offset += 16;

        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ctx_tree, hdr->drep,
                                       hf_dcerpc_cn_ack_trans_ver, &trans_ver);

        if (i > 0)
            col_append_fstr(pinfo->cinfo, COL_INFO, ",");
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", result_str);
    }

    /*
     * XXX - do we need to do anything with the authentication level
     * we get back from this?
     */
    dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, TRUE, &auth_info);
}

static void
dissect_dcerpc_cn_bind_nak(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                           proto_tree *dcerpc_tree, e_dce_cn_common_hdr_t *hdr)
{
    guint16 reason;
    guint8  num_protocols;
    guint   i;

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree,
                                   hdr->drep, hf_dcerpc_cn_reject_reason,
                                   &reason);

    col_append_fstr(pinfo->cinfo, COL_INFO, " reason: %s",
                    val_to_str(reason, reject_reason_vals, "Unknown (%u)"));

    if (reason == PROTOCOL_VERSION_NOT_SUPPORTED) {
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                      hf_dcerpc_cn_num_protocols,
                                      &num_protocols);

        for (i = 0; i < num_protocols; i++) {
            offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree,
                                          hdr->drep, hf_dcerpc_cn_protocol_ver_major,
                                          NULL);
            offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree,
                                          hdr->drep, hf_dcerpc_cn_protocol_ver_minor,
                                          NULL);
        }
    }
}

/* Return a string describing a DCE/RPC fragment as first, middle, or end
   fragment. */

#define PFC_FRAG_MASK  0x03

static const char *
fragment_type(guint8 flags)
{
    static const char* t[4] = {
        "Mid",
        "1st",
        "Last",
        "Single"
    };
    return t[flags & PFC_FRAG_MASK];
}

/* Dissect stub data (payload) of a DCERPC packet. */

static void
dissect_dcerpc_cn_stub(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *dcerpc_tree, proto_tree *tree,
                       e_dce_cn_common_hdr_t *hdr, dcerpc_info *di,
                       dcerpc_auth_info *auth_info, guint32 alloc_hint _U_,
                       guint32 frame)
{
    gint           length, reported_length;
    gboolean       save_fragmented;
    fragment_head *fd_head = NULL;

    tvbuff_t *auth_tvb, *payload_tvb, *decrypted_tvb;
    proto_item *pi;
    proto_item *parent_pi;
    proto_item *dcerpc_tree_item;

    save_fragmented = pinfo->fragmented;

    length = tvb_length_remaining(tvb, offset);
    reported_length = tvb_reported_length_remaining(tvb, offset);
    if (reported_length < 0 ||
        (guint32)reported_length < auth_info->auth_size) {
        /* We don't even have enough bytes for the authentication
           stuff. */
        return;
    }
    reported_length -= auth_info->auth_size;
    if (length > reported_length)
        length = reported_length;
    payload_tvb = tvb_new_subset(tvb, offset, length, reported_length);

    auth_tvb = NULL;
    /*don't bother if we don't have the entire tvb */
    /*XXX we should really make sure we calculate auth_info->auth_data
      and use that one instead of this auth_tvb hack
    */
    if (tvb_length(tvb) == tvb_reported_length(tvb)) {
        if (tvb_length_remaining(tvb, offset+length) > 8) {
            auth_tvb = tvb_new_subset_remaining(tvb, offset+length+8);
        }
    }

    /* Decrypt the PDU if it is encrypted */

    if (auth_info->auth_type &&
        (auth_info->auth_level == DCE_C_AUTHN_LEVEL_PKT_PRIVACY)) {
        /*
         * We know the authentication type, and the authentication
         * level is "Packet privacy", meaning the payload is
         * encrypted; attempt to decrypt it.
         */
        dcerpc_auth_subdissector_fns *auth_fns;

        /* Start out assuming we won't succeed in decrypting. */
        decrypted_tvb = NULL;
        /* Schannel needs information into the footer (verifier) in order to setup decryption keys
         * so we call it in order to have a chance to decipher the data
         */
        if (DCE_C_RPC_AUTHN_PROTOCOL_SEC_CHAN == auth_info->auth_type) {
            dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, TRUE, auth_info);
        }

        if ((auth_fns = get_auth_subdissector_fns(
                 auth_info->auth_level, auth_info->auth_type))) {
            tvbuff_t *result;

            result = decode_encrypted_data(
                payload_tvb, auth_tvb, pinfo, auth_fns,
                hdr->ptype == PDU_REQ, auth_info);

            if (result) {
                if (dcerpc_tree)
                    proto_tree_add_text(
                        dcerpc_tree, payload_tvb, 0, -1,
                        "Encrypted stub data (%d byte%s)",
                        tvb_reported_length(payload_tvb),

                        plurality(tvb_length(payload_tvb), "", "s"));

                add_new_data_source(
                    pinfo, result, "Decrypted stub data");

                /* We succeeded. */
                decrypted_tvb = result;
            }
        }
    } else
        decrypted_tvb = payload_tvb;

    /* if this packet is not fragmented, just dissect it and exit */
    if (PFC_NOT_FRAGMENTED(hdr)) {
        pinfo->fragmented = FALSE;

        dcerpc_try_handoff(
            pinfo, tree, dcerpc_tree, payload_tvb, decrypted_tvb,
            hdr->drep, di, auth_info);

        pinfo->fragmented = save_fragmented;
        return;
    }

    /* The packet is fragmented. */
    pinfo->fragmented = TRUE;

    /* debug output of essential fragment data. */
    /* leave it here for future debugging sessions */
    /*printf("DCE num:%u offset:%u frag_len:%u tvb_len:%u\n",
      pinfo->fd->num, offset, hdr->frag_len, tvb_length(decrypted_tvb));*/

    /* if we are not doing reassembly and this is the first fragment
       then just dissect it and exit
       XXX - if we're not doing reassembly, can we decrypt an
       encrypted stub?
    */
    if ( (!dcerpc_reassemble) && (hdr->flags & PFC_FIRST_FRAG) ) {

        dcerpc_try_handoff(
            pinfo, tree, dcerpc_tree, payload_tvb, decrypted_tvb,
            hdr->drep, di, auth_info);

        expert_add_info_format(pinfo, NULL, &ei_dcerpc_fragment, "%s fragment", fragment_type(hdr->flags));

        pinfo->fragmented = save_fragmented;
        return;
    }

    /* if we have already seen this packet, see if it was reassembled
       and if so dissect the full pdu.
       then exit
    */
    if (pinfo->fd->flags.visited) {
        fd_head = fragment_get_reassembled(&dcerpc_co_reassembly_table, frame);
        goto end_cn_stub;
    }

    /* if we are not doing reassembly and it was neither a complete PDU
       nor the first fragment then there is nothing more we can do
       so we just have to exit
    */
    if ( !dcerpc_reassemble || (tvb_length(tvb) != tvb_reported_length(tvb)) )
        goto end_cn_stub;

    /* if we didn't get 'frame' we don't know where the PDU started and thus
       it is pointless to continue
    */
    if (!frame)
        goto end_cn_stub;

    /* from now on we must attempt to reassemble the PDU
     */

    /* if we get here we know it is the first time we see the packet
       and we also know it is only a fragment and not a full PDU,
       thus we must reassemble it.
    */

    /* Do we have any non-encrypted data to reassemble? */
    if (decrypted_tvb == NULL) {
        /* No.  We can't even try to reassemble.  */
        goto end_cn_stub;
    }

    /* defragmentation is a bit tricky, as there's no offset of the fragment
     * in the protocol data.
     *
     * just use fragment_add_seq_next() and hope that TCP/SMB segments coming
     * in with the correct sequence.
     */
    fd_head = fragment_add_seq_next(&dcerpc_co_reassembly_table,
                                    decrypted_tvb, 0, pinfo, frame, NULL,
                                    tvb_length(decrypted_tvb),
                                    hdr->flags&PFC_LAST_FRAG ? FALSE : TRUE /* more_frags */);

end_cn_stub:

    /* if reassembly is complete and this is the last fragment
     * (multiple fragments in one PDU are possible!)
     * dissect the full PDU
     */
    if (fd_head && (fd_head->flags & FD_DEFRAGMENTED) ) {

        if ((pinfo->fd->num == fd_head->reassembled_in) && (hdr->flags & PFC_LAST_FRAG) ) {
            tvbuff_t *next_tvb;
            proto_item *frag_tree_item;

            next_tvb = tvb_new_chain((decrypted_tvb)?decrypted_tvb:payload_tvb,
                                               fd_head->tvb_data);

            add_new_data_source(pinfo, next_tvb, "Reassembled DCE/RPC");
            show_fragment_tree(fd_head, &dcerpc_frag_items,
                               tree, pinfo, next_tvb, &frag_tree_item);
            /* the toplevel fragment subtree is now behind all desegmented data,
             * move it right behind the DCE/RPC tree */
            dcerpc_tree_item = proto_tree_get_parent(dcerpc_tree);
            if (frag_tree_item && dcerpc_tree_item) {
                proto_tree_move_item(tree, dcerpc_tree_item, frag_tree_item);
            }

            pinfo->fragmented = FALSE;

            expert_add_info_format(pinfo, frag_tree_item, &ei_dcerpc_fragment_reassembled, "%s fragment, reassembled", fragment_type(hdr->flags));

            dcerpc_try_handoff(pinfo, tree, dcerpc_tree, next_tvb,
                               next_tvb, hdr->drep, di, auth_info);

        } else {
            if (decrypted_tvb) {
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_reassembled_in,
                                         decrypted_tvb, 0, 0, fd_head->reassembled_in);
            } else {
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_reassembled_in,
                                         payload_tvb, 0, 0, fd_head->reassembled_in);
            }
            PROTO_ITEM_SET_GENERATED(pi);
            parent_pi = proto_tree_get_parent(dcerpc_tree);
            if (parent_pi != NULL) {
                proto_item_append_text(parent_pi, ", [Reas: #%u]", fd_head->reassembled_in);
            }
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " [DCE/RPC %s fragment, reas: #%u]", fragment_type(hdr->flags), fd_head->reassembled_in);
            expert_add_info_format(pinfo, NULL, &ei_dcerpc_fragment_reassembled, "%s fragment, reassembled in #%u", fragment_type(hdr->flags), fd_head->reassembled_in);
        }
    } else {
        /* Reassembly not complete - some fragments
           are missing.  Just show the stub data. */
        expert_add_info_format(pinfo, NULL, &ei_dcerpc_fragment, "%s fragment", fragment_type(hdr->flags));

        if (decrypted_tvb) {
            show_stub_data(decrypted_tvb, 0, tree, auth_info, FALSE);
        } else {
            show_stub_data(payload_tvb, 0, tree, auth_info, TRUE);
        }
    }

    pinfo->fragmented = save_fragmented;
}

static void
dissect_dcerpc_cn_rqst(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *dcerpc_tree, proto_tree *tree,
                       e_dce_cn_common_hdr_t *hdr)
{
    conversation_t   *conv;
    guint16           ctx_id;
    guint16           opnum;
    e_uuid_t          obj_id = DCERPC_UUID_NULL;
    dcerpc_auth_info  auth_info;
    guint32           alloc_hint;
    proto_item       *pi;
    proto_item       *parent_pi;
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_alloc_hint, &alloc_hint);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_ctx_id, &ctx_id);
    parent_pi = proto_tree_get_parent(dcerpc_tree);
    if (parent_pi != NULL) {
        proto_item_append_text(parent_pi, ", Ctx: %u", ctx_id);
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_opnum, &opnum);

    /* save context ID for use with dcerpc_add_conv_to_bind_table() */
    decode_data->dcectxid = ctx_id;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", opnum: %u, Ctx: %u",
                    opnum, ctx_id);

    if (hdr->flags & PFC_OBJECT_UUID) {
        dcerpc_tvb_get_uuid(tvb, offset, hdr->drep, &obj_id);
        if (dcerpc_tree) {
            proto_tree_add_guid_format(dcerpc_tree, hf_dcerpc_obj_id, tvb,
                                       offset, 16, (e_guid_t *) &obj_id, "Object UUID: %s",
                                       guid_to_ep_str((e_guid_t *) &obj_id));
        }
        offset += 16;
    }

    /*
     * XXX - what if this was set when the connection was set up,
     * and we just have a security context?
     */
    dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, FALSE, &auth_info);

    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
                             pinfo->srcport, pinfo->destport, 0);
    if (!conv)
        show_stub_data(tvb, offset, dcerpc_tree, &auth_info, TRUE);
    else {
        dcerpc_matched_key matched_key, *new_matched_key;
        dcerpc_call_value *value;

        /* !!! we can NOT check flags.visited here since this will interact
           badly with when SMB handles (i.e. calls the subdissector)
           and desegmented pdu's .
           Instead we check if this pdu is already in the matched table or not
        */
        matched_key.frame = pinfo->fd->num;
        matched_key.call_id = hdr->call_id;
        value = (dcerpc_call_value *)g_hash_table_lookup(dcerpc_matched, &matched_key);
        if (!value) {
            dcerpc_bind_key bind_key;
            dcerpc_bind_value *bind_value;

            bind_key.conv = conv;
            bind_key.ctx_id = ctx_id;
            bind_key.smb_fid = dcerpc_get_transport_salt(pinfo);

            if ((bind_value = (dcerpc_bind_value *)g_hash_table_lookup(dcerpc_binds, &bind_key)) ) {
                if (!(hdr->flags&PFC_FIRST_FRAG)) {
                    dcerpc_cn_call_key call_key;
                    dcerpc_call_value *call_value;

                    call_key.conv = conv;
                    call_key.call_id = hdr->call_id;
                    call_key.smb_fid = dcerpc_get_transport_salt(pinfo);
                    if ((call_value = (dcerpc_call_value *)g_hash_table_lookup(dcerpc_cn_calls, &call_key))) {
                        new_matched_key = (dcerpc_matched_key *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_matched_key));
                        *new_matched_key = matched_key;
                        g_hash_table_insert(dcerpc_matched, new_matched_key, call_value);
                        value = call_value;
                    }
                } else {
                    dcerpc_cn_call_key *call_key;
                    dcerpc_call_value *call_value;

                    /* We found the binding and it is the first fragment
                       (or a complete PDU) of a dcerpc pdu so just add
                       the call to both the call table and the
                       matched table
                    */
                    call_key = (dcerpc_cn_call_key *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_cn_call_key));
                    call_key->conv = conv;
                    call_key->call_id = hdr->call_id;
                    call_key->smb_fid = dcerpc_get_transport_salt(pinfo);

                    /* if there is already a matching call in the table
                       remove it so it is replaced with the new one */
                    if (g_hash_table_lookup(dcerpc_cn_calls, call_key)) {
                        g_hash_table_remove(dcerpc_cn_calls, call_key);
                    }

                    call_value = (dcerpc_call_value *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_call_value));
                    call_value->uuid = bind_value->uuid;
                    call_value->ver = bind_value->ver;
                    call_value->object_uuid = obj_id;
                    call_value->opnum = opnum;
                    call_value->req_frame = pinfo->fd->num;
                    call_value->req_time = pinfo->fd->abs_ts;
                    call_value->rep_frame = 0;
                    call_value->max_ptr = 0;
                    call_value->se_data = NULL;
                    call_value->private_data = NULL;
                    call_value->pol = NULL;
                    call_value->flags = 0;
                    if (!memcmp(&bind_value->transport, &uuid_ndr64, sizeof(uuid_ndr64))) {
                        call_value->flags |= DCERPC_IS_NDR64;
                    }

                    g_hash_table_insert(dcerpc_cn_calls, call_key, call_value);

                    new_matched_key = (dcerpc_matched_key *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_matched_key));
                    *new_matched_key = matched_key;
                    g_hash_table_insert(dcerpc_matched, new_matched_key, call_value);
                    value = call_value;
                }
            }
        }

        if (value) {
            dcerpc_info *di;

            di = get_next_di();
            /* handoff this call */
            di->conv = conv;
            di->call_id = hdr->call_id;
            di->smb_fid = dcerpc_get_transport_salt(pinfo);
            di->ptype = PDU_REQ;
            di->call_data = value;
            di->hf_index = -1;

            if (value->rep_frame != 0) {
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_response_in,
                                         tvb, 0, 0, value->rep_frame);
                PROTO_ITEM_SET_GENERATED(pi);
                if (parent_pi != NULL) {
                    proto_item_append_text(parent_pi, ", [Resp: #%u]", value->rep_frame);
                }
            }

            dissect_dcerpc_cn_stub(tvb, offset, pinfo, dcerpc_tree, tree,
                                    hdr, di, &auth_info, alloc_hint,
                                    value->req_frame);
        } else {
            /* no bind information, simply show stub data */
            proto_tree_add_expert_format(dcerpc_tree, pinfo, &ei_dcerpc_cn_ctx_id_no_bind, tvb, offset, 0, "No bind info for interface Context ID %u - capture start too late?", ctx_id);
            show_stub_data(tvb, offset, dcerpc_tree, &auth_info, TRUE);
        }
    }

    /* Dissect the verifier */
    dissect_dcerpc_verifier(tvb, pinfo, dcerpc_tree, hdr, &auth_info);

}

static void
dissect_dcerpc_cn_resp(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *dcerpc_tree, proto_tree *tree,
                       e_dce_cn_common_hdr_t *hdr)
{
    dcerpc_call_value *value       = NULL;
    conversation_t    *conv;
    guint16            ctx_id;
    dcerpc_auth_info   auth_info;
    guint32            alloc_hint;
    proto_item        *pi;
    proto_item        *parent_pi;
    e_uuid_t           obj_id_null = DCERPC_UUID_NULL;
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_alloc_hint, &alloc_hint);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_ctx_id, &ctx_id);
    parent_pi = proto_tree_get_parent(dcerpc_tree);
    if (parent_pi != NULL) {
        proto_item_append_text(parent_pi, ", Ctx: %u", ctx_id);
    }

    /* save context ID for use with dcerpc_add_conv_to_bind_table() */
    decode_data->dcectxid = ctx_id;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Ctx: %u", ctx_id);

    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                  hf_dcerpc_cn_cancel_count, NULL);
    /* padding */
    offset++;

    /*
     * XXX - what if this was set when the connection was set up,
     * and we just have a security context?
     */
    dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, FALSE, &auth_info);

    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
                             pinfo->srcport, pinfo->destport, 0);

    if (!conv) {
        /* no point in creating one here, really */
        show_stub_data(tvb, offset, dcerpc_tree, &auth_info, TRUE);
    } else {
        dcerpc_matched_key matched_key, *new_matched_key;

        /* !!! we can NOT check flags.visited here since this will interact
           badly with when SMB handles (i.e. calls the subdissector)
           and desegmented pdu's .
           Instead we check if this pdu is already in the matched table or not
        */
        matched_key.frame = pinfo->fd->num;
        matched_key.call_id = hdr->call_id;
        value = (dcerpc_call_value *)g_hash_table_lookup(dcerpc_matched, &matched_key);
        if (!value) {
            dcerpc_cn_call_key call_key;
            dcerpc_call_value *call_value;

            call_key.conv = conv;
            call_key.call_id = hdr->call_id;
            call_key.smb_fid = dcerpc_get_transport_salt(pinfo);

            if ((call_value = (dcerpc_call_value *)g_hash_table_lookup(dcerpc_cn_calls, &call_key))) {
                /* extra sanity check,  only match them if the reply
                   came after the request */
                if (call_value->req_frame<pinfo->fd->num) {
                    new_matched_key = (dcerpc_matched_key *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_matched_key));
                    *new_matched_key = matched_key;
                    g_hash_table_insert(dcerpc_matched, new_matched_key, call_value);
                    value = call_value;
                    if (call_value->rep_frame == 0) {
                        call_value->rep_frame = pinfo->fd->num;
                    }
                }
            }
        }

        if (value) {
            dcerpc_info *di;

            di = get_next_di();
            /* handoff this call */
            di->conv = conv;
            di->call_id = hdr->call_id;
            di->smb_fid = dcerpc_get_transport_salt(pinfo);
            di->ptype = PDU_RESP;
            di->call_data = value;

            proto_tree_add_uint(dcerpc_tree, hf_dcerpc_opnum, tvb, 0, 0, value->opnum);

            /* (optional) "Object UUID" from request */
            if (dcerpc_tree && (memcmp(&value->object_uuid, &obj_id_null, sizeof(obj_id_null)) != 0)) {
                pi = proto_tree_add_guid_format(dcerpc_tree, hf_dcerpc_obj_id, tvb,
                                                offset, 0, (e_guid_t *) &value->object_uuid, "Object UUID: %s",
                                                guid_to_ep_str((e_guid_t *) &value->object_uuid));
                PROTO_ITEM_SET_GENERATED(pi);
            }

            /* request in */
            if (value->req_frame != 0) {
                nstime_t delta_ts;
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_request_in,
                                         tvb, 0, 0, value->req_frame);
                PROTO_ITEM_SET_GENERATED(pi);
                if (parent_pi != NULL) {
                    proto_item_append_text(parent_pi, ", [Req: #%u]", value->req_frame);
                }
                nstime_delta(&delta_ts, &pinfo->fd->abs_ts, &value->req_time);
                pi = proto_tree_add_time(dcerpc_tree, hf_dcerpc_time, tvb, offset, 0, &delta_ts);
                PROTO_ITEM_SET_GENERATED(pi);
            } else {
                proto_tree_add_expert(dcerpc_tree, pinfo, &ei_dcerpc_no_request_found, tvb, 0, 0);
            }

            dissect_dcerpc_cn_stub(tvb, offset, pinfo, dcerpc_tree, tree,
                                   hdr, di, &auth_info, alloc_hint,
                                   value->rep_frame);
        } else {
            /* no bind information, simply show stub data */
            proto_tree_add_expert_format(dcerpc_tree, pinfo, &ei_dcerpc_cn_ctx_id_no_bind, tvb, offset, 0, "No bind info for interface Context ID %u - capture start too late?", ctx_id);
            show_stub_data(tvb, offset, dcerpc_tree, &auth_info, TRUE);
        }
    }

    /* Dissect the verifier */
    dissect_dcerpc_verifier(tvb, pinfo, dcerpc_tree, hdr, &auth_info);
}

static void
dissect_dcerpc_cn_fault(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *dcerpc_tree, e_dce_cn_common_hdr_t *hdr)
{
    dcerpc_call_value *value = NULL;
    conversation_t    *conv;
    guint16            ctx_id;
    guint32            status;
    guint32            alloc_hint;
    dcerpc_auth_info   auth_info;
    proto_item        *pi    = NULL;
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_alloc_hint, &alloc_hint);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_ctx_id, &ctx_id);

    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                  hf_dcerpc_cn_cancel_count, NULL);
    /* padding */
    offset++;

#if 0
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_status, &status);
#endif
    status = ((hdr->drep[0] & DREP_LITTLE_ENDIAN)
              ? tvb_get_letohl(tvb, offset)
              : tvb_get_ntohl(tvb, offset));

    pi = proto_tree_add_item(dcerpc_tree, hf_dcerpc_cn_status, tvb, offset, 4, DREP_ENC_INTEGER(hdr->drep));
    offset+=4;

    expert_add_info_format(pinfo, pi, &ei_dcerpc_cn_status, "Fault: %s", val_to_str(status, reject_status_vals, "Unknown (0x%08x)"));

    /* save context ID for use with dcerpc_add_conv_to_bind_table() */
    decode_data->dcectxid = ctx_id;

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    ", Ctx: %u, status: %s", ctx_id,
                    val_to_str(status, reject_status_vals,
                               "Unknown (0x%08x)"));

    /* padding */
    offset += 4;

    /*
     * XXX - what if this was set when the connection was set up,
     * and we just have a security context?
     */
    dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, FALSE, &auth_info);

    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
                             pinfo->srcport, pinfo->destport, 0);
    if (!conv) {
        /* no point in creating one here, really */
    } else {
        dcerpc_matched_key matched_key, *new_matched_key;

        /* !!! we can NOT check flags.visited here since this will interact
           badly with when SMB handles (i.e. calls the subdissector)
           and desegmented pdu's .
           Instead we check if this pdu is already in the matched table or not
        */
        matched_key.frame = pinfo->fd->num;
        matched_key.call_id = hdr->call_id;
        value = (dcerpc_call_value *)g_hash_table_lookup(dcerpc_matched, &matched_key);
        if (!value) {
            dcerpc_cn_call_key call_key;
            dcerpc_call_value *call_value;

            call_key.conv = conv;
            call_key.call_id = hdr->call_id;
            call_key.smb_fid = dcerpc_get_transport_salt(pinfo);

            if ((call_value = (dcerpc_call_value *)g_hash_table_lookup(dcerpc_cn_calls, &call_key))) {
                new_matched_key = (dcerpc_matched_key *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_matched_key));
                *new_matched_key = matched_key;
                g_hash_table_insert(dcerpc_matched, new_matched_key, call_value);

                value = call_value;
                if (call_value->rep_frame == 0) {
                    call_value->rep_frame = pinfo->fd->num;
                }

            }
        }

        if (value) {
            int length, stub_length;
            dcerpc_info *di;
            proto_item *parent_pi;

            di = get_next_di();
            /* handoff this call */
            di->conv = conv;
            di->call_id = hdr->call_id;
            di->smb_fid = dcerpc_get_transport_salt(pinfo);
            di->ptype = PDU_FAULT;
            di->call_data = value;

            proto_tree_add_uint(dcerpc_tree, hf_dcerpc_opnum, tvb, 0, 0, value->opnum);
            if (value->req_frame != 0) {
                nstime_t delta_ts;
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_request_in,
                                         tvb, 0, 0, value->req_frame);
                PROTO_ITEM_SET_GENERATED(pi);
                parent_pi = proto_tree_get_parent(dcerpc_tree);
                if (parent_pi != NULL) {
                    proto_item_append_text(parent_pi, ", [Req: #%u]", value->req_frame);
                }
                nstime_delta(&delta_ts, &pinfo->fd->abs_ts, &value->req_time);
                pi = proto_tree_add_time(dcerpc_tree, hf_dcerpc_time, tvb, offset, 0, &delta_ts);
                PROTO_ITEM_SET_GENERATED(pi);
            } else {
                proto_tree_add_expert(dcerpc_tree, pinfo, &ei_dcerpc_no_request_found, tvb, 0, 0);
            }

            length = tvb_length_remaining(tvb, offset);
            /* as we now create a tvb in dissect_dcerpc_cn() containing only the
             * stub_data, the following calculation is no longer valid:
             * stub_length = hdr->frag_len - offset - auth_info.auth_size;
             * simply use the remaining length of the tvb instead.
             * XXX - or better use the reported_length?!?
             */
            stub_length = length;
            if (length > stub_length)
                length = stub_length;

            /* If we don't have reassembly enabled, or this packet contains
               the entire PDU, or if we don't have all the data in this
               fragment, just call the handoff directly if this is the
               first fragment or the PDU isn't fragmented. */
            if ( (!dcerpc_reassemble) || PFC_NOT_FRAGMENTED(hdr) ||
                !tvb_bytes_exist(tvb, offset, stub_length) ) {
                if (hdr->flags&PFC_FIRST_FRAG) {
                    /* First fragment, possibly the only fragment */
                    /*
                     * XXX - should there be a third routine for each
                     * function in an RPC subdissector, to handle
                     * fault responses?  The DCE RPC 1.1 spec says
                     * three's "stub data" here, which I infer means
                     * that it's protocol-specific and call-specific.
                     *
                     * It should probably get passed the status code
                     * as well, as that might be protocol-specific.
                     */
                    if (dcerpc_tree) {
                        if (stub_length > 0) {
                            tvb_ensure_bytes_exist(tvb, offset, stub_length);
                            proto_tree_add_text(dcerpc_tree, tvb, offset, stub_length,
                                                "Fault stub data (%d byte%s)",
                                                stub_length,
                                                plurality(stub_length, "", "s"));
                        }
                    }
                } else {
                    /* PDU is fragmented and this isn't the first fragment */
                    if (dcerpc_tree) {
                        if (stub_length > 0) {
                            tvb_ensure_bytes_exist(tvb, offset, stub_length);
                            proto_tree_add_text(dcerpc_tree, tvb, offset, stub_length,
                                                "Fragment data (%d byte%s)",
                                                stub_length,
                                                plurality(stub_length, "", "s"));
                        }
                    }
                }
            } else {
                /* Reassembly is enabled, the PDU is fragmented, and
                   we have all the data in the fragment; the first two
                   of those mean we should attempt reassembly, and the
                   third means we can attempt reassembly. */
                if (dcerpc_tree) {
                    if (length > 0) {
                        tvb_ensure_bytes_exist(tvb, offset, stub_length);
                        proto_tree_add_text(dcerpc_tree, tvb, offset, stub_length,
                                            "Fragment data (%d byte%s)",
                                            stub_length,
                                            plurality(stub_length, "", "s"));
                    }
                }
                if (hdr->flags&PFC_FIRST_FRAG) {  /* FIRST fragment */
                    if ( (!pinfo->fd->flags.visited) && value->rep_frame ) {
                        fragment_add_seq_next(&dcerpc_co_reassembly_table,
                                              tvb, offset,
                                              pinfo, value->rep_frame, NULL,
                                              stub_length,
                                              TRUE);
                    }
                } else if (hdr->flags&PFC_LAST_FRAG) {  /* LAST fragment */
                    if ( value->rep_frame ) {
                        fragment_head *fd_head;

                        fd_head = fragment_add_seq_next(&dcerpc_co_reassembly_table,
                                                        tvb, offset,
                                                        pinfo, value->rep_frame, NULL,
                                                        stub_length,
                                                        TRUE);

                        if (fd_head) {
                            /* We completed reassembly */
                            tvbuff_t *next_tvb;
                            proto_item *frag_tree_item;

                            next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
                            add_new_data_source(pinfo, next_tvb, "Reassembled DCE/RPC");
                            show_fragment_tree(fd_head, &dcerpc_frag_items,
                                               dcerpc_tree, pinfo, next_tvb, &frag_tree_item);

                            /*
                             * XXX - should there be a third routine for each
                             * function in an RPC subdissector, to handle
                             * fault responses?  The DCE RPC 1.1 spec says
                             * three's "stub data" here, which I infer means
                             * that it's protocol-specific and call-specific.
                             *
                             * It should probably get passed the status code
                             * as well, as that might be protocol-specific.
                             */
                            if (dcerpc_tree) {
                                if (length > 0) {
                                    tvb_ensure_bytes_exist(tvb, offset, stub_length);
                                    proto_tree_add_text(dcerpc_tree, tvb, offset, stub_length,
                                                        "Fault stub data (%d byte%s)",
                                                        stub_length,
                                                        plurality(stub_length, "", "s"));
                                }
                            }
                        }
                    }
                } else {  /* MIDDLE fragment(s) */
                    if ( (!pinfo->fd->flags.visited) && value->rep_frame ) {
                        fragment_add_seq_next(&dcerpc_co_reassembly_table,
                                              tvb, offset,
                                              pinfo, value->rep_frame, NULL,
                                              stub_length,
                                              TRUE);
                    }
                }
            }
        }
    }
}

static void
dissect_dcerpc_cn_rts(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                      proto_tree *dcerpc_tree, e_dce_cn_common_hdr_t *hdr)
{
    proto_item *tf              = NULL;
    proto_item *parent_pi       = NULL;
    proto_tree *cn_rts_pdu_tree = NULL;
    guint16     rts_flags;
    guint16     commands_nb     = 0;
    guint32    *cmd;
    guint32     i;
    const char *info_str        = NULL;

    /* Dissect specific RTS header */
    rts_flags = dcerpc_tvb_get_ntohs(tvb, offset, hdr->drep);
    if (dcerpc_tree) {
        proto_tree *cn_rts_flags_tree;

        tf = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_cn_rts_flags, tvb, offset, 2, rts_flags);
        cn_rts_flags_tree = proto_item_add_subtree(tf, ett_dcerpc_cn_rts_flags);
        proto_tree_add_boolean(cn_rts_flags_tree, hf_dcerpc_cn_rts_flags_none, tvb, offset, 1, rts_flags);
        proto_tree_add_boolean(cn_rts_flags_tree, hf_dcerpc_cn_rts_flags_ping, tvb, offset, 1, rts_flags);
        proto_tree_add_boolean(cn_rts_flags_tree, hf_dcerpc_cn_rts_flags_other_cmd, tvb, offset, 1, rts_flags);
        proto_tree_add_boolean(cn_rts_flags_tree, hf_dcerpc_cn_rts_flags_recycle_channel, tvb, offset, 1, rts_flags);
        proto_tree_add_boolean(cn_rts_flags_tree, hf_dcerpc_cn_rts_flags_in_channel, tvb, offset, 1, rts_flags);
        proto_tree_add_boolean(cn_rts_flags_tree, hf_dcerpc_cn_rts_flags_out_channel, tvb, offset, 1, rts_flags);
        proto_tree_add_boolean(cn_rts_flags_tree, hf_dcerpc_cn_rts_flags_eof, tvb, offset, 1, rts_flags);
    }
    offset += 2;

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_rts_commands_nb, &commands_nb);

    /* Create the RTS PDU tree - we do not yet know its name */
    tf = proto_tree_add_text(dcerpc_tree, tvb, offset, tvb_length_remaining(tvb, offset), "RTS PDU: %u commands", commands_nb);
    cn_rts_pdu_tree = proto_item_add_subtree(tf, ett_dcerpc_cn_rts_pdu);

    cmd = (guint32 *)wmem_alloc(wmem_packet_scope(), sizeof (guint32) * (commands_nb + 1));

    /* Dissect commands */
    for (i = 0; i < commands_nb; ++i) {
        proto_tree *cn_rts_command_tree = NULL;
        const guint32 command = dcerpc_tvb_get_ntohl(tvb, offset, hdr->drep);
        cmd[i] = command;
        tf = proto_tree_add_uint(cn_rts_pdu_tree, hf_dcerpc_cn_rts_command, tvb, offset, 4, command);
        cn_rts_command_tree = proto_item_add_subtree(tf, ett_dcerpc_cn_rts_command);
        offset += 4;
        switch (command) {
        case RTS_CMD_RECEIVEWINDOWSIZE:
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_receivewindowsize, NULL);
            break;
        case RTS_CMD_FLOWCONTROLACK:
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_fack_bytesreceived, NULL);
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_fack_availablewindow, NULL);
            offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_fack_channelcookie, NULL);
            break;
        case RTS_CMD_CONNECTIONTIMEOUT:
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_connectiontimeout, NULL);
            break;
        case RTS_CMD_COOKIE:
            offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_cookie, NULL);
            break;
        case RTS_CMD_CHANNELLIFETIME:
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_channellifetime, NULL);
            break;
        case RTS_CMD_CLIENTKEEPALIVE:
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_clientkeepalive, NULL);
            break;
        case RTS_CMD_VERSION:
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_version, NULL);
            break;
        case RTS_CMD_EMPTY:
            break;
        case RTS_CMD_PADDING: {
            guint8 *padding;
            const guint32 conformance_count = dcerpc_tvb_get_ntohl(tvb, offset, hdr->drep);
            proto_tree_add_uint(cn_rts_command_tree, hf_dcerpc_cn_rts_command_conformancecount, tvb, offset, 4, conformance_count);
            offset += 4;
            padding = (guint8 *)tvb_memdup(NULL, tvb, offset, conformance_count);
            proto_tree_add_bytes(cn_rts_command_tree, hf_dcerpc_cn_rts_command_padding, tvb, offset, conformance_count, padding);
            offset += conformance_count;
        } break;
        case RTS_CMD_NEGATIVEANCE:
            break;
        case RTS_CMD_ANCE:
            break;
        case RTS_CMD_CLIENTADDRESS: {
            guint8 *padding;
            const guint32 addrtype = dcerpc_tvb_get_ntohl(tvb, offset, hdr->drep);
            proto_tree_add_uint(cn_rts_command_tree, hf_dcerpc_cn_rts_command_addrtype, tvb, offset, 4, addrtype);
            offset += 4;
            switch (addrtype) {
            case RTS_IPV4: {
               const guint32 addr4 = tvb_get_ipv4(tvb, offset);
               proto_tree_add_text(cn_rts_command_tree, tvb, offset, 4, "%s", get_hostname(addr4));
               offset += 4;
            } break;
            case RTS_IPV6: {
               struct e_in6_addr addr6;
               tvb_get_ipv6(tvb, offset, &addr6);
               proto_tree_add_text(cn_rts_command_tree, tvb, offset, 16, "%s", get_hostname6(&addr6));
               offset += 16;
            } break;
            }
            padding = (guint8 *)tvb_memdup(NULL, tvb, offset, 12);
            proto_tree_add_bytes(cn_rts_command_tree, hf_dcerpc_cn_rts_command_padding, tvb, offset, 12, padding);
            offset += 12;
        } break;
        case RTS_CMD_ASSOCIATIONGROUPID:
            offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_associationgroupid, NULL);
            break;
        case RTS_CMD_DESTINATION:
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_forwarddestination, NULL);
            break;
        case RTS_CMD_PINGTRAFFICSENTNOTIFY:
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, cn_rts_command_tree, hdr->drep, hf_dcerpc_cn_rts_command_pingtrafficsentnotify, NULL);
            break;
        default:
            proto_tree_add_text(cn_rts_command_tree, tvb, offset, 0, "unknown RTS command number");
            break;
        }
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RPCH");

    /* Define which PDU Body we are dealing with */
    info_str = "unknown RTS PDU";

    switch (rts_flags) {
    case RTS_FLAG_NONE:
        switch (commands_nb) {
        case 1:
            if (cmd[0] == 0x2) {
                info_str = "CONN/A3";
            } else if (cmd[0] == 0x3) {
                info_str = "IN_R1/A5,IN_R1/A6,IN_R2/A2,IN_R2/A5,OUT_R2/A4";
            } else if (cmd[0] == 0x7) {
                info_str = "IN_R1/B1";
            } else if (cmd[0] == 0x0) {
                info_str = "IN_R1/B2";
            } else if (cmd[0] == 0xD) {
                info_str = "IN_R2/A3,IN_R2/A4";
            } else if (cmd[0] == 0xA) {
                info_str = "OUT_R1/A9,OUT_R1/A10,OUT_R1/A11,OUT_R2/B1,OUT_R2/B2";
            }
            break;
        case 2:
            if ((cmd[0] == 0x0) && (cmd[1] == 0x6)) {
                info_str = "CONN/B3";
            } else if ((cmd[0] == 0xD) && (cmd[1] == 0xA)) {
                info_str = "OUT_R2/A5,OUT_R2/A6";
            }
            break;
        case 3:
            if ((cmd[0] == 0x6) && (cmd[1] == 0x0) && (cmd[2] == 0x2)) {
                info_str = "CONN/C1,CONN/C2";
            }
            break;
        case 4:
            if ((cmd[0] == 0x6) && (cmd[1] == 0x3) && (cmd[2] == 0x3) && (cmd[3] == 0x0)) {
                info_str = "CONN/A1";
            } else if ((cmd[0] == 0xD) && (cmd[1] == 0x6) && (cmd[2] == 0x0) && (cmd[3] == 0x2)) {
                info_str = "IN_R1/A3,IN_R1/A4";
            }
            break;
        case 6:
            if ((cmd[0] == 0x6) && (cmd[1] == 0x3) && (cmd[2] == 0x3) && (cmd[3] == 0x4) && (cmd[4] == 0x5) && (cmd[5] == 0xC)) {
               info_str = "CONN/B1";
            }
            break;
        default:
            break;
        }
        break;
     case RTS_FLAG_PING:
        switch (commands_nb) {
        case 0:
            info_str = "Ping";
            break;
        case 1:
            if ((cmd[0] == 0x7) || (cmd[0] == 0x8)) {
                info_str = "OUT_R2/C1";
            }
            break;
        default:
            break;
        }
        break;
     case RTS_FLAG_OTHER_CMD:
        switch (commands_nb) {
        case 1:
            if (cmd[0] == 0x5) {
                info_str = "Keep-Alive";
            } else if (cmd[0] == 0xE) {
                info_str = "PingTrafficSentNotify";
            } else if (cmd[0] == 0x1) {
                info_str = "FlowControlAck";
            }
            break;
        case 2:
            if ((cmd[0] == 0xD) && (cmd[1] == 0x1)) {
                info_str = "FlowControlAckWithDestination";
            }
            break;
        default:
            break;
        }
        break;
     case RTS_FLAG_RECYCLE_CHANNEL:
        switch (commands_nb) {
        case 1:
            if (cmd[0] == 0xD) {
                info_str = "OUT_R1/A1,OUT_R1/A2,OUT_R2/A1,OUT_R2/A2";
            }
            break;
        case 4:
            if ((cmd[0] == 0x6) && (cmd[1] == 0x3) && (cmd[2] == 0x3) && (cmd[3] == 0x3)) {
                info_str = "IN_R1/A1,IN_R2/A1";
            }
            break;
        case 5:
            if ((cmd[0] == 0x6) && (cmd[1] == 0x3) && (cmd[2] == 0x3) && (cmd[3] == 0x3) && (cmd[4] == 0x0)) {
                info_str = "OUT_R1/A3,OUT_R2/A3";
            }
            break;
        default:
            break;
        }
        break;
     case RTS_FLAG_IN_CHANNEL|RTS_FLAG_RECYCLE_CHANNEL:
        switch (commands_nb) {
        case 6:
            if ((cmd[0] == 0x6) && (cmd[1] == 0x3) && (cmd[2] == 0x3) && (cmd[3] == 0x3) && (cmd[4] == 0x0) && (cmd[5] == 0x2)) {
                info_str = "IN_R1/A2";
            }
            break;
        default:
            break;
        }
     case RTS_FLAG_IN_CHANNEL:
        switch (commands_nb) {
        case 7:
            if ((cmd[0] == 0x6) && (cmd[1] == 0x3) && (cmd[2] == 0x3) && (cmd[3] == 0x0) && (cmd[4] == 0x2) && (cmd[5] == 0xC) && (cmd[6] == 0xB)) {
                info_str = "CONN/B2";
            }
            break;
        default:
            break;
        }
     case RTS_FLAG_OUT_CHANNEL|RTS_FLAG_RECYCLE_CHANNEL:
        switch (commands_nb) {
        case 7:
            if ((cmd[0] == 0x6) && (cmd[1] == 0x3) && (cmd[2] == 0x3) && (cmd[3] == 0x3) && (cmd[4] == 0x4) && (cmd[5] == 0) && (cmd[6] == 0x2)) {
                info_str = "OUT_R1/A4";
            }
            break;
        default:
            break;
        }
        break;
     case RTS_FLAG_OUT_CHANNEL:
        switch (commands_nb) {
        case 2:
            if ((cmd[0] == 0xD) && (cmd[1] == 0x3)) {
                info_str = "OUT_R1/A7,OUT_R1/A8,OUT_R2/A8";
            }
            break;
        case 3:
            if ((cmd[0] == 0xD) && (cmd[1] == 0x6) && (cmd[2] == 0x2)) {
                info_str = "OUT_R1/A5,OUT_R1/A6";
            } else if ((cmd[0] == 0xD) && (cmd[1] == 0x3) && (cmd[2] == 0x6)) {
                info_str = "OUT_R2/A7";
            }
            break;
        case 5:
            if ((cmd[0] == 0x6) && (cmd[1] == 0x3) && (cmd[2] == 0x3) && (cmd[3] == 0x4) && (cmd[4] == 0x0)) {
                info_str = "CONN/A2";
            }
            break;
        default:
            break;
        }
    case RTS_FLAG_EOF:
        switch (commands_nb) {
        case 1:
            if (cmd[0] == 0xA) {
                info_str = "OUT_R2/B3";
            }
            break;
        default:
            break;
        }
        break;
    case RTS_FLAG_ECHO:
        switch (commands_nb) {
        case 0:
            info_str = "Echo";
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s, ", info_str);
    col_set_fence(pinfo->cinfo,COL_INFO);

    parent_pi = proto_tree_get_parent(dcerpc_tree);
    if (parent_pi != NULL) {
        proto_item_append_text(parent_pi, ", %s", info_str);
    }
}

/*
 * DCERPC dissector for connection oriented calls.
 * We use transport type to later multiplex between what kind of
 * pinfo->private_data structure to expect.
 */
static gboolean
dissect_dcerpc_cn(tvbuff_t *tvb, int offset, packet_info *pinfo,
                  proto_tree *tree, gboolean can_desegment, int *pkt_len)
{
    static const guint8 nulls[4]         = { 0 };
    int                    start_offset;
    int                    padding       = 0;
    int                    subtvb_len    = 0;
    proto_item            *ti            = NULL;
    proto_item            *tf            = NULL;
    proto_tree            *dcerpc_tree   = NULL;
    proto_tree            *cn_flags_tree = NULL;
    proto_tree            *drep_tree     = NULL;
    e_dce_cn_common_hdr_t  hdr;
    dcerpc_auth_info       auth_info;
    tvbuff_t              *fragment_tvb;
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    /*
     * when done over nbt, dcerpc requests are padded with 4 bytes of null
     * data for some reason.
     *
     * XXX - if that's always the case, the right way to do this would
     * be to have a "dissect_dcerpc_cn_nb" routine which strips off
     * the 4 bytes of null padding, and make that the dissector
     * used for "netbios".
     */
    if (tvb_memeql(tvb, offset, nulls, 4) == 0) {

        /*
         * Skip the padding.
         */
        offset += 4;
        padding += 4;
    }
    /*
     * Check if this looks like a C/O DCERPC call
     */
    if (!tvb_bytes_exist(tvb, offset, sizeof (hdr))) {
        return FALSE;   /* not enough information to check */
    }
    start_offset = offset;
    hdr.rpc_ver = tvb_get_guint8(tvb, offset++);
    if (hdr.rpc_ver != 5)
        return FALSE;
    hdr.rpc_ver_minor = tvb_get_guint8(tvb, offset++);
    if ((hdr.rpc_ver_minor != 0) && (hdr.rpc_ver_minor != 1))
        return FALSE;
    hdr.ptype = tvb_get_guint8(tvb, offset++);
    if (hdr.ptype > PDU_RTS)
        return FALSE;

    hdr.flags = tvb_get_guint8(tvb, offset++);
    tvb_memcpy(tvb, (guint8 *)hdr.drep, offset, sizeof (hdr.drep));
    offset += (int)sizeof (hdr.drep);

    hdr.frag_len = dcerpc_tvb_get_ntohs(tvb, offset, hdr.drep);
    offset += 2;
    hdr.auth_len = dcerpc_tvb_get_ntohs(tvb, offset, hdr.drep);
    offset += 2;
    hdr.call_id = dcerpc_tvb_get_ntohl(tvb, offset, hdr.drep);
    /*offset += 4;*/

    if (decode_data->dcectxid == 0) {
        col_append_fstr(pinfo->cinfo, COL_DCE_CALL, "%u", hdr.call_id);
    } else {
        /* this is not the first DCE-RPC request/response in this (TCP?-)PDU,
         * prepend a delimiter */
        col_append_fstr(pinfo->cinfo, COL_DCE_CALL, "#%u", hdr.call_id);
    }

    if (can_desegment && pinfo->can_desegment
        && !tvb_bytes_exist(tvb, start_offset, hdr.frag_len)) {
        pinfo->desegment_offset = start_offset;
        pinfo->desegment_len = hdr.frag_len - tvb_length_remaining(tvb, start_offset);
        *pkt_len = 0;   /* desegmentation required */
        return TRUE;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCERPC");

    if (decode_data->dcectxid != 0) {
        /* this is not the first DCE-RPC request/response in this (TCP?-)PDU,
         * append a delimiter and set a column fence */
        col_append_str(pinfo->cinfo, COL_INFO, " # ");
        col_set_fence(pinfo->cinfo,COL_INFO);
    }
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s: call_id: %u",
                 pckt_vals[hdr.ptype].strptr, hdr.call_id);

    if (decode_data->dcectxid != 0) {
        /* this is not the first DCE-RPC request/response in this (TCP?-)PDU */
        expert_add_info(pinfo, NULL, &ei_dcerpc_fragment_multiple);
    }

    offset = start_offset;
    tvb_ensure_bytes_exist(tvb, offset, 16);
    if (tree) {
        ti = proto_tree_add_item(tree, proto_dcerpc, tvb, offset, hdr.frag_len, ENC_NA);
        dcerpc_tree = proto_item_add_subtree(ti, ett_dcerpc);
    }

    proto_tree_add_uint(dcerpc_tree, hf_dcerpc_ver, tvb, offset, 1, hdr.rpc_ver);
    offset++;

    proto_tree_add_uint(dcerpc_tree, hf_dcerpc_ver_minor, tvb, offset, 1, hdr.rpc_ver_minor);
    offset++;

    tf = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_packet_type, tvb, offset, 1, hdr.ptype);
    offset++;

#if 0  /* XXX - too much "output noise", removed for now  */
       if (hdr.ptype == PDU_BIND || hdr.ptype == PDU_ALTER ||
       hdr.ptype == PDU_BIND_ACK || hdr.ptype == PDU_ALTER_ACK)
       expert_add_info_format(pinfo, tf, &ei_dcerpc_context_change, "Context change: %s", val_to_str(hdr.ptype, pckt_vals, "(0x%x)"));
#endif
    if (hdr.ptype == PDU_BIND_NAK)
        expert_add_info(pinfo, tf, &ei_dcerpc_bind_not_acknowledged);

    if (tree) {
        proto_item_append_text(ti, " %s, Fragment: %s",
                               val_to_str(hdr.ptype, pckt_vals, "Unknown (0x%02x)"),
                               fragment_type(hdr.flags));

        tf = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_cn_flags, tvb, offset, 1, hdr.flags);
        cn_flags_tree = proto_item_add_subtree(tf, ett_dcerpc_cn_flags);
    }
    proto_tree_add_boolean(cn_flags_tree, hf_dcerpc_cn_flags_object, tvb, offset, 1, hdr.flags);
    proto_tree_add_boolean(cn_flags_tree, hf_dcerpc_cn_flags_maybe, tvb, offset, 1, hdr.flags);
    proto_tree_add_boolean(cn_flags_tree, hf_dcerpc_cn_flags_dne, tvb, offset, 1, hdr.flags);
    proto_tree_add_boolean(cn_flags_tree, hf_dcerpc_cn_flags_mpx, tvb, offset, 1, hdr.flags);
    proto_tree_add_boolean(cn_flags_tree, hf_dcerpc_cn_flags_reserved, tvb, offset, 1, hdr.flags);
    proto_tree_add_boolean(cn_flags_tree, hf_dcerpc_cn_flags_cancel_pending, tvb, offset, 1, hdr.flags);
    proto_tree_add_boolean(cn_flags_tree, hf_dcerpc_cn_flags_last_frag, tvb, offset, 1, hdr.flags);
    proto_tree_add_boolean(cn_flags_tree, hf_dcerpc_cn_flags_first_frag, tvb, offset, 1, hdr.flags);
    offset++;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Fragment: %s", fragment_type(hdr.flags));

    if (dcerpc_tree) {
        tf = proto_tree_add_bytes(dcerpc_tree, hf_dcerpc_drep, tvb, offset, 4, hdr.drep);
        drep_tree = proto_item_add_subtree(tf, ett_dcerpc_drep);
    }
    proto_tree_add_uint(drep_tree, hf_dcerpc_drep_byteorder, tvb, offset, 1, hdr.drep[0] >> 4);
    proto_tree_add_uint(drep_tree, hf_dcerpc_drep_character, tvb, offset, 1, hdr.drep[0] & 0x0f);
    proto_tree_add_uint(drep_tree, hf_dcerpc_drep_fp, tvb, offset+1, 1, hdr.drep[1]);
    offset += (int)sizeof (hdr.drep);

    proto_tree_add_uint(dcerpc_tree, hf_dcerpc_cn_frag_len, tvb, offset, 2, hdr.frag_len);
    offset += 2;

    proto_tree_add_uint(dcerpc_tree, hf_dcerpc_cn_auth_len, tvb, offset, 2, hdr.auth_len);
    offset += 2;

    proto_tree_add_uint(dcerpc_tree, hf_dcerpc_cn_call_id, tvb, offset, 4, hdr.call_id);
    offset += 4;

    if (ti) {
        proto_item_append_text(ti, ", FragLen: %u, Call: %u", hdr.frag_len, hdr.call_id);
    }

    /*
     * None of the stuff done above should throw an exception, because
     * we would have rejected this as "not DCE RPC" if we didn't have all
     * of it.  (XXX - perhaps we should request reassembly if we have
     * enough of the header to consider it DCE RPC but not enough to
     * get the fragment length; in that case the stuff still wouldn't
     * throw an exception.)
     *
     * The rest of the stuff might, so return the PDU length to our caller.
     * XXX - should we construct a tvbuff containing only the PDU and
     * use that?  Or should we have separate "is this a DCE RPC PDU",
     * "how long is it", and "dissect it" routines - which might let us
     * do most of the work in "tcp_dissect_pdus()"?
     */
    if (pkt_len != NULL)
        *pkt_len = hdr.frag_len + padding;

    /* The remaining bytes in the current tvb might contain multiple
     * DCE/RPC fragments, so create a new tvb subset for this fragment.
     * Only limit the end of the fragment, but not the offset start,
     * as the authentication function dissect_dcerpc_cn_auth() will fail
     * (and other functions might fail as well) computing the right start
     * offset otherwise.
     */
    subtvb_len = MIN(hdr.frag_len, tvb_length(tvb));
    fragment_tvb = tvb_new_subset(tvb, start_offset,
                                  subtvb_len /* length */,
                                  hdr.frag_len /* reported_length */);

    /*
     * Packet type specific stuff is next.
     */
    switch (hdr.ptype) {
    case PDU_BIND:
    case PDU_ALTER:
        dissect_dcerpc_cn_bind(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_BIND_ACK:
    case PDU_ALTER_ACK:
        dissect_dcerpc_cn_bind_ack(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_AUTH3:
        /*
         * Nothing after the common header other than credentials.
         */
        dissect_dcerpc_cn_auth(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr, TRUE,
                               &auth_info);
        break;

    case PDU_REQ:
        dissect_dcerpc_cn_rqst(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, tree, &hdr);
        break;

    case PDU_RESP:
        dissect_dcerpc_cn_resp(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, tree, &hdr);
        break;

    case PDU_FAULT:
        dissect_dcerpc_cn_fault(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_BIND_NAK:
        dissect_dcerpc_cn_bind_nak(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_CO_CANCEL:
    case PDU_ORPHANED:
        /*
         * Nothing after the common header other than an authentication
         * verifier.
         */
        dissect_dcerpc_cn_auth(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr, FALSE,
                               &auth_info);
        break;

    case PDU_SHUTDOWN:
        /*
         * Nothing after the common header, not even an authentication
         * verifier.
         */
        break;
    case PDU_RTS:
      dissect_dcerpc_cn_rts(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr);
      break;

    default:
        /* might as well dissect the auth info */
        dissect_dcerpc_cn_auth(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr, FALSE,
                               &auth_info);
        break;
    }
    return TRUE;
}

/*
 * DCERPC dissector for connection oriented calls over packet-oriented
 * transports
 */
static gboolean
dissect_dcerpc_cn_pk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    /*
     * Only one PDU per transport packet, and only one transport
     * packet per PDU.
     */
    decode_data->dcetransporttype = DCE_TRANSPORT_UNKNOWN;
    if (!dissect_dcerpc_cn(tvb, 0, pinfo, tree, FALSE, NULL)) {
        /*
         * It wasn't a DCERPC PDU.
         */
        return FALSE;
    } else {
        /*
         * It was.
         */
        return TRUE;
    }
}

/*
 * DCERPC dissector for connection oriented calls over byte-stream
 * transports.
 * we need to distinguish here between SMB and non-TCP (more in the future?)
 * to be able to know what kind of private_data structure to expect.
 */
static gboolean
dissect_dcerpc_cn_bs_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    volatile int      offset      = 0;
    int               pdu_len     = 0;
    volatile int      dcerpc_pdus = 0;
    volatile gboolean ret         = FALSE;

    /*
     * There may be multiple PDUs per transport packet; keep
     * processing them.
     */
    while (tvb_reported_length_remaining(tvb, offset) != 0) {
        TRY {
            pdu_len = 0;
            if (dissect_dcerpc_cn(tvb, offset, pinfo, tree,
                                  dcerpc_cn_desegment, &pdu_len)) {
                dcerpc_pdus++;
            }
        } CATCH_NONFATAL_ERRORS {
            /*
             * Somebody threw an exception that means that there
             * was a problem dissecting the payload; that means
             * that a dissector was found, so we don't need to
             * dissect the payload as data or update the protocol
             * or info columns.
             *
             * Just show the exception and then continue dissecting
             * PDUs.
             */
            show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
            /*
             * Presumably it looked enough like a DCE RPC PDU that we
             * dissected enough of it to throw an exception.
             */
            dcerpc_pdus++;
        } ENDTRY;

        if (dcerpc_pdus == 0) {
            gboolean try_desegment = FALSE;
            if (dcerpc_cn_desegment && pinfo->can_desegment &&
                    !tvb_bytes_exist(tvb, offset, sizeof(e_dce_cn_common_hdr_t))) {
                /* look for a previous occurrence of the DCE-RPC protocol */
                wmem_list_frame_t *cur;
                cur = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
                while (cur != NULL) {
                    if (proto_dcerpc == (gint)GPOINTER_TO_UINT(wmem_list_frame_data(cur))) {
                        try_desegment = TRUE;
                        break;
                    }
                    cur = wmem_list_frame_prev(cur);
                }
            }

            if (try_desegment) {
                /* It didn't look like DCE-RPC but we already had one DCE-RPC
                 * layer in this packet and what we have is short. Assume that
                 * it was just too short to tell and ask the TCP layer for more
                 * data. */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = (guint32)(sizeof(e_dce_cn_common_hdr_t) - tvb_length_remaining(tvb, offset));
            } else {
                /* Really not DCE-RPC */
                break;
            }
        }

        /*
         * Well, we've seen at least one DCERPC PDU.
         */
        ret = TRUE;

        /* if we had more than one Req/Resp in this PDU change the protocol column */
        /* this will formerly contain the last interface name, which may not be the same for all Req/Resp */
        if (dcerpc_pdus >= 2)
            col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "%u*DCERPC", dcerpc_pdus);

        if (pdu_len == 0) {
            /*
             * Desegmentation required - bail now, but give the user a hint that desegmentation might be done later.
             */
            proto_tree_add_uint_format(tree, hf_dcerpc_cn_deseg_req, tvb, offset,
                                       0,
                                       tvb_reported_length_remaining(tvb, offset),
                                       "[DCE RPC: %u byte%s left, desegmentation might follow]",
                                       tvb_reported_length_remaining(tvb, offset),
                                       plurality(tvb_reported_length_remaining(tvb, offset), "", "s"));
            break;
        }

        /*
         * Step to the next PDU.
         */
        offset += pdu_len;
    }
    return ret;
}

static gboolean
dissect_dcerpc_cn_bs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    decode_data->dcetransporttype = DCE_TRANSPORT_UNKNOWN;
    return dissect_dcerpc_cn_bs_body(tvb, pinfo, tree);
}

static gboolean
dissect_dcerpc_cn_smbpipe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    decode_data->dcetransporttype = DCE_CN_TRANSPORT_SMBPIPE;
    return dissect_dcerpc_cn_bs_body(tvb, pinfo, tree);
}

static gboolean
dissect_dcerpc_cn_smb2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    decode_data->dcetransporttype = DCE_TRANSPORT_UNKNOWN;
    return dissect_dcerpc_cn_bs_body(tvb, pinfo, tree);
}



static void
dissect_dcerpc_dg_auth(tvbuff_t *tvb, int offset, proto_tree *dcerpc_tree,
                       e_dce_dg_common_hdr_t *hdr, int *auth_level_p)
{
    proto_item *ti        = NULL;
    proto_tree *auth_tree = NULL;
    guint8      protection_level;

    /*
     * Initially set "*auth_level_p" to -1 to indicate that we haven't
     * yet seen any authentication level information.
     */
    if (auth_level_p != NULL)
        *auth_level_p = -1;

    /*
     * The authentication information is at the *end* of the PDU; in
     * request and response PDUs, the request and response stub data
     * come before it.
     *
     * If the full packet is here, and there's data past the end of the
     * packet body, then dissect the auth info.
     */
    offset += hdr->frag_len;
    if (tvb_length_remaining(tvb, offset) > 0) {
        switch (hdr->auth_proto) {

        case DCE_C_RPC_AUTHN_PROTOCOL_KRB5:
            ti = proto_tree_add_text(dcerpc_tree, tvb, offset, -1, "Kerberos authentication verifier");
            auth_tree = proto_item_add_subtree(ti, ett_dcerpc_krb5_auth_verf);
            protection_level = tvb_get_guint8(tvb, offset);
            if (auth_level_p != NULL)
                *auth_level_p = protection_level;
            proto_tree_add_uint(auth_tree, hf_dcerpc_krb5_av_prot_level, tvb, offset, 1, protection_level);
            offset++;
            proto_tree_add_item(auth_tree, hf_dcerpc_krb5_av_key_vers_num, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if (protection_level == DCE_C_AUTHN_LEVEL_PKT_PRIVACY)
                offset += 6;    /* 6 bytes of padding */
            else
                offset += 2;    /* 2 bytes of padding */
            proto_tree_add_item(auth_tree, hf_dcerpc_krb5_av_key_auth_verifier, tvb, offset, 16, ENC_NA);
            /*offset += 16;*/
            break;

        default:
            proto_tree_add_text(dcerpc_tree, tvb, offset, -1, "Authentication verifier");
            break;
        }
    }
}

static void
dissect_dcerpc_dg_cancel_ack(tvbuff_t *tvb, int offset, packet_info *pinfo,
                             proto_tree *dcerpc_tree,
                             e_dce_dg_common_hdr_t *hdr)
{
    guint32 version;

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree,
                                   hdr->drep, hf_dcerpc_dg_cancel_vers,
                                   &version);

    switch (version) {

    case 0:
        /* The only version we know about */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree,
                                       hdr->drep, hf_dcerpc_dg_cancel_id,
                                       NULL);
        /*offset = */dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree,
                                      hdr->drep, hf_dcerpc_dg_server_accepting_cancels,
                                      NULL);
        break;
    }
}

static void
dissect_dcerpc_dg_cancel(tvbuff_t *tvb, int offset, packet_info *pinfo,
                         proto_tree *dcerpc_tree,
                         e_dce_dg_common_hdr_t *hdr)
{
    guint32 version;

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree,
                                   hdr->drep, hf_dcerpc_dg_cancel_vers,
                                   &version);

    switch (version) {

    case 0:
        /* The only version we know about */
        /*offset = */dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree,
                                       hdr->drep, hf_dcerpc_dg_cancel_id,
                                       NULL);
        /* XXX - are NDR Booleans 32 bits? */

        /* XXX - the RPC reference in chapter: "the cancel PDU" doesn't mention
           the accepting_cancels field (it's only in the cancel_ack PDU)! */
        /*offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree,
          hdr->drep, hf_dcerpc_dg_server_accepting_cancels,
          NULL);*/
        break;
    }
}

static void
dissect_dcerpc_dg_fack(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *dcerpc_tree,
                       e_dce_dg_common_hdr_t *hdr)
{
    guint8  version;
    guint16 serial_num;
    guint16 selack_len;
    guint   i;

    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree,
                                  hdr->drep, hf_dcerpc_dg_fack_vers,
                                  &version);
    /* padding */
    offset++;

    switch (version) {

    case 0:     /* The only version documented in the DCE RPC 1.1 spec */
    case 1:     /* This appears to be the same */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree,
                                       hdr->drep, hf_dcerpc_dg_fack_window_size,
                                       NULL);
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree,
                                       hdr->drep, hf_dcerpc_dg_fack_max_tsdu,
                                       NULL);
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree,
                                       hdr->drep, hf_dcerpc_dg_fack_max_frag_size,
                                       NULL);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree,
                                       hdr->drep, hf_dcerpc_dg_fack_serial_num,
                                       &serial_num);
        col_append_fstr(pinfo->cinfo, COL_INFO, " serial: %u",
                         serial_num);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree,
                                       hdr->drep, hf_dcerpc_dg_fack_selack_len,
                                       &selack_len);
        for (i = 0; i < selack_len; i++) {
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree,
                                           hdr->drep, hf_dcerpc_dg_fack_selack,
                                           NULL);
        }

        break;
    }
}

static void
dissect_dcerpc_dg_reject_fault(tvbuff_t *tvb, int offset, packet_info *pinfo,
                               proto_tree *dcerpc_tree,
                               e_dce_dg_common_hdr_t *hdr)
{
    guint32 status;

    /*offset = */dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree,
                                   hdr->drep, hf_dcerpc_dg_status,
                                   &status);

    col_append_fstr (pinfo->cinfo, COL_INFO,
                     ": status: %s",
                     val_to_str(status, reject_status_vals, "Unknown (0x%08x)"));
}

static void
dissect_dcerpc_dg_stub(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *dcerpc_tree, proto_tree *tree,
                       e_dce_dg_common_hdr_t *hdr, dcerpc_info *di)
{
    int            length, reported_length, stub_length;
    gboolean       save_fragmented;
    fragment_head *fd_head;
    tvbuff_t      *next_tvb;
    proto_item    *pi;
    proto_item    *parent_pi;

    col_append_fstr(pinfo->cinfo, COL_INFO, " opnum: %u len: %u",
                    di->call_data->opnum, hdr->frag_len );

    length = tvb_length_remaining(tvb, offset);
    reported_length = tvb_reported_length_remaining(tvb, offset);
    stub_length = hdr->frag_len;
    if (length > stub_length)
        length = stub_length;
    if (reported_length > stub_length)
        reported_length = stub_length;

    save_fragmented = pinfo->fragmented;

    /* If we don't have reassembly enabled, or this packet contains
       the entire PDU, or if this is a short frame (or a frame
       not reassembled at a lower layer) that doesn't include all
       the data in the fragment, just call the handoff directly if
       this is the first fragment or the PDU isn't fragmented. */
    if ( (!dcerpc_reassemble) || !(hdr->flags1 & PFCL1_FRAG) ||
        !tvb_bytes_exist(tvb, offset, stub_length) ) {
        if (hdr->frag_num == 0) {


            /* First fragment, possibly the only fragment */

            /*
             * XXX - authentication info?
             */
            pinfo->fragmented = (hdr->flags1 & PFCL1_FRAG);
            next_tvb = tvb_new_subset(tvb, offset, length,
                                      reported_length);
            dcerpc_try_handoff(pinfo, tree, dcerpc_tree, next_tvb,
                               next_tvb, hdr->drep, di, NULL);
        } else {
            /* PDU is fragmented and this isn't the first fragment */
            if (dcerpc_tree) {
                if (length > 0) {
                    tvb_ensure_bytes_exist(tvb, offset, stub_length);
                    proto_tree_add_text(dcerpc_tree, tvb, offset, stub_length,
                                        "Fragment data (%d byte%s)",
                                        stub_length,
                                        plurality(stub_length, "", "s"));
                }
            }
        }
    } else {
        /* Reassembly is enabled, the PDU is fragmented, and
           we have all the data in the fragment; the first two
           of those mean we should attempt reassembly, and the
           third means we can attempt reassembly. */
        if (dcerpc_tree) {
            if (length > 0) {
                tvb_ensure_bytes_exist(tvb, offset, stub_length);
                proto_tree_add_text(dcerpc_tree, tvb, offset, stub_length,
                                    "Fragment data (%d byte%s)", stub_length,
                                    plurality(stub_length, "", "s"));
            }
        }

        fd_head = fragment_add_seq(&dcerpc_cl_reassembly_table,
                                   tvb, offset,
                                   pinfo, hdr->seqnum, (void *)hdr,
                                   hdr->frag_num, stub_length,
                                   !(hdr->flags1 & PFCL1_LASTFRAG), 0);
        if (fd_head != NULL) {
            /* We completed reassembly... */
            if (pinfo->fd->num == fd_head->reassembled_in) {
                /* ...and this is the reassembled RPC PDU */
                next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
                add_new_data_source(pinfo, next_tvb, "Reassembled DCE/RPC");
                show_fragment_seq_tree(fd_head, &dcerpc_frag_items,
                                       tree, pinfo, next_tvb, &pi);

                /*
                 * XXX - authentication info?
                 */
                pinfo->fragmented = FALSE;
                dcerpc_try_handoff(pinfo, tree, dcerpc_tree, next_tvb,
                                   next_tvb, hdr->drep, di, NULL);
            } else {
                /* ...and this isn't the reassembled RPC PDU */
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_reassembled_in,
                                         tvb, 0, 0, fd_head->reassembled_in);
                PROTO_ITEM_SET_GENERATED(pi);
                parent_pi = proto_tree_get_parent(dcerpc_tree);
                if (parent_pi != NULL) {
                    proto_item_append_text(parent_pi, ", [Reas: #%u]", fd_head->reassembled_in);
                }
                col_append_fstr(pinfo->cinfo, COL_INFO,
                                " [DCE/RPC fragment, reas: #%u]", fd_head->reassembled_in);
            }
        }
    }
    pinfo->fragmented = save_fragmented;
}

static void
dissect_dcerpc_dg_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *dcerpc_tree, proto_tree *tree,
                       e_dce_dg_common_hdr_t *hdr, conversation_t *conv)
{
    dcerpc_info        *di;
    dcerpc_call_value  *value, v;
    dcerpc_matched_key  matched_key, *new_matched_key;
    proto_item         *pi;
    proto_item         *parent_pi;

    di = get_next_di();
    if (!(pinfo->fd->flags.visited)) {
        dcerpc_call_value *call_value;
        dcerpc_dg_call_key *call_key;

        call_key = (dcerpc_dg_call_key *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_dg_call_key));
        call_key->conv = conv;
        call_key->seqnum = hdr->seqnum;
        call_key->act_id = hdr->act_id;

        call_value = (dcerpc_call_value *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_call_value));
        call_value->uuid = hdr->if_id;
        call_value->ver = hdr->if_ver;
        call_value->object_uuid = hdr->obj_id;
        call_value->opnum = hdr->opnum;
        call_value->req_frame = pinfo->fd->num;
        call_value->req_time = pinfo->fd->abs_ts;
        call_value->rep_frame = 0;
        call_value->max_ptr = 0;
        call_value->se_data = NULL;
        call_value->private_data = NULL;
        call_value->pol = NULL;
        /* NDR64 is not available on dg transports ?*/
        call_value->flags = 0;

        g_hash_table_insert(dcerpc_dg_calls, call_key, call_value);

        new_matched_key = (dcerpc_matched_key *)wmem_alloc(wmem_file_scope(), sizeof(dcerpc_matched_key));
        new_matched_key->frame = pinfo->fd->num;
        new_matched_key->call_id = hdr->seqnum;
        g_hash_table_insert(dcerpc_matched, new_matched_key, call_value);
    }

    matched_key.frame = pinfo->fd->num;
    matched_key.call_id = hdr->seqnum;
    value = (dcerpc_call_value *)g_hash_table_lookup(dcerpc_matched, &matched_key);
    if (!value) {
        v.uuid = hdr->if_id;
        v.ver = hdr->if_ver;
        v.object_uuid = hdr->obj_id;
        v.opnum = hdr->opnum;
        v.req_frame = pinfo->fd->num;
        v.rep_frame = 0;
        v.max_ptr = 0;
        v.se_data = NULL;
        v.private_data = NULL;
        value = &v;
    }

    di->conv = conv;
    di->call_id = hdr->seqnum;
    di->smb_fid = -1;
    di->ptype = PDU_REQ;
    di->call_data = value;

    if (value->rep_frame != 0) {
        pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_response_in,
                                 tvb, 0, 0, value->rep_frame);
        PROTO_ITEM_SET_GENERATED(pi);
        parent_pi = proto_tree_get_parent(dcerpc_tree);
        if (parent_pi != NULL) {
            proto_item_append_text(parent_pi, ", [Resp: #%u]", value->rep_frame);
        }
    }
    dissect_dcerpc_dg_stub(tvb, offset, pinfo, dcerpc_tree, tree, hdr, di);
}

static void
dissect_dcerpc_dg_resp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *dcerpc_tree, proto_tree *tree,
                       e_dce_dg_common_hdr_t *hdr, conversation_t *conv)
{
    dcerpc_info        *di;
    dcerpc_call_value  *value, v;
    dcerpc_matched_key  matched_key, *new_matched_key;
    proto_item         *pi;
    proto_item         *parent_pi;

    di = get_next_di();
    if (!(pinfo->fd->flags.visited)) {
        dcerpc_call_value *call_value;
        dcerpc_dg_call_key call_key;

        call_key.conv = conv;
        call_key.seqnum = hdr->seqnum;
        call_key.act_id = hdr->act_id;

        if ((call_value = (dcerpc_call_value *)g_hash_table_lookup(dcerpc_dg_calls, &call_key))) {
            new_matched_key = (dcerpc_matched_key *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_matched_key));
            new_matched_key->frame = pinfo->fd->num;
            new_matched_key->call_id = hdr->seqnum;
            g_hash_table_insert(dcerpc_matched, new_matched_key, call_value);
            if (call_value->rep_frame == 0) {
                call_value->rep_frame = pinfo->fd->num;
            }
        }
    }

    matched_key.frame = pinfo->fd->num;
    matched_key.call_id = hdr->seqnum;
    value = (dcerpc_call_value *)g_hash_table_lookup(dcerpc_matched, &matched_key);
    if (!value) {
        v.uuid = hdr->if_id;
        v.ver = hdr->if_ver;
        v.object_uuid = hdr->obj_id;
        v.opnum = hdr->opnum;
        v.req_frame = 0;
        v.rep_frame = pinfo->fd->num;
        v.se_data = NULL;
        v.private_data = NULL;
        value = &v;
    }

    di->conv = conv;
    di->call_id = 0;
    di->smb_fid = -1;
    di->ptype = PDU_RESP;
    di->call_data = value;

    if (value->req_frame != 0) {
        nstime_t delta_ts;
        pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_request_in,
                                 tvb, 0, 0, value->req_frame);
        PROTO_ITEM_SET_GENERATED(pi);
        parent_pi = proto_tree_get_parent(dcerpc_tree);
        if (parent_pi != NULL) {
            proto_item_append_text(parent_pi, ", [Req: #%u]", value->req_frame);
        }
        nstime_delta(&delta_ts, &pinfo->fd->abs_ts, &value->req_time);
        pi = proto_tree_add_time(dcerpc_tree, hf_dcerpc_time, tvb, offset, 0, &delta_ts);
        PROTO_ITEM_SET_GENERATED(pi);
    } else {
        proto_tree_add_expert(dcerpc_tree, pinfo, &ei_dcerpc_no_request_found, tvb, 0, 0);
    }
    dissect_dcerpc_dg_stub(tvb, offset, pinfo, dcerpc_tree, tree, hdr, di);
}

static void
dissect_dcerpc_dg_ping_ack(tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *dcerpc_tree,
                           e_dce_dg_common_hdr_t *hdr, conversation_t *conv)
{
    proto_item         *parent_pi;
/*    if (!(pinfo->fd->flags.visited)) {*/
    dcerpc_call_value  *call_value;
    dcerpc_dg_call_key  call_key;

    call_key.conv = conv;
    call_key.seqnum = hdr->seqnum;
    call_key.act_id = hdr->act_id;

    if ((call_value = (dcerpc_call_value *)g_hash_table_lookup(dcerpc_dg_calls, &call_key))) {
        proto_item *pi;
        nstime_t delta_ts;

        pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_request_in,
                                 tvb, 0, 0, call_value->req_frame);
        PROTO_ITEM_SET_GENERATED(pi);
        parent_pi = proto_tree_get_parent(dcerpc_tree);
        if (parent_pi != NULL) {
            proto_item_append_text(parent_pi, ", [Req: #%u]", call_value->req_frame);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " [req: #%u]", call_value->req_frame);

        nstime_delta(&delta_ts, &pinfo->fd->abs_ts, &call_value->req_time);
        pi = proto_tree_add_time(dcerpc_tree, hf_dcerpc_time, tvb, offset, 0, &delta_ts);
        PROTO_ITEM_SET_GENERATED(pi);
/*    }*/
    }
}

/*
 * DCERPC dissector for connectionless calls
 */
static gboolean
dissect_dcerpc_dg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item            *ti             = NULL;
    proto_item            *tf             = NULL;
    proto_tree            *dcerpc_tree    = NULL;
    proto_tree            *dg_flags1_tree = NULL;
    proto_tree            *dg_flags2_tree = NULL;
    proto_tree            *drep_tree      = NULL;
    e_dce_dg_common_hdr_t  hdr;
    int                    offset         = 0;
    conversation_t        *conv;
    int                    auth_level;
    char                  *uuid_str;
    const char            *uuid_name      = NULL;

    /*
     * Check if this looks like a CL DCERPC call.  All dg packets
     * have an 80 byte header on them.  Which starts with
     * version (4), pkt_type.
     */
    if (tvb_length(tvb) < sizeof (hdr)) {
        return FALSE;
    }

    /* Version must be 4 */
    hdr.rpc_ver = tvb_get_guint8(tvb, offset++);
    if (hdr.rpc_ver != 4)
        return FALSE;

    /* Type must be <= 19 or it's not DCE/RPC */
    hdr.ptype = tvb_get_guint8(tvb, offset++);
    if (hdr.ptype > 19)
        return FALSE;

    /* flags1 has bit 1 and 8 as reserved so if any of them are set, it is
       probably not a DCE/RPC packet
    */
    hdr.flags1 = tvb_get_guint8(tvb, offset++);
    if (hdr.flags1&0x81)
        return FALSE;

    /* flags2 has all bits except bit 2 as reserved so if any of them are set
       it is probably not DCE/RPC.
    */
    hdr.flags2 = tvb_get_guint8(tvb, offset++);
    if (hdr.flags2&0xfd)
        return FALSE;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCERPC");
    col_add_str(pinfo->cinfo, COL_INFO, pckt_vals[hdr.ptype].strptr);

    tvb_memcpy(tvb, (guint8 *)hdr.drep, offset, sizeof (hdr.drep));
    offset += (int)sizeof (hdr.drep);
    hdr.serial_hi = tvb_get_guint8(tvb, offset++);
    dcerpc_tvb_get_uuid(tvb, offset, hdr.drep, &hdr.obj_id);
    offset += 16;
    dcerpc_tvb_get_uuid(tvb, offset, hdr.drep, &hdr.if_id);
    offset += 16;
    dcerpc_tvb_get_uuid(tvb, offset, hdr.drep, &hdr.act_id);
    offset += 16;
    hdr.server_boot = dcerpc_tvb_get_ntohl(tvb, offset, hdr.drep);
    offset += 4;
    hdr.if_ver = dcerpc_tvb_get_ntohl(tvb, offset, hdr.drep);
    offset += 4;
    hdr.seqnum = dcerpc_tvb_get_ntohl(tvb, offset, hdr.drep);
    offset += 4;
    hdr.opnum = dcerpc_tvb_get_ntohs(tvb, offset, hdr.drep);
    offset += 2;
    hdr.ihint = dcerpc_tvb_get_ntohs(tvb, offset, hdr.drep);
    offset += 2;
    hdr.ahint = dcerpc_tvb_get_ntohs(tvb, offset, hdr.drep);
    offset += 2;
    hdr.frag_len = dcerpc_tvb_get_ntohs(tvb, offset, hdr.drep);
    offset += 2;
    hdr.frag_num = dcerpc_tvb_get_ntohs(tvb, offset, hdr.drep);
    offset += 2;
    hdr.auth_proto = tvb_get_guint8(tvb, offset++);
    hdr.serial_lo = tvb_get_guint8(tvb, offset++);

    if (tree) {
        ti = proto_tree_add_item(tree, proto_dcerpc, tvb, 0, -1, ENC_NA);
        if (ti) {
            dcerpc_tree = proto_item_add_subtree(ti, ett_dcerpc);
            proto_item_append_text(ti, " %s, Seq: %u, Serial: %u, Frag: %u, FragLen: %u",
                                   val_to_str(hdr.ptype, pckt_vals, "Unknown (0x%02x)"),
                                   hdr.seqnum, hdr.serial_hi*256+hdr.serial_lo,
                                   hdr.frag_num, hdr.frag_len);
        }
    }
    offset = 0;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_ver, tvb, offset, 1, hdr.rpc_ver);
    offset++;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_packet_type, tvb, offset, 1, hdr.ptype);
    offset++;

    if (tree) {
        tf = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_flags1, tvb, offset, 1, hdr.flags1);
        dg_flags1_tree = proto_item_add_subtree(tf, ett_dcerpc_dg_flags1);
        if (dg_flags1_tree) {
            proto_tree_add_boolean(dg_flags1_tree, hf_dcerpc_dg_flags1_rsrvd_80, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean(dg_flags1_tree, hf_dcerpc_dg_flags1_broadcast, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean(dg_flags1_tree, hf_dcerpc_dg_flags1_idempotent, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean(dg_flags1_tree, hf_dcerpc_dg_flags1_maybe, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean(dg_flags1_tree, hf_dcerpc_dg_flags1_nofack, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean(dg_flags1_tree, hf_dcerpc_dg_flags1_frag, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean(dg_flags1_tree, hf_dcerpc_dg_flags1_last_frag, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean(dg_flags1_tree, hf_dcerpc_dg_flags1_rsrvd_01, tvb, offset, 1, hdr.flags1);
            if (hdr.flags1) {
                proto_item_append_text(tf, " %s%s%s%s%s%s",
                                       (hdr.flags1 & PFCL1_BROADCAST) ? "\"Broadcast\" " : "",
                                       (hdr.flags1 & PFCL1_IDEMPOTENT) ? "\"Idempotent\" " : "",
                                       (hdr.flags1 & PFCL1_MAYBE) ? "\"Maybe\" " : "",
                                       (hdr.flags1 & PFCL1_NOFACK) ? "\"No Fack\" " : "",
                                       (hdr.flags1 & PFCL1_FRAG) ? "\"Fragment\" " : "",
                                       (hdr.flags1 & PFCL1_LASTFRAG) ? "\"Last Fragment\" " : "");
            }
        }
    }
    offset++;

    if (tree) {
        tf = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_flags2, tvb, offset, 1, hdr.flags2);
        dg_flags2_tree = proto_item_add_subtree(tf, ett_dcerpc_dg_flags2);
        if (dg_flags2_tree) {
            proto_tree_add_boolean(dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_80, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean(dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_40, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean(dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_20, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean(dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_10, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean(dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_08, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean(dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_04, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean(dg_flags2_tree, hf_dcerpc_dg_flags2_cancel_pending, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean(dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_01, tvb, offset, 1, hdr.flags2);
            if (hdr.flags2) {
                proto_item_append_text(tf, " %s",
                                       (hdr.flags2 & PFCL2_CANCEL_PENDING) ? "\"Cancel Pending\" " : "");
            }
        }
    }
    offset++;

    if (tree) {
        tf = proto_tree_add_bytes(dcerpc_tree, hf_dcerpc_drep, tvb, offset, sizeof (hdr.drep), hdr.drep);
        drep_tree = proto_item_add_subtree(tf, ett_dcerpc_drep);
        if (drep_tree) {
            proto_tree_add_uint(drep_tree, hf_dcerpc_drep_byteorder, tvb, offset, 1, hdr.drep[0] >> 4);
            proto_tree_add_uint(drep_tree, hf_dcerpc_drep_character, tvb, offset, 1, hdr.drep[0] & 0x0f);
            proto_tree_add_uint(drep_tree, hf_dcerpc_drep_fp, tvb, offset+1, 1, hdr.drep[1]);
            proto_item_append_text(tf, " (Order: %s, Char: %s, Float: %s)",
                                   val_to_str_const(hdr.drep[0] >> 4, drep_byteorder_vals, "Unknown"),
                                   val_to_str_const(hdr.drep[0] & 0x0f, drep_character_vals, "Unknown"),
                                   val_to_str_const(hdr.drep[1], drep_fp_vals, "Unknown"));
        }
    }
    offset += (int)sizeof (hdr.drep);

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_serial_hi, tvb, offset, 1, hdr.serial_hi);
    offset++;

    if (tree) {
        proto_tree_add_guid_format(dcerpc_tree, hf_dcerpc_obj_id, tvb,
                                   offset, 16, (e_guid_t *) &hdr.obj_id, "Object UUID: %s",
                                   guid_to_ep_str((e_guid_t *) &hdr.obj_id));
    }
    offset += 16;

    if (tree) {
        uuid_str = guid_to_ep_str((e_guid_t*)&hdr.if_id);
        uuid_name = guids_get_uuid_name(&hdr.if_id);
        if (uuid_name) {
            proto_tree_add_guid_format(dcerpc_tree, hf_dcerpc_dg_if_id, tvb,
                                       offset, 16, (e_guid_t *) &hdr.if_id, "Interface: %s UUID: %s", uuid_name, uuid_str);
        } else {
            proto_tree_add_guid_format(dcerpc_tree, hf_dcerpc_dg_if_id, tvb,
                                       offset, 16, (e_guid_t *) &hdr.if_id, "Interface UUID: %s", uuid_str);
        }
    }
    offset += 16;

    if (tree) {
        proto_tree_add_guid_format(dcerpc_tree, hf_dcerpc_dg_act_id, tvb,
                                   offset, 16, (e_guid_t *) &hdr.act_id, "Activity: %s",
                                   guid_to_ep_str((e_guid_t *) &hdr.act_id));
    }
    offset += 16;

    if (tree) {
        nstime_t server_boot;

        server_boot.secs  = hdr.server_boot;
        server_boot.nsecs = 0;

        if (hdr.server_boot == 0)
            proto_tree_add_time_format_value(dcerpc_tree, hf_dcerpc_dg_server_boot,
                                       tvb, offset, 4, &server_boot,
                                       "Unknown (0)");
        else
            proto_tree_add_time(dcerpc_tree, hf_dcerpc_dg_server_boot,
                                tvb, offset, 4, &server_boot);
    }
    offset += 4;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_if_ver, tvb, offset, 4, hdr.if_ver);
    offset += 4;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_seqnum, tvb, offset, 4, hdr.seqnum);
    col_append_fstr(pinfo->cinfo, COL_INFO, ": seq: %u", hdr.seqnum);
    col_append_fstr(pinfo->cinfo, COL_DCE_CALL, "%u", hdr.seqnum);
    offset += 4;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_opnum, tvb, offset, 2, hdr.opnum);
    offset += 2;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_ihint, tvb, offset, 2, hdr.ihint);
    offset += 2;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_ahint, tvb, offset, 2, hdr.ahint);
    offset += 2;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_frag_len, tvb, offset, 2, hdr.frag_len);
    offset += 2;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_frag_num, tvb, offset, 2, hdr.frag_num);
    if (hdr.flags1 & PFCL1_FRAG) {
        /* Fragmented - put the fragment number into the Info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " frag: %u",
                         hdr.frag_num);
    }
    offset += 2;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_auth_proto, tvb, offset, 1, hdr.auth_proto);
    offset++;

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_serial_lo, tvb, offset, 1, hdr.serial_lo);
    if (hdr.flags1 & PFCL1_FRAG) {
        /* Fragmented - put the serial number into the Info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " serial: %u",
                        (hdr.serial_hi << 8) | hdr.serial_lo);
    }
    offset++;

    if (tree) {
        /*
         * XXX - for Kerberos, we get a protection level; if it's
         * DCE_C_AUTHN_LEVEL_PKT_PRIVACY, we can't dissect the
         * stub data.
         */
        dissect_dcerpc_dg_auth(tvb, offset, dcerpc_tree, &hdr,
                               &auth_level);
    }

    /*
     * keeping track of the conversation shouldn't really be necessary
     * for connectionless packets, because everything we need to know
     * to dissect is in the header for each packet.  Unfortunately,
     * Microsoft's implementation is buggy and often puts the
     * completely wrong if_id in the header.  go figure.  So, keep
     * track of the seqnum and use that if possible.  Note: that's not
     * completely correct.  It should really be done based on both the
     * activity_id and seqnum.  I haven't seen anywhere that it would
     * make a difference, but for future reference...
     */
    conv = find_or_create_conversation(pinfo);

    /*
     * Packet type specific stuff is next.
     */

    switch (hdr.ptype) {

    case PDU_CANCEL_ACK:
        /* Body is optional */
        /* XXX - we assume "frag_len" is the length of the body */
        if (hdr.frag_len != 0)
            dissect_dcerpc_dg_cancel_ack(tvb, offset, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_CL_CANCEL:
        /*
         * XXX - The DCE RPC 1.1 spec doesn't say the body is optional,
         * but in at least one capture none of the Cl_cancel PDUs had a
         * body.
         */
        /* XXX - we assume "frag_len" is the length of the body */
        if (hdr.frag_len != 0)
            dissect_dcerpc_dg_cancel(tvb, offset, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_NOCALL:
        /* Body is optional; if present, it's the same as PDU_FACK */
        /* XXX - we assume "frag_len" is the length of the body */
        if (hdr.frag_len != 0)
            dissect_dcerpc_dg_fack(tvb, offset, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_FACK:
        /* Body is optional */
        /* XXX - we assume "frag_len" is the length of the body */
        if (hdr.frag_len != 0)
            dissect_dcerpc_dg_fack(tvb, offset, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_REJECT:
    case PDU_FAULT:
        dissect_dcerpc_dg_reject_fault(tvb, offset, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_REQ:
        dissect_dcerpc_dg_rqst(tvb, offset, pinfo, dcerpc_tree, tree, &hdr, conv);
        break;

    case PDU_RESP:
        dissect_dcerpc_dg_resp(tvb, offset, pinfo, dcerpc_tree, tree, &hdr, conv);
        break;

        /* these requests have no body */
    case PDU_ACK:
    case PDU_PING:
        dissect_dcerpc_dg_ping_ack(tvb, offset, pinfo, dcerpc_tree, &hdr, conv);
        break;
    case PDU_WORKING:
    default:
        break;
    }

    return TRUE;
}

static void
dcerpc_init_protocol(void)
{
    /* structures and data for BIND */
    if (dcerpc_binds) {
        g_hash_table_destroy(dcerpc_binds);
        dcerpc_binds = NULL;
    }
    if (!dcerpc_binds) {
        dcerpc_binds = g_hash_table_new(dcerpc_bind_hash, dcerpc_bind_equal);
    }

    /* structures and data for CALL */
    if (dcerpc_cn_calls) {
        g_hash_table_destroy(dcerpc_cn_calls);
    }
    dcerpc_cn_calls = g_hash_table_new(dcerpc_cn_call_hash, dcerpc_cn_call_equal);
    if (dcerpc_dg_calls) {
        g_hash_table_destroy(dcerpc_dg_calls);
    }
    dcerpc_dg_calls = g_hash_table_new(dcerpc_dg_call_hash, dcerpc_dg_call_equal);

    /* structure and data for MATCHED */
    if (dcerpc_matched) {
        g_hash_table_destroy(dcerpc_matched);
    }
    dcerpc_matched = g_hash_table_new(dcerpc_matched_hash, dcerpc_matched_equal);

    decode_dcerpc_inject_bindings();
}

void
proto_register_dcerpc(void)
{
    static hf_register_info hf[] = {
        { &hf_dcerpc_request_in,
          { "Request in frame", "dcerpc.request_in", FT_FRAMENUM, BASE_NONE,
            NULL, 0, "This packet is a response to the packet with this number", HFILL }},
        { &hf_dcerpc_response_in,
          { "Response in frame", "dcerpc.response_in", FT_FRAMENUM, BASE_NONE,
            NULL, 0, "This packet will be responded in the packet with this number", HFILL }},
        { &hf_dcerpc_referent_id,
          { "Referent ID", "dcerpc.referent_id", FT_UINT32, BASE_HEX,
            NULL, 0, "Referent ID for this NDR encoded pointer", HFILL }},
        { &hf_dcerpc_ver,
          { "Version", "dcerpc.ver", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_ver_minor,
          { "Version (minor)", "dcerpc.ver_minor", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_packet_type,
          { "Packet type", "dcerpc.pkt_type", FT_UINT8, BASE_DEC, VALS(pckt_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_flags,
          { "Packet Flags", "dcerpc.cn_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_flags_first_frag,
          { "First Frag", "dcerpc.cn_flags.first_frag", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFC_FIRST_FRAG, NULL, HFILL }},
        { &hf_dcerpc_cn_flags_last_frag,
          { "Last Frag", "dcerpc.cn_flags.last_frag", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFC_LAST_FRAG, NULL, HFILL }},
        { &hf_dcerpc_cn_flags_cancel_pending,
          { "Cancel Pending", "dcerpc.cn_flags.cancel_pending", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFC_PENDING_CANCEL, NULL, HFILL }},
        { &hf_dcerpc_cn_flags_reserved,
          { "Reserved", "dcerpc.cn_flags.reserved", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFC_RESERVED_1, NULL, HFILL }},
        { &hf_dcerpc_cn_flags_mpx,
          { "Multiplex", "dcerpc.cn_flags.mpx", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFC_CONC_MPX, NULL, HFILL }},
        { &hf_dcerpc_cn_flags_dne,
          { "Did Not Execute", "dcerpc.cn_flags.dne", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFC_DID_NOT_EXECUTE, NULL, HFILL }},
        { &hf_dcerpc_cn_flags_maybe,
          { "Maybe", "dcerpc.cn_flags.maybe", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFC_MAYBE, NULL, HFILL }},
        { &hf_dcerpc_cn_flags_object,
          { "Object", "dcerpc.cn_flags.object", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFC_OBJECT_UUID, NULL, HFILL }},
        { &hf_dcerpc_drep,
          { "Data Representation", "dcerpc.drep", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_drep_byteorder,
          { "Byte order", "dcerpc.drep.byteorder", FT_UINT8, BASE_DEC, VALS(drep_byteorder_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_drep_character,
          { "Character", "dcerpc.drep.character", FT_UINT8, BASE_DEC, VALS(drep_character_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_drep_fp,
          { "Floating-point", "dcerpc.drep.fp", FT_UINT8, BASE_DEC, VALS(drep_fp_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_frag_len,
          { "Frag Length", "dcerpc.cn_frag_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_auth_len,
          { "Auth Length", "dcerpc.cn_auth_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_call_id,
          { "Call ID", "dcerpc.cn_call_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_max_xmit,
          { "Max Xmit Frag", "dcerpc.cn_max_xmit", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_max_recv,
          { "Max Recv Frag", "dcerpc.cn_max_recv", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_assoc_group,
          { "Assoc Group", "dcerpc.cn_assoc_group", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_num_ctx_items,
          { "Num Ctx Items", "dcerpc.cn_num_ctx_items", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_ctx_item,
          { "Ctx Item", "dcerpc.cn_ctx_item", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_ctx_id,
          { "Context ID", "dcerpc.cn_ctx_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_num_trans_items,
          { "Num Trans Items", "dcerpc.cn_num_trans_items", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_abstract_syntax,
          { "Abstract Syntax", "dcerpc.cn_bind_abstract_syntax", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_if_id,
          { "Interface UUID", "dcerpc.cn_bind_to_uuid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_if_ver,
          { "Interface Ver", "dcerpc.cn_bind_if_ver", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_if_ver_minor,
          { "Interface Ver Minor", "dcerpc.cn_bind_if_ver_minor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_trans_syntax,
          { "Transfer Syntax", "dcerpc.cn_bind_trans", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_trans_id,
          { "ID", "dcerpc.cn_bind_trans_id", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_trans_ver,
          { "ver", "dcerpc.cn_bind_trans_ver", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_trans_btfn_01, /* [MS-RPCE] 2.2.2.14 */
          { "Security Context Multiplexing Supported", "dcerpc.cn_bind_trans_btfn.01", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_trans_btfn_02,
          { "Keep Connection On Orphan Supported", "dcerpc.cn_bind_trans_btfn.02", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }},
        { &hf_dcerpc_cn_alloc_hint,
          { "Alloc hint", "dcerpc.cn_alloc_hint", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_sec_addr_len,
          { "Scndry Addr len", "dcerpc.cn_sec_addr_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_sec_addr,
          { "Scndry Addr", "dcerpc.cn_sec_addr", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_num_results,
          { "Num results", "dcerpc.cn_num_results", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_ack_result,
          { "Ack result", "dcerpc.cn_ack_result", FT_UINT16, BASE_DEC, VALS(p_cont_result_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_ack_reason,
          { "Ack reason", "dcerpc.cn_ack_reason", FT_UINT16, BASE_DEC, VALS(p_provider_reason_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_ack_trans_id,
          { "Transfer Syntax", "dcerpc.cn_ack_trans_id", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_ack_trans_ver,
          { "Syntax ver", "dcerpc.cn_ack_trans_ver", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_ack_btfn,
          { "Bind Time Feature Negotiation Bitmask", "dcerpc.cn_ack_btfn", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_reject_reason,
          { "Reject reason", "dcerpc.cn_reject_reason", FT_UINT16, BASE_DEC, VALS(reject_reason_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_num_protocols,
          { "Number of protocols", "dcerpc.cn_num_protocols", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_protocol_ver_major,
          { "Protocol major version", "dcerpc.cn_protocol_ver_major", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_protocol_ver_minor,
          { "Protocol minor version", "dcerpc.cn_protocol_ver_minor", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_cancel_count,
          { "Cancel count", "dcerpc.cn_cancel_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_status,
          { "Status", "dcerpc.cn_status", FT_UINT32, BASE_HEX, VALS(reject_status_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_deseg_req,
          { "Desegmentation Required", "dcerpc.cn_deseg_req", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_auth_type,
          { "Auth type", "dcerpc.auth_type", FT_UINT8, BASE_DEC, VALS(authn_protocol_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_auth_level,
          { "Auth level", "dcerpc.auth_level", FT_UINT8, BASE_DEC, VALS(authn_level_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_auth_pad_len,
          { "Auth pad len", "dcerpc.auth_pad_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_auth_rsrvd,
          { "Auth Rsrvd", "dcerpc.auth_rsrvd", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_auth_ctx_id,
          { "Auth Context ID", "dcerpc.auth_ctx_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_flags1,
          { "Flags1", "dcerpc.dg_flags1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_flags1_rsrvd_01,
          { "Reserved", "dcerpc.dg_flags1_rsrvd_01", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL1_RESERVED_01, NULL, HFILL }},
        { &hf_dcerpc_dg_flags1_last_frag,
          { "Last Fragment", "dcerpc.dg_flags1_last_frag", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL1_LASTFRAG, NULL, HFILL }},
        { &hf_dcerpc_dg_flags1_frag,
          { "Fragment", "dcerpc.dg_flags1_frag", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL1_FRAG, NULL, HFILL }},
        { &hf_dcerpc_dg_flags1_nofack,
          { "No Fack", "dcerpc.dg_flags1_nofack", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL1_NOFACK, NULL, HFILL }},
        { &hf_dcerpc_dg_flags1_maybe,
          { "Maybe", "dcerpc.dg_flags1_maybe", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL1_MAYBE, NULL, HFILL }},
        { &hf_dcerpc_dg_flags1_idempotent,
          { "Idempotent", "dcerpc.dg_flags1_idempotent", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL1_IDEMPOTENT, NULL, HFILL }},
        { &hf_dcerpc_dg_flags1_broadcast,
          { "Broadcast", "dcerpc.dg_flags1_broadcast", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL1_BROADCAST, NULL, HFILL }},
        { &hf_dcerpc_dg_flags1_rsrvd_80,
          { "Reserved", "dcerpc.dg_flags1_rsrvd_80", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL1_RESERVED_80, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2,
          { "Flags2", "dcerpc.dg_flags2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_01,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_01", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_01, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_cancel_pending,
          { "Cancel Pending", "dcerpc.dg_flags2_cancel_pending", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_CANCEL_PENDING, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_04,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_04", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_04, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_08,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_08", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_08, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_10,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_10", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_10, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_20,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_20", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_20, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_40,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_40", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_40, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_80,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_80", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_80, NULL, HFILL }},
        { &hf_dcerpc_dg_serial_lo,
          { "Serial Low", "dcerpc.dg_serial_lo", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_serial_hi,
          { "Serial High", "dcerpc.dg_serial_hi", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_ahint,
          { "Activity Hint", "dcerpc.dg_ahint", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_ihint,
          { "Interface Hint", "dcerpc.dg_ihint", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_frag_len,
          { "Fragment len", "dcerpc.dg_frag_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_frag_num,
          { "Fragment num", "dcerpc.dg_frag_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_auth_proto,
          { "Auth proto", "dcerpc.dg_auth_proto", FT_UINT8, BASE_DEC, VALS(authn_protocol_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_seqnum,
          { "Sequence num", "dcerpc.dg_seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_server_boot,
          { "Server boot time", "dcerpc.dg_server_boot", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_if_ver,
          { "Interface Ver", "dcerpc.dg_if_ver", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_krb5_av_prot_level,
          { "Protection Level", "dcerpc.krb5_av.prot_level", FT_UINT8, BASE_DEC, VALS(authn_level_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_krb5_av_key_vers_num,
          { "Key Version Number", "dcerpc.krb5_av.key_vers_num", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_krb5_av_key_auth_verifier,
          { "Authentication Verifier", "dcerpc.krb5_av.auth_verifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_obj_id,
          { "Object", "dcerpc.obj_id", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_if_id,
          { "Interface", "dcerpc.dg_if_id", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_act_id,
          { "Activity", "dcerpc.dg_act_id", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_opnum,
          { "Opnum", "dcerpc.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_cancel_vers,
          { "Cancel Version", "dcerpc.dg_cancel_vers", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_cancel_id,
          { "Cancel ID", "dcerpc.dg_cancel_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_server_accepting_cancels,
          { "Server accepting cancels", "dcerpc.server_accepting_cancels", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_fack_vers,
          { "FACK Version", "dcerpc.fack_vers", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_fack_window_size,
          { "Window Size", "dcerpc.fack_window_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_fack_max_tsdu,
          { "Max TSDU", "dcerpc.fack_max_tsdu", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_fack_max_frag_size,
          { "Max Frag Size", "dcerpc.fack_max_frag_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_fack_serial_num,
          { "Serial Num", "dcerpc.fack_serial_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_fack_selack_len,
          { "Selective ACK Len", "dcerpc.fack_selack_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_fack_selack,
          { "Selective ACK", "dcerpc.fack_selack", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_dg_status,
          { "Status", "dcerpc.dg_status", FT_UINT32, BASE_HEX, VALS(reject_status_vals), 0x0, NULL, HFILL }},

        { &hf_dcerpc_array_max_count,
          { "Max Count", "dcerpc.array.max_count", FT_UINT32, BASE_DEC, NULL, 0x0, "Maximum Count: Number of elements in the array", HFILL }},

        { &hf_dcerpc_array_offset,
          { "Offset", "dcerpc.array.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "Offset for first element in array", HFILL }},

        { &hf_dcerpc_array_actual_count,
          { "Actual Count", "dcerpc.array.actual_count", FT_UINT32, BASE_DEC, NULL, 0x0, "Actual Count: Actual number of elements in the array", HFILL }},

        { &hf_dcerpc_op,
          { "Operation", "dcerpc.op", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_fragments,
          { "Reassembled DCE/RPC Fragments", "dcerpc.fragments", FT_NONE, BASE_NONE,
            NULL, 0x0, "DCE/RPC Fragments", HFILL }},

        { &hf_dcerpc_fragment,
          { "DCE/RPC Fragment", "dcerpc.fragment", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_fragment_overlap,
          { "Fragment overlap", "dcerpc.fragment.overlap", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},

        { &hf_dcerpc_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap", "dcerpc.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Overlapping fragments contained conflicting data", HFILL }},

        { &hf_dcerpc_fragment_multiple_tails,
          { "Multiple tail fragments found", "dcerpc.fragment.multipletails", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Several tails were found when defragmenting the packet", HFILL }},

        { &hf_dcerpc_fragment_too_long_fragment,
          { "Fragment too long", "dcerpc.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Fragment contained data past end of packet", HFILL }},

        { &hf_dcerpc_fragment_error,
          { "Defragmentation error", "dcerpc.fragment.error", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},

        { &hf_dcerpc_fragment_count,
          { "Fragment count", "dcerpc.fragment.count", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_time,
          { "Time from request", "dcerpc.time", FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0, "Time between Request and Response for DCE-RPC calls", HFILL }},

        { &hf_dcerpc_reassembled_in,
          { "Reassembled PDU in frame", "dcerpc.reassembled_in", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "The DCE/RPC PDU is completely reassembled in the packet with this number", HFILL }},

        { &hf_dcerpc_reassembled_length,
          { "Reassembled DCE/RPC length", "dcerpc.reassembled.length", FT_UINT32, BASE_DEC,
            NULL, 0x0, "The total length of the reassembled payload", HFILL }},

        { &hf_dcerpc_unknown_if_id,
          { "Unknown DCERPC interface id", "dcerpc.unknown_if_id", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dcerpc_cn_rts_flags,
          { "RTS Flags", "dcerpc.cn_rts_flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_flags_none,
          {"None", "dcerpc.cn_rts_flags.none", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RTS_FLAG_NONE, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_flags_ping,
          { "Ping", "dcerpc.cn_rts.flags.ping", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RTS_FLAG_PING, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_flags_other_cmd,
          { "Other Cmd", "dcerpc.cn_rts_flags.other_cmd", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RTS_FLAG_OTHER_CMD, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_flags_recycle_channel,
          { "Recycle Channel", "dcerpc.cn_rts_flags.recycle_channel", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RTS_FLAG_RECYCLE_CHANNEL, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_flags_in_channel,
          { "In Channel", "dcerpc.cn_rts_flags.in_channel", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RTS_FLAG_IN_CHANNEL, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_flags_out_channel,
          { "Out Channel", "dcerpc.cn_rts_flags.out_channel", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RTS_FLAG_OUT_CHANNEL, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_flags_eof,
          { "EOF", "dcerpc.cn_rts_flags.eof", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RTS_FLAG_EOF, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_commands_nb,
          { "RTS Number of Commands", "dcerpc.cn_rts_commands_nb", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command,
          { "RTS Command", "dcerpc.cn_rts_command", FT_UINT32, BASE_HEX, VALS(rts_command_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_receivewindowsize,
          {"Receive Window Size", "dcerpc.cn_rts_command.receivewindowsize", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_fack_bytesreceived,
          {"Bytes Received", "dcerpc.cn_rts_command.fack.bytesreceived", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_fack_availablewindow,
          {"Available Window", "dcerpc.cn_rts_command.fack.availablewindow", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_fack_channelcookie,
          {"Channel Cookie", "dcerpc.cn_rts_command.fack.channelcookie", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_connectiontimeout,
          {"Connection Timeout", "dcerpc.cn_rts_command.connectiontimeout", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_cookie,
          {"Cookie", "dcerpc.cn_rts_command.cookie", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_channellifetime,
          {"Channel Lifetime", "dcerpc.cn_rts_command.channellifetime", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_clientkeepalive,
          {"Client Keepalive", "dcerpc.cn_rts_command.clientkeepalive", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_version,
          {"Version", "dcerpc.cn_rts_command.version", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_conformancecount,
          {"Conformance Count", "dcerpc.cn_rts_command.padding.conformancecount", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_padding,
          { "Padding", "dcerpc.cn_rts_command.padding.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_dcerpc_cn_rts_command_addrtype,
          { "Address Type", "dcerpc.cn_rts_command.addrtype", FT_UINT32, BASE_DEC, VALS(rts_addresstype_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_associationgroupid,
          {"Association Group ID", "dcerpc.cn_rts_command.associationgroupid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_forwarddestination,
          {"Forward Destination", "dcerpc.cn_rts_command.forwarddestination", FT_UINT32, BASE_DEC, VALS(rts_forward_destination_vals), 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_rts_command_pingtrafficsentnotify,
          {"Ping Traffic Sent Notify", "dcerpc.cn_rts_command.pingtrafficsentnotify", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    };
    static gint *ett[] = {
        &ett_dcerpc,
        &ett_dcerpc_cn_flags,
        &ett_dcerpc_cn_ctx,
        &ett_dcerpc_cn_iface,
        &ett_dcerpc_cn_trans_syntax,
        &ett_dcerpc_cn_trans_btfn,
        &ett_dcerpc_cn_rts_flags,
        &ett_dcerpc_cn_rts_command,
        &ett_dcerpc_cn_rts_pdu,
        &ett_dcerpc_drep,
        &ett_dcerpc_dg_flags1,
        &ett_dcerpc_dg_flags2,
        &ett_dcerpc_pointer_data,
        &ett_dcerpc_string,
        &ett_dcerpc_fragments,
        &ett_dcerpc_fragment,
        &ett_dcerpc_krb5_auth_verf,
    };

    static ei_register_info ei[] = {
        { &ei_dcerpc_fragment, { "dcerpc.fragment", PI_REASSEMBLE, PI_CHAT, "%s fragment", EXPFILL }},
        { &ei_dcerpc_fragment_reassembled, { "dcerpc.fragment_reassembled", PI_REASSEMBLE, PI_CHAT, "%s fragment, reassembled", EXPFILL }},
        { &ei_dcerpc_cn_ctx_id_no_bind, { "dcerpc.cn_ctx_id.no_bind", PI_UNDECODED, PI_NOTE, "No bind info for interface Context ID %u - capture start too late?", EXPFILL }},
        { &ei_dcerpc_no_request_found, { "dcerpc.no_request_found", PI_SEQUENCE, PI_NOTE, "No request to this DCE/RPC call found", EXPFILL }},
        { &ei_dcerpc_cn_status, { "dcerpc.cn_status.expert", PI_RESPONSE_CODE, PI_NOTE, "Fault: %s", EXPFILL }},
        { &ei_dcerpc_fragment_multiple, { "dcerpc.fragment_multiple", PI_SEQUENCE, PI_CHAT, "Multiple DCE/RPC fragments/PDU's in one packet", EXPFILL }},
        { &ei_dcerpc_context_change, { "dcerpc.context_change", PI_SEQUENCE, PI_CHAT, "Context change: %s", EXPFILL }},
        { &ei_dcerpc_bind_not_acknowledged, { "dcerpc.bind_not_acknowledged", PI_SEQUENCE, PI_WARN, "Bind not acknowledged", EXPFILL }},
    };

    /* Decode As handling */
    static build_valid_func dcerpc_da_build_value[1] = {dcerpc_value};
    static decode_as_value_t dcerpc_da_values = {dcerpc_prompt, 1, dcerpc_da_build_value};
    static decode_as_t dcerpc_da = {"dcerpc", "DCE-RPC",
                                    /* XXX - DCE/RPC doesn't have a true (sub)dissector table, so
                                     provide a "fake" one to fit the Decode As algorithm */
                                    "dcerpc.fake",
                                    1, 0, &dcerpc_da_values, NULL, NULL,
                                    dcerpc_populate_list, decode_dcerpc_binding_reset, dcerpc_decode_as_change, dcerpc_decode_as_free};

    module_t *dcerpc_module;
    expert_module_t* expert_dcerpc;

    proto_dcerpc = proto_register_protocol("Distributed Computing Environment / Remote Procedure Call (DCE/RPC)", "DCERPC", "dcerpc");
    proto_register_field_array(proto_dcerpc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_dcerpc = expert_register_protocol(proto_dcerpc);
    expert_register_field_array(expert_dcerpc, ei, array_length(ei));

    register_init_routine(dcerpc_init_protocol);
    dcerpc_module = prefs_register_protocol(proto_dcerpc, NULL);
    prefs_register_bool_preference(dcerpc_module,
                                   "desegment_dcerpc",
                                   "Reassemble DCE/RPC messages spanning multiple TCP segments",
                                   "Whether the DCE/RPC dissector should reassemble messages"
                                   " spanning multiple TCP segments."
                                   " To use this option, you must also enable"
                                   " \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &dcerpc_cn_desegment);
    prefs_register_bool_preference(dcerpc_module,
                                   "reassemble_dcerpc",
                                   "Reassemble DCE/RPC fragments",
                                   "Whether the DCE/RPC dissector should reassemble fragmented DCE/RPC PDUs",
                                   &dcerpc_reassemble);
    register_init_routine(dcerpc_reassemble_init);
    dcerpc_uuids = g_hash_table_new(dcerpc_uuid_hash, dcerpc_uuid_equal);
    dcerpc_tap = register_tap("dcerpc");

    register_decode_as(&dcerpc_da);
}

void
proto_reg_handoff_dcerpc(void)
{
    heur_dissector_add("tcp", dissect_dcerpc_cn_bs, proto_dcerpc);
    heur_dissector_add("netbios", dissect_dcerpc_cn_pk, proto_dcerpc);
    heur_dissector_add("udp", dissect_dcerpc_dg, proto_dcerpc);
    heur_dissector_add("smb_transact", dissect_dcerpc_cn_smbpipe, proto_dcerpc);
    heur_dissector_add("smb2_heur_subdissectors", dissect_dcerpc_cn_smb2, proto_dcerpc);
    heur_dissector_add("http", dissect_dcerpc_cn_bs, proto_dcerpc);
    dcerpc_smb_init(proto_dcerpc);

    guids_add_uuid(&uuid_data_repr_proto, "32bit NDR");
    guids_add_uuid(&uuid_ndr64, "64bit NDR");
    guids_add_uuid(&uuid_bind_time_feature_nego_00, "bind time feature negotiation");
    guids_add_uuid(&uuid_bind_time_feature_nego_01, "bind time feature negotiation");
    guids_add_uuid(&uuid_bind_time_feature_nego_02, "bind time feature negotiation");
    guids_add_uuid(&uuid_bind_time_feature_nego_03, "bind time feature negotiation");
    guids_add_uuid(&uuid_asyncemsmdb, "async MAPI");
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
