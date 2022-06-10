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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* The DCE RPC 1.1 specification can be found at:
 *
 *    https://publications.opengroup.org/c706
 *    https://pubs.opengroup.org/onlinepubs/009629399/
 *    https://pubs.opengroup.org/onlinepubs/009629399/toc.htm
 *    https://pubs.opengroup.org/onlinepubs/009629399/toc.pdf
 *
 * Microsoft extensions can be found at:
 *
 *    MS-WPO section 7.3.1 "RPC":
 *      https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wpo/7d2df784-557e-4fde-9281-9509653a0f17
 */

#include "config.h"

#include <stdio.h>      /* for sscanf() */
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/srt_table.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <epan/show_exception.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>

#include <wsutil/str_util.h>
#include "packet-tcp.h"
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"

void proto_register_dcerpc(void);
void proto_reg_handoff_dcerpc(void);

static int dcerpc_tap = -1;

/* 32bit Network Data Representation, see DCE/RPC Appendix I */
static e_guid_t uuid_data_repr_proto        = { 0x8a885d04, 0x1ceb, 0x11c9,
                                                { 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 } };

/* 64bit Network Data Representation, introduced in Windows Server 2008 */
static e_guid_t uuid_ndr64                  = { 0x71710533, 0xbeba, 0x4937,
                                                { 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36 } };

/* see [MS-OXRPC] Appendix A: Full IDL, https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcrpc/70adbb71-85a1-4023-bfdb-41e32ff37bf1 */
static e_guid_t uuid_asyncemsmdb            = { 0x5261574a, 0x4572, 0x206e,
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
#define PFC_HDR_SIGNING         PFC_PENDING_CANCEL /* on bind and alter req */
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
    { 0x00000721, "nca_s_fault_sec_pkg_error" },
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
     * see: https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--1700-3999-
     * and: https://docs.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values
     * and: https://web.archive.org/web/20150825015741/http://www.megos.ch/support/doserrors.txt
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
       int hf_dcerpc_ndr_padding = -1;
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
static int hf_dcerpc_cn_bind_trans_btfn = -1;
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
static int hf_dcerpc_cn_reject_reason = -1;
static int hf_dcerpc_cn_num_protocols = -1;
static int hf_dcerpc_cn_protocol_ver_major = -1;
static int hf_dcerpc_cn_protocol_ver_minor = -1;
static int hf_dcerpc_cn_cancel_count = -1;
static int hf_dcerpc_cn_fault_flags = -1;
static int hf_dcerpc_cn_fault_flags_extended_error_info = -1;
static int hf_dcerpc_cn_status = -1;
static int hf_dcerpc_cn_deseg_req = -1;
static int hf_dcerpc_cn_rts_flags = -1;
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
static int hf_dcerpc_referent_id32 = -1;
static int hf_dcerpc_referent_id64 = -1;
static int hf_dcerpc_null_pointer = -1;
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
static int hf_dcerpc_sec_vt_signature = -1;
static int hf_dcerpc_sec_vt_command = -1;
static int hf_dcerpc_sec_vt_command_cmd = -1;
static int hf_dcerpc_sec_vt_command_end = -1;
static int hf_dcerpc_sec_vt_command_must = -1;
static int hf_dcerpc_sec_vt_command_length = -1;
static int hf_dcerpc_sec_vt_bitmask = -1;
static int hf_dcerpc_sec_vt_bitmask_sign = -1;
static int hf_dcerpc_sec_vt_pcontext_uuid = -1;
static int hf_dcerpc_sec_vt_pcontext_ver = -1;

static int * const sec_vt_command_fields[] = {
    &hf_dcerpc_sec_vt_command_cmd,
    &hf_dcerpc_sec_vt_command_end,
    &hf_dcerpc_sec_vt_command_must,
    NULL
};
static int hf_dcerpc_reserved = -1;
static int hf_dcerpc_unknown = -1;
static int hf_dcerpc_missalign = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_dcerpc_duplicate_ptr = -1;
static int hf_dcerpc_encrypted_stub_data = -1;
static int hf_dcerpc_decrypted_stub_data = -1;
static int hf_dcerpc_payload_stub_data = -1;
static int hf_dcerpc_stub_data_with_sec_vt = -1;
static int hf_dcerpc_stub_data = -1;
static int hf_dcerpc_auth_padding = -1;
static int hf_dcerpc_auth_info = -1;
static int hf_dcerpc_auth_credentials = -1;
static int hf_dcerpc_fault_stub_data = -1;
static int hf_dcerpc_fragment_data = -1;
static int hf_dcerpc_cmd_client_ipv4 = -1;
static int hf_dcerpc_cmd_client_ipv6 = -1;
static int hf_dcerpc_authentication_verifier = -1;

static int * const dcerpc_cn_bind_trans_btfn_fields[] = {
        &hf_dcerpc_cn_bind_trans_btfn_01,
        &hf_dcerpc_cn_bind_trans_btfn_02,
        NULL
};

static int * const sec_vt_bitmask_fields[] = {
    &hf_dcerpc_sec_vt_bitmask_sign,
    NULL
};

static int * const dcerpc_cn_fault_flags_fields[] = {
        &hf_dcerpc_cn_fault_flags_extended_error_info,
        NULL
};

static const value_string sec_vt_command_cmd_vals[] = {
    {1, "BITMASK_1"},
    {2, "PCONTEXT"},
    {3, "HEADER2"},
    {0, NULL}
};

static gint ett_dcerpc = -1;
static gint ett_dcerpc_cn_flags = -1;
static gint ett_dcerpc_cn_ctx = -1;
static gint ett_dcerpc_cn_iface = -1;
static gint ett_dcerpc_cn_trans_syntax = -1;
static gint ett_dcerpc_cn_trans_btfn = -1;
static gint ett_dcerpc_cn_bind_trans_btfn = -1;
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
static gint ett_dcerpc_auth_info = -1;
static gint ett_dcerpc_verification_trailer = -1;
static gint ett_dcerpc_sec_vt_command = -1;
static gint ett_dcerpc_sec_vt_bitmask = -1;
static gint ett_dcerpc_sec_vt_pcontext = -1;
static gint ett_dcerpc_sec_vt_header = -1;
static gint ett_dcerpc_complete_stub_data = -1;
static gint ett_dcerpc_fault_flags = -1;
static gint ett_dcerpc_fault_stub_data = -1;

static expert_field ei_dcerpc_fragment_multiple = EI_INIT;
static expert_field ei_dcerpc_cn_status = EI_INIT;
static expert_field ei_dcerpc_fragment_reassembled = EI_INIT;
static expert_field ei_dcerpc_fragment = EI_INIT;
static expert_field ei_dcerpc_no_request_found = EI_INIT;
/* static expert_field ei_dcerpc_context_change = EI_INIT; */
static expert_field ei_dcerpc_cn_ctx_id_no_bind = EI_INIT;
static expert_field ei_dcerpc_bind_not_acknowledged = EI_INIT;
static expert_field ei_dcerpc_verifier_unavailable = EI_INIT;
static expert_field ei_dcerpc_invalid_pdu_authentication_attempt = EI_INIT;
/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_dcerpc_long_frame = EI_INIT;
static expert_field ei_dcerpc_cn_rts_command = EI_INIT;
static expert_field ei_dcerpc_not_implemented = EI_INIT;

static const guint8 TRAILER_SIGNATURE[] = {0x8a, 0xe3, 0x13, 0x71, 0x02, 0xf4, 0x36, 0x71};
static tvbuff_t *tvb_trailer_signature = NULL;

static GSList *decode_dcerpc_bindings = NULL;
/*
 * To keep track of ctx_id mappings.
 *
 * Every time we see a bind call we update this table.
 * Note that we always specify a SMB FID. For non-SMB transports this
 * value is 0.
 */
static wmem_map_t *dcerpc_binds = NULL;

typedef struct _dcerpc_bind_key {
    conversation_t *conv;
    guint16         ctx_id;
    guint64         transport_salt;
} dcerpc_bind_key;

typedef struct _dcerpc_bind_value {
    e_guid_t uuid;
    guint16  ver;
    e_guid_t transport;
} dcerpc_bind_value;

static wmem_map_t *dcerpc_auths = NULL;

typedef struct _dcerpc_auth_context {
    conversation_t *conv;
    guint64         transport_salt;
    guint8          auth_type;
    guint8          auth_level;
    guint32         auth_context_id;
    guint32         first_frame;
    gboolean        hdr_signing;
} dcerpc_auth_context;

/* Extra data for DCERPC handling and tracking of context ids */
typedef struct _dcerpc_decode_as_data {
    guint16 dcectxid;             /**< Context ID (DCERPC-specific) */
    int     dcetransporttype;     /**< Transport type
                                    * Value -1 means "not a DCERPC packet"
                                    */
    guint64 dcetransportsalt;     /**< fid: if transporttype==DCE_CN_TRANSPORT_SMBPIPE */
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
        conversation_pt_to_endpoint_type(binding->ptype),
        binding->port_a,
        binding->port_b,
        0);

    if (!conv) {
        conv = conversation_new(
            0,
            &binding->addr_a,
            &binding->addr_b,
            conversation_pt_to_endpoint_type(binding->ptype),
            binding->port_a,
            binding->port_b,
            0);
    }

    bind_value = wmem_new(wmem_file_scope(), dcerpc_bind_value);
    bind_value->uuid = binding->uuid;
    bind_value->ver = binding->ver;
    /* For now, assume all DCE/RPC we pick from "decode as" is using
       standard ndr and not ndr64.
       We should make this selectable from the dialog in the future
    */
    bind_value->transport = uuid_data_repr_proto;

    key = wmem_new(wmem_file_scope(), dcerpc_bind_key);
    key->conv = conv;
    key->ctx_id = binding->ctx_id;
    key->transport_salt = binding->transport_salt;

    /* add this entry to the bind table */
    wmem_map_insert(dcerpc_binds, key, bind_value);

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

    free_address(&binding->addr_a);
    free_address(&binding->addr_b);
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

        decode_dcerpc_bindings = g_slist_remove(
            decode_dcerpc_bindings,
            decode_dcerpc_bindings->data);
        decode_dcerpc_binding_free(binding);
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
    g_string_append_printf(str, "&\r\nSMB FID: %"PRIu64"\r\n",
                           dcerpc_get_transport_salt(pinfo));
    g_string_append(str, "with:\r\n");

    (void) g_strlcpy(result, str->str, MAX_DECODE_AS_PROMPT_LEN);
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
    copy_address(&binding->addr_a, &pinfo->src);
    copy_address(&binding->addr_b, &pinfo->dst);
    binding->ptype = pinfo->ptype;
    binding->port_a = pinfo->srcport;
    binding->port_b = pinfo->destport;
    binding->ctx_id = decode_data->dcectxid;
    binding->transport_salt = dcerpc_get_transport_salt(pinfo);
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

    /*guid_key *k = key;*/
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
        addresses_equal(&binding_a->addr_a, &binding_b->addr_a) &&
        addresses_equal(&binding_a->addr_b, &binding_b->addr_b) &&
        binding_a->ptype == binding_b->ptype &&
        binding_a->port_a == binding_b->port_a &&
        binding_a->port_b == binding_b->port_b &&
        binding_a->ctx_id == binding_b->ctx_id &&
        binding_a->transport_salt == binding_b->transport_salt)
    {
        /* equal */
        return 0;
    }

    /* unequal */
    return 1;
}

/* remove a binding (looking the same way as the given one) */
static gboolean
decode_dcerpc_binding_reset(const char *name _U_, gconstpointer pattern)
{
    const decode_dcerpc_bind_values_t *binding = (const decode_dcerpc_bind_values_t *)pattern;
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

    free_address(&old_binding->addr_a);
    free_address(&old_binding->addr_b);
    g_string_free(old_binding->ifname, TRUE);
    g_free(old_binding);
    return FALSE;
}

static gboolean
dcerpc_decode_as_change(const char *name, gconstpointer pattern, gconstpointer handle, const gchar* list_name)
{
    const decode_dcerpc_bind_values_t *binding = (const decode_dcerpc_bind_values_t*)pattern;
    decode_dcerpc_bind_values_t *stored_binding;
    guid_key     *key = *((guid_key *const *)handle);

    /* remove a probably existing old binding */
    decode_dcerpc_binding_reset(name, binding);

    /*
     * Clone the new binding, update the changing parts, and append it
     * to the list.
     */
    stored_binding = g_new(decode_dcerpc_bind_values_t,1);
    *stored_binding = *binding;
    copy_address(&stored_binding->addr_a, &binding->addr_a);
    copy_address(&stored_binding->addr_b, &binding->addr_b);
    stored_binding->ifname = g_string_new(list_name);
    stored_binding->uuid = key->guid;
    stored_binding->ver = key->ver;

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
    e_guid_t act_id;
} dcerpc_fragment_key;

static guint
dcerpc_fragment_hash(gconstpointer k)
{
    const dcerpc_fragment_key* key = (const dcerpc_fragment_key*) k;
    guint hash_val;

    hash_val = 0;

    hash_val += key->id;
    hash_val += key->act_id.data1;
    hash_val += key->act_id.data2 << 16;
    hash_val += key->act_id.data3;

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
             && (addresses_equal(&key1->src, &key2->src))
             && (addresses_equal(&key1->dst, &key2->dst))
             && (memcmp (&key1->act_id, &key2->act_id, sizeof (e_guid_t)) == 0))
            ? TRUE : FALSE);
}

/* allocate a persistent dcerpc fragment key to insert in the hash */
static void *
dcerpc_fragment_temporary_key(const packet_info *pinfo, const guint32 id,
                              const void *data)
{
    dcerpc_fragment_key *key = g_slice_new(dcerpc_fragment_key);
    const e_dce_dg_common_hdr_t *hdr = (const e_dce_dg_common_hdr_t *)data;

    copy_address_shallow(&key->src, &pinfo->src);
    copy_address_shallow(&key->dst, &pinfo->dst);
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
    const e_dce_dg_common_hdr_t *hdr = (const e_dce_dg_common_hdr_t *)data;

    copy_address(&key->src, &pinfo->src);
    copy_address(&key->dst, &pinfo->dst);
    key->id = id;
    key->act_id = hdr->act_id;

    return key;
}

static void
dcerpc_fragment_free_temporary_key(gpointer ptr)
{
    dcerpc_fragment_key *key = (dcerpc_fragment_key *)ptr;

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
        free_address(&key->src);
        free_address(&key->dst);

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

    d = g_new(dcerpc_auth_subdissector, 1);

    d->auth_level = auth_level;
    d->auth_type = auth_type;
    memcpy(&d->auth_fns, fns, sizeof(dcerpc_auth_subdissector_fns));

    dcerpc_auth_subdissector_list = g_slist_append(dcerpc_auth_subdissector_list, d);
}

/* Hand off verifier data to a registered dissector */

static void dissect_auth_verf(packet_info *pinfo,
                              e_dce_cn_common_hdr_t *hdr,
                              dcerpc_auth_info *auth_info)
{
    dcerpc_dissect_fnct_t *fn = NULL;
    /* XXX - "stub" a fake DCERPC INFO STRUCTURE
       If a dcerpc_info is really needed, update
       the call stacks to include it
     */
    FAKE_DCERPC_INFO_STRUCTURE

    if (auth_info == NULL) {
        return;
    }

    if (auth_info->auth_fns == NULL) {
        return;
    }

    switch (hdr->ptype) {
    case PDU_BIND:
    case PDU_ALTER:
        fn = auth_info->auth_fns->bind_fn;
        break;
    case PDU_BIND_ACK:
    case PDU_ALTER_ACK:
        fn = auth_info->auth_fns->bind_ack_fn;
        break;
    case PDU_AUTH3:
        fn = auth_info->auth_fns->auth3_fn;
        break;
    case PDU_REQ:
    case PDU_CO_CANCEL:
    case PDU_ORPHANED:
        fn = auth_info->auth_fns->req_verf_fn;
        break;
    case PDU_RESP:
    case PDU_FAULT:
        fn = auth_info->auth_fns->resp_verf_fn;
        break;

    default:
        /* Don't know how to handle authentication data in this
           pdu type. */
        proto_tree_add_expert_format(auth_info->auth_tree, pinfo,
                                     &ei_dcerpc_invalid_pdu_authentication_attempt,
                                     auth_info->auth_tvb, 0, 0,
                                     "Don't know how to dissect authentication data for %s pdu type",
                                     val_to_str(hdr->ptype, pckt_vals, "Unknown (%u)"));
        return;
        break;
    }

    if (fn)
        fn(auth_info->auth_tvb, 0, pinfo, auth_info->auth_tree, &di, hdr->drep);
    else
        proto_tree_add_expert_format(auth_info->auth_tree, pinfo,
                                     &ei_dcerpc_verifier_unavailable,
                                     auth_info->auth_tvb, 0, hdr->auth_len,
                                     "%s Verifier unavailable",
                                     val_to_str(auth_info->auth_type,
                                                authn_protocol_vals,
                                                "Unknown (%u)"));
}

static proto_item*
proto_tree_add_dcerpc_drep(proto_tree *tree, tvbuff_t *tvb, int offset, guint8 drep[], int drep_len)
{
    const guint8 byteorder = drep[0] >> 4;
    const guint8 character = drep[0] & 0x0f;
    const guint8 fp = drep[1];
    proto_item *ti = proto_tree_add_bytes(tree, hf_dcerpc_drep, tvb, offset, drep_len, drep);
    proto_tree *tr = proto_item_add_subtree(ti, ett_dcerpc_drep);

    proto_tree_add_uint(tr, hf_dcerpc_drep_byteorder, tvb, offset, 1, byteorder);
    proto_tree_add_uint(tr, hf_dcerpc_drep_character, tvb, offset, 1, character);
    proto_tree_add_uint(tr, hf_dcerpc_drep_fp, tvb, offset+1, 1, fp);

    proto_item_append_text(ti, " (Order: %s, Char: %s, Float: %s)",
                           val_to_str(byteorder, drep_byteorder_vals, "Unknown (%u)"),
                           val_to_str(character, drep_character_vals, "Unknown (%u)"),
                           val_to_str(fp, drep_fp_vals, "Unknown (%u)"));
    return ti;
}

/* Hand off payload data to a registered dissector */

static tvbuff_t *decode_encrypted_data(tvbuff_t *header_tvb,
                                       tvbuff_t *payload_tvb,
                                       tvbuff_t *trailer_tvb,
                                       packet_info *pinfo,
                                       e_dce_cn_common_hdr_t *hdr,
                                       dcerpc_auth_info *auth_info)
{
    dcerpc_decode_data_fnct_t *fn = NULL;

    if (auth_info == NULL)
        return NULL;

    if (auth_info->auth_fns == NULL)
        return NULL;

    switch (hdr->ptype) {
    case PDU_REQ:
        fn = auth_info->auth_fns->req_data_fn;
        break;
    case PDU_RESP:
    case PDU_FAULT:
        fn = auth_info->auth_fns->resp_data_fn;
        break;
    }

    if (fn)
        return fn(header_tvb, payload_tvb, trailer_tvb, auth_info->auth_tvb, pinfo, auth_info);

    return NULL;
}

typedef struct _dcerpc_dissector_data
{
    dcerpc_uuid_value *sub_proto;
    dcerpc_info *info;
    gboolean decrypted;
    dcerpc_auth_info *auth_info;
    guint8 *drep;
    proto_tree *dcerpc_tree;
} dcerpc_dissector_data_t;

/*
 * Subdissectors
 */

static dissector_table_t    uuid_dissector_table;

/* the registered subdissectors */
GHashTable *dcerpc_uuids = NULL;

static gint
dcerpc_uuid_equal(gconstpointer k1, gconstpointer k2)
{
    const guid_key *key1 = (const guid_key *)k1;
    const guid_key *key2 = (const guid_key *)k2;
    return ((memcmp(&key1->guid, &key2->guid, sizeof (e_guid_t)) == 0)
            && (key1->ver == key2->ver));
}

static guint
dcerpc_uuid_hash(gconstpointer k)
{
    const guid_key *key = (const guid_key *)k;
    /* This isn't perfect, but the Data1 part of these is almost always
       unique. */
    return key->guid.data1;
}


static int
dissect_verification_trailer(packet_info *pinfo, tvbuff_t *tvb, int stub_offset,
                             proto_tree *parent_tree, int *signature_offset);

static void
show_stub_data(packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *dcerpc_tree,
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
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
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
                proto_tree_add_item(dcerpc_tree, hf_dcerpc_encrypted_stub_data, tvb, offset, length, ENC_NA);
                /* is the padding is still inside the encrypted blob, don't display it explicit */
                auth_pad_len = 0;
            } else {
                proto_tree_add_item(dcerpc_tree, hf_dcerpc_decrypted_stub_data, tvb, offset, plain_length, ENC_NA);
                dissect_verification_trailer(pinfo, tvb, offset, dcerpc_tree, NULL);
            }
        } else {
            proto_tree_add_item(dcerpc_tree, hf_dcerpc_stub_data, tvb, offset, plain_length, ENC_NA);
            dissect_verification_trailer(pinfo, tvb, offset, dcerpc_tree, NULL);
        }
        /* If there is auth padding at the end of the stub, display it */
        if (auth_pad_len != 0) {
            proto_tree_add_item(dcerpc_tree, hf_dcerpc_auth_padding, tvb, auth_pad_offset, auth_pad_len, ENC_NA);
        }
    }
}

static int
dissect_dcerpc_guid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dcerpc_dissector_data_t* dissector_data = (dcerpc_dissector_data_t*)data;
    const gchar          *name     = NULL;
    dcerpc_sub_dissector *proc;
    int (*volatile sub_dissect)(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep) = NULL;
    proto_item           *pi, *sub_item;
    proto_tree           *sub_tree;
    volatile guint        length;
    guint                 reported_length;
    volatile gint         offset   = 0;
    tvbuff_t *volatile    stub_tvb;
    tvbuff_t *volatile    payload_tvb = NULL;
    volatile guint        auth_pad_len;
    volatile int          auth_pad_offset;
    const char *volatile  saved_proto;

    for (proc = dissector_data->sub_proto->procs; proc->name; proc++) {
        if (proc->num == dissector_data->info->call_data->opnum) {
            name = proc->name;
            break;
        }
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, dissector_data->sub_proto->name);

    if (!name)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown operation %u %s",
                     dissector_data->info->call_data->opnum,
                     (dissector_data->info->ptype == PDU_REQ) ? "request" : "response");
    else
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                     name, (dissector_data->info->ptype == PDU_REQ) ? "request" : "response");

    sub_dissect = (dissector_data->info->ptype == PDU_REQ) ?
        proc->dissect_rqst : proc->dissect_resp;

    sub_item = proto_tree_add_item(tree, dissector_data->sub_proto->proto_id,
                                       tvb,//(decrypted_tvb != NULL)?decrypted_tvb:tvb,
                                       0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, dissector_data->sub_proto->ett);
    if (!name)
        proto_item_append_text(sub_item, ", unknown operation %u",
                                dissector_data->info->call_data->opnum);
    else
        proto_item_append_text(sub_item, ", %s", name);

    if (tree) {
        /*
         * Put the operation number into the tree along with
         * the operation's name.
         */
        if (dissector_data->sub_proto->opnum_hf != -1)
            proto_tree_add_uint_format(sub_tree, dissector_data->sub_proto->opnum_hf,
                                       tvb, 0, 0, dissector_data->info->call_data->opnum,
                                       "Operation: %s (%u)",
                                       name ? name : "Unknown operation",
                                       dissector_data->info->call_data->opnum);
        else
            proto_tree_add_uint_format_value(sub_tree, hf_dcerpc_op, tvb,
                                       0, 0, dissector_data->info->call_data->opnum,
                                       "%s (%u)",
                                       name ? name : "Unknown operation",
                                       dissector_data->info->call_data->opnum);

        if ((dissector_data->info->ptype == PDU_REQ) && (dissector_data->info->call_data->rep_frame != 0)) {
            pi = proto_tree_add_uint(sub_tree, hf_dcerpc_response_in,
                                     tvb, 0, 0, dissector_data->info->call_data->rep_frame);
            proto_item_set_generated(pi);
        }
        if ((dissector_data->info->ptype == PDU_RESP) && (dissector_data->info->call_data->req_frame != 0)) {
            pi = proto_tree_add_uint(sub_tree, hf_dcerpc_request_in,
                                     tvb, 0, 0, dissector_data->info->call_data->req_frame);
            proto_item_set_generated(pi);
        }
    } /* tree */

    if (!dissector_data->decrypted || (sub_dissect == NULL))
    {
        show_stub_data(pinfo, tvb, 0, sub_tree, dissector_data->auth_info, !dissector_data->decrypted);
        return tvb_captured_length(tvb);
    }

    /* Either there was no encryption or we successfully decrypted
       the encrypted payload. */

    /* We have a subdissector - call it. */
    saved_proto          = pinfo->current_proto;
    pinfo->current_proto = dissector_data->sub_proto->name;

    init_ndr_pointer_list(dissector_data->info);

    length = tvb_captured_length(tvb);
    reported_length = tvb_reported_length(tvb);

    /*
     * Remove the authentication padding from the stub data.
     */
    if ((dissector_data->auth_info != NULL) && (dissector_data->auth_info->auth_pad_len != 0)) {
        if (reported_length >= dissector_data->auth_info->auth_pad_len) {
            /*
             * OK, the padding length isn't so big that it
             * exceeds the stub length.  Trim the reported
             * length of the tvbuff.
             */
            reported_length -= dissector_data->auth_info->auth_pad_len;

            /*
             * If that exceeds the actual amount of data in
             * the tvbuff (which means we have at least one
             * byte of authentication padding in the tvbuff),
             * trim the actual amount.
             */
            if (length > reported_length)
                length = reported_length;

            stub_tvb = tvb_new_subset_length_caplen(tvb, 0, length, reported_length);
            auth_pad_len = dissector_data->auth_info->auth_pad_len;
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
        stub_tvb = tvb;
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
            proto_tree *stub_tree = NULL;
            int remaining;
            int trailer_start_offset = -1;
            int trailer_end_offset = -1;

            stub_tree = proto_tree_add_subtree_format(dissector_data->dcerpc_tree,
                                stub_tvb, 0, length,
                                ett_dcerpc_complete_stub_data, NULL,
                                "Complete stub data (%d byte%s)", length,
                                plurality(length, "", "s"));
            trailer_end_offset = dissect_verification_trailer(pinfo,
                                                    stub_tvb, 0,
                                                    stub_tree,
                                                    &trailer_start_offset);

            if (trailer_end_offset != -1) {
                remaining = tvb_captured_length_remaining(stub_tvb,
                                                    trailer_start_offset);
                length -= remaining;

                if (sub_item) {
                        proto_item_set_len(sub_item, length);
                }
            } else {
                proto_item *payload_item;

                payload_item = proto_tree_add_item(stub_tree,
                                    hf_dcerpc_payload_stub_data,
                                    stub_tvb, 0, length, ENC_NA);
                proto_item_append_text(payload_item, " (%d byte%s)",
                                        length, plurality(length, "", "s"));
            }

            payload_tvb = tvb_new_subset_length_caplen(stub_tvb, 0, length, length);
            offset = sub_dissect(payload_tvb, 0, pinfo, sub_tree,
                            dissector_data->info, dissector_data->drep);

            /* If we have a subdissector and it didn't dissect all
                data in the tvb, make a note of it. */
            remaining = tvb_reported_length_remaining(stub_tvb, offset);

            if (trailer_end_offset != -1) {
                if (offset > trailer_start_offset) {
                    remaining = offset - trailer_start_offset;
                    proto_tree_add_item(sub_tree, hf_dcerpc_stub_data_with_sec_vt,
                                        stub_tvb, trailer_start_offset, remaining, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO,
                                        "[Payload with Verification Trailer (%d byte%s)]",
                                    remaining,
                                    plurality(remaining, "", "s"));
                    remaining = 0;
                } else {
                    remaining = trailer_start_offset - offset;
                }
            }

            if (remaining > 0) {
                proto_tree_add_expert(sub_tree, pinfo, &ei_dcerpc_long_frame, stub_tvb, offset, remaining);
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
        proto_tree_add_item(sub_tree, hf_dcerpc_auth_padding, tvb, auth_pad_offset, auth_pad_len, ENC_NA);
    }

    pinfo->current_proto = saved_proto;

    return tvb_captured_length(tvb);
}

void
dcerpc_init_uuid(int proto, int ett, e_guid_t *uuid, guint16 ver,
                 dcerpc_sub_dissector *procs, int opnum_hf)
{
    guid_key   *key         = (guid_key *)g_malloc(sizeof (*key));
    dcerpc_uuid_value *value       = (dcerpc_uuid_value *)g_malloc(sizeof (*value));
    header_field_info *hf_info;
    module_t          *samr_module;
    const char        *filter_name = proto_get_protocol_filter_name(proto);
    dissector_handle_t guid_handle;

    key->guid = *uuid;
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

    /* Register the GUID with the dissector table */
    guid_handle = create_dissector_handle( dissect_dcerpc_guid, proto);
    dissector_add_guid( "dcerpc.uuid", key, guid_handle );

    /* add this GUID to the global name resolving */
    guids_add_uuid(uuid, proto_get_protocol_short_name(value->proto));

    /* Register the samr.nt_password preference as obsolete */
    /* This should be in packet-dcerpc-samr.c */
    if (strcmp(filter_name, "samr") == 0) {
        samr_module = prefs_register_protocol_obsolete(proto);
        prefs_register_obsolete_preference(samr_module, "nt_password");
    }
}

/* Function to find the name of a registered protocol
 * or NULL if the protocol/version is not known to wireshark.
 */
const char *
dcerpc_get_proto_name(e_guid_t *uuid, guint16 ver)
{
    dissector_handle_t handle;
    guid_key    key;

    key.guid = *uuid;
    key.ver = ver;

    handle = dissector_get_guid_handle(uuid_dissector_table, &key);
    if (handle == NULL) {
        return NULL;
    }

    return dissector_handle_get_short_name(handle);
}

/* Function to find the opnum hf-field of a registered protocol
 * or -1 if the protocol/version is not known to wireshark.
 */
int
dcerpc_get_proto_hf_opnum(e_guid_t *uuid, guint16 ver)
{
    guid_key    key;
    dcerpc_uuid_value *sub_proto;

    key.guid = *uuid;
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
dcerpc_get_proto_sub_dissector(e_guid_t *uuid, guint16 ver)
{
    guid_key    key;
    dcerpc_uuid_value *sub_proto;

    key.guid = *uuid;
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
            && (key1->transport_salt == key2->transport_salt));
}

static guint
dcerpc_bind_hash(gconstpointer k)
{
    const dcerpc_bind_key *key = (const dcerpc_bind_key *)k;
    guint hash;

    hash = GPOINTER_TO_UINT(key->conv);
    hash += key->ctx_id;
    /* sizeof(guint) might be smaller than sizeof(guint64) */
    hash += (guint)key->transport_salt;
    hash += (guint)(key->transport_salt << sizeof(guint));

    return hash;
}

static gint
dcerpc_auth_context_equal(gconstpointer k1, gconstpointer k2)
{
    const dcerpc_auth_context *key1 = (const dcerpc_auth_context *)k1;
    const dcerpc_auth_context *key2 = (const dcerpc_auth_context *)k2;
    return ((key1->conv == key2->conv)
            && (key1->auth_context_id == key2->auth_context_id)
            && (key1->transport_salt == key2->transport_salt));
}

static guint
dcerpc_auth_context_hash(gconstpointer k)
{
    const dcerpc_auth_context *key = (const dcerpc_auth_context *)k;
    guint hash;

    hash = GPOINTER_TO_UINT(key->conv);
    hash += key->auth_context_id;
    /* sizeof(guint) might be smaller than sizeof(guint64) */
    hash += (guint)key->transport_salt;
    hash += (guint)(key->transport_salt << sizeof(guint));

    return hash;
}

/*
 * To keep track of callid mappings.  Should really use some generic
 * conversation support instead.
 */
static wmem_map_t *dcerpc_cn_calls = NULL;
static wmem_map_t *dcerpc_dg_calls = NULL;

typedef struct _dcerpc_cn_call_key {
    conversation_t *conv;
    guint32 call_id;
    guint64 transport_salt;
} dcerpc_cn_call_key;

typedef struct _dcerpc_dg_call_key {
    conversation_t *conv;
    guint32         seqnum;
    e_guid_t        act_id ;
} dcerpc_dg_call_key;


static gint
dcerpc_cn_call_equal(gconstpointer k1, gconstpointer k2)
{
    const dcerpc_cn_call_key *key1 = (const dcerpc_cn_call_key *)k1;
    const dcerpc_cn_call_key *key2 = (const dcerpc_cn_call_key *)k2;
    return ((key1->conv == key2->conv)
            && (key1->call_id == key2->call_id)
            && (key1->transport_salt == key2->transport_salt));
}

static gint
dcerpc_dg_call_equal(gconstpointer k1, gconstpointer k2)
{
    const dcerpc_dg_call_key *key1 = (const dcerpc_dg_call_key *)k1;
    const dcerpc_dg_call_key *key2 = (const dcerpc_dg_call_key *)k2;
    return ((key1->conv == key2->conv)
            && (key1->seqnum == key2->seqnum)
            && ((memcmp(&key1->act_id, &key2->act_id, sizeof (e_guid_t)) == 0)));
}

static guint
dcerpc_cn_call_hash(gconstpointer k)
{
    const dcerpc_cn_call_key *key = (const dcerpc_cn_call_key *)k;
    guint hash;

    hash = GPOINTER_TO_UINT(key->conv);
    hash += key->call_id;
    /* sizeof(guint) might be smaller than sizeof(guint64) */
    hash += (guint)key->transport_salt;
    hash += (guint)(key->transport_salt << sizeof(guint));

    return hash;
}

static guint
dcerpc_dg_call_hash(gconstpointer k)
{
    const dcerpc_dg_call_key *key = (const dcerpc_dg_call_key *)k;
    return (GPOINTER_TO_UINT(key->conv) + key->seqnum + key->act_id.data1
            + (key->act_id.data2 << 16)    + key->act_id.data3
            + (key->act_id.data4[0] << 24) + (key->act_id.data4[1] << 16)
            + (key->act_id.data4[2] << 8)  + (key->act_id.data4[3] << 0)
            + (key->act_id.data4[4] << 24) + (key->act_id.data4[5] << 16)
            + (key->act_id.data4[6] << 8)  + (key->act_id.data4[7] << 0));
}

/* to keep track of matched calls/responses
   this one uses the same value struct as calls, but the key is the frame id
   and call id; there can be more than one call in a frame.

   XXX - why not just use the same keys as are used for calls?
*/

static wmem_map_t *dcerpc_matched = NULL;

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

static gboolean
uuid_equal(e_guid_t *uuid1, e_guid_t *uuid2)
{
    if( (uuid1->data1    != uuid2->data1)
      ||(uuid1->data2    != uuid2->data2)
      ||(uuid1->data3    != uuid2->data3)
      ||(uuid1->data4[0] != uuid2->data4[0])
      ||(uuid1->data4[1] != uuid2->data4[1])
      ||(uuid1->data4[2] != uuid2->data4[2])
      ||(uuid1->data4[3] != uuid2->data4[3])
      ||(uuid1->data4[4] != uuid2->data4[4])
      ||(uuid1->data4[5] != uuid2->data4[5])
      ||(uuid1->data4[6] != uuid2->data4[6])
      ||(uuid1->data4[7] != uuid2->data4[7]) ){
        return FALSE;
    }
    return TRUE;
}

static void
dcerpcstat_init(struct register_srt* srt, GArray* srt_array)
{
    dcerpcstat_tap_data_t* tap_data = (dcerpcstat_tap_data_t*)get_srt_table_param_data(srt);
    srt_stat_table *dcerpc_srt_table;
    int i, hf_opnum;
    dcerpc_sub_dissector *procs;

    DISSECTOR_ASSERT(tap_data);

    hf_opnum = dcerpc_get_proto_hf_opnum(&tap_data->uuid, tap_data->ver);
    procs    = dcerpc_get_proto_sub_dissector(&tap_data->uuid, tap_data->ver);

    if(hf_opnum != -1){
        dcerpc_srt_table = init_srt_table(tap_data->prog, NULL, srt_array, tap_data->num_procedures, NULL, proto_registrar_get_nth(hf_opnum)->abbrev, tap_data);
    } else {
        dcerpc_srt_table = init_srt_table(tap_data->prog, NULL, srt_array, tap_data->num_procedures, NULL, NULL, tap_data);
    }

    for(i=0;i<tap_data->num_procedures;i++){
        int j;
        const char *proc_name;

        proc_name = "unknown";
        for(j=0;procs[j].name;j++)
        {
            if (procs[j].num == i)
            {
                proc_name = procs[j].name;
            }
        }

        init_srt_table_row(dcerpc_srt_table, i, proc_name);
    }
}

static tap_packet_status
dcerpcstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv, tap_flags_t flags _U_)
{
    guint i = 0;
    srt_stat_table *dcerpc_srt_table;
    srt_data_t *data = (srt_data_t *)pss;
    const dcerpc_info *ri = (const dcerpc_info *)prv;
    dcerpcstat_tap_data_t* tap_data;

    dcerpc_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
    tap_data = (dcerpcstat_tap_data_t*)dcerpc_srt_table->table_specific_data;

    if(!ri->call_data){
        return TAP_PACKET_DONT_REDRAW;
    }
    if(!ri->call_data->req_frame){
        /* we have not seen the request so we don't know the delta*/
        return TAP_PACKET_DONT_REDRAW;
    }
    if(ri->call_data->opnum >= tap_data->num_procedures){
        /* don't handle this since it's outside of known table */
        return TAP_PACKET_DONT_REDRAW;
    }

    /* we are only interested in reply packets */
    if(ri->ptype != PDU_RESP){
        return TAP_PACKET_DONT_REDRAW;
    }

    /* we are only interested in certain program/versions */
    if( (!uuid_equal( (&ri->call_data->uuid), (&tap_data->uuid)))
        ||(ri->call_data->ver != tap_data->ver)){
        return TAP_PACKET_DONT_REDRAW;
    }

    add_srt_table_data(dcerpc_srt_table, ri->call_data->opnum, &ri->call_data->req_time, pinfo);

    return TAP_PACKET_REDRAW;
}

static guint
dcerpcstat_param(register_srt_t* srt, const char* opt_arg, char** err)
{
    int pos = 0;
    guint32 i, max_procs;
    dcerpcstat_tap_data_t* tap_data;
    guint d1,d2,d3,d40,d41,d42,d43,d44,d45,d46,d47;
    int major, minor;
    guint16 ver;
    dcerpc_sub_dissector *procs;

    if (sscanf(opt_arg, ",%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x,%d.%d%n",
           &d1,&d2,&d3,&d40,&d41,&d42,&d43,&d44,&d45,&d46,&d47,&major,&minor,&pos) == 13)
    {
        if ((major < 0) || (major > 65535)) {
            *err = ws_strdup_printf("dcerpcstat_init() Major version number %d is invalid - must be positive and <= 65535", major);
            return pos;
        }
        if ((minor < 0) || (minor > 65535)) {
            *err = ws_strdup_printf("dcerpcstat_init() Minor version number %d is invalid - must be positive and <= 65535", minor);
            return pos;
        }
        ver = major;

        tap_data = g_new0(dcerpcstat_tap_data_t, 1);

        tap_data->uuid.data1    = d1;
        tap_data->uuid.data2    = d2;
        tap_data->uuid.data3    = d3;
        tap_data->uuid.data4[0] = d40;
        tap_data->uuid.data4[1] = d41;
        tap_data->uuid.data4[2] = d42;
        tap_data->uuid.data4[3] = d43;
        tap_data->uuid.data4[4] = d44;
        tap_data->uuid.data4[5] = d45;
        tap_data->uuid.data4[6] = d46;
        tap_data->uuid.data4[7] = d47;

        procs             = dcerpc_get_proto_sub_dissector(&tap_data->uuid, ver);
        tap_data->prog    = dcerpc_get_proto_name(&tap_data->uuid, ver);
        tap_data->ver     = ver;

        for(i=0,max_procs=0;procs[i].name;i++)
        {
            if(procs[i].num>max_procs)
            {
                max_procs = procs[i].num;
            }
        }
        tap_data->num_procedures = max_procs+1;

        set_srt_table_param_data(srt, tap_data);
    }
    else
    {
        *err = ws_strdup_printf("<uuid>,<major version>.<minor version>[,<filter>]");
    }

    return pos;
}


/*
 * Utility functions.  Modeled after packet-rpc.c
 */

int
dissect_dcerpc_char(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                     proto_tree *tree, guint8 *drep,
                     int hfindex, guint8 *pdata)
{
    guint8 data;

    /*
     * XXX - fix to handle EBCDIC if we ever support EBCDIC FT_CHAR.
     */
    data = tvb_get_guint8(tvb, offset);
    if (hfindex != -1) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 1, ENC_ASCII|DREP_ENC_INTEGER(drep));
    }
    if (pdata)
        *pdata = data;
    tvb_ensure_bytes_exist(tvb, offset, 1);
    return offset + 1;
}

int
dissect_dcerpc_uint8(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                     proto_tree *tree, guint8 *drep,
                     int hfindex, guint8 *pdata)
{
    guint8 data;

    data = tvb_get_guint8(tvb, offset);
    if (hfindex != -1) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 1, DREP_ENC_INTEGER(drep));
    }
    if (pdata)
        *pdata = data;
    tvb_ensure_bytes_exist(tvb, offset, 1);
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

    if (hfindex != -1) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 2, DREP_ENC_INTEGER(drep));
    }
    if (pdata)
        *pdata = data;
    tvb_ensure_bytes_exist(tvb, offset, 2);
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

    if (hfindex != -1) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 4, DREP_ENC_INTEGER(drep));
    }
    if (pdata)
        *pdata = data;
    tvb_ensure_bytes_exist(tvb, offset, 4);
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
    if (hfindex != -1) {
        if (data == 0xffffffff) {
            /* special case,   no time specified */
            proto_tree_add_time_format_value(tree, hfindex, tvb, offset, 4, &tv, "No time specified");
        } else {
            proto_tree_add_time(tree, hfindex, tvb, offset, 4, &tv);
        }
    }
    if (pdata)
        *pdata = data;

    tvb_ensure_bytes_exist(tvb, offset, 4);
    return offset+4;
}

int
dissect_dcerpc_uint64(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, dcerpc_info *di, guint8 *drep,
                      int hfindex, guint64 *pdata)
{
    guint64 data;

    data = ((drep[0] & DREP_LITTLE_ENDIAN)
            ? tvb_get_letoh64(tvb, offset)
            : tvb_get_ntoh64(tvb, offset));

    if (hfindex != -1) {
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
            /* The value is truncated to 32bits.  64bit values have only been
               seen on fuzz-tested files */
            DISSECTOR_ASSERT((di->call_data->flags & DCERPC_IS_NDR64) || (data <= G_MAXUINT32));
            proto_tree_add_uint(tree, hfindex, tvb, offset, 8, (guint32)data);
        }
    }
    if (pdata)
        *pdata = data;
    tvb_ensure_bytes_exist(tvb, offset, 8);
    return offset+8;
}


int
dissect_dcerpc_float(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                     proto_tree *tree, guint8 *drep,
                     int hfindex, gfloat *pdata)
{
    gfloat data;


    switch (drep[1]) {
    case(DCE_RPC_DREP_FP_IEEE):
        data = ((drep[0] & DREP_LITTLE_ENDIAN)
                ? tvb_get_letohieee_float(tvb, offset)
                : tvb_get_ntohieee_float(tvb, offset));
        if (tree && hfindex != -1) {
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
        proto_tree_add_expert_format(tree, pinfo, &ei_dcerpc_not_implemented, tvb, offset, 4,
                                     "DCE RPC: dissection of non IEEE floating formats currently not implemented (drep=%u)!",
                                     drep[1]);
    }
    if (pdata)
        *pdata = data;
    tvb_ensure_bytes_exist(tvb, offset, 4);
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
        if (tree && hfindex != -1) {
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
        proto_tree_add_expert_format(tree, pinfo, &ei_dcerpc_not_implemented, tvb, offset, 8,
                                     "DCE RPC: dissection of non IEEE double formats currently not implemented (drep=%u)!",
                                     drep[1]);
    }
    if (pdata)
        *pdata = data;
    tvb_ensure_bytes_exist(tvb, offset, 8);
    return offset + 8;
}


int
dissect_dcerpc_uuid_t(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                      proto_tree *tree, guint8 *drep,
                      int hfindex, e_guid_t *pdata)
{
    e_guid_t uuid;


    if (drep[0] & DREP_LITTLE_ENDIAN) {
        tvb_get_letohguid(tvb, offset, (e_guid_t *) &uuid);
    } else {
        tvb_get_ntohguid(tvb, offset, (e_guid_t *) &uuid);
    }
    if (tree && hfindex != -1) {
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
dcerpc_tvb_get_uuid(tvbuff_t *tvb, gint offset, guint8 *drep, e_guid_t *uuid)
{
    if (drep[0] & DREP_LITTLE_ENDIAN) {
        tvb_get_letohguid(tvb, offset, (e_guid_t *) uuid);
    } else {
        tvb_get_ntohguid(tvb, offset, (e_guid_t *) uuid);
    }
}


/* NDR arrays */
/* function to dissect a unidimensional conformant array */
static int
dissect_ndr_ucarray_core(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                    proto_tree *tree, dcerpc_info *di, guint8 *drep,
                    dcerpc_dissect_fnct_t *fnct_bytes,
                    dcerpc_dissect_fnct_blk_t *fnct_block)
{
    guint32      i;
    int          old_offset;
    int          conformance_size = 4;

    /* ensure that just one pointer is set in the call */
    DISSECTOR_ASSERT((fnct_bytes && !fnct_block) || (!fnct_bytes && fnct_block));

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
        if (fnct_block) {
                offset = (*fnct_block)(tvb, offset, di->array_max_count,
                                       pinfo, tree, di, drep);
        } else {
            for (i=0 ;i<di->array_max_count; i++) {
                offset = (*fnct_bytes)(tvb, offset, pinfo, tree, di, drep);
            }
        }
    }

    return offset;
}

int
dissect_ndr_ucarray_block(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                          proto_tree *tree, dcerpc_info *di, guint8 *drep,
                          dcerpc_dissect_fnct_blk_t *fnct)
{
    return dissect_ndr_ucarray_core(tvb, offset, pinfo, tree, di, drep, NULL, fnct);
}

int
dissect_ndr_ucarray(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                    proto_tree *tree, dcerpc_info *di, guint8 *drep,
                    dcerpc_dissect_fnct_t *fnct)
{
    return dissect_ndr_ucarray_core(tvb, offset, pinfo, tree, di, drep, fnct, NULL);
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
                offset = (*fnct_block)(tvb, offset, di->array_actual_count,
                                       pinfo, tree, di, drep);
        } else if (fnct_bytes) {
            for (i=0 ;i<di->array_actual_count; i++) {
                old_offset = offset;
                offset = (*fnct_bytes)(tvb, offset, pinfo, tree, di, drep);
                /* Make sure we're moving forward */
                if (old_offset >= offset)
                    break;
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
    if (len) {
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
    DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_STRING);

    if (di->conformant_run) {
        /* just a run to handle conformant arrays, no scalars to dissect */
        return offset;
    }

    if (add_subtree) {
        string_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dcerpc_string, &string_item,
                                          proto_registrar_get_name(hfindex));
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

    /* The value is truncated to 32bits.  64bit values have only been
       seen on fuzztested files */
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
        s = tvb_get_string_enc(pinfo->pool, tvb, offset, buffer_len,
                               ENC_UTF_16|DREP_ENC_INTEGER(drep));
    } else {
        /*
         * XXX - what if size_is is neither 1 nor 2?
         */
        s = tvb_get_string_enc(pinfo->pool, tvb, offset, buffer_len,
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
           && (!pinfo->fd->visited)) {
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
    DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_STRING);

    if (di->conformant_run) {
        /* just a run to handle conformant arrays, no scalars to dissect */
        return offset;
    }

    if (add_subtree) {
        string_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dcerpc_string, &string_item,
                                          proto_registrar_get_name(hfindex));
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
        s = tvb_get_string_enc(pinfo->pool, tvb, offset, buffer_len,
                               ENC_UTF_16|DREP_ENC_INTEGER(drep));
    } else {
        /*
         * XXX - what if size_is is neither 1 nor 2?
         */
        s = tvb_get_string_enc(pinfo->pool, tvb, offset, buffer_len,
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
/* Should we re-read the size of the list ?
 * Instead of re-calculating the size everytime, use the stored value unless this
 * flag is set which means: re-read the size of the list
 */
static gboolean must_check_size = FALSE;
/*
 * List of pointers encountered so far in the current level. Points to an
 * element of list_ndr_pointer_list.
 */
static GSList *ndr_pointer_list = NULL;

static GHashTable *ndr_pointer_hash = NULL;
/*
 * List of pointer list, in order to avoid huge performance penalty
 * when dealing with list bigger than 100 elements due to the way we
 * try to insert in the list.
 * We instead maintain a stack of pointer list
 * To make it easier to manage we just use a list to materialize the stack
 */
static GSList *list_ndr_pointer_list = NULL;

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

    while (list_ndr_pointer_list) {
        GSList *list = (GSList *)g_slist_nth_data(list_ndr_pointer_list, 0);
        list_ndr_pointer_list = g_slist_remove(list_ndr_pointer_list, list);
        g_slist_free_full(list, g_free);
    }
    g_slist_free_full(list_ndr_pointer_list, g_free);

    list_ndr_pointer_list = NULL;
    pointers_are_top_level = TRUE;
    must_check_size = FALSE;

    ndr_pointer_list = NULL;
    if (ndr_pointer_hash) {
        g_hash_table_destroy(ndr_pointer_hash);
    }
    ndr_pointer_hash = g_hash_table_new(g_int_hash, g_int_equal);
}

int
dissect_deferred_pointers(packet_info *pinfo, tvbuff_t *tvb, int offset, dcerpc_info *di, guint8 *drep)
{
    int          found_new_pointer;
    int          old_offset;
    int          next_pointer;
    unsigned     original_depth;
    int          len;
    GSList      *current_ndr_pointer_list;

    /*
     * pidl has a difficiency of unconditionally emitting calls
     * dissect_deferred_pointers() to the generated dissectors.
     */
    if (list_ndr_pointer_list == NULL) {
        return offset;
    }

    /* Probably not necessary, it is supposed to prevent more pointers from
     * being added to the list. */
    ndr_pointer_list = NULL;

    next_pointer = 0;

    /* Obtain the current list of pointers at this level. */
    current_ndr_pointer_list = (GSList *)g_slist_last(list_ndr_pointer_list)->data;
    original_depth = g_slist_length(list_ndr_pointer_list);

    len = g_slist_length(current_ndr_pointer_list);
    do {
        int i;

        found_new_pointer = 0;
process_list:
        for (i=next_pointer; i<len; i++) {
            ndr_pointer_data_t *tnpd = (ndr_pointer_data_t *)g_slist_nth_data(current_ndr_pointer_list, i);

            if (tnpd->fnct) {
                GSList *saved_ndr_pointer_list = NULL;

                dcerpc_dissect_fnct_t *fnct;

                next_pointer = i+1;
                found_new_pointer = 1;
                fnct = tnpd->fnct;
                tnpd->fnct = NULL;
                di->hf_index = tnpd->hf_index;
                /* first a run to handle any conformant
                   array headers */
                di->conformant_run = 1;
                di->conformant_eaten = 0;
                old_offset = offset;
                saved_ndr_pointer_list = current_ndr_pointer_list;
                ndr_pointer_list = NULL;
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
                if (ndr_pointer_list) {
                    /* We found some pointers to dissect, descend into it. */
                    next_pointer = 0;
                    len = g_slist_length(ndr_pointer_list);
                    current_ndr_pointer_list = ndr_pointer_list;
                    ndr_pointer_list = NULL;
                    goto process_list;          /* Process the new current_ndr_pointer_list */
                } else {
                    current_ndr_pointer_list = saved_ndr_pointer_list;
                }
            }
            /* If we found the end of the list, but add_pointer_to_list extended
             * it, then be sure to handle those extra elements. */
            if (i == (len - 1) && (must_check_size == TRUE)) {
                len = g_slist_length(ndr_pointer_list);
                must_check_size = FALSE;
            }
        }

        /* We reached the end of one level, go to the level bellow if possible
         * reset list a level n
         */
        if ((i >= (len - 1)) && (g_slist_length(list_ndr_pointer_list) > original_depth)) {
            GSList *list;
            /* Remove existing list */
            g_slist_free_full(current_ndr_pointer_list, g_free);
            list = (GSList *)g_slist_last(list_ndr_pointer_list)->data;
            list_ndr_pointer_list = g_slist_remove(list_ndr_pointer_list, list);

            /* Rewind on the lower level, in theory it's not too great because we
             * will one more time iterate on pointers already done
             * In practice it shouldn't be that bad !
             */
            next_pointer = 0;
            /* Move to the next list of pointers. */
            current_ndr_pointer_list = (GSList *)g_slist_last(list_ndr_pointer_list)->data;
            len = g_slist_length(current_ndr_pointer_list);
            found_new_pointer = 1;
        }

    } while (found_new_pointer);
    DISSECTOR_ASSERT(original_depth == g_slist_length(list_ndr_pointer_list));

    g_slist_free_full(ndr_pointer_list, g_free);
    /* Restore the previous list of pointers. */
    ndr_pointer_list = (GSList *)g_slist_last(list_ndr_pointer_list)->data;

    return offset;
}

static int
find_pointer_index(guint32 id)
{
    guint *p = (guint*) g_hash_table_lookup(ndr_pointer_hash, &id);

    return (p != NULL);
}

static void
add_pointer_to_list(packet_info *pinfo, proto_tree *tree, proto_item *item,
                    dcerpc_info *di, dcerpc_dissect_fnct_t *fnct, guint32 id, int hf_index,
                    dcerpc_callback_fnct_t *callback, void *callback_args)
{
    ndr_pointer_data_t *npd;
    guint *p_id;

    /* check if this pointer is valid */
    if (id != 0xffffffff) {
        dcerpc_call_value *value;

        value = di->call_data;

        if (di->ptype == PDU_REQ) {
            if (!(pinfo->fd->visited)) {
                if (id > value->max_ptr) {
                    value->max_ptr = id;
                }
            }
        } else {
            /* if we haven't seen the request bail out since we can't
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

    npd = g_new(ndr_pointer_data_t, 1);
    npd->id   = id;
    npd->tree = tree;
    npd->item = item;
    npd->fnct = fnct;
    npd->hf_index = hf_index;
    npd->callback = callback;
    npd->callback_args = callback_args;
    p_id = wmem_new(wmem_file_scope(), guint);
    *p_id = id;

    /* Update the list of pointers for use by dissect_deferred_pointers. If this
     * is the first pointer, create a list and add it to the stack. */
    if (!ndr_pointer_list) {
        ndr_pointer_list = g_slist_append(NULL, npd);
        list_ndr_pointer_list = g_slist_append(list_ndr_pointer_list, ndr_pointer_list);
    } else {
        ndr_pointer_list = g_slist_append(ndr_pointer_list, npd);
    }
    g_hash_table_insert(ndr_pointer_hash, p_id, p_id);
    must_check_size = TRUE;
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
        tr = proto_tree_add_subtree(tree, tvb, offset, 0,
                                   ett_dcerpc_pointer_data, &item, text);

        add_pointer_to_list(pinfo, tr, item, di, fnct, 0xffffffff,
                            hf_index, callback, callback_args);
        goto after_ref_id;
    }

    /*TOP LEVEL FULL POINTER*/
    if ( pointers_are_top_level
        && (type == NDR_POINTER_PTR) ) {
        int found;
        guint64 id;
        proto_item *item;

        /* get the referent id */
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, NULL, di, drep, -1, &id);

        /* we got a NULL pointer */
        if (id == 0) {
            proto_tree_add_bytes_format_value(tree, hf_dcerpc_null_pointer, tvb, offset-pointer_size,
                                pointer_size, NULL, "%s", text);
            goto after_ref_id;
        }

        /* see if we have seen this pointer before
           The value is truncated to 32bits.  64bit values have only been
           seen on fuzz-tested files */
        found = find_pointer_index((guint32)id);

        /* we have seen this pointer before */
        if (found) {
            proto_tree_add_string(tree, hf_dcerpc_duplicate_ptr, tvb, offset-pointer_size, pointer_size, text);
            goto after_ref_id;
        }

        /* new pointer */
        tr = proto_tree_add_subtree(tree, tvb, offset-pointer_size,
                                   pointer_size, ett_dcerpc_pointer_data, &item, text);
        if (di->call_data->flags & DCERPC_IS_NDR64) {
            proto_tree_add_uint64(tr, hf_dcerpc_referent_id64, tvb,
                                offset-pointer_size, pointer_size, id);
        } else {
            proto_tree_add_uint(tr, hf_dcerpc_referent_id32, tvb,
                                offset-pointer_size, pointer_size, (guint32)id);
        }
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

        /* we got a NULL pointer */
        if (id == 0) {
            proto_tree_add_bytes_format_value(tree, hf_dcerpc_null_pointer, tvb, offset-pointer_size,
                                pointer_size, NULL, "%s",text);
            goto after_ref_id;
        }

        /* new pointer */
        tr = proto_tree_add_subtree(tree, tvb, offset-pointer_size,
                                   pointer_size,
                                   ett_dcerpc_pointer_data, &item, text);
        if (di->call_data->flags & DCERPC_IS_NDR64) {
            proto_tree_add_uint64(tr, hf_dcerpc_referent_id64, tvb,
                            offset-pointer_size, pointer_size, id);
        } else {
            proto_tree_add_uint(tr, hf_dcerpc_referent_id32, tvb,
                            offset-pointer_size, pointer_size, (guint32)id);
        }
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

        /* new pointer */
        tr = proto_tree_add_subtree(tree, tvb, offset-pointer_size,
                                 pointer_size,
                                 ett_dcerpc_pointer_data,&item,text);
        if (di->call_data->flags & DCERPC_IS_NDR64) {
            proto_tree_add_uint64(tr, hf_dcerpc_referent_id64, tvb,
                            offset-pointer_size, pointer_size, id);
        } else {
            proto_tree_add_uint(tr, hf_dcerpc_referent_id32, tvb,
                            offset-pointer_size, pointer_size, (guint32)id);
        }
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

        /* we got a NULL pointer */
        if (id == 0) {
            proto_tree_add_bytes_format_value(tree, hf_dcerpc_null_pointer, tvb, offset-pointer_size,
                                pointer_size, NULL, "%s",text);
            goto after_ref_id;
        }

        /* new pointer */
        tr = proto_tree_add_subtree(tree, tvb, offset-pointer_size,
                                   pointer_size,
                                   ett_dcerpc_pointer_data,&item,text);
        if (di->call_data->flags & DCERPC_IS_NDR64) {
            proto_tree_add_uint64(tr, hf_dcerpc_referent_id64, tvb,
                            offset-pointer_size, pointer_size, id);
        } else {
            proto_tree_add_uint(tr, hf_dcerpc_referent_id32, tvb,
                            offset-pointer_size, pointer_size, (guint32)id);
        }
        add_pointer_to_list(pinfo, tr, item, di, fnct, 0xffffffff,
                            hf_index, callback, callback_args);
        goto after_ref_id;
    }

    /*EMBEDDED FULL POINTER*/
    if ( (!pointers_are_top_level)
        && (type == NDR_POINTER_PTR) ) {
        int found;
        guint64 id;
        proto_item *item;

        /* get the referent id */
        offset = dissect_ndr_uint3264(tvb, offset, pinfo, NULL, di, drep, -1, &id);

        /* we got a NULL pointer */
        if (id == 0) {
            proto_tree_add_bytes_format_value(tree, hf_dcerpc_null_pointer, tvb, offset-pointer_size,
                                pointer_size, NULL, "%s",text);
            goto after_ref_id;
        }

        /* see if we have seen this pointer before
           The value is truncated to 32bits.  64bit values have only been
           seen on fuzztested files */
        found = find_pointer_index((guint32)id);

        /* we have seen this pointer before */
        if (found) {
            proto_tree_add_string(tree, hf_dcerpc_duplicate_ptr, tvb, offset-pointer_size, pointer_size, text);
            goto after_ref_id;
        }

        /* new pointer */
        tr = proto_tree_add_subtree(tree, tvb, offset-pointer_size,
                                   pointer_size,
                                   ett_dcerpc_pointer_data, &item, text);
        if (di->call_data->flags & DCERPC_IS_NDR64) {
            proto_tree_add_uint64(tr, hf_dcerpc_referent_id64, tvb,
                            offset-pointer_size, pointer_size, id);
        } else {
            proto_tree_add_uint(tr, hf_dcerpc_referent_id32, tvb,
                            offset-pointer_size, pointer_size, (guint32)id);
        }
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
dissect_sec_vt_bitmask(proto_tree *tree, tvbuff_t *tvb)
{
    proto_tree_add_bitmask(tree, tvb, 0,
                           hf_dcerpc_sec_vt_bitmask,
                           ett_dcerpc_sec_vt_bitmask,
                           sec_vt_bitmask_fields,
                           ENC_LITTLE_ENDIAN);
}

static void
dissect_sec_vt_pcontext(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    int offset = 0;
    proto_item *ti = NULL;
    proto_tree *tr = proto_tree_add_subtree(tree, tvb, offset, -1,
                                            ett_dcerpc_sec_vt_pcontext,
                                            &ti, "pcontext");
    e_guid_t uuid;
    const char *uuid_name;

    tvb_get_letohguid(tvb, offset, &uuid);
    uuid_name = guids_get_uuid_name(&uuid, pinfo->pool);
    if (!uuid_name) {
            uuid_name = guid_to_str(pinfo->pool, &uuid);
    }

    proto_tree_add_guid_format(tr, hf_dcerpc_sec_vt_pcontext_uuid, tvb,
                               offset, 16, &uuid, "Abstract Syntax: %s", uuid_name);
    offset += 16;

    proto_tree_add_item(tr, hf_dcerpc_sec_vt_pcontext_ver,
                        tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    tvb_get_letohguid(tvb, offset, &uuid);
    uuid_name = guids_get_uuid_name(&uuid, pinfo->pool);
    if (!uuid_name) {
            uuid_name = guid_to_str(pinfo->pool, &uuid);
    }

    proto_tree_add_guid_format(tr, hf_dcerpc_sec_vt_pcontext_uuid, tvb,
                               offset, 16, &uuid, "Transfer Syntax: %s", uuid_name);
    offset += 16;

    proto_tree_add_item(tr, hf_dcerpc_sec_vt_pcontext_ver,
                        tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_item_set_len(ti, offset);
}

static void
dissect_sec_vt_header(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    int offset = 0;
    proto_item *ti = NULL;
    proto_tree *tr = proto_tree_add_subtree(tree, tvb, offset, -1,
                                            ett_dcerpc_sec_vt_header,
                                            &ti, "header2");
    guint8 drep[4];
    guint8 ptype = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tr, hf_dcerpc_packet_type, tvb, offset, 1, ptype);
    offset += 1;

    proto_tree_add_item(tr, hf_dcerpc_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tr, hf_dcerpc_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    tvb_memcpy(tvb, drep, offset, 4);
    proto_tree_add_dcerpc_drep(tr, tvb, offset, drep, 4);
    offset += 4;

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tr, drep,
                                   hf_dcerpc_cn_call_id, NULL);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tr, drep,
                                   hf_dcerpc_cn_ctx_id, NULL);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tr, drep,
                                   hf_dcerpc_opnum, NULL);

    proto_item_set_len(ti, offset);
}

static int
dissect_verification_trailer_impl(packet_info *pinfo, tvbuff_t *tvb, int stub_offset,
                                  proto_tree *parent_tree, int *signature_offset)
{
    int remaining = tvb_captured_length_remaining(tvb, stub_offset);
    int offset;
    gint signature_start;
    gint payload_length;
    typedef enum {
        SEC_VT_COMMAND_BITMASK_1    = 0x0001,
        SEC_VT_COMMAND_PCONTEXT     = 0x0002,
        SEC_VT_COMMAND_HEADER2      = 0x0003,
        SEC_VT_COMMAND_END          = 0x4000,
        SEC_VT_MUST_PROCESS_COMMAND = 0x8000,
        SEC_VT_COMMAND_MASK         = 0x3fff,
    } sec_vt_command;
    proto_item *payload_item;
    proto_item *item;
    proto_tree *tree;

    if (signature_offset != NULL) {
        *signature_offset = -1;
    }

    /* We need at least signature + the header of one command */
    if (remaining < (int)(sizeof(TRAILER_SIGNATURE) + 4)) {
         return -1;
    }

    /* We only scan the last 512 bytes for a possible trailer */
    if (remaining > 512) {
         offset = remaining - 512;
         remaining = 512;
    } else {
         offset = 0;
    }
    offset += stub_offset;

    signature_start = tvb_find_tvb(tvb, tvb_trailer_signature, offset);
    if (signature_start == -1) {
        return -1;
    }
    payload_length = signature_start - stub_offset;
    payload_item = proto_tree_add_item(parent_tree,
                                       hf_dcerpc_payload_stub_data,
                                       tvb, stub_offset, payload_length, ENC_NA);
    proto_item_append_text(payload_item, " (%d byte%s)",
                           payload_length, plurality(payload_length, "", "s"));

    if (signature_offset != NULL) {
        *signature_offset = signature_start;
    }
    remaining -= (signature_start - offset);
    offset = signature_start;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1,
                                  ett_dcerpc_verification_trailer,
                                  &item, "Verification Trailer");

    proto_tree_add_item(tree, hf_dcerpc_sec_vt_signature,
                        tvb, offset, sizeof(TRAILER_SIGNATURE), ENC_NA);
    offset += (int)sizeof(TRAILER_SIGNATURE);
    remaining -= (int)sizeof(TRAILER_SIGNATURE);

    while (remaining >= 4) {
        sec_vt_command cmd;
        guint16 len, len_missalign;
        gboolean cmd_end, cmd_must;
        proto_item *ti;
        proto_tree *tr;
        tvbuff_t *cmd_tvb = NULL;

        cmd = (sec_vt_command)tvb_get_letohs(tvb, offset);
        len = tvb_get_letohs(tvb, offset + 2);
        cmd_end = cmd & SEC_VT_COMMAND_END;
        cmd_must = cmd & SEC_VT_MUST_PROCESS_COMMAND;
        cmd = (sec_vt_command)(cmd & SEC_VT_COMMAND_MASK);

        tr = proto_tree_add_subtree_format(tree, tvb, offset, 4 + len,
                                           ett_dcerpc_sec_vt_pcontext,
                                           &ti, "Command: %s",
                                             val_to_str(cmd, sec_vt_command_cmd_vals,
                                                        "Unknown (0x%04x)"));

        if (cmd_must) {
            proto_item_append_text(ti, "!!!");
        }
        if (cmd_end) {
            proto_item_append_text(ti, ", END");
        }

        proto_tree_add_bitmask(tr, tvb, offset,
                               hf_dcerpc_sec_vt_command,
                               ett_dcerpc_sec_vt_command,
                               sec_vt_command_fields,
                               ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tr, hf_dcerpc_sec_vt_command_length, tvb,
                            offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        cmd_tvb = tvb_new_subset_length(tvb, offset, len);
        switch (cmd) {
        case SEC_VT_COMMAND_BITMASK_1:
            dissect_sec_vt_bitmask(tr, cmd_tvb);
            break;
        case SEC_VT_COMMAND_PCONTEXT:
            dissect_sec_vt_pcontext(pinfo, tr, cmd_tvb);
            break;
        case SEC_VT_COMMAND_HEADER2:
            dissect_sec_vt_header(pinfo, tr, cmd_tvb);
            break;
        default:
            proto_tree_add_item(tr, hf_dcerpc_unknown, cmd_tvb, 0, len, ENC_NA);
            break;
        }

        offset += len;
        remaining -= (4 + len);

        len_missalign = len & 1;

        if (len_missalign) {
            int l = 2-len_missalign;
            proto_tree_add_item(tr, hf_dcerpc_missalign, tvb, offset, l, ENC_NA);
            offset += l;
            remaining -= l;
        }

        if (cmd_end) {
            break;
        }
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}

static int
dissect_verification_trailer(packet_info *pinfo, tvbuff_t *tvb, int stub_offset,
                             proto_tree *parent_tree, int *signature_offset)
{
    volatile int ret = -1;
    TRY {
        /*
         * Even if we found a signature we can't be sure to have a
         * valid verification trailer, we're only relatively sure
         * if we manage to dissect it completely, otherwise it
         * may be part of the real payload. That's why we have
         * a try/catch block here.
         */
        ret = dissect_verification_trailer_impl(pinfo, tvb, stub_offset, parent_tree, signature_offset);
    } CATCH_NONFATAL_ERRORS {
    } ENDTRY;
    return ret;
}

static int
dcerpc_try_handoff(packet_info *pinfo, proto_tree *tree,
                   proto_tree *dcerpc_tree,
                   tvbuff_t *volatile tvb, gboolean decrypted,
                   guint8 *drep, dcerpc_info *info,
                   dcerpc_auth_info *auth_info)
{
    volatile gint         offset   = 0;
    guid_key              key;
    dcerpc_dissector_data_t dissector_data;
    proto_item           *hidden_item;

    /* GUID and UUID are same size, but compiler complains about structure "name" differences */
    memcpy(&key.guid, &info->call_data->uuid, sizeof(key.guid));
    key.ver = info->call_data->ver;

    dissector_data.sub_proto = (dcerpc_uuid_value *)g_hash_table_lookup(dcerpc_uuids, &key);
    dissector_data.info = info;
    dissector_data.decrypted = decrypted;
    dissector_data.auth_info = auth_info;
    dissector_data.drep = drep;
    dissector_data.dcerpc_tree = dcerpc_tree;

    /* Check the dissector table before the hash table.  Hopefully the hash table entries can
       all be converted to use dissector table */
    if ((dissector_data.sub_proto == NULL) ||
        (!dissector_try_guid_new(uuid_dissector_table, &key, tvb, pinfo, tree, FALSE, &dissector_data))) {
        /*
         * We don't have a dissector for this UUID, or the protocol
         * for that UUID is disabled.
         */

        hidden_item = proto_tree_add_boolean(dcerpc_tree, hf_dcerpc_unknown_if_id,
                                             tvb, offset, 0, TRUE);
        proto_item_set_hidden(hidden_item);
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s V%u",
        guids_resolve_guid_to_str(&info->call_data->uuid, pinfo->pool), info->call_data->ver);

        show_stub_data(pinfo, tvb, 0, dcerpc_tree, auth_info, !decrypted);
        return -1;
    }

    tap_queue_packet(dcerpc_tap, pinfo, info);
    return 0;
}

static void
dissect_dcerpc_cn_auth_move(dcerpc_auth_info *auth_info, proto_tree *dcerpc_tree)
{
    if (auth_info->auth_item != NULL) {
        proto_item *last_item = proto_tree_add_item(dcerpc_tree, hf_dcerpc_auth_info,
                                                    auth_info->auth_tvb, 0, 0, ENC_NA);
        if (last_item != NULL) {
            proto_item_set_hidden(last_item);
            proto_tree_move_item(dcerpc_tree, last_item, auth_info->auth_item);
        }
    }
}

static dcerpc_auth_context *find_or_create_dcerpc_auth_context(packet_info *pinfo,
                                                               dcerpc_auth_info *auth_info)
{
    dcerpc_auth_context auth_key = {
        .conv = find_or_create_conversation(pinfo),
        .transport_salt = dcerpc_get_transport_salt(pinfo),
        .auth_type = auth_info->auth_type,
        .auth_level = auth_info->auth_level,
        .auth_context_id = auth_info->auth_context_id,
        .first_frame = G_MAXUINT32,
    };
    dcerpc_auth_context *auth_value = NULL;

    auth_value = (dcerpc_auth_context *)wmem_map_lookup(dcerpc_auths, &auth_key);
    if (auth_value != NULL) {
        goto return_value;
    }

    auth_value = wmem_new(wmem_file_scope(), dcerpc_auth_context);
    if (auth_value == NULL) {
        return NULL;
    }

    *auth_value = auth_key;
    wmem_map_insert(dcerpc_auths, auth_value, auth_value);

return_value:
    if (pinfo->fd->num < auth_value->first_frame) {
        auth_value->first_frame = pinfo->fd->num;
    }
    return auth_value;
}

static void
dissect_dcerpc_cn_auth(tvbuff_t *tvb, int stub_offset, packet_info *pinfo,
                       proto_tree *dcerpc_tree, e_dce_cn_common_hdr_t *hdr,
                       dcerpc_auth_info *auth_info)
{
    volatile int offset;

    /*
     * Initially set auth_level and auth_type to zero to indicate that we
     * haven't yet seen any authentication level information.
     */
    auth_info->hdr_signing     = FALSE;
    auth_info->auth_type       = 0;
    auth_info->auth_level      = 0;
    auth_info->auth_context_id = 0;
    auth_info->auth_pad_len    = 0;
    auth_info->auth_size       = 0;
    auth_info->auth_fns        = NULL;
    auth_info->auth_tvb        = NULL;
    auth_info->auth_item       = NULL;
    auth_info->auth_tree       = NULL;
    auth_info->auth_hdr_tvb    = NULL;

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
            dcerpc_auth_context *auth_context = NULL;
            int auth_offset = offset;

            /* Compute the size of the auth block.  Note that this should not
               include auth padding, since when NTLMSSP encryption is used, the
               padding is actually inside the encrypted stub */
            auth_info->auth_size = hdr->auth_len + 8;

            auth_info->auth_item = proto_tree_add_item(dcerpc_tree, hf_dcerpc_auth_info,
                                                       tvb, offset, auth_info->auth_size, ENC_NA);
            auth_info->auth_tree = proto_item_add_subtree(auth_info->auth_item, ett_dcerpc_auth_info);

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
                offset = dissect_dcerpc_uint8(tvb, offset, pinfo, auth_info->auth_tree, hdr->drep,
                                              hf_dcerpc_auth_type,
                                              &auth_info->auth_type);
                offset = dissect_dcerpc_uint8(tvb, offset, pinfo, auth_info->auth_tree, hdr->drep,
                                              hf_dcerpc_auth_level,
                                              &auth_info->auth_level);

                offset = dissect_dcerpc_uint8(tvb, offset, pinfo, auth_info->auth_tree, hdr->drep,
                                              hf_dcerpc_auth_pad_len,
                                              &auth_info->auth_pad_len);
                offset = dissect_dcerpc_uint8(tvb, offset, pinfo, auth_info->auth_tree, hdr->drep,
                                              hf_dcerpc_auth_rsrvd, NULL);
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, auth_info->auth_tree, hdr->drep,
                                               hf_dcerpc_auth_ctx_id,
                                               &auth_info->auth_context_id);

                proto_item_append_text(auth_info->auth_item,
                                       ": %s, %s, AuthContextId(%d)",
                                       val_to_str(auth_info->auth_type,
                                                  authn_protocol_vals,
                                                  "AuthType(%u)"),
                                       val_to_str(auth_info->auth_level,
                                                  authn_level_vals,
                                                  "AuthLevel(%u)"),
                                       auth_info->auth_context_id);

                /*
                 * Dissect the authentication data.
                 */
                auth_info->auth_hdr_tvb = tvb_new_subset_length_caplen(tvb, auth_offset, 8, 8);
                auth_info->auth_tvb = tvb_new_subset_length_caplen(tvb, offset,
                                              MIN(hdr->auth_len,tvb_reported_length_remaining(tvb, offset)),
                                              hdr->auth_len);

                auth_context = find_or_create_dcerpc_auth_context(pinfo, auth_info);
                if (auth_context != NULL) {
                    if (hdr->ptype == PDU_BIND || hdr->ptype == PDU_ALTER) {
                        if (auth_context->first_frame == pinfo->fd->num) {
                            auth_context->hdr_signing = (hdr->flags & PFC_HDR_SIGNING);
                        }
                    }

                    auth_info->hdr_signing = auth_context->hdr_signing;
                }

                auth_info->auth_fns = get_auth_subdissector_fns(auth_info->auth_level,
                                                                auth_info->auth_type);
                if (auth_info->auth_fns != NULL)
                    dissect_auth_verf(pinfo, hdr, auth_info);
                else
                    proto_tree_add_item(auth_info->auth_tree,
                                        hf_dcerpc_auth_credentials,
                                        auth_info->auth_tvb, 0,
                                        hdr->auth_len, ENC_NA);

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

guint64
dcerpc_get_transport_salt(packet_info *pinfo)
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

void
dcerpc_set_transport_salt(guint64 dcetransportsalt, packet_info *pinfo)
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
    e_guid_t          if_id;
    e_guid_t          trans_id;
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

            uuid_str = guid_to_str(pinfo->pool, (e_guid_t*)&if_id);
            uuid_name = guids_get_uuid_name(&if_id, pinfo->pool);
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

            dcerpc_tvb_get_uuid(tvb, offset, hdr->drep, &trans_id);
            if (ctx_tree) {

                trans_item = proto_tree_add_item(ctx_tree, hf_dcerpc_cn_bind_trans_syntax, tvb, offset, 0, ENC_NA);
                trans_tree = proto_item_add_subtree(trans_item, ett_dcerpc_cn_trans_syntax);

                uuid_str = guid_to_str(pinfo->pool, (e_guid_t *) &trans_id);
                uuid_name = guids_get_uuid_name(&trans_id, pinfo->pool);

                /* check for [MS-RPCE] 3.3.1.5.3 Bind Time Feature Negotiation */
                if (trans_id.data1 == 0x6cb71c2c && trans_id.data2 == 0x9812 && trans_id.data3 == 0x4540) {
                    proto_tree_add_guid_format(trans_tree, hf_dcerpc_cn_bind_trans_id,
                                               tvb, offset, 16, (e_guid_t *) &trans_id,
                                               "Transfer Syntax: Bind Time Feature Negotiation UUID:%s",
                                               uuid_str);
                    proto_tree_add_bitmask(trans_tree, tvb, offset + 8,
                               hf_dcerpc_cn_bind_trans_btfn,
                               ett_dcerpc_cn_bind_trans_btfn,
                               dcerpc_cn_bind_trans_btfn_fields,
                               ENC_LITTLE_ENDIAN);
                    proto_item_append_text(trans_item, "[%u]: Bind Time Feature Negotiation", j+1);
                    proto_item_append_text(ctx_item, ", Bind Time Feature Negotiation");
                } else if (uuid_name) {
                    proto_tree_add_guid_format(trans_tree, hf_dcerpc_cn_bind_trans_id,
                                               tvb, offset, 16, (e_guid_t *) &trans_id,
                                               "Transfer Syntax: %s UUID:%s", uuid_name, uuid_str);
                    proto_item_append_text(trans_item, "[%u]: %s", j+1, uuid_name);
                    proto_item_append_text(ctx_item, ", %s", uuid_name);
                } else {
                    proto_tree_add_guid_format(trans_tree, hf_dcerpc_cn_bind_trans_id,
                                               tvb, offset, 16, (e_guid_t *) &trans_id,
                                               "Transfer Syntax: %s", uuid_str);
                    proto_item_append_text(trans_item, "[%u]: %s", j+1, uuid_str);
                    proto_item_append_text(ctx_item, ", %s", uuid_str);
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
        if (!(pinfo->fd->visited)) {
            dcerpc_bind_key   *key;
            dcerpc_bind_value *value;

            key = wmem_new(wmem_file_scope(), dcerpc_bind_key);
            key->conv = conv;
            key->ctx_id = ctx_id;
            key->transport_salt = dcerpc_get_transport_salt(pinfo);

            value = wmem_new(wmem_file_scope(), dcerpc_bind_value);
            value->uuid = if_id;
            value->ver = if_ver;
            value->transport = trans_id;

            /* add this entry to the bind table */
            wmem_map_insert(dcerpc_binds, key, value);
        }

        if (i > 0)
            col_append_fstr(pinfo->cinfo, COL_INFO, ",");
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s V%u.%u (%s)",
                        guids_resolve_guid_to_str(&if_id, pinfo->pool), if_ver, if_ver_minor,
                        guids_resolve_guid_to_str(&trans_id, pinfo->pool));

        if (ctx_tree) {
            proto_item_set_len(ctx_item, offset - ctx_offset);
        }
    }

    /*
     * XXX - we should save the authentication type *if* we have
     * an authentication header, and associate it with an authentication
     * context, so subsequent PDUs can use that context.
     */
    dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, &auth_info);
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
    e_guid_t          trans_id;
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
        proto_tree_add_item(dcerpc_tree, hf_dcerpc_cn_sec_addr, tvb, offset,
                            sec_addr_len, ENC_ASCII);
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
            ctx_tree = proto_tree_add_subtree_format(dcerpc_tree, tvb, offset, 24, ett_dcerpc_cn_ctx, &ctx_item, "Ctx Item[%u]:", i+1);
        }

        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ctx_tree,
                                       hdr->drep, hf_dcerpc_cn_ack_result,
                                       &result);

        /* [MS-RPCE] 3.3.1.5.3 check if this Ctx Item is the response to a Bind Time Feature Negotiation request */
        if (result == 3) {
            proto_tree_add_bitmask(ctx_tree, tvb, offset,
                                   hf_dcerpc_cn_bind_trans_btfn,
                                   ett_dcerpc_cn_bind_trans_btfn,
                                   dcerpc_cn_bind_trans_btfn_fields,
                                   ENC_LITTLE_ENDIAN);
            offset += 2;
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
            uuid_name = guids_get_uuid_name(&trans_id, pinfo->pool);
            if (! uuid_name) {
                uuid_name = guid_to_str(pinfo->pool, (e_guid_t *) &trans_id);
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
    dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, &auth_info);
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

    tvbuff_t *header_tvb = NULL, *trailer_tvb = NULL;
    tvbuff_t *payload_tvb, *decrypted_tvb = NULL;
    proto_item *pi;
    proto_item *parent_pi;
    proto_item *dcerpc_tree_item;

    save_fragmented = pinfo->fragmented;

    length = tvb_reported_length_remaining(tvb, offset);
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
    header_tvb = tvb_new_subset_length_caplen(tvb, 0, offset, offset);
    payload_tvb = tvb_new_subset_length_caplen(tvb, offset, length, reported_length);
    trailer_tvb = auth_info->auth_hdr_tvb;

    /* Decrypt the PDU if it is encrypted */

    if (auth_info->auth_type &&
        (auth_info->auth_level == DCE_C_AUTHN_LEVEL_PKT_PRIVACY)) {

        /* Start out assuming we won't succeed in decrypting. */

        if (auth_info->auth_fns != NULL) {
            tvbuff_t *result;

            result = decode_encrypted_data(header_tvb, payload_tvb, trailer_tvb,
                                           pinfo, hdr, auth_info);
            if (result) {
                proto_tree_add_item(dcerpc_tree, hf_dcerpc_encrypted_stub_data, payload_tvb, 0, -1, ENC_NA);

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

        dcerpc_try_handoff(pinfo, tree, dcerpc_tree,
            ((decrypted_tvb != NULL) ? decrypted_tvb : payload_tvb),
            ((decrypted_tvb != NULL) ? TRUE : FALSE),
            hdr->drep, di, auth_info);

        pinfo->fragmented = save_fragmented;
        return;
    }

    /* The packet is fragmented. */
    pinfo->fragmented = TRUE;

    /* debug output of essential fragment data. */
    /* leave it here for future debugging sessions */
    /*printf("DCE num:%u offset:%u frag_len:%u tvb_len:%u\n",
      pinfo->num, offset, hdr->frag_len, tvb_reported_length(decrypted_tvb));*/

    /* if we are not doing reassembly and this is the first fragment
       then just dissect it and exit
       XXX - if we're not doing reassembly, can we decrypt an
       encrypted stub?
    */
    if ( (!dcerpc_reassemble) && (hdr->flags & PFC_FIRST_FRAG) ) {

        dcerpc_try_handoff(pinfo, tree, dcerpc_tree,
            ((decrypted_tvb != NULL) ? decrypted_tvb : payload_tvb),
            ((decrypted_tvb != NULL) ? TRUE : FALSE),
            hdr->drep, di, auth_info);

        expert_add_info_format(pinfo, NULL, &ei_dcerpc_fragment, "%s fragment", fragment_type(hdr->flags));

        pinfo->fragmented = save_fragmented;
        return;
    }

    /* if we have already seen this packet, see if it was reassembled
       and if so dissect the full pdu.
       then exit
    */
    if (pinfo->fd->visited) {
        fd_head = fragment_get_reassembled_id(&dcerpc_co_reassembly_table, pinfo, frame);
        goto end_cn_stub;
    }

    /* if we are not doing reassembly and it was neither a complete PDU
       nor the first fragment then there is nothing more we can do
       so we just have to exit
    */
    if ( !dcerpc_reassemble || (tvb_captured_length(tvb) != tvb_reported_length(tvb)) )
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
                                    tvb_reported_length(decrypted_tvb),
                                    !(hdr->flags & PFC_LAST_FRAG) /* more_frags */);

end_cn_stub:

    /* if reassembly is complete and this is the last fragment
     * (multiple fragments in one PDU are possible!)
     * dissect the full PDU
     */
    if (fd_head && (fd_head->flags & FD_DEFRAGMENTED) ) {

        if ((pinfo->num == fd_head->reassembled_in) && (hdr->flags & PFC_LAST_FRAG) ) {
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

            dcerpc_try_handoff(pinfo, tree, dcerpc_tree, next_tvb, TRUE, hdr->drep, di, auth_info);

        } else {
            if (decrypted_tvb) {
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_reassembled_in,
                                         decrypted_tvb, 0, 0, fd_head->reassembled_in);
            } else {
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_reassembled_in,
                                         payload_tvb, 0, 0, fd_head->reassembled_in);
            }
            proto_item_set_generated(pi);
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
            show_stub_data(pinfo, decrypted_tvb, 0, tree, auth_info, FALSE);
        } else {
            show_stub_data(pinfo, payload_tvb, 0, tree, auth_info, TRUE);
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
    e_guid_t          obj_id = DCERPC_UUID_NULL;
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
                                       guid_to_str(pinfo->pool, (e_guid_t *) &obj_id));
        }
        offset += 16;
    }

    /*
     * XXX - what if this was set when the connection was set up,
     * and we just have a security context?
     */
    dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, &auth_info);

    conv = find_conversation_pinfo(pinfo, 0);
    if (!conv)
        show_stub_data(pinfo, tvb, offset, dcerpc_tree, &auth_info, TRUE);
    else {
        dcerpc_matched_key matched_key, *new_matched_key;
        dcerpc_call_value *value;

        /* !!! we can NOT check visited here since this will interact
           badly with when SMB handles (i.e. calls the subdissector)
           and desegmented pdu's .
           Instead we check if this pdu is already in the matched table or not
        */
        matched_key.frame = pinfo->num;
        matched_key.call_id = hdr->call_id;
        value = (dcerpc_call_value *)wmem_map_lookup(dcerpc_matched, &matched_key);
        if (!value) {
            dcerpc_bind_key bind_key;
            dcerpc_bind_value *bind_value;

            bind_key.conv = conv;
            bind_key.ctx_id = ctx_id;
            bind_key.transport_salt = dcerpc_get_transport_salt(pinfo);

            if ((bind_value = (dcerpc_bind_value *)wmem_map_lookup(dcerpc_binds, &bind_key)) ) {
                if (!(hdr->flags&PFC_FIRST_FRAG)) {
                    dcerpc_cn_call_key call_key;
                    dcerpc_call_value *call_value;

                    call_key.conv = conv;
                    call_key.call_id = hdr->call_id;
                    call_key.transport_salt = dcerpc_get_transport_salt(pinfo);
                    if ((call_value = (dcerpc_call_value *)wmem_map_lookup(dcerpc_cn_calls, &call_key))) {
                        new_matched_key = wmem_new(wmem_file_scope(), dcerpc_matched_key);
                        *new_matched_key = matched_key;
                        wmem_map_insert(dcerpc_matched, new_matched_key, call_value);
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
                    call_key = wmem_new(wmem_file_scope(), dcerpc_cn_call_key);
                    call_key->conv = conv;
                    call_key->call_id = hdr->call_id;
                    call_key->transport_salt = dcerpc_get_transport_salt(pinfo);

                    /* if there is already a matching call in the table
                       remove it so it is replaced with the new one */
                    if (wmem_map_lookup(dcerpc_cn_calls, call_key)) {
                        wmem_map_remove(dcerpc_cn_calls, call_key);
                    }

                    call_value = wmem_new(wmem_file_scope(), dcerpc_call_value);
                    call_value->uuid = bind_value->uuid;
                    call_value->ver = bind_value->ver;
                    call_value->object_uuid = obj_id;
                    call_value->opnum = opnum;
                    call_value->req_frame = pinfo->num;
                    call_value->req_time = pinfo->abs_ts;
                    call_value->rep_frame = 0;
                    call_value->max_ptr = 0;
                    call_value->se_data = NULL;
                    call_value->private_data = NULL;
                    call_value->pol = NULL;
                    call_value->flags = 0;
                    if (!memcmp(&bind_value->transport, &uuid_ndr64, sizeof(uuid_ndr64))) {
                        call_value->flags |= DCERPC_IS_NDR64;
                    }

                    wmem_map_insert(dcerpc_cn_calls, call_key, call_value);

                    new_matched_key = wmem_new(wmem_file_scope(), dcerpc_matched_key);
                    *new_matched_key = matched_key;
                    wmem_map_insert(dcerpc_matched, new_matched_key, call_value);
                    value = call_value;
                }
            }
        }

        if (value) {
            dcerpc_info *di;

            di = wmem_new0(pinfo->pool, dcerpc_info);
            /* handoff this call */
            di->dcerpc_procedure_name = "";
            di->conv = conv;
            di->call_id = hdr->call_id;
            di->transport_salt = dcerpc_get_transport_salt(pinfo);
            di->ptype = PDU_REQ;
            di->call_data = value;
            di->hf_index = -1;

            if (value->rep_frame != 0) {
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_response_in,
                                         tvb, 0, 0, value->rep_frame);
                proto_item_set_generated(pi);
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
            show_stub_data(pinfo, tvb, offset, dcerpc_tree, &auth_info, TRUE);
        }
    }

    /*
     * Move the auth_info subtree to the end,
     * as it's also at the end of the pdu on the wire.
     */
    dissect_dcerpc_cn_auth_move(&auth_info, dcerpc_tree);
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
    e_guid_t           obj_id_null = DCERPC_UUID_NULL;
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
    dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, &auth_info);

    conv = find_conversation_pinfo(pinfo, 0);

    if (!conv) {
        /* no point in creating one here, really */
        show_stub_data(pinfo, tvb, offset, dcerpc_tree, &auth_info, TRUE);
    } else {
        dcerpc_matched_key matched_key, *new_matched_key;

        /* !!! we can NOT check visited here since this will interact
           badly with when SMB handles (i.e. calls the subdissector)
           and desegmented pdu's .
           Instead we check if this pdu is already in the matched table or not
        */
        matched_key.frame = pinfo->num;
        matched_key.call_id = hdr->call_id;
        value = (dcerpc_call_value *)wmem_map_lookup(dcerpc_matched, &matched_key);
        if (!value) {
            dcerpc_cn_call_key call_key;
            dcerpc_call_value *call_value;

            call_key.conv = conv;
            call_key.call_id = hdr->call_id;
            call_key.transport_salt = dcerpc_get_transport_salt(pinfo);

            if ((call_value = (dcerpc_call_value *)wmem_map_lookup(dcerpc_cn_calls, &call_key))) {
                /* extra sanity check,  only match them if the reply
                   came after the request */
                if (call_value->req_frame<pinfo->num) {
                    new_matched_key = wmem_new(wmem_file_scope(), dcerpc_matched_key);
                    *new_matched_key = matched_key;
                    wmem_map_insert(dcerpc_matched, new_matched_key, call_value);
                    value = call_value;
                    if (call_value->rep_frame == 0) {
                        call_value->rep_frame = pinfo->num;
                    }
                }
            }
        }

        if (value) {
            dcerpc_info *di;

            di = wmem_new0(pinfo->pool, dcerpc_info);
            /* handoff this call */
            di->dcerpc_procedure_name = "";
            di->conv = conv;
            di->call_id = hdr->call_id;
            di->transport_salt = dcerpc_get_transport_salt(pinfo);
            di->ptype = PDU_RESP;
            di->call_data = value;

            pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_opnum, tvb, 0, 0, value->opnum);
            proto_item_set_generated(pi);

            /* (optional) "Object UUID" from request */
            if (dcerpc_tree && (memcmp(&value->object_uuid, &obj_id_null, sizeof(obj_id_null)) != 0)) {
                pi = proto_tree_add_guid_format(dcerpc_tree, hf_dcerpc_obj_id, tvb,
                                                offset, 0, (e_guid_t *) &value->object_uuid, "Object UUID: %s",
                                                guid_to_str(pinfo->pool, (e_guid_t *) &value->object_uuid));
                proto_item_set_generated(pi);
            }

            /* request in */
            if (value->req_frame != 0) {
                nstime_t delta_ts;
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_request_in,
                                         tvb, 0, 0, value->req_frame);
                proto_item_set_generated(pi);
                if (parent_pi != NULL) {
                    proto_item_append_text(parent_pi, ", [Req: #%u]", value->req_frame);
                }
                nstime_delta(&delta_ts, &pinfo->abs_ts, &value->req_time);
                pi = proto_tree_add_time(dcerpc_tree, hf_dcerpc_time, tvb, offset, 0, &delta_ts);
                proto_item_set_generated(pi);
            } else {
                proto_tree_add_expert(dcerpc_tree, pinfo, &ei_dcerpc_no_request_found, tvb, 0, 0);
            }

            dissect_dcerpc_cn_stub(tvb, offset, pinfo, dcerpc_tree, tree,
                                   hdr, di, &auth_info, alloc_hint,
                                   value->rep_frame);
        } else {
            /* no bind information, simply show stub data */
            proto_tree_add_expert_format(dcerpc_tree, pinfo, &ei_dcerpc_cn_ctx_id_no_bind, tvb, offset, 0, "No bind info for interface Context ID %u - capture start too late?", ctx_id);
            show_stub_data(pinfo, tvb, offset, dcerpc_tree, &auth_info, TRUE);
        }
    }

    /*
     * Move the auth_info subtree to the end,
     * as it's also at the end of the pdu on the wire.
     */
    dissect_dcerpc_cn_auth_move(&auth_info, dcerpc_tree);
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
    gint               length, reported_length;
    tvbuff_t          *stub_tvb = NULL;
    proto_item        *pi    = NULL;
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_alloc_hint, &alloc_hint);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_ctx_id, &ctx_id);

    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                  hf_dcerpc_cn_cancel_count, NULL);
    proto_tree_add_bitmask(dcerpc_tree, tvb, offset,
                           hf_dcerpc_cn_fault_flags,
                           ett_dcerpc_fault_flags,
                           dcerpc_cn_fault_flags_fields,
                           DREP_ENC_INTEGER(hdr->drep));
    offset += 1;

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
    proto_tree_add_item(dcerpc_tree, hf_dcerpc_reserved, tvb, offset, 4, ENC_NA);
    offset += 4;

    /*
     * XXX - what if this was set when the connection was set up,
     * and we just have a security context?
     */
    dissect_dcerpc_cn_auth(tvb, offset, pinfo, dcerpc_tree, hdr, &auth_info);

    length = tvb_captured_length_remaining(tvb, offset);
    reported_length = tvb_reported_length_remaining(tvb, offset);
    if (reported_length < 0 ||
        (guint32)reported_length < auth_info.auth_size) {
        /* We don't even have enough bytes for the authentication
           stuff. */
        return;
    }
    reported_length -= auth_info.auth_size;
    if (length > reported_length)
        length = reported_length;
    stub_tvb = tvb_new_subset_length_caplen(tvb, offset, length, reported_length);

    conv = find_conversation_pinfo(pinfo, 0);
    if (!conv) {
        /* no point in creating one here, really */
    } else {
        dcerpc_matched_key matched_key, *new_matched_key;

        /* !!! we can NOT check visited here since this will interact
           badly with when SMB handles (i.e. calls the subdissector)
           and desegmented pdu's .
           Instead we check if this pdu is already in the matched table or not
        */
        matched_key.frame = pinfo->num;
        matched_key.call_id = hdr->call_id;
        value = (dcerpc_call_value *)wmem_map_lookup(dcerpc_matched, &matched_key);
        if (!value) {
            dcerpc_cn_call_key call_key;
            dcerpc_call_value *call_value;

            call_key.conv = conv;
            call_key.call_id = hdr->call_id;
            call_key.transport_salt = dcerpc_get_transport_salt(pinfo);

            if ((call_value = (dcerpc_call_value *)wmem_map_lookup(dcerpc_cn_calls, &call_key))) {
                new_matched_key = wmem_new(wmem_file_scope(), dcerpc_matched_key);
                *new_matched_key = matched_key;
                wmem_map_insert(dcerpc_matched, new_matched_key, call_value);

                value = call_value;
                if (call_value->rep_frame == 0) {
                    call_value->rep_frame = pinfo->num;
                }

            }
        }

        if (value) {
            proto_tree *stub_tree = NULL;
            gint stub_length;
            dcerpc_info *di;
            proto_item *parent_pi;

            di = wmem_new0(pinfo->pool, dcerpc_info);
            /* handoff this call */
            di->dcerpc_procedure_name = "";
            di->conv = conv;
            di->call_id = hdr->call_id;
            di->transport_salt = dcerpc_get_transport_salt(pinfo);
            di->ptype = PDU_FAULT;
            di->call_data = value;

            pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_opnum, tvb, 0, 0, value->opnum);
            proto_item_set_generated(pi);
            if (value->req_frame != 0) {
                nstime_t delta_ts;
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_request_in,
                                         tvb, 0, 0, value->req_frame);
                proto_item_set_generated(pi);
                parent_pi = proto_tree_get_parent(dcerpc_tree);
                if (parent_pi != NULL) {
                    proto_item_append_text(parent_pi, ", [Req: #%u]", value->req_frame);
                }
                nstime_delta(&delta_ts, &pinfo->abs_ts, &value->req_time);
                pi = proto_tree_add_time(dcerpc_tree, hf_dcerpc_time, tvb, offset, 0, &delta_ts);
                proto_item_set_generated(pi);
            } else {
                proto_tree_add_expert(dcerpc_tree, pinfo, &ei_dcerpc_no_request_found, tvb, 0, 0);
            }

            length = tvb_reported_length_remaining(stub_tvb, 0);
            /* as we now create a tvb in dissect_dcerpc_cn() containing only the
             * stub_data, the following calculation is no longer valid:
             * stub_length = hdr->frag_len - offset - auth_info.auth_size;
             * simply use the remaining length of the tvb instead.
             * XXX - or better use the reported_length?!?
             */
            stub_length = length;

            stub_tree = proto_tree_add_subtree_format(dcerpc_tree,
                                stub_tvb, 0, stub_length,
                                ett_dcerpc_fault_stub_data, NULL,
                                "Fault stub data (%d byte%s)", stub_length,
                                plurality(stub_length, "", "s"));

            /* If we don't have reassembly enabled, or this packet contains
               the entire PDU, or if we don't have all the data in this
               fragment, just call the handoff directly if this is the
               first fragment or the PDU isn't fragmented. */
            if ( (!dcerpc_reassemble) || PFC_NOT_FRAGMENTED(hdr) ||
                !tvb_bytes_exist(stub_tvb, 0, stub_length) ) {
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
                    if (stub_length > 0) {
                        proto_tree_add_item(stub_tree, hf_dcerpc_fault_stub_data, stub_tvb, 0, stub_length, ENC_NA);
                    }
                } else {
                    /* PDU is fragmented and this isn't the first fragment */
                    if (stub_length > 0) {
                        proto_tree_add_item(stub_tree, hf_dcerpc_fragment_data, stub_tvb, 0, stub_length, ENC_NA);
                    }
                }
            } else {
                /* Reassembly is enabled, the PDU is fragmented, and
                   we have all the data in the fragment; the first two
                   of those mean we should attempt reassembly, and the
                   third means we can attempt reassembly. */
                if (dcerpc_tree) {
                    if (length > 0) {
                        proto_tree_add_item(stub_tree, hf_dcerpc_fragment_data, stub_tvb, 0, stub_length, ENC_NA);
                    }
                }
                if (hdr->flags&PFC_FIRST_FRAG) {  /* FIRST fragment */
                    if ( (!pinfo->fd->visited) && value->rep_frame ) {
                        fragment_add_seq_next(&dcerpc_co_reassembly_table,
                                              stub_tvb, 0,
                                              pinfo, value->rep_frame, NULL,
                                              stub_length,
                                              TRUE);
                    }
                } else if (hdr->flags&PFC_LAST_FRAG) {  /* LAST fragment */
                    if ( value->rep_frame ) {
                        fragment_head *fd_head;

                        fd_head = fragment_add_seq_next(&dcerpc_co_reassembly_table,
                                                        stub_tvb, 0,
                                                        pinfo, value->rep_frame, NULL,
                                                        stub_length,
                                                        TRUE);

                        if (fd_head) {
                            /* We completed reassembly */
                            tvbuff_t *next_tvb;
                            proto_item *frag_tree_item;

                            next_tvb = tvb_new_chain(stub_tvb, fd_head->tvb_data);
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
                                    proto_tree_add_item(dcerpc_tree, hf_dcerpc_stub_data, stub_tvb, 0, stub_length, ENC_NA);
                                }
                            }
                        }
                    }
                } else {  /* MIDDLE fragment(s) */
                    if ( (!pinfo->fd->visited) && value->rep_frame ) {
                        fragment_add_seq_next(&dcerpc_co_reassembly_table,
                                              stub_tvb, 0,
                                              pinfo, value->rep_frame, NULL,
                                              stub_length,
                                              TRUE);
                    }
                }
            }
        }
    }

    /*
     * Move the auth_info subtree to the end,
     * as it's also at the end of the pdu on the wire.
     */
    dissect_dcerpc_cn_auth_move(&auth_info, dcerpc_tree);
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
    static int * const flags[] = {
        &hf_dcerpc_cn_rts_flags_ping,
        &hf_dcerpc_cn_rts_flags_other_cmd,
        &hf_dcerpc_cn_rts_flags_recycle_channel,
        &hf_dcerpc_cn_rts_flags_in_channel,
        &hf_dcerpc_cn_rts_flags_out_channel,
        &hf_dcerpc_cn_rts_flags_eof,
        NULL
    };

    /* Dissect specific RTS header */
    rts_flags = dcerpc_tvb_get_ntohs(tvb, offset, hdr->drep);
    proto_tree_add_bitmask_value_with_flags(dcerpc_tree, tvb, offset, hf_dcerpc_cn_rts_flags,
                                ett_dcerpc_cn_rts_flags, flags, rts_flags, BMT_NO_APPEND);
    offset += 2;

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_rts_commands_nb, &commands_nb);

    /* Create the RTS PDU tree - we do not yet know its name */
    cn_rts_pdu_tree = proto_tree_add_subtree_format(dcerpc_tree, tvb, offset, -1, ett_dcerpc_cn_rts_pdu, &tf, "RTS PDU: %u commands", commands_nb);

    cmd = (guint32 *)wmem_alloc(pinfo->pool, sizeof (guint32) * (commands_nb + 1));

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
            padding = (guint8 *)tvb_memdup(pinfo->pool, tvb, offset, conformance_count);
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
               proto_tree_add_ipv4_format_value(cn_rts_command_tree, hf_dcerpc_cmd_client_ipv4, tvb, offset, 4, addr4, "%s", get_hostname(addr4));
               offset += 4;
            } break;
            case RTS_IPV6: {
               ws_in6_addr addr6;
               tvb_get_ipv6(tvb, offset, &addr6);
               proto_tree_add_ipv6_format_value(cn_rts_command_tree, hf_dcerpc_cmd_client_ipv6, tvb, offset, 16, &addr6, "%s", get_hostname6(&addr6));
               offset += 16;
            } break;
            }
            padding = (guint8 *)tvb_memdup(pinfo->pool, tvb, offset, 12);
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
            expert_add_info(pinfo, tf, &ei_dcerpc_cn_rts_command);
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
        break;
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
        break;
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
        break;
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

/* Test to see if this looks like a connection oriented PDU */
static gboolean
is_dcerpc(tvbuff_t *tvb, int offset, packet_info *pinfo _U_)
{
    guint8 rpc_ver;
    guint8 rpc_ver_minor;
    guint8 ptype;
    guint8 drep[4];
    guint16 frag_len;

    if (!tvb_bytes_exist(tvb, offset, sizeof(e_dce_cn_common_hdr_t)))
        return FALSE;   /* not enough information to check */

    rpc_ver = tvb_get_guint8(tvb, offset++);
    if (rpc_ver != 5)
        return FALSE;
    rpc_ver_minor = tvb_get_guint8(tvb, offset++);
    if ((rpc_ver_minor != 0) && (rpc_ver_minor != 1))
        return FALSE;
    ptype = tvb_get_guint8(tvb, offset++);
    if (ptype > PDU_RTS)
        return FALSE;
    /* Skip flags, nothing good to check */
    offset++;

    tvb_memcpy(tvb, (guint8 *)drep, offset, sizeof (drep));
    if (drep[0]&0xee)
        return FALSE;
    if (drep[1] > DCE_RPC_DREP_FP_IBM)
        return FALSE;
    offset += (int)sizeof(drep);
    frag_len = dcerpc_tvb_get_ntohs(tvb, offset, drep);
    if (frag_len < sizeof(e_dce_cn_common_hdr_t)) {
        return FALSE;
    }

    return TRUE;
}

/*
 * DCERPC dissector for connection oriented calls.
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
    e_dce_cn_common_hdr_t  hdr;
    dcerpc_auth_info       auth_info;
    tvbuff_t              *fragment_tvb;
    dcerpc_decode_as_data* decode_data = dcerpc_get_decode_data(pinfo);
    static int * const hdr_flags[] = {
        &hf_dcerpc_cn_flags_object,
        &hf_dcerpc_cn_flags_maybe,
        &hf_dcerpc_cn_flags_dne,
        &hf_dcerpc_cn_flags_mpx,
        &hf_dcerpc_cn_flags_reserved,
        &hf_dcerpc_cn_flags_cancel_pending,
        &hf_dcerpc_cn_flags_last_frag,
        &hf_dcerpc_cn_flags_first_frag,
        NULL
    };

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
    if (!is_dcerpc(tvb, offset, pinfo))
        return FALSE;

    start_offset = offset;
    hdr.rpc_ver = tvb_get_guint8(tvb, offset++);
    hdr.rpc_ver_minor = tvb_get_guint8(tvb, offset++);
    hdr.ptype = tvb_get_guint8(tvb, offset++);

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
        pinfo->desegment_len = hdr.frag_len - tvb_reported_length_remaining(tvb, start_offset);
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
    }

    proto_tree_add_bitmask_value_with_flags(dcerpc_tree, tvb, offset, hf_dcerpc_cn_flags,
                                ett_dcerpc_cn_flags, hdr_flags, hdr.flags, BMT_NO_APPEND);
    offset++;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Fragment: %s", fragment_type(hdr.flags));

    proto_tree_add_dcerpc_drep(dcerpc_tree, tvb, offset, hdr.drep, (int)sizeof (hdr.drep));
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
    subtvb_len = MIN(hdr.frag_len, tvb_reported_length(tvb));
    fragment_tvb = tvb_new_subset_length_caplen(tvb, start_offset,
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
        dissect_dcerpc_cn_auth(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr,
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
        dissect_dcerpc_cn_auth(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr,
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
        dissect_dcerpc_cn_auth(fragment_tvb, MIN(offset - start_offset, subtvb_len), pinfo, dcerpc_tree, &hdr,
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
                pinfo->desegment_len = (guint32)(sizeof(e_dce_cn_common_hdr_t) - tvb_reported_length_remaining(tvb, offset));
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

static guint
get_dcerpc_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                   int offset, void *data _U_)
{
    guint8 drep[4];
    guint16 frag_len;

    tvb_memcpy(tvb, (guint8 *)drep, offset+4, sizeof(drep));
    frag_len = dcerpc_tvb_get_ntohs(tvb, offset+8, drep);

    if (!frag_len) {
        /* tcp_dissect_pdus() interprets a 0 return value as meaning
         * "a PDU starts here, but the length cannot be determined yet, so
         * we need at least one more segment." However, a frag_len of 0 here
         * is instead a bogus length. Instead return 1, another bogus length
         * also less than our fixed length, so that the TCP dissector will
         * correctly interpret it as a bogus and report an error.
         */
        frag_len = 1;
    }
    return frag_len;
}

static int
dissect_dcerpc_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int  pdu_len     = 0;
    dissect_dcerpc_cn(tvb, 0, pinfo, tree,
                                  /* Desegment is already handled by TCP, don't confuse it */
                                  FALSE,
                                  &pdu_len);
    return pdu_len;
}

static gboolean
dissect_dcerpc_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dcerpc_decode_as_data* decode_data;

    if (!is_dcerpc(tvb, 0, pinfo))
        return 0;

    decode_data = dcerpc_get_decode_data(pinfo);
    decode_data->dcetransporttype = DCE_TRANSPORT_UNKNOWN;

    tcp_dissect_pdus(tvb, pinfo, tree, dcerpc_cn_desegment, sizeof(e_dce_cn_common_hdr_t), get_dcerpc_pdu_len, dissect_dcerpc_pdu, data);
    return TRUE;
}

static int
dissect_dcerpc_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dcerpc_decode_as_data* decode_data;

    decode_data = dcerpc_get_decode_data(pinfo);
    decode_data->dcetransporttype = DCE_TRANSPORT_UNKNOWN;

    tcp_dissect_pdus(tvb, pinfo, tree, dcerpc_cn_desegment, sizeof(e_dce_cn_common_hdr_t), get_dcerpc_pdu_len, dissect_dcerpc_pdu, data);
    return tvb_captured_length(tvb);
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

    decode_data->dcetransporttype = DCE_CN_TRANSPORT_SMBPIPE;
    return dissect_dcerpc_cn_bs_body(tvb, pinfo, tree);
}



static void
dissect_dcerpc_dg_auth(tvbuff_t *tvb, int offset, proto_tree *dcerpc_tree,
                       e_dce_dg_common_hdr_t *hdr, int *auth_level_p)
{
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
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        switch (hdr->auth_proto) {

        case DCE_C_RPC_AUTHN_PROTOCOL_KRB5:
            auth_tree = proto_tree_add_subtree(dcerpc_tree, tvb, offset, -1, ett_dcerpc_krb5_auth_verf, NULL, "Kerberos authentication verifier");
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
            proto_tree_add_item(dcerpc_tree, hf_dcerpc_authentication_verifier, tvb, offset, -1, ENC_NA);
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

    length = tvb_reported_length_remaining(tvb, offset);
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
            next_tvb = tvb_new_subset_length_caplen(tvb, offset, length,
                                      reported_length);
            dcerpc_try_handoff(pinfo, tree, dcerpc_tree, next_tvb, TRUE, hdr->drep, di, NULL);
        } else {
            /* PDU is fragmented and this isn't the first fragment */
            if (length > 0) {
                proto_tree_add_item(dcerpc_tree, hf_dcerpc_fragment_data, tvb, offset, stub_length, ENC_NA);
            }
        }
    } else {
        /* Reassembly is enabled, the PDU is fragmented, and
           we have all the data in the fragment; the first two
           of those mean we should attempt reassembly, and the
           third means we can attempt reassembly. */
        if (length > 0) {
            proto_tree_add_item(dcerpc_tree, hf_dcerpc_fragment_data, tvb, offset, stub_length, ENC_NA);
        }

        fd_head = fragment_add_seq(&dcerpc_cl_reassembly_table,
                                   tvb, offset,
                                   pinfo, hdr->seqnum, (void *)hdr,
                                   hdr->frag_num, stub_length,
                                   !(hdr->flags1 & PFCL1_LASTFRAG), 0);
        if (fd_head != NULL) {
            /* We completed reassembly... */
            if (pinfo->num == fd_head->reassembled_in) {
                /* ...and this is the reassembled RPC PDU */
                next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
                add_new_data_source(pinfo, next_tvb, "Reassembled DCE/RPC");
                show_fragment_seq_tree(fd_head, &dcerpc_frag_items,
                                       tree, pinfo, next_tvb, &pi);

                /*
                 * XXX - authentication info?
                 */
                pinfo->fragmented = FALSE;
                dcerpc_try_handoff(pinfo, tree, dcerpc_tree, next_tvb, TRUE, hdr->drep, di, NULL);
            } else {
                /* ...and this isn't the reassembled RPC PDU */
                pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_reassembled_in,
                                         tvb, 0, 0, fd_head->reassembled_in);
                proto_item_set_generated(pi);
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
    dcerpc_call_value  *value;
    dcerpc_matched_key  matched_key, *new_matched_key;
    proto_item         *pi;
    proto_item         *parent_pi;

    if (!(pinfo->fd->visited)) {
        dcerpc_call_value *call_value;
        dcerpc_dg_call_key *call_key;

        call_key = wmem_new(wmem_file_scope(), dcerpc_dg_call_key);
        call_key->conv = conv;
        call_key->seqnum = hdr->seqnum;
        call_key->act_id = hdr->act_id;

        call_value = wmem_new(wmem_file_scope(), dcerpc_call_value);
        call_value->uuid = hdr->if_id;
        call_value->ver = hdr->if_ver;
        call_value->object_uuid = hdr->obj_id;
        call_value->opnum = hdr->opnum;
        call_value->req_frame = pinfo->num;
        call_value->req_time = pinfo->abs_ts;
        call_value->rep_frame = 0;
        call_value->max_ptr = 0;
        call_value->se_data = NULL;
        call_value->private_data = NULL;
        call_value->pol = NULL;
        /* NDR64 is not available on dg transports ?*/
        call_value->flags = 0;

        wmem_map_insert(dcerpc_dg_calls, call_key, call_value);

        new_matched_key = wmem_new(wmem_file_scope(), dcerpc_matched_key);
        new_matched_key->frame = pinfo->num;
        new_matched_key->call_id = hdr->seqnum;
        wmem_map_insert(dcerpc_matched, new_matched_key, call_value);
    }

    matched_key.frame = pinfo->num;
    matched_key.call_id = hdr->seqnum;
    value = (dcerpc_call_value *)wmem_map_lookup(dcerpc_matched, &matched_key);
    if (!value) {
        value = wmem_new(pinfo->pool, dcerpc_call_value);
        value->uuid = hdr->if_id;
        value->ver = hdr->if_ver;
        value->object_uuid = hdr->obj_id;
        value->opnum = hdr->opnum;
        value->req_frame = pinfo->num;
        value->rep_frame = 0;
        value->max_ptr = 0;
        value->se_data = NULL;
        value->private_data = NULL;
    }

    di = wmem_new0(pinfo->pool, dcerpc_info);
    di->dcerpc_procedure_name = "";
    di->conv = conv;
    di->call_id = hdr->seqnum;
    di->transport_salt = -1;
    di->ptype = PDU_REQ;
    di->call_data = value;

    if (value->rep_frame != 0) {
        pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_response_in,
                                 tvb, 0, 0, value->rep_frame);
        proto_item_set_generated(pi);
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
    dcerpc_call_value  *value;
    dcerpc_matched_key  matched_key, *new_matched_key;
    proto_item         *pi;
    proto_item         *parent_pi;

    if (!(pinfo->fd->visited)) {
        dcerpc_call_value *call_value;
        dcerpc_dg_call_key call_key;

        call_key.conv = conv;
        call_key.seqnum = hdr->seqnum;
        call_key.act_id = hdr->act_id;

        if ((call_value = (dcerpc_call_value *)wmem_map_lookup(dcerpc_dg_calls, &call_key))) {
            new_matched_key = wmem_new(wmem_file_scope(), dcerpc_matched_key);
            new_matched_key->frame = pinfo->num;
            new_matched_key->call_id = hdr->seqnum;
            wmem_map_insert(dcerpc_matched, new_matched_key, call_value);
            if (call_value->rep_frame == 0) {
                call_value->rep_frame = pinfo->num;
            }
        }
    }

    matched_key.frame = pinfo->num;
    matched_key.call_id = hdr->seqnum;
    value = (dcerpc_call_value *)wmem_map_lookup(dcerpc_matched, &matched_key);
    if (!value) {
        value = wmem_new0(pinfo->pool, dcerpc_call_value);
        value->uuid = hdr->if_id;
        value->ver = hdr->if_ver;
        value->object_uuid = hdr->obj_id;
        value->opnum = hdr->opnum;
        value->rep_frame = pinfo->num;
    }

    di = wmem_new0(pinfo->pool, dcerpc_info);
    di->dcerpc_procedure_name = "";
    di->conv = conv;
    di->transport_salt = -1;
    di->ptype = PDU_RESP;
    di->call_data = value;

    if (value->req_frame != 0) {
        nstime_t delta_ts;
        pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_request_in,
                                 tvb, 0, 0, value->req_frame);
        proto_item_set_generated(pi);
        parent_pi = proto_tree_get_parent(dcerpc_tree);
        if (parent_pi != NULL) {
            proto_item_append_text(parent_pi, ", [Req: #%u]", value->req_frame);
        }
        nstime_delta(&delta_ts, &pinfo->abs_ts, &value->req_time);
        pi = proto_tree_add_time(dcerpc_tree, hf_dcerpc_time, tvb, offset, 0, &delta_ts);
        proto_item_set_generated(pi);
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
/*    if (!(pinfo->fd->visited)) {*/
    dcerpc_call_value  *call_value;
    dcerpc_dg_call_key  call_key;

    call_key.conv = conv;
    call_key.seqnum = hdr->seqnum;
    call_key.act_id = hdr->act_id;

    if ((call_value = (dcerpc_call_value *)wmem_map_lookup(dcerpc_dg_calls, &call_key))) {
        proto_item *pi;
        nstime_t delta_ts;

        pi = proto_tree_add_uint(dcerpc_tree, hf_dcerpc_request_in,
                                 tvb, 0, 0, call_value->req_frame);
        proto_item_set_generated(pi);
        parent_pi = proto_tree_get_parent(dcerpc_tree);
        if (parent_pi != NULL) {
            proto_item_append_text(parent_pi, ", [Req: #%u]", call_value->req_frame);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " [req: #%u]", call_value->req_frame);

        nstime_delta(&delta_ts, &pinfo->abs_ts, &call_value->req_time);
        pi = proto_tree_add_time(dcerpc_tree, hf_dcerpc_time, tvb, offset, 0, &delta_ts);
        proto_item_set_generated(pi);
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
    proto_tree            *dcerpc_tree    = NULL;
    e_dce_dg_common_hdr_t  hdr;
    int                    offset         = 0;
    conversation_t        *conv;
    int                    auth_level;
    char                  *uuid_str;
    const char            *uuid_name      = NULL;
    static int * const hdr_flags1[] = {
        &hf_dcerpc_dg_flags1_rsrvd_80,
        &hf_dcerpc_dg_flags1_broadcast,
        &hf_dcerpc_dg_flags1_idempotent,
        &hf_dcerpc_dg_flags1_maybe,
        &hf_dcerpc_dg_flags1_nofack,
        &hf_dcerpc_dg_flags1_frag,
        &hf_dcerpc_dg_flags1_last_frag,
        &hf_dcerpc_dg_flags1_rsrvd_01,
        NULL
    };

    static int * const hdr_flags2[] = {
        &hf_dcerpc_dg_flags2_rsrvd_80,
        &hf_dcerpc_dg_flags2_rsrvd_40,
        &hf_dcerpc_dg_flags2_rsrvd_20,
        &hf_dcerpc_dg_flags2_rsrvd_10,
        &hf_dcerpc_dg_flags2_rsrvd_08,
        &hf_dcerpc_dg_flags2_rsrvd_04,
        &hf_dcerpc_dg_flags2_cancel_pending,
        &hf_dcerpc_dg_flags2_rsrvd_01,
        NULL
    };

    /*
     * Check if this looks like a CL DCERPC call.  All dg packets
     * have an 80 byte header on them.  Which starts with
     * version (4), pkt_type.
     */
    if (tvb_reported_length(tvb) < sizeof (hdr)) {
        return FALSE;
    }

    /* Version must be 4 */
    hdr.rpc_ver = tvb_get_guint8(tvb, offset++);
    if (hdr.rpc_ver != 4)
        return FALSE;

    /* Type must be <= PDU_CANCEL_ACK or it's not connectionless DCE/RPC */
    hdr.ptype = tvb_get_guint8(tvb, offset++);
    if (hdr.ptype > PDU_CANCEL_ACK)
        return FALSE;

    /* flags1 has bit 1 and 8 as reserved for implementations, with no
       indication that they must be set to 0, so we don't check them.
    */
    hdr.flags1 = tvb_get_guint8(tvb, offset++);

    /* flags2 has bit 1 reserved for implementations, bit 2 used,
       and the other bits reserved for future use and specified
       as "must be set to 0", so if any of the other bits are set
       it is probably not DCE/RPC.
    */
    hdr.flags2 = tvb_get_guint8(tvb, offset++);
    if (hdr.flags2&0xfc)
        return FALSE;

    tvb_memcpy(tvb, (guint8 *)hdr.drep, offset, sizeof (hdr.drep));
    offset += (int)sizeof (hdr.drep);
    if (hdr.drep[0]&0xee)
        return FALSE;
    if (hdr.drep[1] > DCE_RPC_DREP_FP_IBM)
        return FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCERPC");
    col_add_str(pinfo->cinfo, COL_INFO, pckt_vals[hdr.ptype].strptr);

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

    proto_tree_add_uint(dcerpc_tree, hf_dcerpc_ver, tvb, offset, 1, hdr.rpc_ver);
    offset++;

    proto_tree_add_uint(dcerpc_tree, hf_dcerpc_packet_type, tvb, offset, 1, hdr.ptype);
    offset++;

    proto_tree_add_bitmask_value(dcerpc_tree, tvb, offset, hf_dcerpc_dg_flags1,
                                ett_dcerpc_dg_flags1, hdr_flags1, hdr.flags1);
    offset++;

    proto_tree_add_bitmask_value(dcerpc_tree, tvb, offset, hf_dcerpc_dg_flags2,
                                ett_dcerpc_dg_flags2, hdr_flags2, hdr.flags2);
    offset++;

    if (tree) {
        proto_tree_add_dcerpc_drep(dcerpc_tree, tvb, offset, hdr.drep, (int)sizeof (hdr.drep));
    }
    offset += (int)sizeof (hdr.drep);

    if (tree)
        proto_tree_add_uint(dcerpc_tree, hf_dcerpc_dg_serial_hi, tvb, offset, 1, hdr.serial_hi);
    offset++;

    if (tree) {
        proto_tree_add_guid_format(dcerpc_tree, hf_dcerpc_obj_id, tvb,
                                   offset, 16, (e_guid_t *) &hdr.obj_id, "Object UUID: %s",
                                   guid_to_str(pinfo->pool, (e_guid_t *) &hdr.obj_id));
    }
    offset += 16;

    if (tree) {
        uuid_str = guid_to_str(pinfo->pool, (e_guid_t*)&hdr.if_id);
        uuid_name = guids_get_uuid_name(&hdr.if_id, pinfo->pool);
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
                                   guid_to_str(pinfo->pool, (e_guid_t *) &hdr.act_id));
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
dcerpc_auth_subdissector_list_free(gpointer p, gpointer user_data _U_)
{
    g_free(p);
}

static void
dcerpc_shutdown(void)
{
    g_slist_foreach(dcerpc_auth_subdissector_list, dcerpc_auth_subdissector_list_free, NULL);
    g_slist_free(dcerpc_auth_subdissector_list);
    g_hash_table_destroy(dcerpc_uuids);
    tvb_free(tvb_trailer_signature);
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
        { &hf_dcerpc_referent_id32,
          { "Referent ID", "dcerpc.referent_id", FT_UINT32, BASE_HEX,
            NULL, 0, "Referent ID for this NDR encoded pointer", HFILL }},
        { &hf_dcerpc_referent_id64,
          { "Referent ID", "dcerpc.referent_id64", FT_UINT64, BASE_HEX,
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
        { &hf_dcerpc_ndr_padding,
          { "NDR-Padding", "dcerpc.ndr_padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
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
        { &hf_dcerpc_cn_bind_trans_btfn, /* [MS-RPCE] 2.2.2.14 */
          {"Bind Time Features", "dcerpc.cn_bind_trans_btfn", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_trans_btfn_01,
          { "Security Context Multiplexing Supported", "dcerpc.cn_bind_trans_btfn.01", FT_BOOLEAN, 16, NULL, 0x01, NULL, HFILL }},
        { &hf_dcerpc_cn_bind_trans_btfn_02,
          { "Keep Connection On Orphan Supported", "dcerpc.cn_bind_trans_btfn.02", FT_BOOLEAN, 16, NULL, 0x02, NULL, HFILL }},
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
        { &hf_dcerpc_cn_fault_flags,
          { "Fault flags", "dcerpc.cn_fault_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cn_fault_flags_extended_error_info,
          { "Extended error information present", "dcerpc.cn_fault_flags.extended_error", FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL }},
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
          { "Reserved for implementation", "dcerpc.dg_flags1_rsrvd_01", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL1_RESERVED_01, NULL, HFILL }},
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
          { "Reserved for implementation", "dcerpc.dg_flags1_rsrvd_80", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL1_RESERVED_80, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2,
          { "Flags2", "dcerpc.dg_flags2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_01,
          { "Reserved for implementation", "dcerpc.dg_flags2_rsrvd_01", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_01, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_cancel_pending,
          { "Cancel Pending", "dcerpc.dg_flags2_cancel_pending", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_CANCEL_PENDING, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_04,
          { "Reserved for future use (MBZ)", "dcerpc.dg_flags2_rsrvd_04", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_04, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_08,
          { "Reserved for future use (MBZ)", "dcerpc.dg_flags2_rsrvd_08", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_08, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_10,
          { "Reserved for future use (MBZ)", "dcerpc.dg_flags2_rsrvd_10", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_10, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_20,
          { "Reserved for future use (MBZ)", "dcerpc.dg_flags2_rsrvd_20", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_20, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_40,
          { "Reserved for future use (MBZ)", "dcerpc.dg_flags2_rsrvd_40", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_40, NULL, HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_80,
          { "Reserved for future use (MBZ)", "dcerpc.dg_flags2_rsrvd_80", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PFCL2_RESERVED_80, NULL, HFILL }},
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

        { &hf_dcerpc_null_pointer,
          { "NULL Pointer", "dcerpc.null_pointer", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

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
        { &hf_dcerpc_sec_vt_signature,
          {"SEC_VT_SIGNATURE", "dcerpc.rpc_sec_vt.signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_sec_vt_command_end,
          {"SEC_VT_COMMAND_END", "dcerpc.rpc_sec_vt.command.end", FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL }},
        { &hf_dcerpc_sec_vt_command_must,
          {"SEC_VT_MUST_PROCESS_COMMAND", "dcerpc.rpc_sec_vt.command.must_process", FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }},
        { &hf_dcerpc_sec_vt_command_cmd,
          {"Cmd", "dcerpc.rpc_sec_vt.command.cmd", FT_UINT16, BASE_HEX, VALS(sec_vt_command_cmd_vals), 0x3fff, NULL, HFILL }},
        { &hf_dcerpc_sec_vt_command,
          {"Command", "dcerpc.rpc_sec_vt.command", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_dcerpc_sec_vt_command_length,
          {"Length", "dcerpc.rpc_sec_vt.command.length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_dcerpc_sec_vt_bitmask,
          {"rpc_sec_vt_bitmask", "dcerpc.rpc_sec_vt.bitmask", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_dcerpc_sec_vt_bitmask_sign,
          {"CLIENT_SUPPORT_HEADER_SIGNING", "dcerpc.rpc_sec_vt.bitmask.sign", FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL }},
        { &hf_dcerpc_sec_vt_pcontext_uuid,
          {"UUID", "dcerpc.rpc_sec_vt.pcontext.interface.uuid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_dcerpc_sec_vt_pcontext_ver,
          {"Version", "dcerpc.rpc_sec_vt.pcontext.interface.ver", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_dcerpc_reserved,
          {"Reserved", "dcerpc.reserved", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_dcerpc_unknown,
          {"Unknown", "dcerpc.unknown", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_dcerpc_missalign,
          {"missalign", "dcerpc.missalign", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_dcerpc_duplicate_ptr, { "duplicate PTR", "dcerpc.duplicate_ptr", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_encrypted_stub_data, { "Encrypted stub data", "dcerpc.encrypted_stub_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_decrypted_stub_data, { "Decrypted stub data", "dcerpc.decrypted_stub_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_payload_stub_data, { "Payload stub data", "dcerpc.payload_stub_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_stub_data_with_sec_vt, { "Stub data with rpc_sec_verification_trailer", "dcerpc.stub_data_with_sec_vt", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_stub_data, { "Stub data", "dcerpc.stub_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_auth_padding, { "Auth Padding", "dcerpc.auth_padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_auth_info, { "Auth Info", "dcerpc.auth_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_auth_credentials, { "Auth Credentials", "dcerpc.auth_credentials", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_fault_stub_data, { "Fault stub data", "dcerpc.fault_stub_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_fragment_data, { "Fragment data", "dcerpc.fragment_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cmd_client_ipv4, { "RTS Client address", "dcerpc.cmd_client_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_cmd_client_ipv6, { "RTS Client address", "dcerpc.cmd_client_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dcerpc_authentication_verifier, { "Authentication verifier", "dcerpc.authentication_verifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };
    static gint *ett[] = {
        &ett_dcerpc,
        &ett_dcerpc_cn_flags,
        &ett_dcerpc_cn_ctx,
        &ett_dcerpc_cn_iface,
        &ett_dcerpc_cn_trans_syntax,
        &ett_dcerpc_cn_trans_btfn,
        &ett_dcerpc_cn_bind_trans_btfn,
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
        &ett_dcerpc_auth_info,
        &ett_dcerpc_verification_trailer,
        &ett_dcerpc_sec_vt_command,
        &ett_dcerpc_sec_vt_bitmask,
        &ett_dcerpc_sec_vt_pcontext,
        &ett_dcerpc_sec_vt_header,
        &ett_dcerpc_complete_stub_data,
        &ett_dcerpc_fault_flags,
        &ett_dcerpc_fault_stub_data,
    };

    static ei_register_info ei[] = {
        { &ei_dcerpc_fragment, { "dcerpc.fragment.reassemble", PI_REASSEMBLE, PI_CHAT, "Fragment", EXPFILL }},
        { &ei_dcerpc_fragment_reassembled, { "dcerpc.fragment_reassembled", PI_REASSEMBLE, PI_CHAT, "Fragment, reassembled", EXPFILL }},
        { &ei_dcerpc_cn_ctx_id_no_bind, { "dcerpc.cn_ctx_id.no_bind", PI_UNDECODED, PI_NOTE, "No bind info for interface Context ID", EXPFILL }},
        { &ei_dcerpc_no_request_found, { "dcerpc.no_request_found", PI_SEQUENCE, PI_NOTE, "No request to this DCE/RPC call found", EXPFILL }},
        { &ei_dcerpc_cn_status, { "dcerpc.cn_status.expert", PI_RESPONSE_CODE, PI_NOTE, "Fault", EXPFILL }},
        { &ei_dcerpc_fragment_multiple, { "dcerpc.fragment_multiple", PI_SEQUENCE, PI_CHAT, "Multiple DCE/RPC fragments/PDU's in one packet", EXPFILL }},
#if 0  /* XXX - too much "output noise", removed for now  */
        { &ei_dcerpc_context_change, { "dcerpc.context_change", PI_SEQUENCE, PI_CHAT, "Context change", EXPFILL }},
#endif
        { &ei_dcerpc_bind_not_acknowledged, { "dcerpc.bind_not_acknowledged", PI_SEQUENCE, PI_WARN, "Bind not acknowledged", EXPFILL }},
        { &ei_dcerpc_verifier_unavailable, { "dcerpc.verifier_unavailable", PI_UNDECODED, PI_WARN, "Verifier unavailable", EXPFILL }},
        { &ei_dcerpc_invalid_pdu_authentication_attempt, { "dcerpc.invalid_pdu_authentication_attempt", PI_UNDECODED, PI_WARN, "Invalid authentication attempt", EXPFILL }},
        /* Generated from convert_proto_tree_add_text.pl */
        { &ei_dcerpc_long_frame, { "dcerpc.long_frame", PI_PROTOCOL, PI_WARN, "Long frame", EXPFILL }},
        { &ei_dcerpc_cn_rts_command, { "dcerpc.cn_rts_command.unknown", PI_PROTOCOL, PI_WARN, "unknown RTS command number", EXPFILL }},
        { &ei_dcerpc_not_implemented, { "dcerpc.not_implemented", PI_UNDECODED, PI_WARN, "dissection not implemented", EXPFILL }},
    };

    /* Decode As handling */
    static build_valid_func dcerpc_da_build_value[1] = {dcerpc_value};
    static decode_as_value_t dcerpc_da_values = {dcerpc_prompt, 1, dcerpc_da_build_value};
    static decode_as_t dcerpc_da = {"dcerpc", "dcerpc.uuid",
                                    1, 0, &dcerpc_da_values, NULL, NULL,
                                    dcerpc_populate_list, decode_dcerpc_binding_reset, dcerpc_decode_as_change, dcerpc_decode_as_free};

    module_t *dcerpc_module;
    expert_module_t* expert_dcerpc;

    proto_dcerpc = proto_register_protocol("Distributed Computing Environment / Remote Procedure Call (DCE/RPC)", "DCERPC", "dcerpc");
    proto_register_field_array(proto_dcerpc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_dcerpc = expert_register_protocol(proto_dcerpc);
    expert_register_field_array(expert_dcerpc, ei, array_length(ei));

    uuid_dissector_table = register_dissector_table("dcerpc.uuid", "DCE/RPC UUIDs", proto_dcerpc, FT_GUID, BASE_HEX);

    /* structures and data for BIND */
    dcerpc_binds = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), dcerpc_bind_hash, dcerpc_bind_equal);

    dcerpc_auths = wmem_map_new_autoreset(wmem_epan_scope(),
                                          wmem_file_scope(),
                                          dcerpc_auth_context_hash,
                                          dcerpc_auth_context_equal);

    /* structures and data for CALL */
    dcerpc_cn_calls = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), dcerpc_cn_call_hash, dcerpc_cn_call_equal);
    dcerpc_dg_calls = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), dcerpc_dg_call_hash, dcerpc_dg_call_equal);

    /* structure and data for MATCHED */
    dcerpc_matched = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), dcerpc_matched_hash, dcerpc_matched_equal);

    register_init_routine(decode_dcerpc_inject_bindings);

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

    /*
     * XXX - addresses_ports_reassembly_table_functions?
     * Or can a single connection-oriented DCE RPC session persist
     * over multiple transport layer connections?
     */
    reassembly_table_register(&dcerpc_co_reassembly_table,
                          &addresses_reassembly_table_functions);
    reassembly_table_register(&dcerpc_cl_reassembly_table,
                          &dcerpc_cl_reassembly_table_functions);

    dcerpc_uuids = g_hash_table_new_full(dcerpc_uuid_hash, dcerpc_uuid_equal, g_free, g_free);
    dcerpc_tap = register_tap("dcerpc");

    register_decode_as(&dcerpc_da);

    register_srt_table(proto_dcerpc, NULL, 1, dcerpcstat_packet, dcerpcstat_init, dcerpcstat_param);

    tvb_trailer_signature = tvb_new_real_data(TRAILER_SIGNATURE,
                                              sizeof(TRAILER_SIGNATURE),
                                              sizeof(TRAILER_SIGNATURE));

    register_shutdown_routine(dcerpc_shutdown);
}

void
proto_reg_handoff_dcerpc(void)
{
    dissector_handle_t dcerpc_tcp_handle;

    heur_dissector_add("tcp", dissect_dcerpc_tcp_heur, "DCE/RPC over TCP", "dcerpc_tcp", proto_dcerpc, HEURISTIC_ENABLE);
    heur_dissector_add("netbios", dissect_dcerpc_cn_pk, "DCE/RPC over NetBios", "dcerpc_netbios", proto_dcerpc, HEURISTIC_ENABLE);
    heur_dissector_add("udp", dissect_dcerpc_dg, "DCE/RPC over UDP", "dcerpc_udp", proto_dcerpc, HEURISTIC_ENABLE);
    heur_dissector_add("smb_transact", dissect_dcerpc_cn_smbpipe, "DCE/RPC over SMB", "dcerpc_smb_transact", proto_dcerpc, HEURISTIC_ENABLE);
    heur_dissector_add("smb2_pipe_subdissectors", dissect_dcerpc_cn_smb2, "DCE/RPC over SMB2", "dcerpc_smb2", proto_dcerpc, HEURISTIC_ENABLE);
    heur_dissector_add("http", dissect_dcerpc_cn_bs, "DCE/RPC over HTTP", "dcerpc_http", proto_dcerpc, HEURISTIC_ENABLE);
    dcerpc_smb_init(proto_dcerpc);

    dcerpc_tcp_handle = create_dissector_handle(dissect_dcerpc_tcp, proto_dcerpc);
    dissector_add_for_decode_as("tcp.port", dcerpc_tcp_handle);

    guids_add_uuid(&uuid_data_repr_proto, "32bit NDR");
    guids_add_uuid(&uuid_ndr64, "64bit NDR");
    guids_add_uuid(&uuid_asyncemsmdb, "async MAPI");
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
