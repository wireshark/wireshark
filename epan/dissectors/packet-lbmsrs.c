/* packet-lbmsrs.c
* Routines for SRS Packet dissection
*
* Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*
* Special thanks to the team at https://github.com/rsocket/rsocket-wireshark
* for getting us started on the right path for this Ultra Messaging rsocket dissector.
* Rsocket Protocol Description: https://rsocket.io/docs/Protocol.html
*/

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <packet-lbm.h>
#include <epan/proto.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <wsutil/pint.h>
#include <dissectors/packet-tcp.h>



static gint proto_lbmsrs = -1;

void proto_register_lbmsrs(void);
void proto_reg_handoff_lbmsrs(void);

/****************************************LBMSRS Packet definitions**************************************************/
/*******************************************************************************************************************/
#define LBM_SRS_PROTOCOL_VERSION 1
#define L_LBM_SRS_MESSAGE_ID 2

/* LBMSRS Registration Request
typedef struct lbm_srs_registration_request_info_t_stct {
    lbm_uint8_t app_type;
    lbm_uint32_t client_addr;
    lbm_uint16_t client_port;
    lbm_uint32_t session_id;
    lbm_uint32_t host_id;
    lbm_uint8_t protocol_version;
    lbm_uint8_t interest_mode;
    lbm_uint32_t local_domain_id;
} lbm_srs_registration_request_info_t;
*/
#define L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_APP_TYPE 1
#define L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_CLIENT_ADDR 4
#define L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_CLIENT_PORT 2
#define L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_SESSION_ID 4
#define L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_HOST_ID 4
#define L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_PROTOCOL_VERSION 1
#define L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_INTEREST_MODE 1
#define L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_LOCAL_DOMAIN_ID 4
#define L_LBM_SRS_REGISTRATION_REQUEST_INFO_T 21 /*padding is giving length as 24 above*/


#define LBM_SRS_INTEREST_MODE_FLOOD 0
#define LBM_SRS_INTEREST_MODE_FILTER 1
#define LBM_SRS_INTEREST_MODE_FLOOD_FORWARD_INTEREST 2
#define LBM_SRS_INTEREST_MODE_FILTER_FORWARD_INTEREST 3
#define LBM_SRS_APP_TYPE_APPLICATION 0
#define LBM_SRS_APP_TYPE_TNWGD 1
#define LBM_SRS_APP_TYPE_STORE 2

/* LBMSRS Registration Response
typedef struct lbm_srs_registration_response_info_t_stct {
    lbm_uint64_t client_id;
    lbm_uint32_t local_domain_id;
    lbm_uint8_t protocol_version;
} lbm_srs_registration_response_info_t;
*/
#define L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T_CLIENT_ID 8
#define L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T_PROTOCOL_VERSION 4
#define L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T_LOCAL_DOMAIN_ID 1
#define L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T 13


/* LBMSRS Stream Request
typedef struct lbm_srs_stream_request_info_t_stct {
    lbm_uint8_t unused;
} lbm_srs_stream_request_info_t;
*/
#define L_LBM_SRS_STREAM_REQUEST_INFO_T_UNUSED 1
#define L_LBM_SRS_STREAM_REQUEST_INFO_T 1

/* LBMSRS Source Info
typedef struct lbm_srs_src_info_info_t_stct {
    char * otid;
    lbm_uint8_t topic_len;
    char * topic;
    lbm_uint8_t source_len;
    char * source;
    lbm_uint32_t host_id;
    lbm_uint32_t topic_idx;
    lbm_uint32_t functionality_flags;
    lbm_uint32_t request_ip;
    lbm_uint16_t request_port;
    lbm_uint32_t domain_id;
    lbm_uint8_t encryption;
    lbm_uint8_t compression;
    lbm_uint32_t ulb_src_id;
    lbm_uint32_t ulb_queue_id;
    lbm_uint64_t ulb_reg_id;
    char* context_instance;
    lbm_uint8_t context_type;
    lbm_uint32_t version;
    lbm_uint32_t version_flags;
    lbm_uint16_t ttl;
    lbm_uint32_t cost;
} lbm_srs_src_info_info_t;
*/
#define L_LBM_SRS_SRC_INFO_INFO_T_OTID 32 //fixed length
#define L_LBM_SRS_SRC_INFO_INFO_T_TOPIC_LEN 1
#define L_LBM_SRS_SRC_INFO_INFO_T_SOURCE_LEN 1
#define L_LBM_SRS_SRC_INFO_INFO_T_HOST_ID 4
#define L_LBM_SRS_SRC_INFO_INFO_T_TOPIC_IDX 4
#define L_LBM_SRS_SRC_INFO_INFO_T_FUNCTIONALITY_FLAGS 4
#define L_LBM_SRS_SRC_INFO_INFO_T_REQUEST_IP 4
#define L_LBM_SRS_SRC_INFO_INFO_T_REQUEST_PORT 2
#define L_LBM_SRS_SRC_INFO_INFO_T_DOMAIN_ID 4
#define L_LBM_SRS_SRC_INFO_INFO_T_ENCRYPTION 1
#define L_LBM_SRS_SRC_INFO_INFO_T_COMPRESSION 1
#define L_LBM_SRS_SRC_INFO_INFO_T_ULB_SRC_ID 4
#define L_LBM_SRS_SRC_INFO_INFO_T_ULB_QUEUE_ID 4
#define L_LBM_SRS_SRC_INFO_INFO_T_ULB_REG_ID 8
#define L_LBM_SRS_SRC_INFO_INFO_T_CONTEXT_INSTANCE 8
#define L_LBM_SRS_SRC_INFO_INFO_T_CONTEXT_TYPE 1
#define L_LBM_SRS_SRC_INFO_INFO_T_VERSION 4
#define L_LBM_SRS_SRC_INFO_INFO_T_VERSION_FLAGS 4
#define L_LBM_SRS_SRC_INFO_INFO_T_TTL 2
#define L_LBM_SRS_SRC_INFO_INFO_T_COST 4


/* LBMSRS Source Delete Info
typedef struct lbm_srs_src_delete_info_t_stct {
    char * otid;
    lbm_uint8_t topic_len;
    char * topic;
} lbm_srs_src_delete_info_t;
*/
#define L_LBM_SRS_SRC_DELETE_INFO_T_OTID 32
#define L_LBM_SRS_SRC_DELETE_INFO_T_TOPIC_LEN 1


/* LBMSRS Receiver Info
typedef struct lbm_srs_rcv_info_info_t_stct {
    lbm_uint8_t topic_len;
    char * topic;
    lbm_uint32_t domain_id;
    char* context_instance;
    lbm_uint8_t context_type;
    lbm_uint32_t version;
    lbm_uint32_t version_flags;
    lbm_uint32_t reserved;
} lbm_srs_rcv_info_info_t;
*/
#define L_LBM_SRS_RCV_INFO_INFO_T_TOPIC_LEN 1
#define L_LBM_SRS_RCV_INFO_INFO_T_DOMAIN_ID 4
#define L_LBM_SRS_RCV_INFO_INFO_T_CONTEXT_INSTANCE 8
#define L_LBM_SRS_RCV_INFO_INFO_T_CONTEXT_TYPE 1
#define L_LBM_SRS_RCV_INFO_INFO_T_VERSION 4
#define L_LBM_SRS_RCV_INFO_INFO_T_VERSION_FLAGS 4
#define L_LBM_SRS_RCV_INFO_INFO_T_RESERVED 4


/* LBMSRS Receiver Delete Info
typedef struct lbm_srs_rcv_delete_info_t_stct {
    lbm_uint8_t topic_len;
    char * topic;
    lbm_uint32_t domain_id;
    char* context_instance;
    lbm_uint8_t context_type;
    lbm_uint32_t version;
    lbm_uint32_t version_flags;
    lbm_uint32_t reserved;
} lbm_srs_rcv_delete_info_t;
*/
#define L_LBM_SRS_RCV_DELETE_INFO_T_TOPIC_LEN 1
#define L_LBM_SRS_RCV_DELETE_INFO_T_DOMAIN_ID 4
#define L_LBM_SRS_RCV_DELETE_INFO_T_CONTEXT_INSTANCE 8
#define L_LBM_SRS_RCV_DELETE_INFO_T_CONTEXT_TYPE 1
#define L_LBM_SRS_RCV_DELETE_INFO_T_VERSION 4
#define L_LBM_SRS_RCV_DELETE_INFO_T_VERSION_FLAGS 4
#define L_LBM_SRS_RCV_DELETE_INFO_T_RESERVED 4

/* LBMSRS Receiver End info
typedef struct lbm_srs_rcv_end_info_t_stct {
    lbm_uint8_t topic_len;
    char * topic;
    lbm_uint32_t domain_id;
    char* context_iinstance;
    lbm_uint8_t context_type;
    lbm_uint32_t version;
    lbm_uint32_t version_flags;
    lbm_uint32_t reserved;
} lbm_srs_rcv_end_info_t;
*/
#define L_LBM_SRS_RCV_END_INFO_T_TOPIC_LEN 1
#define L_LBM_SRS_RCV_END_INFO_T_DOMAIN_ID 4
#define L_LBM_SRS_RCV_END_INFO_T_CONTEXT_INSTANCE 8
#define L_LBM_SRS_RCV_END_INFO_T_CONTEXT_TYPE 1
#define L_LBM_SRS_RCV_END_INFO_T_VERSION 4
#define L_LBM_SRS_RCV_END_INFO_T_VERSION_FLAGS 4
#define L_LBM_SRS_RCV_END_INFO_T_RESERVED 4


/* LBMSRS Wildcard Receiver Info
typedef struct lbm_srs_wrcv_info_info_t_stct {
    lbm_uint8_t pattern_len;
    char * pattern;
    lbm_uint32_t domain_id;
    char* context_instance;
    lbm_uint8_t context_type;
    lbm_uint32_t version;
    lbm_uint32_t version_flags;
    lbm_uint32_t reserved;
} lbm_srs_wrcv_info_info_t;
*/
#define L_LBM_SRS_WRCV_INFO_INFO_T_PATTERN_LEN 1
#define L_LBM_SRS_WRCV_INFO_INFO_T_DOMAIN_ID 4
#define L_LBM_SRS_WRCV_INFO_INFO_T_CONTEXT_INSTANCE 8
#define L_LBM_SRS_WRCV_INFO_INFO_T_CONTEXT_TYPE 1
#define L_LBM_SRS_WRCV_INFO_INFO_T_VERSION 4
#define L_LBM_SRS_WRCV_INFO_INFO_T_VERSION_FLAGS 4
#define L_LBM_SRS_WRCV_INFO_INFO_T_RESERVED 4


/* LBMSRS Wildcard Receive Delete Info
typedef struct lbm_srs_wrcv_delete_info_t_stct {
    lbm_uint8_t pattern_len;
    char * pattern;
    lbm_uint32_t domain_id;
    char* context_instance;
    lbm_uint8_t context_type;
    lbm_uint32_t version;
    lbm_uint32_t version_flags;
    lbm_uint32_t reserved;
} lbm_srs_wrcv_delete_info_t;
*/
#define L_LBM_SRS_WRCV_DELETE_INFO_T_PATTERN_LEN 1
#define L_LBM_SRS_WRCV_DELETE_INFO_T_DOMAIN_ID 4
#define L_LBM_SRS_WRCV_DELETE_INFO_T_CONTEXT_INSTANCE 8
#define L_LBM_SRS_WRCV_DELETE_INFO_T_CONTEXT_TYPE 1
#define L_LBM_SRS_WRCV_DELETE_INFO_T_VERSION 4
#define L_LBM_SRS_WRCV_DELETE_INFO_T_VERSION_FLAGS 4
#define L_LBM_SRS_WRCV_DELETE_INFO_T_RESERVED 4


/* LBMSRS Wildcard Receive End Info
typedef struct lbm_srs_wrcv_end_info_t_stct {
    lbm_uint8_t pattern_len;
    char * pattern;
    lbm_uint32_t domain_id;
    char* context_instance;
    lbm_uint8_t context_type;
    lbm_uint32_t version;
    lbm_uint32_t version_flags;
    lbm_uint32_t reserved;
} lbm_srs_wrcv_end_info_t;
*/
#define L_LBM_SRS_WRCV_END_INFO_T_PATTERN_LEN 1
#define L_LBM_SRS_WRCV_END_INFO_T_DOMAIN_ID 4
#define L_LBM_SRS_WRCV_END_INFO_T_CONTEXT_INSTANCE 8
#define L_LBM_SRS_WRCV_END_INFO_T_CONTEXT_TYPE 1
#define L_LBM_SRS_WRCV_END_INFO_T_VERSION 4
#define L_LBM_SRS_WRCV_END_INFO_T_VERSION_FLAGS 4
#define L_LBM_SRS_WRCV_END_INFO_T_RESERVED 4


/* LBMSRS Source Leave Info
typedef struct lbm_srs_src_leave_info_t_stct {
    char * otid;
    lbm_uint8_t topic_len;
    char * topic;
    lbm_uint8_t source_len;
    char * source;
    char* context_instance;
    lbm_uint8_t context_type;
    lbm_uint32_t version;
    lbm_uint32_t version_flags;
    lbm_uint32_t reserved;
}lbm_srs_src_leave_info_t;
*/
#define L_LBM_SRS_SRC_LEAVE_INFO_T_OTID 32 //fixed length
#define L_LBM_SRS_SRC_LEAVE_INFO_T_TOPIC_LEN 1
#define L_LBM_SRS_SRC_LEAVE_INFO_T_SOURCE_LEN 1
#define L_LBM_SRS_SRC_LEAVE_INFO_T_CONTEXT_INSTANCE 8
#define L_LBM_SRS_SRC_LEAVE_INFO_T_CONTEXT_TYPE 1
#define L_LBM_SRS_SRC_LEAVE_INFO_T_VERSION 4
#define L_LBM_SRS_SRC_LEAVE_INFO_T_VERSION_FLAGS 4
#define L_LBM_SRS_SRC_LEAVE_INFO_T_RESERVED 4


/*SRS Message IDs*/
#define MSG_ID_REGISTRATION_REQUEST 1
#define MSG_ID_REGISTRATION_RESPONSE 2
#define MSG_ID_STREAM_REQUEST 3
#define MSG_ID_SOURCE_INFO 4
#define MSG_ID_SOURCE_DELETE 5
#define MSG_ID_RCV_INFO 6
#define MSG_ID_RCV_DELETE 7
#define MSG_ID_RCV_END 8
#define MSG_ID_WRCV_INFO 9
#define MSG_ID_WRCV_DELETE 10
#define MSG_ID_WRCV_END 11
#define MSG_ID_SRC_LEAVE 12

/*SRS Tag definitions*/
typedef struct
{
    char * name;
    char * ip_address;
    guint32 ip_address_val_h;
    guint32 tcp_port;
} lbmsrs_tag_entry_t;

static lbmsrs_tag_entry_t* lbmsrs_tag_entry;
static guint lbmsrs_tag_count = 0;

UAT_CSTRING_CB_DEF(lbmsrs_tag, name, lbmsrs_tag_entry_t)
UAT_IPV4_CB_DEF(lbmsrs_tag, ip_address, lbmsrs_tag_entry_t)
UAT_DEC_CB_DEF(lbmsrs_tag, tcp_port, lbmsrs_tag_entry_t)

static uat_field_t lbmsrs_tag_array[] =
{
    UAT_FLD_CSTRING(lbmsrs_tag, name, "Tag name", "Tag name"),
    UAT_FLD_IPV4(lbmsrs_tag, ip_address, "LBMSRS IP Address", "LBMSRS IP Address"),
    UAT_FLD_DEC(lbmsrs_tag, tcp_port, "LBMSRS TCP port", "LBMSRS TCP port"),
    UAT_END_FIELDS
};

static const value_string lbmsrsMessageId[] =
{
    { MSG_ID_REGISTRATION_REQUEST, "SRS_REGISTRATION_REQUEST" },
    { MSG_ID_REGISTRATION_RESPONSE, "SRS_REGISTRATION_RESPONSE" },
    { MSG_ID_STREAM_REQUEST, "SRS_STREAM_REQUEST" },
    { MSG_ID_SOURCE_INFO, "SRS_SRC_INFO" },
    { MSG_ID_SOURCE_DELETE, "SRS_SRC_DELETE" },
    { MSG_ID_RCV_INFO, "SRS_RCV_INFO" },
    { MSG_ID_RCV_DELETE, "SRS_RCV_DELETE" },
    { MSG_ID_RCV_END, "SRS_RCV_END" },
    { MSG_ID_WRCV_INFO, "SRS_WRCV_INFO" },
    { MSG_ID_WRCV_DELETE, "SRS_WRCV_DELETE" },
    { MSG_ID_WRCV_END, "SRS_WRCV_END" },
    { MSG_ID_SRC_LEAVE, "SRS_LEAVE_INFO" },
    { 0,NULL}
};
static const value_string lbmsrsInterestMode[]=
{
    { LBM_SRS_INTEREST_MODE_FLOOD, "INTEREST_MODE_FLOOD"},
    { LBM_SRS_INTEREST_MODE_FILTER, "INTEREST_MODE_FILTER" },
    { LBM_SRS_INTEREST_MODE_FLOOD_FORWARD_INTEREST, "INTEREST_MODE_FLOOD_FORWARD_INTEREST" },
    { LBM_SRS_INTEREST_MODE_FILTER_FORWARD_INTEREST, "INTEREST_MODE_FILTER_FORWARD_INTEREST" },
    { 0,NULL}
};
static const value_string lbmsrsApplicationType[] =
{
    { LBM_SRS_APP_TYPE_APPLICATION, "APP_TYPE_APPLICATION" },
    { LBM_SRS_APP_TYPE_TNWGD, "APP_TYPE_TNWGD" },
    { LBM_SRS_APP_TYPE_STORE, "APP_TYPE_STORE" },
    { 0,NULL}
};

/* Dissector field handles */
static gint hf_lbmsrs_message_id = -1;

/*handles for registration request*/
static gint hf_lbmsrs_app_type = -1;
static gint hf_lbmsrs_client_addr = -1;
static gint hf_lbmsrs_client_port = -1;
static gint hf_lbmsrs_session_id = -1;
static gint hf_lbmsrs_host_id = -1;
static gint hf_lbmsrs_protocol_version = -1;
static gint hf_lbmsrs_interest_mode = -1;
static gint hf_lbmsrs_req_local_domain_id = -1;

/*handles for registration respose*/
static gint hf_lbmsrs_client_id = -1;
static gint hf_lbmsrs_resp_local_domain_id = -1;
static gint hf_lbmsrs_reg_resp_protocol_version = -1;

/*handles for stream request*/
static gint hf_lbmsrs_stream_req_unused = -1;

/*handles for source info*/
static gint hf_lbmsrs_sir = -1;
static gint hf_lbmsrs_sir_otid = -1;
static gint hf_lbmsrs_sir_topic_len = -1;
static gint hf_lbmsrs_sir_topic = -1;
static gint hf_lbmsrs_sir_source_len = -1;
static gint hf_lbmsrs_sir_source = -1;
static gint hf_lbmsrs_sir_host_id = -1;
static gint hf_lbmsrs_sir_topic_idx = -1;
static gint hf_lbmsrs_sir_functionality_flags = -1;
static gint hf_lbmsrs_sir_request_ip = -1;
static gint hf_lbmsrs_sir_request_port = -1;
static gint hf_lbmsrs_sir_domain_id = -1;
static gint hf_lbmsrs_sir_encryption = -1;
static gint hf_lbmsrs_sir_compression = -1;
static gint hf_lbmsrs_sir_ulb_src_id = -1;
static gint hf_lbmsrs_sir_ulb_queue_id = -1;
static gint hf_lbmsrs_sir_ulb_reg_id = -1;
static gint hf_lbmsrs_sir_context_instance = -1;
static gint hf_lbmsrs_sir_context_type = -1;
static gint hf_lbmsrs_sir_version = -1;
static gint hf_lbmsrs_sir_version_flags = -1;
static gint hf_lbmsrs_sir_ttl = -1;
static gint hf_lbmsrs_sir_cost = -1;

/*handles for source delete*/
static gint hf_lbmsrs_sdr = -1;
static gint hf_lbmsrs_sdr_otid = -1;
static gint hf_lbmsrs_sdr_topic_len = -1;
static gint hf_lbmsrs_sdr_topic = -1;

/*handles for receiver info*/
static gint hf_lbmsrs_rir = -1;
static gint hf_lbmsrs_rir_topic_len = -1;
static gint hf_lbmsrs_rir_topic = -1;
static gint hf_lbmsrs_rir_domain_id = -1;
static gint hf_lbmsrs_rir_context_instance = -1;
static gint hf_lbmsrs_rir_context_type = -1;
static gint hf_lbmsrs_rir_version = -1;
static gint hf_lbmsrs_rir_version_flags = -1;
static gint hf_lbmsrs_rir_reserved = -1;

/*handles for receiver delete*/
static gint hf_lbmsrs_rdr = -1;
static gint hf_lbmsrs_rdr_topic_len = -1;
static gint hf_lbmsrs_rdr_topic = -1;
static gint hf_lbmsrs_rdr_domain_id = -1;
static gint hf_lbmsrs_rdr_context_instance = -1;
static gint hf_lbmsrs_rdr_context_type = -1;
static gint hf_lbmsrs_rdr_version = -1;
static gint hf_lbmsrs_rdr_version_flags = -1;
static gint hf_lbmsrs_rdr_reserved = -1;

/*handles for receiver end*/
static gint hf_lbmsrs_rer = -1;
static gint hf_lbmsrs_rer_topic_len = -1;
static gint hf_lbmsrs_rer_topic = -1;
static gint hf_lbmsrs_rer_domain_id = -1;
static gint hf_lbmsrs_rer_context_instance = -1;
static gint hf_lbmsrs_rer_context_type = -1;
static gint hf_lbmsrs_rer_version = -1;
static gint hf_lbmsrs_rer_version_flags = -1;
static gint hf_lbmsrs_rer_reserved = -1;

/*handles for wildcard receiver info*/
static gint hf_lbmsrs_wir = -1;
static gint hf_lbmsrs_wir_pattern_len = -1;
static gint hf_lbmsrs_wir_pattern = -1;
static gint hf_lbmsrs_wir_domain_id = -1;
static gint hf_lbmsrs_wir_context_instance = -1;
static gint hf_lbmsrs_wir_context_type = -1;
static gint hf_lbmsrs_wir_version = -1;
static gint hf_lbmsrs_wir_version_flags = -1;
static gint hf_lbmsrs_wir_reserved = -1;

/*handles for wildcard receiver delete*/
static gint hf_lbmsrs_wdr = -1;
static gint hf_lbmsrs_wdr_pattern_len = -1;
static gint hf_lbmsrs_wdr_pattern = -1;
static gint hf_lbmsrs_wdr_domain_id = -1;
static gint hf_lbmsrs_wdr_context_instance = -1;
static gint hf_lbmsrs_wdr_context_type = -1;
static gint hf_lbmsrs_wdr_version = -1;
static gint hf_lbmsrs_wdr_version_flags = -1;
static gint hf_lbmsrs_wdr_reserved = -1;

/*handles for wildcard receiver end*/
static gint hf_lbmsrs_wer = -1;
static gint hf_lbmsrs_wer_pattern_len = -1;
static gint hf_lbmsrs_wer_pattern = -1;
static gint hf_lbmsrs_wer_domain_id = -1;
static gint hf_lbmsrs_wer_context_instance = -1;
static gint hf_lbmsrs_wer_context_type = -1;
static gint hf_lbmsrs_wer_version = -1;
static gint hf_lbmsrs_wer_version_flags = -1;
static gint hf_lbmsrs_wer_reserved = -1;

/*handles for src leave info*/
static gint hf_lbmsrs_sli = -1;
static gint hf_lbmsrs_sli_otid = -1;
static gint hf_lbmsrs_sli_topic_len = -1;
static gint hf_lbmsrs_sli_topic = -1;
static gint hf_lbmsrs_sli_source_len = -1;
static gint hf_lbmsrs_sli_source = -1;
static gint hf_lbmsrs_sli_context_instance = -1;
static gint hf_lbmsrs_sli_context_type = -1;
static gint hf_lbmsrs_sli_version = -1;
static gint hf_lbmsrs_sli_version_flags = -1;
static gint hf_lbmsrs_sli_reserved = -1;


/*rsocket dissector field handles*/
static gint hf_lbmsrs_rsocket_frame_len = -1;
static gint hf_lbmsrs_rsocket_stream_id = -1;
static gint hf_lbmsrs_rsocket_frame_type = -1;
static gint hf_lbmsrs_rsocket_mdata_len = -1;
static gint hf_lbmsrs_rsocket_mdata = -1;
static gint hf_lbmsrs_rsocket_major_version = -1;
static gint hf_lbmsrs_rsocket_minor_version = -1;
static gint hf_lbmsrs_rsocket_keepalive_interval = -1;
static gint hf_lbmsrs_rsocket_max_lifetime = -1;
static gint hf_lbmsrs_rsocket_mdata_mime_length = -1;
static gint hf_lbmsrs_rsocket_mdata_mime_type = -1;
static gint hf_lbmsrs_rsocket_data_mime_length = -1;
static gint hf_lbmsrs_rsocket_data_mime_type = -1;
static gint hf_lbmsrs_rsocket_req_n = -1;
static gint hf_lbmsrs_rsocket_error_code = -1;
static gint hf_lbmsrs_rsocket_keepalive_last_rcvd_pos = -1;
static gint hf_lbmsrs_rsocket_resume_token_len = -1;
static gint hf_lbmsrs_rsocket_resume_token = -1;

// other flags
static gint hf_lbmsrs_rsocket_ignore_flag = -1;
static gint hf_lbmsrs_rsocket_metadata_flag = -1;
static gint hf_lbmsrs_rsocket_resume_flag = -1;
static gint hf_lbmsrs_rsocket_lease_flag = -1;
static gint hf_lbmsrs_rsocket_follows_flag = -1;
static gint hf_lbmsrs_rsocket_complete_flag = -1;
static gint hf_lbmsrs_rsocket_next_flag = -1;
static gint hf_lbmsrs_rsocket_respond_flag = -1;

/*dissector tree handles*/
static gint ett_lbmsrs = -1;
static gint ett_lbmsrs_data = -1;
static gint ett_lbmsrs_details = -1;
static gint ett_lbmsrs_sir = -1;
static gint ett_lbmsrs_sdr = -1;
static gint ett_lbmsrs_ser = -1;
static gint ett_lbmsrs_rir = -1;
static gint ett_lbmsrs_rdr = -1;
static gint ett_lbmsrs_rer = -1;
static gint ett_lbmsrs_wir = -1;
static gint ett_lbmsrs_wdr = -1;
static gint ett_lbmsrs_wer = -1;
static gint ett_lbmsrs_sli = -1;

static gint ett_lbmsrs_rsocket_frame = -1;

/*Expert analysis fields*/
static expert_field ei_lbmsrs_analysis_invalid_msg_id = EI_INIT;

/* Dissector handle */
static dissector_handle_t lbmsrs_dissector_handle;

static const guint rsocket_frame_len_field_size = 3;
static const guint rsocket_stream_id_field_size = 4;

/* SRS default definitions*/
#define LBMSRS_DEFAULT_SOURCE_PORT 0
#define LBMSRS_DEFAULT_SOURCE_IP "127.0.0.1"

static guint32 lbmsrs_source_ip_address;
static const char* global_lbmsrs_source_ip_address = LBMSRS_DEFAULT_SOURCE_IP;
static guint32 global_lbmsrs_source_port = LBMSRS_DEFAULT_SOURCE_PORT;
static gboolean global_lbmsrs_use_tag = FALSE;
static guint32 lbmsrs_source_port = LBMSRS_DEFAULT_SOURCE_PORT;
static gboolean lbmsrs_use_tag = FALSE;


#define RSOCKET_FRAME_RESERVED 0x00
#define RSOCKET_FRAME_SETUP 0x01
#define RSOCKET_FRAME_LEASE 0x02
#define RSOCKET_FRAME_KEEPALIVE 0x03
#define RSOCKET_FRAME_REQUEST_RESPONSE 0x04
#define RSOCKET_FRAME_REQUEST_FNF 0x05
#define RSOCKET_FRAME_REQUEST_STREAM 0x06
#define RSOCKET_FRAME_REQUEST_CHANNEL 0x07
#define RSOCKET_FRAME_REQUEST_N 0x08
#define RSOCKET_FRAME_CANCEL 0x09
#define RSOCKET_FRAME_PAYLOAD 0x0A
#define RSOCKET_FRAME_ERROR 0x0B
#define RSOCKET_FRAME_METADATA_PUSH 0x0C
#define RSOCKET_FRAME_RESUME 0x0D
#define RSOCKET_FRAME_RESUME_OK 0x0E
#define RSOCKET_FRAME_EXT 0x3F

#define RSOCKET_FRAME_SETUP_MIN_SIZE 14
#define RSOCKET_FRAME_KEEPALIVE_SIZE 10
#define RSOCKET_FRAME_REQUEST_RESPONSE_SIZE 2
#define RSOCKET_FRAME_REQUEST_FNF_SIZE 2
#define RSOCKET_FRAME_REQUEST_STREAM_SIZE 6
#define RSOCKET_FRAME_REQUEST_CHANNEL_SIZE 6
#define RSOCKET_FRAME_REQUEST_N_SIZE 6
#define RSOCKET_FRAME_CANCEL_SIZE 2
#define RSOCKET_FRAME_PAYLOAD_SIZE 2

static const value_string rSocketFrameTypeNames[] = {
    { RSOCKET_FRAME_RESERVED, "RESERVED" },
    { RSOCKET_FRAME_SETUP, "SETUP" },
    { RSOCKET_FRAME_LEASE, "LEASE" },
    { RSOCKET_FRAME_KEEPALIVE, "KEEPALIVE" },
    { RSOCKET_FRAME_REQUEST_RESPONSE, "REQUEST_RESPONSE" },
    { RSOCKET_FRAME_REQUEST_FNF, "REQUEST_FNF" },
    { RSOCKET_FRAME_REQUEST_STREAM, "REQUEST_STREAM" },
    { RSOCKET_FRAME_REQUEST_CHANNEL, "REQUEST_CHANNEL" },
    { RSOCKET_FRAME_REQUEST_N, "REQUEST_N" },
    { RSOCKET_FRAME_CANCEL, "CANCEL" },
    { RSOCKET_FRAME_PAYLOAD, "PAYLOAD" },
    { RSOCKET_FRAME_ERROR, "ERROR" },
    { RSOCKET_FRAME_METADATA_PUSH, "METADATA_PUSH" },
    { RSOCKET_FRAME_RESUME, "RESUME" },
    { RSOCKET_FRAME_RESUME_OK, "RESUME_OK" },
    { RSOCKET_FRAME_EXT, "EXT" },
    { 0,NULL} };


static const value_string rSocketErrorCodeNames[] =
{
    { 0x00000000, "RESERVED" },
    { 0x00000001, "INVALID_SETUP" },
    { 0x00000002, "UNSUPPORTED_SETUP" },
    { 0x00000003, "REJECTED_SETUP" },
    { 0x00000004, "REJECTED_RESUME" },
    { 0x00000101, "CONNECTION_ERROR" },
    { 0x00000102, "CONNECTION_CLOSE" },
    { 0x00000201, "APPLICATION_ERROR" },
    { 0x00000202, "REJECTED" },
    { 0x00000203, "CANCELED" },
    { 0x00000204, "INVALID" },
    { 0xFFFFFFFF, "REJECTED" },
    { 0,NULL}
};

/*----------------------------------------------------------------------------*/
/* UAT callback functions.                                                    */
/*----------------------------------------------------------------------------*/
static gboolean lbmsrs_tag_update_cb(void * record, char * * error_string)
{
    lbmsrs_tag_entry_t * tag = (lbmsrs_tag_entry_t *)record;

    if (tag->name == NULL)
    {
        *error_string = g_strdup("Tag name can't be empty");
        return FALSE;
    }
    else
    {
        g_strstrip(tag->name);
        if (tag->name[0] == 0)
        {
            *error_string = g_strdup("Tag name can't be empty");
            return FALSE;
        }
    }
    return TRUE;
}

static void * lbmsrs_tag_copy_cb(void * destination, const void * source, size_t length _U_)
{
    const lbmsrs_tag_entry_t * src = (const lbmsrs_tag_entry_t *)source;
    lbmsrs_tag_entry_t * dest = (lbmsrs_tag_entry_t *)destination;

    dest->name = g_strdup(src->name);
    dest->ip_address = g_strdup(src->ip_address);
    dest->ip_address_val_h = src->ip_address_val_h;
    dest->tcp_port = src->tcp_port;
    return (dest);
}

static void lbmsrs_tag_free_cb(void * record)
{
    lbmsrs_tag_entry_t * tag = (lbmsrs_tag_entry_t *)record;

    if (tag->name != NULL)
    {
        g_free(tag->name);
        tag->name = NULL;
    }

    if (tag->ip_address != NULL)
    {
        g_free(tag->ip_address);
        tag->ip_address = NULL;
    }
}

/*Tag helper functions*/
static gboolean lbmsrs_match_packet(packet_info * pinfo, const lbmsrs_tag_entry_t * entry)
{
    if ((pinfo->dst.type != AT_IPv4) || (pinfo->dst.len != 4) ||
        (pinfo->src.type != AT_IPv4) || (pinfo->src.len != 4))
        return (FALSE);

    guint32 dest_addr_h = pntoh32(pinfo->dst.data);
    guint32 src_addr_h = pntoh32(pinfo->src.data);

    guint32 ip_address_val_h = 0;
    if (NULL != entry->ip_address)
    {
        ip_address_val_h = entry->ip_address_val_h;
    }

    /*if only port number is specified*/
    if ((entry->tcp_port > 0) && (ip_address_val_h == 0))
    {
        if ((entry->tcp_port == pinfo->destport) || (entry->tcp_port == pinfo->srcport))
        {
            return (TRUE);
        }
    }
    /*if only IP is specified*/
    else if ((entry->tcp_port == 0) && (ip_address_val_h > 0))
    {
        if ((ip_address_val_h == dest_addr_h) || (ip_address_val_h == src_addr_h))
        {
            return (TRUE);
        }
    }
    /*if both IP and port is specified*/
    else
    {
        if (((ip_address_val_h == dest_addr_h) && (entry->tcp_port == pinfo->destport))
            || ((ip_address_val_h == src_addr_h) && (entry->tcp_port == pinfo->srcport)))
        {
            return (TRUE);
        }
    }

    return (FALSE);
}

static char * lbmsrs_tag_find(packet_info * pinfo)
{
    guint idx;
    lbmsrs_tag_entry_t * tag = NULL;

    if (!lbmsrs_use_tag)
    {
        return (NULL);
    }
    for (idx = 0; idx < lbmsrs_tag_count; ++idx)
    {
        tag = &(lbmsrs_tag_entry[idx]);
        if (lbmsrs_match_packet(pinfo, tag))
        {
            return tag->name;
        }
    }
    return (NULL);
}

/*Utility functions*/
static const gchar *getFrameTypeName(const guint64 frame_type) {
    for (size_t i = 0; i < sizeof(rSocketFrameTypeNames) / sizeof(value_string);
        i++) {
        if (rSocketFrameTypeNames[i].value == frame_type) {
            return rSocketFrameTypeNames[i].strptr;
        }
    }
    return NULL;
}

static gboolean check_lbmsrs_packet(tvbuff_t *tvb, guint offset)
{
    /*check if valid rsocket packet*/
    guint start_offset = offset;
    offset += rsocket_frame_len_field_size;

    /*check the length*/
    /*rsocket data maybe split accross multiple packets*/
    guint32 tvb_length = tvb_captured_length(tvb);

    if (tvb_length < (offset - start_offset + rsocket_stream_id_field_size))
    {
        return FALSE;
    }

    /*get the stream-id*/
    guint32 rsocket_stream_id = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);

    /*move the offset past the stream id field*/
    offset += rsocket_stream_id_field_size;

    if (tvb_length < (offset - start_offset + 1))
    {
        return FALSE;
    }

    /*get the rsocket frame type*/
    guint64 rsocket_frame_type = tvb_get_bits64(tvb, offset * 8, 6, ENC_BIG_ENDIAN);

    /*read the rsocket metadata flag*/
    guint8 rsocket_metadata_flag = tvb_get_bits8(tvb, (offset * 8) + 6, 2);

    /*check if valid rsocket frame type*/
    /*update the offset according to the frame type*/
    switch (rsocket_frame_type)
    {
    case RSOCKET_FRAME_SETUP:
    case RSOCKET_FRAME_KEEPALIVE:
    case RSOCKET_FRAME_METADATA_PUSH:
    case RSOCKET_FRAME_RESUME:
    case RSOCKET_FRAME_RESUME_OK:
    {
        /*for these frame types stream id must be 0 */
        if (rsocket_stream_id != 0)
        {
            return FALSE;
        }

        return TRUE;
    }
    case RSOCKET_FRAME_EXT:
    {
        return TRUE;
    }

    case RSOCKET_FRAME_REQUEST_RESPONSE:
    case RSOCKET_FRAME_REQUEST_FNF:
    case RSOCKET_FRAME_CANCEL:
    case RSOCKET_FRAME_PAYLOAD:
    {
        offset += 2;
        break;
    }

    case RSOCKET_FRAME_REQUEST_STREAM:
    case RSOCKET_FRAME_REQUEST_CHANNEL:
    case RSOCKET_FRAME_REQUEST_N:
    case RSOCKET_FRAME_ERROR:
    {
        offset += 6;
        break;
    }

    default:
        return FALSE;
    }

    /*if rsocket metadata is available get the metadata length*/
    if (rsocket_metadata_flag)
    {
        if (tvb_length < (offset - start_offset + 3))
        {
            return FALSE;
        }

        /*add the rsocket metadata length field*/
        guint32 rsocket_metadata_len = tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN);;
        offset += 3;
        /*move the offset by the metadata length*/
        offset += rsocket_metadata_len;
        if (tvb_length < (offset - start_offset + 6))
        {
            return FALSE;
        }
    }


    /*check the SRS message id*/

    guint32 rsocket_payload_len = tvb_length - offset;
    /*if payload is available start processing for SRS*/
    if (rsocket_payload_len > 2)
    {
        guint16 message_id = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
        switch (message_id)
        {
        case MSG_ID_REGISTRATION_REQUEST:
        case MSG_ID_REGISTRATION_RESPONSE:
        case MSG_ID_STREAM_REQUEST:
        case MSG_ID_SOURCE_INFO:
        case MSG_ID_SOURCE_DELETE:
        case MSG_ID_RCV_INFO:
        case MSG_ID_RCV_DELETE:
        case MSG_ID_RCV_END:
        case MSG_ID_WRCV_INFO:
        case MSG_ID_WRCV_DELETE:
        case MSG_ID_WRCV_END:
        case MSG_ID_SRC_LEAVE:
        {
            return TRUE;
        }

        default:
            return FALSE;

        }
    }

    return FALSE;
}



static guint get_rsocket_frame_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    /*get the rsocket frame length (3-byte long field)*/
    /*offset argument points to the begining of the Rsocket PDU*/
    guint32 rsocket_frame_len = tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN);

    /*return total RSocket PDU size*/
    return (rsocket_frame_len + rsocket_frame_len_field_size);
}

/*----------------Main Dissection Functions----------------------*/
/*Rsocket dissector function*/
static guint dissect_rsocket_frame(guint64 rsocket_frame_type,proto_tree* rsocket_frame_tree, tvbuff_t * tvb,guint offset, gboolean *can_dissect_further)
{
    guint total_payload_len = tvb_captured_length(tvb);
    guint remaining_payload_len = total_payload_len - offset;
    guint start_offset = offset;

    switch (rsocket_frame_type)
    {
        case RSOCKET_FRAME_SETUP:/*SETUP Frame*/
        {

            if (remaining_payload_len < RSOCKET_FRAME_SETUP_MIN_SIZE)
            {
                *can_dissect_further = FALSE;
                break;
            }

            gint8 resume_flag = tvb_get_bits8(tvb, (offset + 1) * 8, 1);
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_resume_flag, tvb, offset, 2,ENC_BIG_ENDIAN);
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_lease_flag, tvb, offset, 2,ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_major_version, tvb, offset, 2,ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_minor_version, tvb, offset, 2,ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_keepalive_interval, tvb, offset, 4,ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_max_lifetime, tvb, offset, 4,ENC_BIG_ENDIAN);
            offset += 4;
            if (resume_flag) {
                if ((total_payload_len - offset) < 2)
                {
                    *can_dissect_further = FALSE;
                    break;
                }
                guint resume_token_len;
                proto_tree_add_item_ret_uint(rsocket_frame_tree, hf_lbmsrs_rsocket_resume_token_len, tvb, offset,2, ENC_BIG_ENDIAN, &resume_token_len);
                offset += 2;

                if ((total_payload_len - offset) < resume_token_len)
                {
                    *can_dissect_further = FALSE;
                    break;
                }
                proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_resume_token, tvb, offset,resume_token_len, ENC_STRING);
                offset += resume_token_len;
            }

            if ((total_payload_len - offset) < 1)
            {
                *can_dissect_further = FALSE;
                break;
            }

            guint mdata_mime_length;
            proto_tree_add_item_ret_uint(rsocket_frame_tree, hf_lbmsrs_rsocket_mdata_mime_length, tvb, offset,1, ENC_BIG_ENDIAN, &mdata_mime_length);
            offset += 1;

            if ((total_payload_len - offset) < mdata_mime_length)
            {
                *can_dissect_further = FALSE;
                break;
            }

            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_mdata_mime_type, tvb, offset,mdata_mime_length, ENC_ASCII | ENC_NA);
            offset += mdata_mime_length;

            if ((total_payload_len - offset) < 1)
            {
                *can_dissect_further = FALSE;
                break;
            }
            guint data_mime_length;
            proto_tree_add_item_ret_uint(rsocket_frame_tree, hf_lbmsrs_rsocket_data_mime_length, tvb, offset,1, ENC_BIG_ENDIAN, &data_mime_length);
            offset += 1;

            if ((total_payload_len - offset) < data_mime_length)
            {
                *can_dissect_further = FALSE;
                break;
            }

            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_data_mime_type, tvb, offset,data_mime_length, ENC_ASCII | ENC_NA);
            offset += data_mime_length;
            break;
        }

        case RSOCKET_FRAME_KEEPALIVE:/*KEEPALIVE FRAME*/
        {

            if (remaining_payload_len < RSOCKET_FRAME_KEEPALIVE_SIZE)
            {
                *can_dissect_further = FALSE;
                break;
            }

            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_respond_flag, tvb, offset, 2,ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_keepalive_last_rcvd_pos, tvb, offset, 8,ENC_BIG_ENDIAN);
            offset += 8;

            break;
        }

        case RSOCKET_FRAME_REQUEST_RESPONSE:/*REQUEST_RESPONSE FRAME*/
        {

            if (remaining_payload_len < RSOCKET_FRAME_REQUEST_RESPONSE_SIZE)
            {
                *can_dissect_further = FALSE;
                break;
            }
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_follows_flag, tvb, offset, 2,ENC_BIG_ENDIAN);
            offset += 2;

            break;
        }

        case RSOCKET_FRAME_REQUEST_FNF:/*FNF FRAME*/
        {
            if (remaining_payload_len < RSOCKET_FRAME_REQUEST_FNF_SIZE)
            {
                *can_dissect_further = FALSE;
                break;
            }
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_follows_flag, tvb, offset, 2,ENC_BIG_ENDIAN);
            offset += 2;
            break;
        }

        case RSOCKET_FRAME_REQUEST_STREAM:/*REQ_STREAM FRAME*/
        {
            if (remaining_payload_len < RSOCKET_FRAME_REQUEST_STREAM_SIZE)
            {
                *can_dissect_further = FALSE;
                break;
            }
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_follows_flag, tvb, offset, 2,ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_req_n, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        }

        case RSOCKET_FRAME_REQUEST_CHANNEL:/*REQ_CHANNEL FRAME*/
        {
            if (remaining_payload_len < RSOCKET_FRAME_REQUEST_CHANNEL_SIZE)
            {
                *can_dissect_further = FALSE;
                break;
            }
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_follows_flag, tvb, offset, 2,ENC_BIG_ENDIAN);
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_complete_flag, tvb, offset, 2,ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_req_n, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        }

        case RSOCKET_FRAME_REQUEST_N:/*REQ_N FRAME*/
        {
            if (remaining_payload_len < RSOCKET_FRAME_REQUEST_N_SIZE)
            {
                *can_dissect_further = FALSE;
                break;
            }
            offset += 2;
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_req_n, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        }

        case RSOCKET_FRAME_CANCEL:/*CANCEL FRAME*/
        {
            if (remaining_payload_len < RSOCKET_FRAME_CANCEL_SIZE)
            {
                *can_dissect_further = FALSE;
                break;
            }
            offset += 2;
            break;
        }

        case RSOCKET_FRAME_PAYLOAD:/*PAYLOAD FRAME*/
        {
            if (remaining_payload_len < RSOCKET_FRAME_PAYLOAD_SIZE)
            {
                *can_dissect_further = FALSE;
                break;
            }
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_follows_flag, tvb, offset, 2,ENC_BIG_ENDIAN);
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_complete_flag, tvb, offset, 2,ENC_BIG_ENDIAN);
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_next_flag, tvb, offset, 2,ENC_BIG_ENDIAN);

            offset += 2;
            break;
        }

        case RSOCKET_FRAME_ERROR:
        {
            if (remaining_payload_len < 6)
            {
                *can_dissect_further = FALSE;
                break;
            }
            offset += 2;
            proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_error_code, tvb, offset, 4,ENC_BIG_ENDIAN);
            offset += 4;
            break;
        }

        default:
        {
            *can_dissect_further = FALSE;
        }

    }

    return (offset - start_offset);

}

static guint dissect_lbmsrs_sir_ser(tvbuff_t * tvb, proto_tree * tree, guint offset, guint *cnt_sir, guint *cnt_ser, gboolean *can_dissect_further)
{
    guint total_payload_len = tvb_captured_length(tvb);
    guint start_offset = offset;

    /*first filed is OTID, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_OTID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return 0;
    }

    proto_item *batch_item = NULL;

    batch_item = proto_tree_add_none_format(tree, hf_lbmsrs_sir, tvb, offset, -1, "SIR");
    proto_tree *sir_tree = proto_item_add_subtree(batch_item, ett_lbmsrs_sir);

    proto_tree_add_item(sir_tree, hf_lbmsrs_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_otid, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_OTID, ENC_NA);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_OTID;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_TOPIC_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    guint8 topic_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_topic_len, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_TOPIC_LEN, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_TOPIC_LEN;

    if ((total_payload_len - offset) < topic_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    gint len;
    char* name = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_topic, tvb, offset, topic_len, ENC_ASCII | ENC_NA);
    offset += topic_len;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_SOURCE_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    guint8 source_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_source_len, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_SOURCE_LEN, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_SOURCE_LEN;

    if ((total_payload_len - offset) < source_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }

    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_source, tvb, offset, source_len, ENC_ASCII | ENC_NA);
    offset += source_len;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_HOST_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_host_id, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_HOST_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_HOST_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_TOPIC_IDX)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_topic_idx, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_TOPIC_IDX, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_TOPIC_IDX;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_FUNCTIONALITY_FLAGS)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_functionality_flags, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_FUNCTIONALITY_FLAGS, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_FUNCTIONALITY_FLAGS;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_REQUEST_IP)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_request_ip, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_REQUEST_IP, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_REQUEST_IP;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_REQUEST_PORT)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_request_port, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_REQUEST_PORT, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_REQUEST_PORT;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_DOMAIN_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_domain_id, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_DOMAIN_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_ENCRYPTION)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_encryption, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_ENCRYPTION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_ENCRYPTION;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_COMPRESSION)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_compression, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_COMPRESSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_COMPRESSION;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_ULB_SRC_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_ulb_src_id, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_ULB_SRC_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_ULB_SRC_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_ULB_QUEUE_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_ulb_queue_id, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_ULB_QUEUE_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_ULB_QUEUE_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_ULB_REG_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_ulb_reg_id, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_ULB_REG_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_ULB_REG_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_CONTEXT_INSTANCE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_context_instance, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_CONTEXT_INSTANCE, ENC_NA);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_CONTEXT_INSTANCE;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_CONTEXT_TYPE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_context_type, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_CONTEXT_TYPE, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_CONTEXT_TYPE;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_VERSION)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_version, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_VERSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_VERSION;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_VERSION_FLAGS)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_version_flags, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_VERSION_FLAGS, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_VERSION_FLAGS;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_TTL)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sir_tree, hf_lbmsrs_sir_ttl, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_TTL, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_TTL;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_COST)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    gint32 cost;
    proto_tree_add_item_ret_int(sir_tree, hf_lbmsrs_sir_cost, tvb, offset, L_LBM_SRS_SRC_INFO_INFO_T_COST, ENC_BIG_ENDIAN, &cost);
    offset += L_LBM_SRS_SRC_INFO_INFO_T_COST;

    if (-1 == cost)
    {
        proto_item_set_text(batch_item, "SER:Topic:%s", name);
        (*cnt_ser)++;
    }
    else
    {
        proto_item_set_text(batch_item, "SIR:Topic:%s", name);
        (*cnt_sir)++;
    }


    proto_item_set_len(batch_item, (offset - start_offset));
    return (offset - start_offset);
}

static guint dissect_lbmsrs_sdr(tvbuff_t * tvb, proto_tree * tree, guint offset, guint *cnt_sdr,gboolean *can_dissect_further)
{
    guint total_payload_len = tvb_captured_length(tvb);
    guint start_offset = offset;

    /*first filed is OTID, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_OTID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return 0;
    }

    /*add a sub-tree for SDR */
    proto_item * batch_item = proto_tree_add_none_format(tree, hf_lbmsrs_sdr, tvb, offset, -1, "SDR");
    proto_tree *sdr_tree = proto_item_add_subtree(batch_item, ett_lbmsrs_sdr);

    proto_tree_add_item(sdr_tree, hf_lbmsrs_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*first filed is OTID, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_SRC_INFO_INFO_T_OTID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }

    proto_tree_add_item(sdr_tree, hf_lbmsrs_sdr_otid, tvb, offset, L_LBM_SRS_SRC_DELETE_INFO_T_OTID, ENC_NA);
    offset += L_LBM_SRS_SRC_DELETE_INFO_T_OTID;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_DELETE_INFO_T_TOPIC_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    guint8 topic_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(sdr_tree, hf_lbmsrs_sdr_topic_len, tvb, offset, L_LBM_SRS_SRC_DELETE_INFO_T_TOPIC_LEN, ENC_BIG_ENDIAN);

    offset += L_LBM_SRS_SRC_DELETE_INFO_T_TOPIC_LEN;

    if ((total_payload_len - offset) < topic_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    gint len;
    char* name = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
    proto_tree_add_item(sdr_tree, hf_lbmsrs_sdr_topic, tvb, offset, topic_len, ENC_ASCII | ENC_NA);
    offset += topic_len;

    proto_item_set_text(batch_item, "SDR:Topic:%s", name);
    (*cnt_sdr)++;

    proto_item_set_len(batch_item, (offset - start_offset));
    return (offset - start_offset);

}

static guint dissect_lbmsrs_rir(tvbuff_t * tvb, proto_tree * tree, guint offset, guint *cnt_rir, gboolean *can_dissect_further)
{
    guint total_payload_len = tvb_captured_length(tvb);
    guint start_offset = offset;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_RCV_INFO_INFO_T_TOPIC_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return 0;
    }

    /*add a sub-tree for RIR */
    proto_item * batch_item = proto_tree_add_none_format(tree, hf_lbmsrs_rir, tvb, offset, -1, "RIR");
    proto_tree *rir_tree = proto_item_add_subtree(batch_item, ett_lbmsrs_rir);

    proto_tree_add_item(rir_tree, hf_lbmsrs_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_RCV_INFO_INFO_T_TOPIC_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }

    guint8 topic_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(rir_tree, hf_lbmsrs_rir_topic_len, tvb, offset, L_LBM_SRS_RCV_INFO_INFO_T_TOPIC_LEN, ENC_BIG_ENDIAN);

    offset += L_LBM_SRS_RCV_INFO_INFO_T_TOPIC_LEN;

    if ((total_payload_len - offset) < topic_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    gint len;
    char* name = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
    proto_tree_add_item(rir_tree, hf_lbmsrs_rir_topic, tvb, offset, topic_len, ENC_ASCII | ENC_NA);
    offset += topic_len;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_INFO_INFO_T_DOMAIN_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rir_tree, hf_lbmsrs_rir_domain_id, tvb, offset, L_LBM_SRS_RCV_INFO_INFO_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_INFO_INFO_T_DOMAIN_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_INFO_INFO_T_CONTEXT_INSTANCE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rir_tree, hf_lbmsrs_rir_context_instance, tvb, offset, L_LBM_SRS_RCV_INFO_INFO_T_CONTEXT_INSTANCE, ENC_NA);
    offset += L_LBM_SRS_RCV_INFO_INFO_T_CONTEXT_INSTANCE;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_INFO_INFO_T_CONTEXT_TYPE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rir_tree, hf_lbmsrs_rir_context_type, tvb, offset, L_LBM_SRS_RCV_INFO_INFO_T_CONTEXT_TYPE, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_INFO_INFO_T_CONTEXT_TYPE;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_INFO_INFO_T_VERSION)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rir_tree, hf_lbmsrs_rir_version, tvb, offset, L_LBM_SRS_RCV_INFO_INFO_T_VERSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_INFO_INFO_T_VERSION;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_INFO_INFO_T_VERSION_FLAGS)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rir_tree, hf_lbmsrs_rir_version_flags, tvb, offset, L_LBM_SRS_RCV_INFO_INFO_T_VERSION_FLAGS, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_INFO_INFO_T_VERSION_FLAGS;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_INFO_INFO_T_RESERVED)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rir_tree, hf_lbmsrs_rir_reserved, tvb, offset, L_LBM_SRS_RCV_INFO_INFO_T_RESERVED, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_INFO_INFO_T_RESERVED;

    proto_item_set_text(batch_item, "RIR:Topic:%s", name);
    (*cnt_rir)++;

    proto_item_set_len(batch_item, (offset - start_offset));
    return (offset - start_offset);

}

static guint dissect_lbmsrs_rer(tvbuff_t * tvb, proto_tree * tree, guint offset, guint *cnt_rer, gboolean *can_dissect_further)
{
    guint total_payload_len = tvb_captured_length(tvb);
    guint start_offset = offset;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_RCV_END_INFO_T_TOPIC_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return 0;
    }

    /*add a sub-tree for RIR */
    proto_item * batch_item = proto_tree_add_none_format(tree, hf_lbmsrs_rer, tvb, offset, -1, "RER");
    proto_tree *rer_tree = proto_item_add_subtree(batch_item, ett_lbmsrs_rer);

    proto_tree_add_item(rer_tree, hf_lbmsrs_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_RCV_END_INFO_T_TOPIC_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }

    guint8 topic_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(rer_tree, hf_lbmsrs_rer_topic_len, tvb, offset, L_LBM_SRS_RCV_END_INFO_T_TOPIC_LEN, ENC_BIG_ENDIAN);

    offset += L_LBM_SRS_RCV_END_INFO_T_TOPIC_LEN;

    if ((total_payload_len - offset) < topic_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    gint len;
    char* name = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
    proto_tree_add_item(rer_tree, hf_lbmsrs_rer_topic, tvb, offset, topic_len, ENC_ASCII | ENC_NA);
    offset += topic_len;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_END_INFO_T_DOMAIN_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rer_tree, hf_lbmsrs_rer_domain_id, tvb, offset, L_LBM_SRS_RCV_END_INFO_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_END_INFO_T_DOMAIN_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_END_INFO_T_CONTEXT_INSTANCE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rer_tree, hf_lbmsrs_rer_context_instance, tvb, offset, L_LBM_SRS_RCV_END_INFO_T_CONTEXT_INSTANCE, ENC_NA);
    offset += L_LBM_SRS_RCV_END_INFO_T_CONTEXT_INSTANCE;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_END_INFO_T_CONTEXT_TYPE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rer_tree, hf_lbmsrs_rer_context_type, tvb, offset, L_LBM_SRS_RCV_END_INFO_T_CONTEXT_TYPE, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_END_INFO_T_CONTEXT_TYPE;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_END_INFO_T_VERSION)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rer_tree, hf_lbmsrs_rer_version, tvb, offset, L_LBM_SRS_RCV_END_INFO_T_VERSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_END_INFO_T_VERSION;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_END_INFO_T_VERSION_FLAGS)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rer_tree, hf_lbmsrs_rer_version_flags, tvb, offset, L_LBM_SRS_RCV_END_INFO_T_VERSION_FLAGS, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_END_INFO_T_VERSION_FLAGS;


    if ((total_payload_len - offset) < L_LBM_SRS_RCV_END_INFO_T_RESERVED)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rer_tree, hf_lbmsrs_rer_reserved, tvb, offset, L_LBM_SRS_RCV_END_INFO_T_RESERVED, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_END_INFO_T_RESERVED;

    proto_item_set_text(batch_item, "RER:Topic:%s", name);
    (*cnt_rer)++;

    proto_item_set_len(batch_item, (offset - start_offset));
    return (offset - start_offset);

}

static guint dissect_lbmsrs_rdr(tvbuff_t * tvb, proto_tree * tree, guint offset, guint *cnt_rdr, gboolean *can_dissect_further)
{
    guint total_payload_len = tvb_captured_length(tvb);
    guint start_offset = offset;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_RCV_DELETE_INFO_T_TOPIC_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return 0;
    }

    /*add a sub-tree for RIR */
    proto_item * batch_item = proto_tree_add_none_format(tree, hf_lbmsrs_rdr, tvb, offset, -1, "RDR");
    proto_tree *rdr_tree = proto_item_add_subtree(batch_item, ett_lbmsrs_rdr);

    proto_tree_add_item(rdr_tree, hf_lbmsrs_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_RCV_DELETE_INFO_T_TOPIC_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }

    guint8 topic_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(rdr_tree, hf_lbmsrs_rdr_topic_len, tvb, offset, L_LBM_SRS_RCV_DELETE_INFO_T_TOPIC_LEN, ENC_BIG_ENDIAN);

    offset += L_LBM_SRS_RCV_DELETE_INFO_T_TOPIC_LEN;

    if ((total_payload_len - offset) < topic_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    gint len;
    char* name = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
    proto_tree_add_item(rdr_tree, hf_lbmsrs_rdr_topic, tvb, offset, topic_len, ENC_ASCII | ENC_NA);
    offset += topic_len;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_DELETE_INFO_T_DOMAIN_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rdr_tree, hf_lbmsrs_rdr_domain_id, tvb, offset, L_LBM_SRS_RCV_DELETE_INFO_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_DELETE_INFO_T_DOMAIN_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_DELETE_INFO_T_CONTEXT_INSTANCE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rdr_tree, hf_lbmsrs_rdr_context_instance, tvb, offset, L_LBM_SRS_RCV_DELETE_INFO_T_CONTEXT_INSTANCE, ENC_NA);
    offset += L_LBM_SRS_RCV_DELETE_INFO_T_CONTEXT_INSTANCE;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_DELETE_INFO_T_CONTEXT_TYPE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rdr_tree, hf_lbmsrs_rdr_context_type, tvb, offset, L_LBM_SRS_RCV_DELETE_INFO_T_CONTEXT_TYPE, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_DELETE_INFO_T_CONTEXT_TYPE;


    if ((total_payload_len - offset) < L_LBM_SRS_RCV_DELETE_INFO_T_VERSION)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rdr_tree, hf_lbmsrs_rdr_version, tvb, offset, L_LBM_SRS_RCV_DELETE_INFO_T_VERSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_DELETE_INFO_T_VERSION;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_DELETE_INFO_T_VERSION_FLAGS)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rdr_tree, hf_lbmsrs_rdr_version_flags, tvb, offset, L_LBM_SRS_RCV_DELETE_INFO_T_VERSION_FLAGS, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_INFO_INFO_T_VERSION_FLAGS;

    if ((total_payload_len - offset) < L_LBM_SRS_RCV_DELETE_INFO_T_RESERVED)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(rdr_tree, hf_lbmsrs_rdr_reserved, tvb, offset, L_LBM_SRS_RCV_DELETE_INFO_T_RESERVED, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_RCV_DELETE_INFO_T_RESERVED;

    proto_item_set_text(batch_item, "RDR:Topic:%s", name);
    (*cnt_rdr)++;

    proto_item_set_len(batch_item, (offset - start_offset));
    return (offset - start_offset);

}

static guint dissect_lbmsrs_wir(tvbuff_t * tvb, proto_tree * tree, guint offset, guint *cnt_wir, gboolean *can_dissect_further)
{
    guint total_payload_len = tvb_captured_length(tvb);
    guint start_offset = offset;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_INFO_INFO_T_PATTERN_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return 0;
    }

    /*add a sub-tree for RIR */
    proto_item * batch_item = proto_tree_add_none_format(tree, hf_lbmsrs_wir, tvb, offset, -1, "WIR");
    proto_tree *wir_tree = proto_item_add_subtree(batch_item, ett_lbmsrs_wir);

    proto_tree_add_item(wir_tree, hf_lbmsrs_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_INFO_INFO_T_PATTERN_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }

    guint8 pattern_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(wir_tree, hf_lbmsrs_wir_pattern_len, tvb, offset, L_LBM_SRS_WRCV_INFO_INFO_T_PATTERN_LEN, ENC_BIG_ENDIAN);

    offset += L_LBM_SRS_WRCV_INFO_INFO_T_PATTERN_LEN;

    if ((total_payload_len - offset) < pattern_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    gint len;
    char* name = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
    proto_tree_add_item(wir_tree, hf_lbmsrs_wir_pattern, tvb, offset, pattern_len, ENC_ASCII | ENC_NA);
    offset += pattern_len;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_INFO_INFO_T_DOMAIN_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wir_tree, hf_lbmsrs_wir_domain_id, tvb, offset, L_LBM_SRS_WRCV_INFO_INFO_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_INFO_INFO_T_DOMAIN_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_INFO_INFO_T_CONTEXT_INSTANCE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wir_tree, hf_lbmsrs_wir_context_instance, tvb, offset, L_LBM_SRS_WRCV_INFO_INFO_T_CONTEXT_INSTANCE, ENC_NA);
    offset += L_LBM_SRS_WRCV_INFO_INFO_T_CONTEXT_INSTANCE;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_INFO_INFO_T_CONTEXT_TYPE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wir_tree, hf_lbmsrs_wir_context_type, tvb, offset, L_LBM_SRS_WRCV_INFO_INFO_T_CONTEXT_TYPE, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_INFO_INFO_T_CONTEXT_TYPE;


    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_INFO_INFO_T_VERSION)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wir_tree, hf_lbmsrs_wir_version, tvb, offset, L_LBM_SRS_WRCV_INFO_INFO_T_VERSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_INFO_INFO_T_VERSION;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_INFO_INFO_T_VERSION_FLAGS)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wir_tree, hf_lbmsrs_wir_version_flags, tvb, offset, L_LBM_SRS_WRCV_INFO_INFO_T_VERSION_FLAGS, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_INFO_INFO_T_VERSION_FLAGS;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_INFO_INFO_T_RESERVED)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wir_tree, hf_lbmsrs_wir_reserved, tvb, offset, L_LBM_SRS_WRCV_INFO_INFO_T_RESERVED, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_INFO_INFO_T_RESERVED;

    proto_item_set_text(batch_item, "WIR:Topic:%s", name);
    (*cnt_wir)++;

    proto_item_set_len(batch_item, (offset - start_offset));
    return (offset - start_offset);

}

static guint dissect_lbmsrs_wdr(tvbuff_t * tvb, proto_tree * tree, guint offset, guint *cnt_wdr, gboolean *can_dissect_further)
{
    guint total_payload_len = tvb_captured_length(tvb);
    guint start_offset = offset;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_DELETE_INFO_T_PATTERN_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return 0;
    }

    /*add a sub-tree for RIR */
    proto_item * batch_item = proto_tree_add_none_format(tree, hf_lbmsrs_wdr, tvb, offset, -1, "WDR");
    proto_tree *wdr_tree = proto_item_add_subtree(batch_item, ett_lbmsrs_wdr);

    proto_tree_add_item(wdr_tree, hf_lbmsrs_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_DELETE_INFO_T_PATTERN_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }

    guint8 pattern_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(wdr_tree, hf_lbmsrs_wdr_pattern_len, tvb, offset, L_LBM_SRS_WRCV_DELETE_INFO_T_PATTERN_LEN, ENC_BIG_ENDIAN);

    offset += L_LBM_SRS_WRCV_DELETE_INFO_T_PATTERN_LEN;

    if ((total_payload_len - offset) < pattern_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    gint len;
    char* name = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
    proto_tree_add_item(wdr_tree, hf_lbmsrs_wdr_pattern, tvb, offset, pattern_len, ENC_ASCII | ENC_NA);
    offset += pattern_len;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_DELETE_INFO_T_DOMAIN_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wdr_tree, hf_lbmsrs_wdr_domain_id, tvb, offset, L_LBM_SRS_WRCV_DELETE_INFO_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_DELETE_INFO_T_DOMAIN_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_DELETE_INFO_T_CONTEXT_INSTANCE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wdr_tree, hf_lbmsrs_wdr_context_instance, tvb, offset, L_LBM_SRS_WRCV_DELETE_INFO_T_CONTEXT_INSTANCE, ENC_NA);
    offset += L_LBM_SRS_WRCV_DELETE_INFO_T_CONTEXT_INSTANCE;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_DELETE_INFO_T_CONTEXT_TYPE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wdr_tree, hf_lbmsrs_wdr_context_type, tvb, offset, L_LBM_SRS_WRCV_DELETE_INFO_T_CONTEXT_TYPE, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_DELETE_INFO_T_CONTEXT_TYPE;


    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_DELETE_INFO_T_VERSION)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wdr_tree, hf_lbmsrs_wdr_version, tvb, offset, L_LBM_SRS_WRCV_DELETE_INFO_T_VERSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_DELETE_INFO_T_VERSION;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_DELETE_INFO_T_VERSION_FLAGS)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wdr_tree, hf_lbmsrs_wdr_version_flags, tvb, offset, L_LBM_SRS_WRCV_DELETE_INFO_T_VERSION_FLAGS, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_DELETE_INFO_T_VERSION_FLAGS;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_DELETE_INFO_T_RESERVED)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wdr_tree, hf_lbmsrs_wdr_reserved, tvb, offset, L_LBM_SRS_WRCV_DELETE_INFO_T_RESERVED, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_DELETE_INFO_T_RESERVED;

    proto_item_set_text(batch_item, "WDR:Topic:%s", name);
    (*cnt_wdr)++;

    proto_item_set_len(batch_item, (offset - start_offset));
    return (offset - start_offset);

}

static guint dissect_lbmsrs_wer(tvbuff_t * tvb, proto_tree * tree, guint offset, guint *cnt_wer, gboolean *can_dissect_further)
{
    guint total_payload_len = tvb_captured_length(tvb);
    gint start_offset = offset;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_END_INFO_T_PATTERN_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return 0;
    }

    /*add a sub-tree for WER */
    proto_item * batch_item = proto_tree_add_none_format(tree, hf_lbmsrs_wer, tvb, offset, -1, "WER");
    proto_tree *wer_tree = proto_item_add_subtree(batch_item, ett_lbmsrs_wer);

    proto_tree_add_item(wer_tree, hf_lbmsrs_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*first field is Topic length, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_END_INFO_T_PATTERN_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }

    guint8 pattern_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(wer_tree, hf_lbmsrs_wer_pattern_len, tvb, offset, L_LBM_SRS_WRCV_END_INFO_T_PATTERN_LEN, ENC_BIG_ENDIAN);

    offset += L_LBM_SRS_WRCV_END_INFO_T_PATTERN_LEN;

    if ((total_payload_len - offset) < pattern_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    gint len;
    char* name = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
    proto_tree_add_item(wer_tree, hf_lbmsrs_wer_pattern, tvb, offset, pattern_len, ENC_ASCII | ENC_NA);
    offset += pattern_len;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_END_INFO_T_DOMAIN_ID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wer_tree, hf_lbmsrs_wer_domain_id, tvb, offset, L_LBM_SRS_WRCV_END_INFO_T_DOMAIN_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_END_INFO_T_DOMAIN_ID;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_END_INFO_T_CONTEXT_INSTANCE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wer_tree, hf_lbmsrs_wer_context_instance, tvb, offset, L_LBM_SRS_WRCV_END_INFO_T_CONTEXT_INSTANCE, ENC_NA);
    offset += L_LBM_SRS_WRCV_END_INFO_T_CONTEXT_INSTANCE;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_END_INFO_T_CONTEXT_TYPE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wer_tree, hf_lbmsrs_wer_context_type, tvb, offset, L_LBM_SRS_WRCV_END_INFO_T_CONTEXT_TYPE, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_END_INFO_T_CONTEXT_TYPE;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_END_INFO_T_VERSION)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wer_tree, hf_lbmsrs_wer_version, tvb, offset, L_LBM_SRS_WRCV_END_INFO_T_VERSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_END_INFO_T_VERSION;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_END_INFO_T_VERSION_FLAGS)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wer_tree, hf_lbmsrs_wer_version_flags, tvb, offset, L_LBM_SRS_WRCV_END_INFO_T_VERSION_FLAGS, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_END_INFO_T_VERSION_FLAGS;

    if ((total_payload_len - offset) < L_LBM_SRS_WRCV_END_INFO_T_RESERVED)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(wer_tree, hf_lbmsrs_wer_reserved, tvb, offset, L_LBM_SRS_WRCV_END_INFO_T_RESERVED, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_WRCV_END_INFO_T_RESERVED;

    proto_item_set_text(batch_item, "WER:Topic:%s", name);
    (*cnt_wer)++;

    proto_item_set_len(batch_item, (offset - start_offset));
    return (offset - start_offset);

}

static guint dissect_lbmsrs_sli(tvbuff_t * tvb,  proto_tree * tree, guint offset, guint *cnt_sli, gboolean *can_dissect_further)
{
    guint total_payload_len = tvb_captured_length(tvb);
    guint start_offset = offset;

    /*first filed is OTID, check if that many bytes are left to process*/
    if ((total_payload_len - offset) < L_LBM_SRS_SRC_LEAVE_INFO_T_OTID)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return 0;
    }

    proto_item *batch_item = NULL;

    batch_item = proto_tree_add_none_format(tree, hf_lbmsrs_sli, tvb, offset, -1, "SLI");
    proto_tree *sli_tree = proto_item_add_subtree(batch_item, ett_lbmsrs_sli);

    proto_tree_add_item(sli_tree, hf_lbmsrs_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(sli_tree, hf_lbmsrs_sli_otid, tvb, offset, L_LBM_SRS_SRC_LEAVE_INFO_T_OTID, ENC_NA);
    offset += L_LBM_SRS_SRC_LEAVE_INFO_T_OTID;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_LEAVE_INFO_T_TOPIC_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    guint8 topic_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(sli_tree, hf_lbmsrs_sli_topic_len, tvb, offset, L_LBM_SRS_SRC_LEAVE_INFO_T_TOPIC_LEN, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_LEAVE_INFO_T_TOPIC_LEN;

    if ((total_payload_len - offset) < topic_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    gint len;
    char* name = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
    proto_tree_add_item(sli_tree, hf_lbmsrs_sli_topic, tvb, offset, topic_len, ENC_ASCII | ENC_NA);
    offset += topic_len;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_LEAVE_INFO_T_SOURCE_LEN)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    guint8 source_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(sli_tree, hf_lbmsrs_sli_source_len, tvb, offset, L_LBM_SRS_SRC_LEAVE_INFO_T_SOURCE_LEN, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_LEAVE_INFO_T_SOURCE_LEN;

    if ((total_payload_len - offset) < source_len)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sli_tree, hf_lbmsrs_sli_source, tvb, offset, source_len, ENC_ASCII | ENC_NA);
    offset += source_len;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_LEAVE_INFO_T_CONTEXT_INSTANCE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sli_tree, hf_lbmsrs_sli_context_instance, tvb, offset, L_LBM_SRS_SRC_LEAVE_INFO_T_CONTEXT_INSTANCE, ENC_NA);
    offset += L_LBM_SRS_SRC_LEAVE_INFO_T_CONTEXT_INSTANCE;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_LEAVE_INFO_T_CONTEXT_TYPE)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sli_tree, hf_lbmsrs_sli_context_type, tvb, offset, L_LBM_SRS_SRC_LEAVE_INFO_T_CONTEXT_TYPE, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_LEAVE_INFO_T_CONTEXT_TYPE;


    if ((total_payload_len - offset) < L_LBM_SRS_SRC_LEAVE_INFO_T_VERSION)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sli_tree, hf_lbmsrs_sli_version, tvb, offset, L_LBM_SRS_SRC_LEAVE_INFO_T_VERSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_LEAVE_INFO_T_VERSION;

    if ((total_payload_len - offset) < L_LBM_SRS_SRC_LEAVE_INFO_T_VERSION_FLAGS)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sli_tree, hf_lbmsrs_sli_version_flags, tvb, offset, L_LBM_SRS_SRC_LEAVE_INFO_T_VERSION_FLAGS, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_LEAVE_INFO_T_VERSION_FLAGS;


    if ((total_payload_len - offset) < L_LBM_SRS_SRC_LEAVE_INFO_T_RESERVED)
    {
        /*stop processing in case not available*/
        *can_dissect_further = FALSE;
        return (offset - start_offset);
    }
    proto_tree_add_item(sli_tree, hf_lbmsrs_sli_reserved, tvb, offset, L_LBM_SRS_SRC_LEAVE_INFO_T_RESERVED, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_SRC_LEAVE_INFO_T_RESERVED;

    proto_item_set_text(batch_item, "SLI:Topic:%s", name);
    (*cnt_sli)++;

    proto_item_set_len(batch_item, (offset - start_offset));
    return (offset - start_offset);
}

/*Function to dissect SRS SIR/SER/SDR*/
static guint dissect_lbmsrs_batch(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint offset, guint32 rsocket_payload_len)
{
    guint start_offset = offset;
    guint total_payload_len = tvb_captured_length(tvb);
    guint cnt_sir = 0, cnt_ser = 0, cnt_sdr = 0;
    guint cnt_rir = 0, cnt_rer = 0, cnt_rdr = 0;
    guint cnt_wir = 0, cnt_wer = 0, cnt_wdr = 0;
    guint cnt_sli = 0;


    col_append_fstr(pinfo->cinfo, COL_INFO, "[");
    /*add a sub-tree for the batch */

    proto_item *srs_batch;
    proto_tree_add_subtree(tree, tvb, offset, rsocket_payload_len, ett_lbmsrs_details, &srs_batch, "SRS SIR/SER/SDR/RIR/RDR/RER/WIR/WDR/WER");

    /*this is a start of the batch which will contain SIR,SDR,SER*/
    while (offset < total_payload_len)
    {
        /*at least two bytes required to check the message id*/
        if ((total_payload_len - offset) < L_LBM_SRS_MESSAGE_ID)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "SIR:%u SER:%u SDR:%u RIR:%u RER:%u RDR:%u WIR:%u WER:%u WDR:%u SLI:%u]",
                cnt_sir, cnt_ser, cnt_sdr, cnt_rir, cnt_rer, cnt_rdr, cnt_wir, cnt_wer, cnt_wdr, cnt_sli);
            proto_item_set_text(srs_batch, "SRS:[SIR:%u SER:%u SDR:%u RIR:%u RER:%u RDR:%u WIR:%u WER:%u WDR:%u SLI:%u]",
                cnt_sir, cnt_ser, cnt_sdr, cnt_rir, cnt_rer, cnt_rdr, cnt_wir, cnt_wer, cnt_wdr, cnt_sli);
            proto_item_set_len(srs_batch, (offset - start_offset));
            return (offset - start_offset);
        }

        guint16 message_id = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);

        /*process the SIR/SDR/SER*/
        guint len_dissected = 0;
        gboolean can_dissect_further = TRUE;
        switch (message_id)
        {
            case MSG_ID_SOURCE_INFO:
            {
                len_dissected = dissect_lbmsrs_sir_ser(tvb,tree, offset, &cnt_sir, &cnt_ser,&can_dissect_further);
                break;
            }

            case MSG_ID_SOURCE_DELETE:
            {
                len_dissected = dissect_lbmsrs_sdr(tvb, tree, offset, &cnt_sdr, &can_dissect_further);
                break;
            }

            case MSG_ID_RCV_INFO:
            {
                len_dissected = dissect_lbmsrs_rir(tvb, tree, offset, &cnt_rir, &can_dissect_further);
                break;
            }
            case MSG_ID_RCV_DELETE:
            {
                len_dissected = dissect_lbmsrs_rdr(tvb, tree, offset, &cnt_rdr, &can_dissect_further);
                break;
            }
            case MSG_ID_RCV_END:
            {
                len_dissected = dissect_lbmsrs_rer(tvb, tree, offset, &cnt_rer, &can_dissect_further);
                break;
            }
            case MSG_ID_WRCV_INFO:
            {
                len_dissected = dissect_lbmsrs_wir(tvb, tree, offset, &cnt_wir, &can_dissect_further);
                break;
            }
            case MSG_ID_WRCV_DELETE:
            {
                len_dissected = dissect_lbmsrs_wdr(tvb, tree, offset, &cnt_wdr, &can_dissect_further);
                break;
            }
            case MSG_ID_WRCV_END:
            {
                len_dissected = dissect_lbmsrs_wer(tvb, tree, offset, &cnt_wer, &can_dissect_further);
                break;
            }
            case MSG_ID_SRC_LEAVE:
            {
                len_dissected = dissect_lbmsrs_sli(tvb, tree, offset, &cnt_sli, &can_dissect_further);
                break;
            }

            default:
                break;
        }

        /*if nothing is dissected then return the current offset*/
        if (FALSE == can_dissect_further || len_dissected < 1)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "SIR:%u SER:%u SDR:%u RIR:%u RER:%u RDR:%u WIR:%u WER:%u WDR:%u SLI:%u]",
                cnt_sir, cnt_ser, cnt_sdr, cnt_rir, cnt_rer, cnt_rdr, cnt_wir, cnt_wer, cnt_wdr, cnt_sli);
            proto_item_set_text(srs_batch, "SRS:[SIR:%u SER:%u SDR:%u RIR:%u RER:%u RDR:%u WIR:%u WER:%u WDR:%u SLI:%u]",
                cnt_sir, cnt_ser, cnt_sdr, cnt_rir, cnt_rer, cnt_rdr, cnt_wir, cnt_wer, cnt_wdr, cnt_sli);
            proto_item_set_len(srs_batch, (offset - start_offset));
            return (offset - start_offset);
        }
        offset += len_dissected;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "SIR:%u SER:%u SDR:%u RIR:%u RER:%u RDR:%u WIR:%u WER:%u WDR:%u SLI:%u]",
        cnt_sir, cnt_ser, cnt_sdr, cnt_rir, cnt_rer, cnt_rdr, cnt_wir, cnt_wer, cnt_wdr, cnt_sli);
    proto_item_set_text(srs_batch, "SRS:[SIR:%u SER:%u SDR:%u RIR:%u RER:%u RDR:%u WIR:%u WER:%u WDR:%u SLI:%u]",
        cnt_sir, cnt_ser, cnt_sdr, cnt_rir, cnt_rer, cnt_rdr, cnt_wir, cnt_wer, cnt_wdr, cnt_sli);
    proto_item_set_len(srs_batch, (offset - start_offset));

    return (offset - start_offset);
}

static guint dissect_lbmsrs_registration_request(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint offset, guint32 rsocket_payload_len)
{
    guint start_offset = offset;
    proto_tree_add_item(tree, hf_lbmsrs_message_id, tvb, offset, L_LBM_SRS_MESSAGE_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_MESSAGE_ID;

    /*reduce by message id field length*/
    rsocket_payload_len -= L_LBM_SRS_MESSAGE_ID;
    if (L_LBM_SRS_REGISTRATION_REQUEST_INFO_T != rsocket_payload_len)
    {
        return (offset - start_offset);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "[SRS REGISTRATION REQUEST]");
    /*add a sub-tree for SRS */
    proto_item *lbmsrs_details;
    proto_tree *lbmsrs_details_tree = proto_tree_add_subtree(tree, tvb, offset, rsocket_payload_len, ett_lbmsrs_details, &lbmsrs_details, "SRS Registration Request");

    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_app_type, tvb, offset, L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_APP_TYPE, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_APP_TYPE;
    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_client_addr, tvb, offset, L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_CLIENT_ADDR, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_CLIENT_ADDR;
    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_client_port, tvb, offset, L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_CLIENT_PORT, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_CLIENT_PORT;
    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_session_id, tvb, offset, L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_SESSION_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_SESSION_ID;
    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_host_id, tvb, offset, L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_HOST_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_HOST_ID;
    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_protocol_version, tvb, offset, L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_PROTOCOL_VERSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_PROTOCOL_VERSION;
    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_interest_mode, tvb, offset, L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_INTEREST_MODE, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_INTEREST_MODE;
    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_req_local_domain_id, tvb, offset, L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_LOCAL_DOMAIN_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_REQUEST_INFO_T_LOCAL_DOMAIN_ID;

    return (offset - start_offset); //return the total length dissected

}

static guint dissect_lbmsrs_registration_response(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint offset, guint32 rsocket_payload_len)
{
    guint start_offset = offset;
    proto_tree_add_item(tree, hf_lbmsrs_message_id, tvb, offset, L_LBM_SRS_MESSAGE_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_MESSAGE_ID;

    /*reduce by message id field length*/
    rsocket_payload_len -= L_LBM_SRS_MESSAGE_ID;

    if (L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T != rsocket_payload_len)
    {
        return (offset - start_offset);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "[SRS REGISTRATION RESPONSE]");

    /*add a sub-tree for SRS */
    proto_item *lbmsrs_details;
    proto_tree *lbmsrs_details_tree = proto_tree_add_subtree(tree, tvb, offset, rsocket_payload_len, ett_lbmsrs_details, &lbmsrs_details, "SRS Registration Response");

    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_client_id, tvb, offset, L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T_CLIENT_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T_CLIENT_ID;
    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_resp_local_domain_id, tvb, offset, L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T_LOCAL_DOMAIN_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T_LOCAL_DOMAIN_ID;
    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_reg_resp_protocol_version, tvb, offset, L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T_PROTOCOL_VERSION, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_REGISTRATION_RESPONSE_INFO_T_PROTOCOL_VERSION;

    return (offset - start_offset);
}

static guint dissect_lbmsrs_stream_request(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint offset, guint32 rsocket_payload_len)
{
    guint start_offset = offset;
    proto_tree_add_item(tree, hf_lbmsrs_message_id, tvb, offset, L_LBM_SRS_MESSAGE_ID, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_MESSAGE_ID;

    /*reduce by message id field length*/
    rsocket_payload_len -= L_LBM_SRS_MESSAGE_ID;

    if (L_LBM_SRS_STREAM_REQUEST_INFO_T != rsocket_payload_len)
    {
        return (offset - start_offset);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "[SRS STREAM REQUEST]");

    /*add a sub-tree for SRS */
    proto_item *lbmsrs_details;
    proto_tree *lbmsrs_details_tree = proto_tree_add_subtree(tree, tvb, offset, rsocket_payload_len, ett_lbmsrs_details, &lbmsrs_details, "SRS Stream Request");

    proto_tree_add_item(lbmsrs_details_tree, hf_lbmsrs_stream_req_unused, tvb, offset, L_LBM_SRS_STREAM_REQUEST_INFO_T_UNUSED, ENC_BIG_ENDIAN);
    offset += L_LBM_SRS_STREAM_REQUEST_INFO_T_UNUSED;

    return (offset - start_offset);
}
/*Function to dissect SRS as part of Rsocket payload/metadata*/
static guint dissect_lbmsrs_data(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint offset, guint32 rsocket_payload_len)
{
    guint total_payload_len = tvb_captured_length(tvb);
    guint len_dissected = 0;

    if ((total_payload_len - offset) < L_LBM_SRS_MESSAGE_ID)
    {
        return 0;
    }

    /*add and get the SRS message id*/
    guint16 message_id = tvb_get_guint16(tvb,offset, ENC_BIG_ENDIAN);

    switch (message_id)
    {
        case MSG_ID_REGISTRATION_REQUEST:
        {
            len_dissected = dissect_lbmsrs_registration_request(tvb,pinfo,tree,offset,rsocket_payload_len);
            break;
        }
        case MSG_ID_REGISTRATION_RESPONSE:
        {
            len_dissected = dissect_lbmsrs_registration_response(tvb, pinfo, tree, offset, rsocket_payload_len);
            break;
        }
        case MSG_ID_STREAM_REQUEST:
        {
            len_dissected = dissect_lbmsrs_stream_request(tvb, pinfo, tree, offset, rsocket_payload_len);
            break;
        }
        case MSG_ID_SOURCE_INFO:
        case MSG_ID_SOURCE_DELETE:
        case MSG_ID_RCV_INFO:
        case MSG_ID_RCV_DELETE:
        case MSG_ID_RCV_END:
        case MSG_ID_WRCV_INFO:
        case MSG_ID_WRCV_DELETE:
        case MSG_ID_WRCV_END:
        case MSG_ID_SRC_LEAVE:
        {
            len_dissected = dissect_lbmsrs_batch(tvb, pinfo, tree, offset, rsocket_payload_len);
            break;
        }

        default:
        {
            expert_add_info_format(pinfo, tree, &ei_lbmsrs_analysis_invalid_msg_id,
                "Invalid LBMSRS Message Id :%" PRIu16, message_id);

        }

    }

    return len_dissected;
}

/* This is the main dissector function
Return 0 - If the data does not belong to the protocol
Return > 0 - If the data is dissected properly, return the actual length dissected
Return < 0 - If need more data for dissection, return the negative of the length required*/
static int dissect_lbmsrs_pdus(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * user_data _U_)
{
    guint offset = 0;
    guint tvb_length = tvb_captured_length(tvb);

    if (tvb_length < rsocket_frame_len_field_size)
    {
        return 0;
    }

    /*get the rsocket frame length*/
    guint32 rsocket_frame_len = tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN);
    /*adjust the rscoket tree size correctly so as to accomodate
    only the available data, its always possible that the rsocket length reported
    in the rsocket PDU is more than the data captured in this packet or vice-versa*/
    guint32 rsocket_tree_length = rsocket_frame_len;
    if (tvb_length < (rsocket_frame_len + rsocket_frame_len_field_size))
    {
        rsocket_tree_length = tvb_length - rsocket_frame_len_field_size;
    }

    /*check if nothing is available to dissect*/
    if (rsocket_tree_length <= 0)
    {
        return 0;
    }
    /*add the srs subtree, this will allow to use the "srs" filter*/
    proto_item *ti = proto_tree_add_item(tree, proto_lbmsrs, tvb, offset, -1, ENC_NA);
    proto_tree *srs_tree = proto_item_add_subtree(ti, ett_lbmsrs);

    /*add the rsocket frame length field*/
    proto_tree_add_item(srs_tree, hf_lbmsrs_rsocket_frame_len, tvb, offset,
        rsocket_frame_len_field_size, ENC_BIG_ENDIAN);
    offset += rsocket_frame_len_field_size;


    /*add the rsocket frame subtree*/
    proto_item *rsocket_frame;
    proto_tree *rsocket_frame_tree = proto_tree_add_subtree(
        srs_tree, tvb, offset, rsocket_tree_length, ett_lbmsrs_rsocket_frame, &rsocket_frame, "RSocket Frame");

    /*add the rocket stream id*/
    if ((tvb_length - offset) < rsocket_stream_id_field_size)
    {
        return offset;
    }
    proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_stream_id, tvb, offset, 4,
        ENC_BIG_ENDIAN);
    offset += rsocket_stream_id_field_size;


    /*read and add the rsocket frame type*/
    if ((tvb_length - offset) < 1)
    {
        return offset;
    }
    guint64 rsocket_frame_type;
    proto_tree_add_bits_ret_val(rsocket_frame_tree, hf_lbmsrs_rsocket_frame_type, tvb,
        offset * 8, 6, &rsocket_frame_type, ENC_BIG_ENDIAN);


    const gchar *frameName = getFrameTypeName(rsocket_frame_type);

    if (frameName) {
        col_add_str(pinfo->cinfo, COL_INFO, frameName);
    }
    else {
        col_add_str(pinfo->cinfo, COL_INFO, "UNDEFINED");
    }

    /*add the rsocket ignore flag*/
    proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_ignore_flag, tvb, offset, 2,
        ENC_BIG_ENDIAN);

    /*read the rsocket metadata flag*/
    guint8 rsocket_metadata_flag = tvb_get_bits8(tvb, (offset * 8) + 6, 2);
    proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_metadata_flag, tvb, offset, 2,
        ENC_BIG_ENDIAN);

    /*dissect rsocket frame based on type */
    gboolean can_dissect_further = TRUE;
    int rsocket_dissected_len  = dissect_rsocket_frame(rsocket_frame_type, rsocket_frame_tree, tvb, offset,&can_dissect_further);
    offset += rsocket_dissected_len;

    if (FALSE == can_dissect_further)
    {
        return (offset - rsocket_frame_len);
    }

    /*if rsocket metadata is available add it to the tree*/
    if (rsocket_metadata_flag)
    {
        /*add the rsocket metadata length field*/
        if ((tvb_length - offset) < 3)
        {
            return (offset - rsocket_frame_len);
        }
        guint32 rsocket_metadata_len;
        proto_tree_add_item_ret_uint(rsocket_frame_tree, hf_lbmsrs_rsocket_mdata_len, tvb, offset,3, ENC_BIG_ENDIAN, &rsocket_metadata_len);
        offset += 3;

        /*add the rsocket metadata*/
        if ((tvb_length - offset) < rsocket_metadata_len)
        {
            return (offset - rsocket_frame_len);
        }
        proto_tree_add_item(rsocket_frame_tree, hf_lbmsrs_rsocket_mdata, tvb, offset, rsocket_metadata_len,ENC_ASCII | ENC_NA);
        offset += rsocket_metadata_len;
    }

    /*get the remaining payload length*/
    guint32 rsocket_payload_len = tvb_length - offset;

    /*if payload is available start processing for SRS*/
    if (rsocket_payload_len > 0) {
        proto_item *lbmsrs_data;
        proto_tree *lbmsrs_data_tree = proto_tree_add_subtree(rsocket_frame_tree, tvb, offset, rsocket_payload_len, ett_lbmsrs_data, &lbmsrs_data, "LBMSRS Data");
        offset += dissect_lbmsrs_data(tvb, pinfo, lbmsrs_data_tree, offset, rsocket_payload_len);
    }

    return (offset - rsocket_frame_len);
}

/*common dissection function for LBMSRS*/
static guint dissect_lbmsrs_real(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data _U_)
{
    char* tag_name = NULL;
    if (lbmsrs_use_tag)
    {
        tag_name = lbmsrs_tag_find(pinfo);
    }
    col_clear(pinfo->cinfo, COL_INFO);
    if (tag_name != NULL)
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "[Tag: %s]", tag_name);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LBMSRS");
    col_set_fence(pinfo->cinfo, COL_INFO);

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 3, get_rsocket_frame_len, dissect_lbmsrs_pdus, data);
    return tvb_captured_length(tvb);
}

/*normal dissection function*/
static int dissect_lbmsrs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!check_lbmsrs_packet(tvb, 0))
    {
        return 0;
    }

    return dissect_lbmsrs_real(tvb,pinfo,tree,data);
}

/*heuristic dissection function*/
static gboolean test_lbmsrs_packet(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * user_data _U_)
{
    gboolean valid_packet = FALSE;
    lbmsrs_tag_entry_t entry;

    /* Must be a TCP packet. */
    if (pinfo->ptype != PT_TCP)
    {
        return (FALSE);
    }

    if (lbmsrs_use_tag)
    {
        if (lbmsrs_tag_find(pinfo) != NULL)
        {
            valid_packet = TRUE;
        }
    }
    else
    {
        entry.name = NULL;
        entry.ip_address = LBMSRS_DEFAULT_SOURCE_IP;
        if (*global_lbmsrs_source_ip_address == '\0')
        {
            entry.ip_address = NULL;
        }
        entry.ip_address_val_h = lbmsrs_source_ip_address;
        entry.tcp_port = lbmsrs_source_port;
        valid_packet = lbmsrs_match_packet(pinfo, &entry);
    }

    if (!check_lbmsrs_packet(tvb, 0))
    {
        return FALSE;
    }

    if (valid_packet)
    {
        dissect_lbmsrs_real(tvb, pinfo, tree, user_data);
        return (TRUE);
    }

    return (FALSE);

}

void proto_register_lbmsrs(void)
{
    static hf_register_info hf[] = {
        { &hf_lbmsrs_message_id,
        { "Message ID", "lbmsrs.message_id", FT_UINT16, BASE_DEC, VALS(lbmsrsMessageId), 0x0, NULL, HFILL } },
        /*rsocket related items start*/
        { &hf_lbmsrs_rsocket_frame_len,
        { "Frame Length", "lbmsrs.rsocket.frame_len", FT_UINT24, BASE_DEC, NULL, 0x0,NULL, HFILL } },
        { &hf_lbmsrs_rsocket_stream_id,
        { "Stream ID", "lbmsrs.rsocket.stream_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,HFILL } },
        { &hf_lbmsrs_rsocket_frame_type,
        { "Frame Type", "lbmsrs.rsocket.frame_type", FT_UINT8, BASE_DEC,VALS(rSocketFrameTypeNames), 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_mdata_len,
        { "Metadata Length", "lbmsrs.rsocket.metadata_len", FT_UINT24, BASE_DEC, NULL,0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_mdata,
        { "Metadata", "lbmsrs.rsocket.metadata", FT_STRING, BASE_NONE, NULL, 0x0, NULL,HFILL } },
        { &hf_lbmsrs_rsocket_ignore_flag,
        { "Ignore", "lbmsrs.rsocket.flags.ignore", FT_BOOLEAN, 16, NULL, 0x0200, NULL,HFILL } },
        { &hf_lbmsrs_rsocket_metadata_flag,
        { "Metadata", "lbmsrs.rsocket.flags.metadata", FT_BOOLEAN, 16, NULL, 0x0100,NULL, HFILL } },
        { &hf_lbmsrs_rsocket_resume_flag,
        { "Resume", "lbmsrs.rsocket.flags.resume", FT_BOOLEAN, 16, NULL, 0x0080, NULL,HFILL } },
        { &hf_lbmsrs_rsocket_lease_flag,
        { "Lease", "lbmsrs.rsocket.flags.lease", FT_BOOLEAN, 16, NULL, 0x0040, NULL,HFILL } },
        { &hf_lbmsrs_rsocket_follows_flag,
        { "Follows", "lbmsrs.rsocket.flags.follows", FT_BOOLEAN, 16, NULL, 0x0080, NULL,HFILL } },
        { &hf_lbmsrs_rsocket_complete_flag,
        { "Complete", "lbmsrs.rsocket.flags.complete", FT_BOOLEAN, 16, NULL, 0x0040,NULL, HFILL } },
        { &hf_lbmsrs_rsocket_next_flag,
        { "Next", "lbmsrs.rsocket.flags.next", FT_BOOLEAN, 16, NULL, 0x0020, NULL,HFILL } },
        { &hf_lbmsrs_rsocket_respond_flag,
        { "Respond", "lbmsrs.rsocket.flags.respond", FT_BOOLEAN, 16, NULL, 0x0080, NULL,HFILL } },
        { &hf_lbmsrs_rsocket_major_version,
        { "Major Version", "lbmsrs.rsocket.version.major", FT_UINT16, BASE_DEC, NULL,0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_minor_version,
        { "Minor Version", "lbmsrs.rsocket.version.minor", FT_UINT16, BASE_DEC, NULL,0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_keepalive_interval,
        { "Keepalive Interval", "lbmsrs.rsocket.keepalive.interval", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_max_lifetime,
        { "Max Lifetime", "lbmsrs.rsocket.max_lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL } },
        { &hf_lbmsrs_rsocket_mdata_mime_length,
        { "Metadata MIME Length", "lbmsrs.rsocket.mdata_mime_length", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_mdata_mime_type,
        { "Metadata MIME Type", "lbmsrs.rsocket.mdata_mime_type", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_data_mime_length,
        { "Data MIME Length", "lbmsrs.rsocket.data_mime_length", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_data_mime_type,
        { "Data MIME Type", "lbmsrs.rsocket.data_mime_type", FT_STRING, BASE_NONE, NULL,0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_req_n,
        { "Request N", "lbmsrs.rsocket.request_n", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,HFILL } },
        { &hf_lbmsrs_rsocket_error_code,
        { "Error Code", "lbmsrs.rsocket.error_code", FT_UINT32, BASE_DEC,VALS(rSocketErrorCodeNames), 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_keepalive_last_rcvd_pos,
        { "Keepalive Last Received Position","lbmsrs.rsocket.keepalive_last_received_position", FT_UINT64, BASE_DEC, NULL,0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_resume_token_len,
        { "Resume Token Length", "lbmsrs.rsocket.resume.token.len", FT_UINT16, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rsocket_resume_token,
        { "Resume Token", "lbmsrs.rsocket.resume.token", FT_STRING, BASE_NONE, NULL, 0x0,NULL, HFILL } },
        /*rsocket related items end*/

        /*SRS Registration Request items start*/
        { &hf_lbmsrs_app_type,
        { "Application Type", "lbmsrs.registration_request.app_type", FT_UINT8, BASE_DEC,VALS(lbmsrsApplicationType), 0x0, NULL, HFILL } },
        { &hf_lbmsrs_client_addr,
        { "Client Address", "lbmsrs.registration_request.client_addr", FT_IPv4, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_client_port,
        { "Client Port", "lbmsrs.registration_request.client_port", FT_UINT16, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_session_id,
        { "Session ID", "lbmsrs.registration_request.session_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_host_id,
        { "Host ID", "lbmsrs.registration_request.host_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_protocol_version,
        { "Protocol Version", "lbmsrs.registration_request.protocol_version", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_interest_mode,
        { "Interest Mode", "lbmsrs.registration_request.interest_mode", FT_UINT8, BASE_DEC,VALS(lbmsrsInterestMode), 0x0, NULL, HFILL } },
        { &hf_lbmsrs_req_local_domain_id,
        { "Local Domain ID", "lbmsrs.registration_request.local_domain_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        /*SRS Registration Request items end*/

        /*SRS Registration Response items start*/
        { &hf_lbmsrs_client_id,
        { "Client ID", "lbmsrs.registration_response.client_id", FT_UINT64, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_resp_local_domain_id,
        { "Local Domain ID", "lbmsrs.registration_response.local_domain_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_reg_resp_protocol_version,
        { "Protocol Version", "lbmsrs.registration_response.protocol_version", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        /*SRS Registration Response items end*/

        /*SRS Stream Request items start*/
        { &hf_lbmsrs_stream_req_unused,
        { "Unused", "lbmsrs.stream_req.unused", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        /*SRS Stream Request items end*/

        /*SRS Source Info items start*/
        { &hf_lbmsrs_sir,
        { "SIR", "lbmsrs.sir", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_otid,
        { "OTID", "lbmsrs.sir.otid", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_topic_len,
        { "Topic Length", "lbmsrs.sir.topic_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_topic,
        { "Topic", "lbmsrs.sir.topic", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_source_len,
        { "Source Length", "lbmsrs.sir.source_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_source,
        { "Source", "lbmsrs.sir.source", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_host_id,
        { "Host ID", "lbmsrs.sir.host_id", FT_UINT32, BASE_DEC_HEX,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_topic_idx,
        { "Topic Index", "lbmsrs.sir.topic_idx", FT_UINT32, BASE_DEC_HEX,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_functionality_flags,
        { "Functionality Flags", "lbmsrs.sir.functionality_flags", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_request_ip,
        { "Request IP", "lbmsrs.sir.request_ip", FT_IPv4, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_request_port,
        { "Request Port", "lbmsrs.sir.request_port", FT_UINT16, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_domain_id,
        { "Domain ID", "lbmsrs.sir.domain_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_encryption,
        { "Encryption", "lbmsrs.sir.encryption", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_compression,
        { "Compression", "lbmsrs.sir.compression", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_ulb_src_id,
        { "ULB Source ID", "lbmsrs.sir.ulb_src_id", FT_UINT32, BASE_DEC_HEX,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_ulb_queue_id,
        { "ULB Queue ID", "lbmsrs.sir.ulb_queue_id", FT_UINT32, BASE_DEC_HEX,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_ulb_reg_id,
        { "ULB Registration ID", "lbmsrs.sir.ulb_reg_id", FT_UINT64, BASE_DEC_HEX,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_context_instance,
        { "Context Instance", "lbmsrs.sir.context_instance", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_context_type,
        { "Context Type", "lbmsrs.sir.context_type", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_version,
        { "Version", "lbmsrs.sir.version", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_version_flags,
        { "Version Flags", "lbmsrs.sir.version_flags", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_ttl,
        { "TTL", "lbmsrs.sir.ttl", FT_UINT16, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sir_cost,
        { "Cost", "lbmsrs.sir.cost", FT_INT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        /*SRS Source Info items end*/

        /*SRS Source Delete items start*/
        { &hf_lbmsrs_sdr,
        { "SDR", "lbmsrs.sdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sdr_otid,
        { "OTID", "lbmsrs.sdr.otid", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sdr_topic_len,
        { "Topic Length", "lbmsrs.sdr.topic_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sdr_topic,
        { "Topic", "lbmsrs.sdr.topic", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        /*SRS Source Delete items end*/

        /*SRS Receiver Info items start*/
        { &hf_lbmsrs_rir,
        { "RIR", "lbmsrs.rir", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rir_topic_len,
        { "Topic Length", "lbmsrs.rir.topic_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rir_topic,
        { "Topic", "lbmsrs.rir.topic", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rir_domain_id,
        { "Domain ID", "lbmsrs.rir.domain_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rir_context_instance,
        { "Context Instance", "lbmsrs.rir.context_instance", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rir_context_type,
        { "Context Type", "lbmsrs.rir.context_type", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rir_version,
        { "Version", "lbmsrs.rir.version", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rir_version_flags,
        { "Version Flags", "lbmsrs.rir.version_flags", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rir_reserved,
        { "Reserved", "lbmsrs.rir.reserved", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        /*SRS Receiver Info items end*/

        /*SRS Receiver Delete Info items start*/
        { &hf_lbmsrs_rdr,
        { "RDR", "lbmsrs.rdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rdr_topic_len,
        { "Topic Length", "lbmsrs.rdr.topic_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rdr_topic,
        { "Topic", "lbmsrs.rdr.topic", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rdr_domain_id,
        { "Domain ID", "lbmsrs.rdr.domain_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rdr_context_instance,
        { "Context Instance", "lbmsrs.rdr.context_instance", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rdr_context_type,
        { "Context Type", "lbmsrs.rdr.context_type", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rdr_version,
        { "Version", "lbmsrs.rdr.version", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rdr_version_flags,
        { "Version Flags", "lbmsrs.rdr.version_flags", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rdr_reserved,
        { "Reserved", "lbmsrs.rdr.reserved", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        /*SRS Receiver Delete items end*/

        /*SRS Receiver End Info items start*/
        { &hf_lbmsrs_rer,
        { "RER", "lbmsrs.rer", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rer_topic_len,
        { "Topic Length", "lbmsrs.rer.topic_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rer_topic,
        { "Topic", "lbmsrs.rer.topic", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rer_domain_id,
        { "Domain ID", "lbmsrs.rer.domain_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rer_context_instance,
        { "Context Instance", "lbmsrs.rer.context_instance", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rer_context_type,
        { "Context Type", "lbmsrs.rer.context_type", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rer_version,
        { "Version", "lbmsrs.rer.version", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rer_version_flags,
        { "Version Flags", "lbmsrs.rer.version_flags", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_rer_reserved,
        { "Reserved", "lbmsrs.rer.reserved", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        /*SRS Receiver End items end*/


        /*SRS Wildcard Receiver Info items start*/
        { &hf_lbmsrs_wir,
        { "WIR", "lbmsrs.wir", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wir_pattern_len,
        { "Topic Length", "lbmsrs.wir.pattern_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wir_pattern,
        { "Topic", "lbmsrs.wir.pattern", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wir_domain_id,
        { "Domain ID", "lbmsrs.wir.domain_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wir_context_instance,
        { "Context Instance", "lbmsrs.wir.context_instance", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wir_context_type,
        { "Context Type", "lbmsrs.wir.context_type", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wir_version,
        { "Version", "lbmsrs.wir.version", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wir_version_flags,
        { "Version Flags", "lbmsrs.wir.version_flags", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wir_reserved,
        { "Reserved", "lbmsrs.wir.reserved", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        /*SRS Wildcard Receiver Info items end*/

        /*SRS Wildcard Receiver Delete Info items start*/
        { &hf_lbmsrs_wdr,
        { "WDR", "lbmsrs.wdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wdr_pattern_len,
        { "Topic Length", "lbmsrs.wdr.pattern_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wdr_pattern,
        { "Topic", "lbmsrs.wdr.pattern", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wdr_domain_id,
        { "Domain ID", "lbmsrs.wdr.domain_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wdr_context_instance,
        { "Context Instance", "lbmsrs.wdr.context_instance", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wdr_context_type,
        { "Context Type", "lbmsrs.wdr.context_type", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wdr_version,
        { "Version", "lbmsrs.wdr.version", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wdr_version_flags,
        { "Version Flags", "lbmsrs.wdr.version_flags", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wdr_reserved,
        { "Reserved", "lbmsrs.wdr.reserved", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        /*SRS Wildcard Receiver Delete items end*/

        /*SRS Wildcard Receiver End Info items start*/
        { &hf_lbmsrs_wer,
        { "WER", "lbmsrs.wer", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wer_pattern_len,
        { "Topic Length", "lbmsrs.wer.pattern_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wer_pattern,
        { "Topic", "lbmsrs.wer.pattern", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wer_domain_id,
        { "Domain ID", "lbmsrs.wer.domain_id", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wer_context_instance,
        { "Context Instance", "lbmsrs.wer.context_instance", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wer_context_type,
        { "Context Type", "lbmsrs.wer.context_type", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wer_version,
        { "Version", "lbmsrs.wer.version", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wer_version_flags,
        { "Version Flags", "lbmsrs.wer.version_flags", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_wer_reserved,
        { "Reserved", "lbmsrs.wer.reserved", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        /*SRS Wildcard Receiver End items end*/

        /*SRS Source Leave Info items start*/
        { &hf_lbmsrs_sli,
        { "SLI", "lbmsrs.sli", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sli_otid,
        { "OTID", "lbmsrs.sli.otid", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sli_topic_len,
        { "Topic Length", "lbmsrs.sli.topic_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sli_topic,
        { "Topic", "lbmsrs.sli.topic", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sli_source_len,
        { "Source Length", "lbmsrs.sli.source_len", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sli_source,
        { "Source", "lbmsrs.sli.source", FT_STRING, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sli_context_instance,
        { "Context Instance", "lbmsrs.sli.context_instance", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sli_context_type,
        { "Context Type", "lbmsrs.sli.context_type", FT_UINT8, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sli_version,
        { "Version", "lbmsrs.sli.version", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sli_version_flags,
        { "Version Flags", "lbmsrs.sli.version_flags", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } },
        { &hf_lbmsrs_sli_reserved,
        { "Reserved", "lbmsrs.sli.reserved", FT_UINT32, BASE_DEC,NULL, 0x0, NULL, HFILL } }
        /*SRS Source Leave Info items end*/
    };

    static gint *ett[] =
    {
        &ett_lbmsrs,
        &ett_lbmsrs_rsocket_frame,
        &ett_lbmsrs_data,
        &ett_lbmsrs_details,
        &ett_lbmsrs_sir,
        &ett_lbmsrs_sdr,
        &ett_lbmsrs_ser,
        &ett_lbmsrs_rir,
        &ett_lbmsrs_rdr,
        &ett_lbmsrs_rer,
        &ett_lbmsrs_wir,
        &ett_lbmsrs_wdr,
        &ett_lbmsrs_wer,
        &ett_lbmsrs_sli
    };

    static ei_register_info ei[] =
    {
        { &ei_lbmsrs_analysis_invalid_msg_id, { "lbmsrs.analysis.invalid_msg_id", PI_MALFORMED, PI_ERROR, "Invalid LBMSRS Message Id", EXPFILL } }
    };
    proto_lbmsrs = proto_register_protocol("LBM Stateful Resolution Service Protocol", "LBMSRS", "lbmsrs");
    proto_register_field_array(proto_lbmsrs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_lbmsrs = expert_register_protocol(proto_lbmsrs);
    expert_register_field_array(expert_lbmsrs, ei, array_length(ei));

    /*Set the preference menu items*/
    module_t* lbmsrs_module = prefs_register_protocol_subtree("29West", proto_lbmsrs, proto_reg_handoff_lbmsrs);

    guint32 addr;
    ws_inet_pton4(LBMSRS_DEFAULT_SOURCE_IP, &addr);
    lbmsrs_source_ip_address = g_ntohl(addr);
    prefs_register_string_preference(lbmsrs_module,
        "source_ip_address",
        "Source IP address (default " LBMSRS_DEFAULT_SOURCE_IP ")",
        "Set the LBMSRS IP Address",
        &global_lbmsrs_source_ip_address);

    prefs_register_uint_preference(lbmsrs_module,
        "source_port",
        "Source port (default " MAKESTRING(LBMSRS_DEFAULT_SOURCE_PORT)")",
        "Set the source TCP port",
        10,
        &global_lbmsrs_source_port);

    prefs_register_bool_preference(lbmsrs_module,
        "use_lbmsrs_domain",
        "Use LBMSRS tag table",
        "Use table of LBMSRS tags to decode the packet instead of above values",
        &global_lbmsrs_use_tag);

    uat_t *tag_uat = uat_new("LBMSRS tag definitions",
        sizeof(lbmsrs_tag_entry_t),
        "lbmsrs_domains",
        TRUE,
        (void * *)&lbmsrs_tag_entry,
        &lbmsrs_tag_count,
        UAT_AFFECTS_DISSECTION,
        NULL,
        lbmsrs_tag_copy_cb,
        lbmsrs_tag_update_cb,
        lbmsrs_tag_free_cb,
        NULL,
        NULL,
        lbmsrs_tag_array);

    /*add the tag edit table*/
    prefs_register_uat_preference(lbmsrs_module,
        "tnw_lbmsrs_tags",
        "LBMSRS Tags",
        "A table to define LBMSRS tags",
        tag_uat);
}

void proto_reg_handoff_lbmsrs(void)
{
    static gboolean already_registered = FALSE;
    guint32 addr;

    if (!already_registered)
    {
        lbmsrs_dissector_handle = create_dissector_handle(dissect_lbmsrs, proto_lbmsrs);
        dissector_add_for_decode_as_with_preference("tcp.port", lbmsrs_dissector_handle);
        heur_dissector_add("tcp", test_lbmsrs_packet, "LBM Stateful Resolution Service over RSocket", "lbmsrs_tcp", proto_lbmsrs, HEURISTIC_ENABLE);
    }

    ws_inet_pton4(global_lbmsrs_source_ip_address, &addr);
    lbmsrs_source_ip_address = g_ntohl(addr);
    lbmsrs_source_port = global_lbmsrs_source_port;
    lbmsrs_use_tag = global_lbmsrs_use_tag;
    already_registered = TRUE;
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
