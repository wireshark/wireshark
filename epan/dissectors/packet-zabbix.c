/* packet-zabbix.c
 * Routines for Zabbix protocol dissection
 * Copyright 2023, Markku Leiniö <markku.leinio@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Zabbix protocol specifications can be found in Zabbix documentation:
 * https://www.zabbix.com/documentation/current/en/manual/appendix/protocols
 */

#include "config.h"

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/inet_addr.h>
#include <wsutil/nstime.h>
#include <wsutil/wsjson.h>
#include "packet-tcp.h"

void proto_register_zabbix(void);
void proto_reg_handoff_zabbix(void);

static dissector_handle_t zabbix_handle;

/* Desegmentation of Zabbix protocol over TCP */
static bool zabbix_desegment = true;

/* Initialize the protocol and registered fields */
static int proto_zabbix;
static int hf_zabbix_header;
static int hf_zabbix_flags;
static int hf_zabbix_flag_zabbix_communications;
static int hf_zabbix_flag_compressed;
static int hf_zabbix_flag_largepacket;
static int hf_zabbix_flag_reserved;
static int hf_zabbix_length;
static int hf_zabbix_reserved;
static int hf_zabbix_uncompressed_length;
static int hf_zabbix_large_length;
static int hf_zabbix_large_reserved;
static int hf_zabbix_large_uncompressed_length;
static int hf_zabbix_data;
static int hf_zabbix_error;
static int hf_zabbix_time;
static int hf_zabbix_agent;
static int hf_zabbix_agent_commands;
static int hf_zabbix_agent_config;
static int hf_zabbix_agent_data;
static int hf_zabbix_agent_redirection;
static int hf_zabbix_agent_passive;
static int hf_zabbix_agent_name;
static int hf_zabbix_agent_hb;
static int hf_zabbix_agent_hb_freq;
static int hf_zabbix_agent_hostmetadata;
static int hf_zabbix_agent_hostinterface;
static int hf_zabbix_agent_listenipv4;
static int hf_zabbix_agent_listenipv6;
static int hf_zabbix_agent_listenport;
static int hf_zabbix_agent_variant;
static int hf_zabbix_proxy;
static int hf_zabbix_proxy_hb;
static int hf_zabbix_proxy_name;
static int hf_zabbix_proxy_data;
static int hf_zabbix_proxy_config;
static int hf_zabbix_proxy_fullsync;
static int hf_zabbix_proxy_incr_config;
static int hf_zabbix_proxy_no_config_change;
static int hf_zabbix_proxy_tasks;
static int hf_zabbix_sender;
static int hf_zabbix_sender_name;
static int hf_zabbix_request;
static int hf_zabbix_response;
static int hf_zabbix_success;
static int hf_zabbix_failed;
static int hf_zabbix_config_revision;
static int hf_zabbix_hostmap_revision;
static int hf_zabbix_session;
static int hf_zabbix_version;

/* Initialize the subtree pointers */
static int ett_zabbix;

/* Initialize expert fields */
static expert_field ei_zabbix_packet_too_large;
static expert_field ei_zabbix_json_error;

/* Other dissector-specifics */
static range_t *zabbix_port_range;

static const char ZABBIX_HDR_SIGNATURE[] = "ZBXD";
static const char ZABBIX_UNKNOWN[] = "<unknown>";
static const char ZABBIX_ZBX_NOTSUPPORTED[] = "ZBX_NOTSUPPORTED";

typedef struct _zabbix_conv_info_t {
    uint32_t req_framenum;
    nstime_t req_timestamp;
    uint16_t oper_flags;         /* ZABBIX_T_XXX macros below */
    const char *host_name;
} zabbix_conv_info_t;

#define ZABBIX_HDR_MIN_LEN          13              /* When not large packet */
#define ZABBIX_HDR_MAX_LEN          21              /* When large packet */
#define ZABBIX_MAX_LENGTH_ALLOWED   1024*1024*1024  /* 1 GB */
#define ZABBIX_TCP_PORTS            "10050,10051"   /* IANA registered ports */

#define ZABBIX_FLAG_ZABBIX_COMMUNICATIONS   0x01
#define ZABBIX_FLAG_COMPRESSED              0x02
#define ZABBIX_FLAG_LARGEPACKET             0x04
#define ZABBIX_FLAG_RESERVED                0xf8

/* Response flags are not saved in the conversations */
#define ZABBIX_RESPONSE_SUCCESS     0x01
#define ZABBIX_RESPONSE_FAILED      0x02
#define ZABBIX_RESPONSE_FULLSYNC    0x04
#define ZABBIX_RESPONSE_INCREMENTAL 0x08
#define ZABBIX_RESPONSE_NOCHANGE    0x10

/* Flags for saving and comparing operation types,
 * max 16 bits as defined in zabbix_conv_info_t above */
#define ZABBIX_T_REQUEST            0x00000001
#define ZABBIX_T_RESPONSE           0x00000002
#define ZABBIX_T_ACTIVE             0x00000004
#define ZABBIX_T_PASSIVE            0x00000008
#define ZABBIX_T_AGENT              0x00000010
#define ZABBIX_T_PROXY              0x00000020
#define ZABBIX_T_SENDER             0x00000040
#define ZABBIX_T_CONFIG             0x00000080
#define ZABBIX_T_DATA               0x00000100
#define ZABBIX_T_TASKS              0x00000200
#define ZABBIX_T_HEARTBEAT          0x00000400
#define ZABBIX_T_LEGACY             0x00000800   /* pre-7.0 non-JSON protocol */

#define ADD_ZABBIX_T_FLAGS(flags)       (zabbix_info->oper_flags |= (flags))
#define CLEAR_ZABBIX_T_FLAGS(flags)     (zabbix_info->oper_flags &= (0xffff-(flags)))
#define IS_ZABBIX_T_FLAGS(flags)        ((zabbix_info->oper_flags & (flags)) == (flags))

#define CONV_IS_ZABBIX_REQUEST(zabbix_info,pinfo)           ((zabbix_info)->req_framenum == (pinfo)->fd->num)
#define CONV_IS_ZABBIX_RESPONSE(zabbix_info,pinfo)          ((zabbix_info)->req_framenum != (pinfo)->fd->num)

#define ZABBIX_NAME_OR_UNKNOWN(name)       ((name) ? (name) : ZABBIX_UNKNOWN)


static zabbix_conv_info_t*
zabbix_find_conversation_and_get_conv_data(packet_info *pinfo)
{
    conversation_t *conversation;
    zabbix_conv_info_t *zabbix_info = NULL;

    conversation = find_conversation_pinfo(pinfo, 0);
    if (conversation) {
        zabbix_info = (zabbix_conv_info_t *)conversation_get_proto_data(conversation, proto_zabbix);
    } else {
        conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst,
            conversation_pt_to_conversation_type(pinfo->ptype),
            pinfo->srcport, pinfo->destport, 0);
    }
    if (!zabbix_info) {
        /* New conversation, or there was no Zabbix data yet in the existing conv */
        zabbix_info = wmem_alloc(wmem_file_scope(), sizeof(zabbix_conv_info_t));
        if (value_is_in_range(zabbix_port_range, pinfo->destport)) {
            /* Let's assume this is the first Zabbix packet (request) */
            zabbix_info->req_framenum = pinfo->fd->num;
            zabbix_info->req_timestamp = pinfo->abs_ts;
        }
        else {
            /* For any reason we didn't have Zabbix data yet but this is not
             * the first packet for the connection, so don't save it as a request
             */
            zabbix_info->req_framenum = 0;
            nstime_set_unset(&zabbix_info->req_timestamp);
            /* For some reason this produces "syntax error: '{'" when compiling:
            zabbix_info->req_timestamp = NSTIME_INIT_UNSET;
            */
        }
        zabbix_info->oper_flags = 0;
        zabbix_info->host_name = NULL;
        conversation_add_proto_data(conversation, proto_zabbix, (void *)zabbix_info);
    }
    return zabbix_info;
}

static void
zabbix_add_expert_info_if_too_large(packet_info *pinfo, proto_tree *tree_item,
    uint64_t length, bool *is_too_large)
{
    if (length > ZABBIX_MAX_LENGTH_ALLOWED) {
        expert_add_info(pinfo, tree_item, &ei_zabbix_packet_too_large);
        *is_too_large = true;
    }
    return;
}

static int
dissect_zabbix_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    int agent_hb_freq = 0;
    unsigned oper_response = 0;
    proto_item *ti;
    proto_item *pi;
    proto_tree *temp_ti;
    proto_tree *zabbix_tree = NULL;
    uint8_t flags;
    uint16_t agent_listenport = 0;
    uint64_t length;
    uint64_t uncompressed_length;
    uint64_t datalen;
    int64_t agent_variant = 0;
    int64_t config_revision = -1;
    int64_t hostmap_revision = -1;
    bool is_compressed;
    bool is_large_packet;
    bool is_too_large = false;
    bool is_redirection = false;
    char *json_str;
    char *passive_agent_data_str = NULL;
    jsmntok_t *commands_array = NULL;
    jsmntok_t *data_array = NULL;
    jsmntok_t *data_object = NULL;
    const char *agent_name = NULL;
    const char *agent_hostmetadata = NULL;
    const char *agent_hostinterface = NULL;
    const char *agent_listenip = NULL;
    const char *proxy_name = NULL;
    const char *sender_name = NULL;
    const char *session = NULL;
    const char *request_type = NULL;
    const char *response_status = NULL;
    const char *version = NULL;
    double temp_double;
    tvbuff_t *next_tvb;
    zabbix_conv_info_t *zabbix_info;
    static int* const flagbits[] = {
        &hf_zabbix_flag_reserved,
        &hf_zabbix_flag_largepacket,
        &hf_zabbix_flag_compressed,
        &hf_zabbix_flag_zabbix_communications,
        NULL
    };

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Zabbix");
    col_clear(pinfo->cinfo, COL_INFO);

    if ((tvb_reported_length(tvb) < ZABBIX_HDR_MIN_LEN) ||
        (tvb_memeql(tvb, offset, ZABBIX_HDR_SIGNATURE, 4) == -1)) {
        /* Encrypted or not Zabbix at all */
        return 0;
    }
    flags = tvb_get_uint8(tvb, offset+4);
    if (!(flags & ZABBIX_FLAG_ZABBIX_COMMUNICATIONS)) {
        return 0;
    }

    zabbix_info = zabbix_find_conversation_and_get_conv_data(pinfo);

    is_compressed = (flags & ZABBIX_FLAG_COMPRESSED) > 0;
    is_large_packet = (flags & ZABBIX_FLAG_LARGEPACKET) > 0;

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_zabbix, tvb, 0, -1, ENC_NA);
    zabbix_tree = proto_item_add_subtree(ti, ett_zabbix);
    proto_tree_add_item(zabbix_tree, hf_zabbix_header, tvb, offset, 4, ENC_UTF_8);
    offset += 4;
    proto_tree_add_bitmask(zabbix_tree, tvb, offset, hf_zabbix_flags, ett_zabbix, flagbits, ENC_BIG_ENDIAN);
    offset += 1;
    if (is_large_packet) {
        /* 8-byte values */
        temp_ti = proto_tree_add_item_ret_uint64(zabbix_tree,
            hf_zabbix_large_length, tvb, offset, 8, ENC_LITTLE_ENDIAN, &length);
        zabbix_add_expert_info_if_too_large(pinfo, temp_ti, length, &is_too_large);
        offset += 8;
        if (is_compressed) {
            temp_ti = proto_tree_add_item_ret_uint64(zabbix_tree,
                hf_zabbix_large_uncompressed_length, tvb, offset, 8, ENC_LITTLE_ENDIAN, &uncompressed_length);
            zabbix_add_expert_info_if_too_large(pinfo, temp_ti, uncompressed_length, &is_too_large);
        } else {
            proto_tree_add_item(zabbix_tree, hf_zabbix_large_reserved, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        }
        offset += 8;
    } else {
        /* 4-byte values */
        uint32_t temp_uint32;
        temp_ti = proto_tree_add_item_ret_uint(zabbix_tree,
            hf_zabbix_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &temp_uint32);
        length = (uint64_t)temp_uint32;
        zabbix_add_expert_info_if_too_large(pinfo, temp_ti, length, &is_too_large);
        offset += 4;
        if (is_compressed) {
            temp_ti = proto_tree_add_item_ret_uint(zabbix_tree,
                hf_zabbix_uncompressed_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &temp_uint32);
            uncompressed_length = (uint64_t)temp_uint32;
            zabbix_add_expert_info_if_too_large(pinfo, temp_ti, uncompressed_length, &is_too_large);
        } else {
            proto_tree_add_item(zabbix_tree, hf_zabbix_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        }
        offset += 4;
    }
    if (is_too_large) {
        /* Set next_tvb for response time calculation to work later */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        /* ... but don't do any content-based inspection, just skip to the end */
        goto final_outputs;
    } else if (is_compressed) {
        next_tvb = tvb_uncompress_zlib(tvb, offset, tvb_reported_length_remaining(tvb, offset));
        if (next_tvb) {
            tvb_set_child_real_data_tvbuff(tvb, next_tvb);
            add_new_data_source(pinfo, next_tvb, "Uncompressed data");
            datalen = uncompressed_length;
        } else {
            /* Handle uncompressed */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            datalen = length;
        }
    } else {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        datalen = length;
    }

    /* Use only next_tvb and datalen for data extraction from here on! */
    offset = 0;

    /* Rewrite the default texts in the protocol tree and initialize request/response flags */
    if (CONV_IS_ZABBIX_REQUEST(zabbix_info, pinfo)) {
        proto_item_set_text(ti, "Zabbix Protocol request");
        ADD_ZABBIX_T_FLAGS(ZABBIX_T_REQUEST);
        CLEAR_ZABBIX_T_FLAGS(ZABBIX_T_RESPONSE);
    }
    else if (CONV_IS_ZABBIX_RESPONSE(zabbix_info, pinfo)) {
        proto_item_set_text(ti, "Zabbix Protocol response");
        ADD_ZABBIX_T_FLAGS(ZABBIX_T_RESPONSE);
        CLEAR_ZABBIX_T_FLAGS(ZABBIX_T_REQUEST);
    }

    /*
     * Note that json_str is modified when using json_get_xxx() functions below!
     * So don't use it to anything else (make a wmem_strdup() if needed, see below)
     */
    json_str = tvb_get_string_enc(pinfo->pool, next_tvb, offset, (int)datalen, ENC_UTF_8);
    /* First check if this is a pre-7.0 passive agent.
     * Note that even pre-7.0 passive agent *responses* can be JSON, so don't just check
     * for JSON validation but check the conversation data!
     */
    if (
        !json_validate(json_str, datalen) ||
        (
            CONV_IS_ZABBIX_RESPONSE(zabbix_info, pinfo) &&
            IS_ZABBIX_T_FLAGS(ZABBIX_T_AGENT | ZABBIX_T_PASSIVE | ZABBIX_T_LEGACY)
        )
    ) {
        /* The only non-JSON Zabbix request/response is passive agent before Zabbix 7.0,
         * ensure the conversation data is set, then set the texts
         */
        ADD_ZABBIX_T_FLAGS(ZABBIX_T_AGENT | ZABBIX_T_PASSIVE | ZABBIX_T_LEGACY);
        if (CONV_IS_ZABBIX_REQUEST(zabbix_info, pinfo)) {
            proto_item_set_text(ti, "Zabbix Server/proxy request for passive agent checks");
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Server/proxy request for passive agent checks");
        } else if (CONV_IS_ZABBIX_RESPONSE(zabbix_info, pinfo)) {
            proto_item_set_text(ti, "Zabbix Agent response for passive checks");
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Agent response for passive checks");
        }
        /* Make a copy of the data string for later error message lookup use */
        passive_agent_data_str = wmem_strndup(pinfo->pool, json_str, (size_t)datalen);
        /* Don't do content-based searches for pre-7.0 passive agents */
        goto show_agent_outputs;
    }
    /* Parse JSON, first get the token count */
    int token_count = json_parse(json_str, NULL, 0);
    if (token_count <= 0) {
        temp_ti = proto_tree_add_item(zabbix_tree, hf_zabbix_data, next_tvb, 0, (int)datalen, ENC_UTF_8);
        expert_add_info_format(pinfo, temp_ti, &ei_zabbix_json_error, "Error in initial JSON parse");
        goto final_outputs;
    }
    jsmntok_t *tokens = wmem_alloc_array(pinfo->pool, jsmntok_t, token_count);
    int ret = json_parse(json_str, tokens, token_count);
    if (ret <= 0) {
        temp_ti = proto_tree_add_item(zabbix_tree, hf_zabbix_data, next_tvb, 0, (int)datalen, ENC_UTF_8);
        expert_add_info_format(pinfo, temp_ti, &ei_zabbix_json_error, "Error parsing JSON tokens");
        goto final_outputs;
    }

    /*
     * Now we have JSON tokens analyzed, let's do all the logic to populate the fields.
     * Also set Zabbix tree item and Info column texts, Len= and ports will be added later below.
     */

    /* First populate common fields */
    version = json_get_string(json_str, tokens, "version");
    if (json_get_double(json_str, tokens, "variant", &temp_double)) {
        agent_variant = (int64_t)temp_double;
    }
    session = json_get_string(json_str, tokens, "session");
    if (json_get_double(json_str, tokens, "config_revision", &temp_double)) {
        config_revision = (int64_t)temp_double;
    }
    if (json_get_double(json_str, tokens, "hostmap_revision", &temp_double)) {
        hostmap_revision = (int64_t)temp_double;
    } else {
        jsmntok_t *proxy_group_object = json_get_object(json_str, tokens, "proxy_group");
        if (proxy_group_object) {
            if (json_get_double(json_str, proxy_group_object, "hostmap_revision", &temp_double)) {
                hostmap_revision = (int64_t)temp_double;
            }
        }
    }
    request_type = json_get_string(json_str, tokens, "request");
    response_status = json_get_string(json_str, tokens, "response");
    commands_array = json_get_array(json_str, tokens, "commands");
    data_array = json_get_array(json_str, tokens, "data");
    data_object = json_get_object(json_str, tokens, "data");
    /* Find the packet type primarily based on "request" field */
    if (request_type) {
        if (strcmp(request_type, "active checks") == 0) {
            /* Active agent requesting configs */
            ADD_ZABBIX_T_FLAGS(ZABBIX_T_AGENT | ZABBIX_T_CONFIG | ZABBIX_T_ACTIVE);
            agent_name = json_get_string(json_str, tokens, "host");
            if (agent_name && !PINFO_FD_VISITED(pinfo)) {
                zabbix_info->host_name = wmem_strdup(wmem_file_scope(), agent_name);
            }
            proto_item_set_text(ti,
                "Zabbix Agent request for active checks for \"%s\"", ZABBIX_NAME_OR_UNKNOWN(agent_name));
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Zabbix Agent request for active checks for \"%s\"", ZABBIX_NAME_OR_UNKNOWN(agent_name));
            agent_hostmetadata = json_get_string(json_str, tokens, "host_metadata");
            agent_hostinterface = json_get_string(json_str, tokens, "interface");
            agent_listenip = json_get_string(json_str, tokens, "ip");
            if (json_get_double(json_str, tokens, "port", &temp_double)) {
                agent_listenport = (uint16_t)temp_double;
            }
        }
        else if (strcmp(request_type, "agent data") == 0) {
            /* Active agent sending data */
            ADD_ZABBIX_T_FLAGS(ZABBIX_T_AGENT | ZABBIX_T_DATA | ZABBIX_T_ACTIVE);
            /* Zabbix Agent 2 has Host in the top level */
            agent_name = json_get_string(json_str, tokens, "host");
            if (!agent_name) {
                /* For Zabbix Agent try parsing agent name inside data array */
                jsmntok_t *tok = json_get_array(json_str, tokens, "data");
                if (tok && json_get_array_len(tok) > 0) {
                    jsmntok_t *datatok = json_get_array_index(tok, 0);
                    agent_name = json_get_string(json_str, datatok, "host");
                }
            }
            if (agent_name && !PINFO_FD_VISITED(pinfo)) {
                zabbix_info->host_name = wmem_strdup(wmem_file_scope(), agent_name);
            }
            proto_item_set_text(ti,
                "Zabbix Agent data from \"%s\"", ZABBIX_NAME_OR_UNKNOWN(agent_name));
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Zabbix Agent data from \"%s\"", ZABBIX_NAME_OR_UNKNOWN(agent_name));
        }
        else if (strcmp(request_type, "active check heartbeat") == 0) {
            /* Active agent sending heartbeat */
            ADD_ZABBIX_T_FLAGS(ZABBIX_T_AGENT | ZABBIX_T_HEARTBEAT | ZABBIX_T_ACTIVE);
            agent_name = json_get_string(json_str, tokens, "host");
            if (agent_name && !PINFO_FD_VISITED(pinfo)) {
                zabbix_info->host_name = wmem_strdup(wmem_file_scope(), agent_name);
            }
            if (json_get_double(json_str, tokens, "heartbeat_freq", &temp_double)) {
                agent_hb_freq = (int)temp_double;
            }
            proto_item_set_text(ti,
                "Zabbix Agent heartbeat from \"%s\"", ZABBIX_NAME_OR_UNKNOWN(agent_name));
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Zabbix Agent heartbeat from \"%s\"", ZABBIX_NAME_OR_UNKNOWN(agent_name));
        }
        else if (strcmp(request_type, "passive checks") == 0) {
            /* Passive agent checks since Zabbix 7.0 */
            ADD_ZABBIX_T_FLAGS(ZABBIX_T_AGENT | ZABBIX_T_PASSIVE);
            proto_item_set_text(ti, "Zabbix Server/proxy request for passive agent checks");
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Server/proxy request for passive agent checks");
        }
        else if (strcmp(request_type, "sender data") == 0) {
            /* Sender/trapper */
            ADD_ZABBIX_T_FLAGS(ZABBIX_T_SENDER);
            /* Try to get the sender name from the first data array item */
            jsmntok_t *tok = json_get_array(json_str, tokens, "data");
            if (tok && json_get_array_len(tok) > 0) {
                jsmntok_t *datatok = json_get_array_index(tok, 0);
                sender_name = json_get_string(json_str, datatok, "host");
                if (sender_name && !PINFO_FD_VISITED(pinfo)) {
                    zabbix_info->host_name = wmem_strdup(wmem_file_scope(), sender_name);
                }
            }
            proto_item_set_text(ti,
                "Zabbix Sender data from \"%s\"", ZABBIX_NAME_OR_UNKNOWN(sender_name));
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Zabbix Sender data from \"%s\"", ZABBIX_NAME_OR_UNKNOWN(sender_name));
        }
        else if ((strcmp(request_type, "proxy data") == 0) ||
                (strcmp(request_type, "host availability") == 0) ||
                (strcmp(request_type, "history data") == 0) ||
                (strcmp(request_type, "discovery data") == 0) ||
                (strcmp(request_type, "auto registration") == 0)) {
            /* Either active or passive proxy; "proxy data" = Zabbix 3.4+,
             * others = Zabbix 3.2 or older */
            proxy_name = json_get_string(json_str, tokens, "host");
            if (token_count == 3) {     /* Only '{"request":"xxx"}' */
                /* This is Zabbix server connecting to passive proxy */
                ADD_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_DATA | ZABBIX_T_PASSIVE);
                proto_item_set_text(ti, "Zabbix Proxy data request to passive proxy");
                col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Proxy data request to passive proxy");
            }
            else if (proxy_name) {
                /* This is an active proxy connecting to server */
                ADD_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_DATA | ZABBIX_T_ACTIVE);
                if (proxy_name && !PINFO_FD_VISITED(pinfo)) {
                    zabbix_info->host_name = wmem_strdup(wmem_file_scope(), proxy_name);
                }
                proto_item_set_text(ti, "Zabbix Proxy data from \"%s\"", proxy_name);
                col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Proxy data from \"%s\"", proxy_name);
            }
        }
        else if (strcmp(request_type, "proxy config") == 0) {
            /* Either active or passive proxy */
            proxy_name = json_get_string(json_str, tokens, "host");
            if (token_count == 3) {     /* Only '{"request":"proxy config"}' */
                /* This is Zabbix 6.4+ server connecting to passive proxy */
                ADD_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_CONFIG | ZABBIX_T_PASSIVE);
                proto_item_set_text(ti, "Zabbix Proxy config request to passive proxy");
                col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Proxy config request to passive proxy");
            }
            else if (proxy_name) {
                /* This is an active proxy connecting to server */
                ADD_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_CONFIG | ZABBIX_T_ACTIVE);
                if (proxy_name && !PINFO_FD_VISITED(pinfo)) {
                    zabbix_info->host_name = wmem_strdup(wmem_file_scope(), proxy_name);
                }
                proto_item_set_text(ti, "Zabbix Request proxy config for \"%s\"", proxy_name);
                col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Request proxy config for \"%s\"", proxy_name);
            }
        }
        else if (strcmp(request_type, "proxy tasks") == 0) {
            /* Zabbix server connecting to passive proxy, only '{"request":"proxy tasks"}' */
            ADD_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_TASKS | ZABBIX_T_PASSIVE);
            proto_item_set_text(ti, "Zabbix Proxy tasks request to passive proxy");
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Proxy tasks request to passive proxy");
        }
        else if (strcmp(request_type, "proxy heartbeat") == 0) {
            /* Heartbeat from active proxy, not used in Zabbix 6.4+ */
            ADD_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_HEARTBEAT | ZABBIX_T_ACTIVE);
            proxy_name = json_get_string(json_str, tokens, "host");
            if (proxy_name && !PINFO_FD_VISITED(pinfo)) {
                zabbix_info->host_name = wmem_strdup(wmem_file_scope(), proxy_name);
            }
            proto_item_set_text(ti, "Zabbix Proxy heartbeat from \"%s\"", proxy_name);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Proxy heartbeat from \"%s\"", proxy_name);
        }
    }
    /* There was no "request" field match, continue with other ways to recognize the packet */
    else if (json_get_object(json_str, tokens, "globalmacro")) {
        /* This is Zabbix server before 6.4 sending configurations to active proxy */
        ADD_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_CONFIG | ZABBIX_T_ACTIVE);
        proxy_name = zabbix_info->host_name;
        proto_item_set_text(ti,
            "Zabbix Server response for proxy config for \"%s\"", ZABBIX_NAME_OR_UNKNOWN(proxy_name));
        col_add_fstr(pinfo->cinfo, COL_INFO,
            "Zabbix Server response for proxy config for \"%s\"", ZABBIX_NAME_OR_UNKNOWN(proxy_name));
    }
    else if (json_get_double(json_str, tokens, "full_sync", &temp_double)) {
        /* This is Zabbix 6.4+ server sending proxy config to active or passive proxy */
        /* Only present when value is 1 */
        ADD_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_CONFIG);
        oper_response |= ZABBIX_RESPONSE_FULLSYNC;
        /* Active/passive flag was set in the earlier packet */
        if (IS_ZABBIX_T_FLAGS(ZABBIX_T_PASSIVE)) {
            /* There is no proxy name anywhere to use */
            proto_item_set_text(ti, "Zabbix Passive proxy config");
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Passive proxy config");
        }
        else {
            /* Active proxy */
            proxy_name = zabbix_info->host_name;
            proto_item_set_text(ti,
                "Zabbix Server response for proxy config for \"%s\"", ZABBIX_NAME_OR_UNKNOWN(proxy_name));
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Zabbix Server response for proxy config for \"%s\"", ZABBIX_NAME_OR_UNKNOWN(proxy_name));
        }
    }
    else if (response_status) {
        if (strcmp(response_status, "success") == 0) {
            oper_response |= ZABBIX_RESPONSE_SUCCESS;
        }
        else if (strcmp(response_status, "failed") == 0) {
            oper_response |= ZABBIX_RESPONSE_FAILED;
        }
        if (IS_ZABBIX_T_FLAGS(ZABBIX_T_AGENT)) {
            agent_name = zabbix_info->host_name;
            if (json_get_object(json_str, tokens, "redirect")) {
                /* Agent redirection response from a Zabbix 7.0+ proxy in load balancing configuration.
                 * Not added in the conversation flags to prevent it from showing in the request packet,
                 * just set a local variable for later usage.
                 */
                is_redirection = true;
                proto_item_set_text(ti,
                    "Zabbix Agent redirection for \"%s\"", ZABBIX_NAME_OR_UNKNOWN(agent_name));
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Zabbix Agent redirection for \"%s\"", ZABBIX_NAME_OR_UNKNOWN(agent_name));
            }
            else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_CONFIG | ZABBIX_T_ACTIVE)) {
                proto_item_set_text(ti,
                    "Zabbix Server/proxy response for active checks for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(agent_name), response_status);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Zabbix Server/proxy response for active checks for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(agent_name), response_status);
            }
            else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_DATA | ZABBIX_T_ACTIVE)) {
                proto_item_set_text(ti,
                    "Zabbix Server/proxy response for agent data for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(agent_name), response_status);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Zabbix Server/proxy response for agent data for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(agent_name), response_status);
            }
        }
        else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_PROXY)) {
            proxy_name = zabbix_info->host_name;
            if (IS_ZABBIX_T_FLAGS(ZABBIX_T_CONFIG | ZABBIX_T_ACTIVE)) {
                proto_item_set_text(ti,
                    "Zabbix Response for active proxy config request for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(proxy_name), response_status);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Zabbix Response for active proxy config request for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(proxy_name), response_status);
            }
            else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_DATA | ZABBIX_T_ACTIVE)) {
                proto_item_set_text(ti,
                    "Zabbix Server response for active proxy data for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(proxy_name), response_status);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Zabbix Server response for active proxy data for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(proxy_name), response_status);
            }
            else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_CONFIG | ZABBIX_T_PASSIVE)) {
                proto_item_set_text(ti,
                    "Zabbix Proxy response for passive proxy config (%s)", response_status);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Zabbix Proxy response for passive proxy config (%s)", response_status);
            }
            else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_DATA | ZABBIX_T_PASSIVE)) {
                proto_item_set_text(ti,
                    "Zabbix Server response for passive proxy data (%s)", response_status);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Zabbix Server response for passive proxy data (%s)", response_status);
            }
            else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_TASKS | ZABBIX_T_PASSIVE)) {
                proto_item_set_text(ti,
                    "Zabbix Server response for passive proxy tasks (%s)", response_status);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Zabbix Server response for passive proxy tasks (%s)", response_status);
            }
            else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_HEARTBEAT | ZABBIX_T_ACTIVE)) {
                proto_item_set_text(ti,
                    "Zabbix Server response for active proxy heartbeat for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(proxy_name), response_status);
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Zabbix Server response for active proxy heartbeat for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(proxy_name), response_status);
            }
        }
        else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_SENDER)) {
            sender_name = zabbix_info->host_name;
            proto_item_set_text(ti,
                "Zabbix Server/proxy response for sender data for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(sender_name), response_status);
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Zabbix Server/proxy response for sender data for \"%s\" (%s)", ZABBIX_NAME_OR_UNKNOWN(sender_name), response_status);
        }
    }
    else if (version && data_array) {
        /* This looks like passive agent response in Zabbix 7.0+ */
        ADD_ZABBIX_T_FLAGS(ZABBIX_T_AGENT | ZABBIX_T_PASSIVE);
        proto_item_set_text(ti, "Zabbix Agent response for passive checks");
        col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Agent response for passive checks");
    }
    else if (data_object || data_array || tokens->size == 0) {
        /* No other match above, let's assume this is server sending incremental
         * configuration to a proxy
         */
        ADD_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_CONFIG);
        if ((data_object && (data_object->size == 0)) || tokens->size == 0) {
            /* Empty data object or the whole JSON is empty */
            oper_response |= ZABBIX_RESPONSE_NOCHANGE;
        }
        else if (data_array) {
            /* This was not a "full_sync" but data array exists */
            oper_response |= ZABBIX_RESPONSE_INCREMENTAL;
        }
        if (IS_ZABBIX_T_FLAGS(ZABBIX_T_PASSIVE)) {
            /* There is no proxy name anywhere to use */
            proto_item_set_text(ti, "Zabbix Passive proxy config");
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Passive proxy config");
        }
        else {
            proxy_name = zabbix_info->host_name;
            proto_item_set_text(ti,
                "Zabbix Server response for proxy config for \"%s\"", ZABBIX_NAME_OR_UNKNOWN(proxy_name));
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Zabbix Server response for proxy config for \"%s\"", ZABBIX_NAME_OR_UNKNOWN(proxy_name));
        }
    }
    /* Final guesses to provide customized packet information */
    else if (session && version) {
        /* Config or data responses from passive proxy */
        if (IS_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_CONFIG | ZABBIX_T_PASSIVE)) {
            proto_item_set_text(ti, "Zabbix Passive proxy response for config push");
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Passive proxy response for config push");
        }
        else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_DATA | ZABBIX_T_PASSIVE)) {
            proto_item_set_text(ti, "Zabbix Passive proxy data response");
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Passive proxy data response");
        }
    }
    else if (version) {
        /* Tasks response from passive proxy */
        if (IS_ZABBIX_T_FLAGS(ZABBIX_T_PROXY | ZABBIX_T_TASKS | ZABBIX_T_PASSIVE)) {
            proto_item_set_text(ti, "Zabbix Passive proxy response for tasks request");
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Passive proxy response for tasks request");
        }
    }


    /* Add all relevant fields to the tree */

show_agent_outputs:
    if (IS_ZABBIX_T_FLAGS(ZABBIX_T_AGENT)) {
        temp_ti = proto_tree_add_boolean(zabbix_tree, hf_zabbix_agent, NULL, 0, 0, true);
        proto_item_set_text(temp_ti, "This is an agent connection");
        proto_item_set_generated(temp_ti);
        if (IS_ZABBIX_T_FLAGS(ZABBIX_T_DATA)) {
            temp_ti = proto_tree_add_boolean(zabbix_tree, hf_zabbix_agent_data, NULL, 0, 0, true);
            if (IS_ZABBIX_T_FLAGS(ZABBIX_T_RESPONSE)) {
                /* Set as generated, not seen in data */
                proto_item_set_generated(temp_ti);
            }
        }
        else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_CONFIG)) {
            temp_ti = proto_tree_add_boolean(zabbix_tree, hf_zabbix_agent_config, NULL, 0, 0, true);
            if (IS_ZABBIX_T_FLAGS(ZABBIX_T_RESPONSE)) {
                /* Set as generated, not seen in data */
                proto_item_set_generated(temp_ti);
            }
        }
        else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_HEARTBEAT)) {
            proto_tree_add_boolean(zabbix_tree, hf_zabbix_agent_hb, NULL, 0, 0, true);
        }
        else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_PASSIVE)) {
            temp_ti = proto_tree_add_boolean(zabbix_tree, hf_zabbix_agent_passive, NULL, 0, 0, true);
            proto_item_set_text(temp_ti, "Agent is in passive mode");
            proto_item_set_generated(temp_ti);
        }
        if (is_redirection) {
            proto_tree_add_boolean(zabbix_tree, hf_zabbix_agent_redirection, NULL, 0, 0, true);
        }
    }
    else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_PROXY)) {
        temp_ti = proto_tree_add_boolean(zabbix_tree, hf_zabbix_proxy, NULL, 0, 0, true);
        proto_item_set_text(temp_ti, "This is a proxy connection");
        proto_item_set_generated(temp_ti);
    }
    else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_SENDER)) {
        temp_ti = proto_tree_add_boolean(zabbix_tree, hf_zabbix_sender, NULL, 0, 0, true);
        proto_item_set_text(temp_ti, "This is a sender connection");
        proto_item_set_generated(temp_ti);
    }
    if (oper_response & ZABBIX_RESPONSE_SUCCESS) {
        proto_tree_add_boolean(zabbix_tree, hf_zabbix_success, NULL, 0, 0, true);
    }
    else if (oper_response & ZABBIX_RESPONSE_FAILED) {
        proto_tree_add_boolean(zabbix_tree, hf_zabbix_failed, NULL, 0, 0, true);
    }
    if (IS_ZABBIX_T_FLAGS(ZABBIX_T_AGENT)) {
        if (agent_name) {
            temp_ti = proto_tree_add_string(zabbix_tree, hf_zabbix_agent_name, NULL, 0, 0, agent_name);
            if (IS_ZABBIX_T_FLAGS(ZABBIX_T_RESPONSE)) {
                /* agent_name was populated from the conversation */
                proto_item_set_generated(temp_ti);
                proto_item_append_text(temp_ti, " (from the request)");
            }
        }
        if (agent_variant) {
            proto_tree_add_int64(zabbix_tree, hf_zabbix_agent_variant, NULL, 0, 0, agent_variant);
        }
        if (agent_hb_freq) {
            proto_tree_add_int(zabbix_tree, hf_zabbix_agent_hb_freq, NULL, 0, 0, agent_hb_freq);
        }
        if (agent_hostmetadata) {
            proto_tree_add_string(zabbix_tree, hf_zabbix_agent_hostmetadata, NULL, 0, 0, agent_hostmetadata);
        }
        if (agent_hostinterface) {
            proto_tree_add_string(zabbix_tree, hf_zabbix_agent_hostinterface, NULL, 0, 0, agent_hostinterface);
        }
        if (agent_listenip) {
            if (strstr(agent_listenip, ":") != NULL) {
                ws_in6_addr addr6;
                if (ws_inet_pton6(agent_listenip, &addr6)) {
                    proto_tree_add_ipv6(zabbix_tree, hf_zabbix_agent_listenipv6, NULL, 0, 0, &addr6);
                }
            }
            else {
                ws_in4_addr addr4;
                if (ws_inet_pton4(agent_listenip, &addr4)) {
                    proto_tree_add_ipv4(zabbix_tree, hf_zabbix_agent_listenipv4, NULL, 0, 0, addr4);
                }
            }
        }
        if (agent_listenport) {
            proto_tree_add_uint(zabbix_tree, hf_zabbix_agent_listenport, NULL, 0, 0, agent_listenport);
        }
        if (commands_array) {
            proto_tree_add_boolean(zabbix_tree, hf_zabbix_agent_commands, NULL, 0, 0, true);
        }
    }
    else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_PROXY)) {
        if (proxy_name) {
            temp_ti = proto_tree_add_string(zabbix_tree, hf_zabbix_proxy_name, NULL, 0, 0, proxy_name);
            if (IS_ZABBIX_T_FLAGS(ZABBIX_T_RESPONSE)) {
                /* proxy_name was populated from the conversation */
                proto_item_set_generated(temp_ti);
                proto_item_append_text(temp_ti, " (from the request)");
            }
        }
        if (IS_ZABBIX_T_FLAGS(ZABBIX_T_DATA)) {
            proto_tree_add_boolean(zabbix_tree, hf_zabbix_proxy_data, NULL, 0, 0, true);
        }
        else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_CONFIG)) {
            proto_tree_add_boolean(zabbix_tree, hf_zabbix_proxy_config, NULL, 0, 0, true);
            if (oper_response & ZABBIX_RESPONSE_FULLSYNC) {
                proto_tree_add_boolean(zabbix_tree, hf_zabbix_proxy_fullsync, NULL, 0, 0, true);
            }
            else if (oper_response & ZABBIX_RESPONSE_INCREMENTAL) {
                proto_tree_add_boolean(zabbix_tree, hf_zabbix_proxy_incr_config, NULL, 0, 0, true);
            }
            else if (oper_response & ZABBIX_RESPONSE_NOCHANGE) {
                proto_tree_add_boolean(zabbix_tree, hf_zabbix_proxy_no_config_change, NULL, 0, 0, true);
            }
        }
        else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_TASKS)) {
            proto_tree_add_boolean(zabbix_tree, hf_zabbix_proxy_tasks, NULL, 0, 0, true);
        }
        else if (IS_ZABBIX_T_FLAGS(ZABBIX_T_HEARTBEAT)) {
            proto_tree_add_boolean(zabbix_tree, hf_zabbix_proxy_hb, NULL, 0, 0, true);
        }
    }
    else if (sender_name) {
        temp_ti = proto_tree_add_string(zabbix_tree, hf_zabbix_sender_name, NULL, 0, 0, sender_name);
        if (IS_ZABBIX_T_FLAGS(ZABBIX_T_RESPONSE)) {
            /* sender_name was populated from the conversation */
            proto_item_set_generated(temp_ti);
            proto_item_append_text(temp_ti, " (from the request)");
        }
    }
    if (version) {
        proto_tree_add_string(zabbix_tree, hf_zabbix_version, NULL, 0, 0, version);
    }
    if (config_revision > -1) {
        proto_tree_add_int64(zabbix_tree, hf_zabbix_config_revision, NULL, 0, 0, config_revision);
    }
    if (hostmap_revision > -1) {
        proto_tree_add_int64(zabbix_tree, hf_zabbix_hostmap_revision, NULL, 0, 0, hostmap_revision);
    }
    if (session) {
        proto_tree_add_string(zabbix_tree, hf_zabbix_session, NULL, 0, 0, session);
    }
    /* Show also the full JSON, or pre-7.0 passive agent request/response (or error message).
     * Note that ZABBIX_ZBX_NOTSUPPORTED does not include the \0 that is in the
     * protocol specification! Therefore +1/-1's are present
     */
    if (passive_agent_data_str &&
        strlen(passive_agent_data_str) >= strlen(ZABBIX_ZBX_NOTSUPPORTED) &&
        strncmp(passive_agent_data_str, ZABBIX_ZBX_NOTSUPPORTED, strlen(ZABBIX_ZBX_NOTSUPPORTED)) == 0) {
        /* Pre-7.0 passive agent error, first ZBX_NOTSUPPORTED\0 and then the error message */
        proto_tree_add_item(zabbix_tree, hf_zabbix_data,
            next_tvb, 0, (int)strlen(ZABBIX_ZBX_NOTSUPPORTED)+1, ENC_UTF_8);
        proto_tree_add_item(zabbix_tree, hf_zabbix_error,
            next_tvb, (int)strlen(ZABBIX_ZBX_NOTSUPPORTED)+1, (int)datalen-(int)strlen(ZABBIX_ZBX_NOTSUPPORTED)-1, ENC_UTF_8);
    } else {
        /* JSON or pre-7.0 passive agent without error */
        proto_tree_add_item(zabbix_tree, hf_zabbix_data, next_tvb, 0, (int)datalen, ENC_UTF_8);
    }

final_outputs:

    /* These are common for all cases, too large or not */

    /* Check the ZABBIX_T_REQUEST flag (and not CONV_IS_ZABBIX_REQUEST macro) because
     * heartbeats are not marked as requests */
    if (IS_ZABBIX_T_FLAGS(ZABBIX_T_REQUEST)) {
        temp_ti = proto_tree_add_boolean(zabbix_tree, hf_zabbix_request, NULL, 0, 0, true);
        proto_item_set_text(temp_ti, "This is Zabbix request");
    } else if (CONV_IS_ZABBIX_RESPONSE(zabbix_info, pinfo)) {
        temp_ti = proto_tree_add_boolean(zabbix_tree, hf_zabbix_response, NULL, 0, 0, true);
        proto_item_set_text(temp_ti, "This is Zabbix response");
        if (!nstime_is_unset(&zabbix_info->req_timestamp)) {
            nstime_t delta;
            nstime_delta(&delta, &pinfo->abs_ts, &zabbix_info->req_timestamp);
            pi = proto_tree_add_time(zabbix_tree, hf_zabbix_time, next_tvb, 0, 0, &delta);
            proto_item_set_generated(pi);
        }
    }

    /* Add length to the Zabbix tree text */
    proto_item_append_text(ti, ", Len=%u", (unsigned)length);
    /* Add/set Info column texts */
    const char *info_text = col_get_text(pinfo->cinfo, COL_INFO);
    if (!info_text || !strlen(info_text)) {
        /* Info column is still empty, set the default text */
        if (CONV_IS_ZABBIX_REQUEST(zabbix_info, pinfo)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Protocol request, Flags=0x%02x", flags);
        } else if (CONV_IS_ZABBIX_RESPONSE(zabbix_info, pinfo)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Protocol response, Flags=0x%02x", flags);
        } else {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Zabbix Protocol, Flags=0x%02x", flags);
        }
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Len=%u (", (unsigned)length);
    col_append_ports(pinfo->cinfo, COL_INFO, PT_TCP, pinfo->srcport, pinfo->destport);
    col_append_str(pinfo->cinfo, COL_INFO, ")");

    return tvb_reported_length(tvb);
}

/* Determine PDU length of Zabbix protocol */
static unsigned
get_zabbix_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint8_t flags;
    uint64_t length;

    flags = tvb_get_uint8(tvb, offset+4);
    if (flags & ZABBIX_FLAG_LARGEPACKET) {
        /* 8-byte length field
         * Note that ZABBIX_HDR_MIN_LEN check (in dissect_zabbix()) is still enough
         * due to the header structure (there are reserved bytes)
         */
        length = tvb_get_uint64(tvb, offset+5, ENC_LITTLE_ENDIAN) + ZABBIX_HDR_MAX_LEN;
    } else {
        /* 4-byte length */
        length = tvb_get_uint32(tvb, offset+5, ENC_LITTLE_ENDIAN) + ZABBIX_HDR_MIN_LEN;
    }
    return (unsigned)length;
}

/* The main dissecting routine */
static int
dissect_zabbix(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint8_t flags;

    if (tvb_captured_length(tvb) < ZABBIX_HDR_MIN_LEN) {
        /* Not enough data */
        return 0;
    }
    if (tvb_memeql(tvb, 0, ZABBIX_HDR_SIGNATURE, 4)) {
        /* Encrypted or not Zabbix at all */
        return 0;
    }
    flags = tvb_get_uint8(tvb, 4);
    if (!(flags & ZABBIX_FLAG_ZABBIX_COMMUNICATIONS)) {
        return 0;
    }
    /* This is unencrypted Zabbix protocol, continue with dissecting it */
    tcp_dissect_pdus(tvb, pinfo, tree, zabbix_desegment, ZABBIX_HDR_MIN_LEN,
        get_zabbix_pdu_len, dissect_zabbix_pdu, data);
    return tvb_reported_length(tvb);
}

/* Register the protocol with Wireshark */

void
proto_register_zabbix(void)
{
    static hf_register_info hf[] = {
        { &hf_zabbix_header,
            { "Header", "zabbix.header",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_flags,
            { "Flags", "zabbix.flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_flag_zabbix_communications,
            { "Zabbix communications protocol", "zabbix.flags.zabbix",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), ZABBIX_FLAG_ZABBIX_COMMUNICATIONS,
            NULL, HFILL }
        },
        { &hf_zabbix_flag_compressed,
            { "Compressed", "zabbix.flags.compressed",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), ZABBIX_FLAG_COMPRESSED,
            NULL, HFILL }
        },
        { &hf_zabbix_flag_largepacket,
            { "Large packet", "zabbix.flags.large_packet",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), ZABBIX_FLAG_LARGEPACKET,
            NULL, HFILL }
        },
        { &hf_zabbix_flag_reserved,
            { "Reserved bits", "zabbix.flags.reserved",
            FT_UINT8, BASE_DEC, NULL, ZABBIX_FLAG_RESERVED,
            NULL, HFILL }
        },
        { &hf_zabbix_length,
            { "Length", "zabbix.len",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_reserved,
            { "Reserved", "zabbix.reserved",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_uncompressed_length,
            { "Uncompressed length", "zabbix.uncompressed_len",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_large_length,
            { "Large length", "zabbix.large.len",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_large_reserved,
            { "Large reserved", "zabbix.large.reserved",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_large_uncompressed_length,
            { "Large uncompressed length", "zabbix.large.uncompressed_len",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_data,
            { "Data", "zabbix.data",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_error,
            { "Error message", "zabbix.error",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_time,
            { "Response time", "zabbix.time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_request,
            { "Zabbix protocol request", "zabbix.request",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_response,
            { "Zabbix protocol response", "zabbix.response",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_success,
            { "Success", "zabbix.success",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_failed,
            { "Failed", "zabbix.failed",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent,
            { "Zabbix agent connection", "zabbix.agent",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_commands,
            { "Zabbix agent commands", "zabbix.agent.commands",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_config,
            { "Zabbix agent config", "zabbix.agent.config",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_data,
            { "Zabbix agent data", "zabbix.agent.data",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_redirection,
            { "Agent redirection", "zabbix.agent.redirection",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_passive,
            { "Passive agent", "zabbix.agent.passive",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_name,
            { "Agent name", "zabbix.agent.name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_hb,
            { "Agent heartbeat", "zabbix.agent.heartbeat",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_hb_freq,
            { "Agent heartbeat frequency", "zabbix.agent.heartbeat_freq",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_hostmetadata,
            { "Agent host metadata", "zabbix.agent.host_metadata",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_hostinterface,
            { "Agent host interface", "zabbix.agent.host_interface",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_listenipv4,
            { "Agent listen IPv4", "zabbix.agent.listen_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_listenipv6,
            { "Agent listen IPv6", "zabbix.agent.listen_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_listenport,
            { "Agent listen port", "zabbix.agent.listen_port",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_agent_variant,
            { "Agent variant", "zabbix.agent.variant",
            FT_INT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_proxy,
            { "Proxy connection", "zabbix.proxy",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_proxy_name,
            { "Proxy name", "zabbix.proxy.name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_proxy_hb,
            { "Proxy heartbeat", "zabbix.proxy.heartbeat",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_proxy_data,
            { "Proxy data", "zabbix.proxy.data",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_proxy_config,
            { "Proxy config", "zabbix.proxy.config",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_proxy_fullsync,
            { "Proxy config full sync", "zabbix.proxy.full_sync",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_proxy_incr_config,
            { "Proxy incremental config", "zabbix.proxy.incremental_config",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_proxy_no_config_change,
            { "Proxy no config changes", "zabbix.proxy.no_config_changes",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_proxy_tasks,
            { "Proxy tasks", "zabbix.proxy.tasks",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_sender,
            { "Sender connection", "zabbix.sender",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0,
            NULL, HFILL }
        },
        { &hf_zabbix_sender_name,
            { "Sender name", "zabbix.sender.name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_version,
            { "Version", "zabbix.version",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_session,
            { "Session", "zabbix.session",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_config_revision,
            { "Config revision", "zabbix.config_revision",
            FT_INT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_zabbix_hostmap_revision,
            { "Hostmap revision", "zabbix.hostmap_revision",
            FT_INT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        {
            &ei_zabbix_packet_too_large,
                { "zabbix.packet_too_large", PI_UNDECODED, PI_WARN,
                "Packet is too large for detailed dissection", EXPFILL }
        },
        {
            &ei_zabbix_json_error,
                { "zabbix.json_error", PI_PROTOCOL, PI_ERROR,
                "Cannot parse JSON", EXPFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_zabbix,
    };

    module_t *zabbix_module;
    expert_module_t *expert_zabbix;

    /* Register the protocol name and description */
    proto_zabbix = proto_register_protocol("Zabbix Protocol", "Zabbix", "zabbix");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_zabbix, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    zabbix_module = prefs_register_protocol(proto_zabbix, NULL);

    prefs_register_bool_preference(zabbix_module, "desegment",
        "Reassemble Zabbix messages spanning multiple TCP segments",
        "Whether the Zabbix protocol dissector should reassemble messages spanning multiple TCP segments."
        " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
        &zabbix_desegment);

    zabbix_handle = register_dissector("zabbix", dissect_zabbix, proto_zabbix);

    expert_zabbix = expert_register_protocol(proto_zabbix);
    expert_register_field_array(expert_zabbix, ei, array_length(ei));
}

void
proto_reg_handoff_zabbix(void)
{
    dissector_add_uint_range_with_preference("tcp.port", ZABBIX_TCP_PORTS, zabbix_handle);
    zabbix_port_range = prefs_get_range_value("Zabbix", "tcp.port");
    dissector_add_uint_range("tls.port", zabbix_port_range, zabbix_handle);
}
