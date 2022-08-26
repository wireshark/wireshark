/* packet-socks.c
 * Routines for socks versions 4 &5  packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 * Copyright 2008, Jelmer Vernooij <jelmer@samba.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *
 * The Version 4 decode is based on SOCKS4.protocol and SOCKS4A.protocol.
 * The Version 5 decoder is based upon rfc-1928
 * The Version 5 User/Password authentication is based on rfc-1929.
 *
 * See
 *  http://www.openssh.org/txt/socks4.protocol
 *  http://www.openssh.org/txt/socks4a.protocol
 *
 * for information on SOCKS version 4 and 4a.
 *
 * Revisions:
 *
 * 2003-09-18 JCFoster Fixed problem with socks tunnel in socks tunnel
 *          causing heap overflow because of an infinite loop
 *          where the socks dissect was call over and over.
 *
 *          Also remove some old code marked with __JUNK__
 *
 * 2001-01-08 JCFoster Fixed problem with NULL pointer for hash data.
 *          Now test and exit if hash_info is null.
 */

/* Possible enhancements -
 *
 * Add GSS-API authentication per rfc-1961
 * Add CHAP authentication
 * Decode FLAG bits per
 *  https://tools.ietf.org/html/draft-ietf-aft-socks-pro-v5-04
 * In call_next_dissector, could load the destination address into
 *  pinfo->src or pinfo->dst structure before calling next dissector.
*/




#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/proto_data.h>

#include "packet-tcp.h"
#include "packet-udp.h"
#include "packet-tls.h"

#include <epan/strutil.h>

#define TCP_PORT_SOCKS 1080


/**************** Socks commands ******************/

#define CONNECT_COMMAND         1
#define BIND_COMMAND            2
#define UDP_ASSOCIATE_COMMAND   3
#define PING_COMMAND            0x80
#define TRACERT_COMMAND         0x81


/********** V5 Authentication methods *************/

#define NO_AUTHENTICATION           0
#define GSS_API_AUTHENTICATION      1
#define USER_NAME_AUTHENTICATION    2
#define CHAP_AUTHENTICATION         3
#define AUTHENTICATION_FAILED       0xff

void proto_register_socks(void);
void proto_reg_handoff_socks(void);

/*********** Header field identifiers *************/

static int proto_socks = -1;

static int ett_socks = -1;
static int ett_socks_auth = -1;
static int ett_socks_name = -1;

static int hf_socks_ver = -1;
static int hf_socks_ip_dst = -1;
static int hf_socks_ip6_dst = -1;
static int hf_gssapi_payload = -1;
static int hf_gssapi_command = -1;
static int hf_gssapi_length = -1;
static int hf_v4a_dns_name = -1;
static int hf_socks_dstport = -1;
static int hf_socks_cmd = -1;
static int hf_socks_results_4 = -1;
static int hf_socks_results_5 = -1;
static int hf_client_auth_method_count = -1;
static int hf_client_auth_method = -1;
static int hf_socks_reserved = -1;
static int hf_socks_reserved2 = -1;
static int hf_client_port = -1;
static int hf_server_accepted_auth_method = -1;
static int hf_server_auth_status = -1;
static int hf_server_remote_host_port = -1;
static int hf_socks_subnegotiation_version = -1;
static int hf_socks_username = -1;
static int hf_socks_password = -1;
static int hf_socks_remote_name = -1;
static int hf_socks_address_type = -1;
static int hf_socks_fragment_number = -1;
static int hf_socks_ping_end_command = -1;
static int hf_socks_ping_results = -1;
static int hf_socks_traceroute_end_command = -1;
static int hf_socks_traceroute_results = -1;

/************* Dissector handles ***********/

static dissector_handle_t socks_handle;
static dissector_handle_t socks_handle_tls;
static dissector_handle_t socks_udp_handle;

/************* State Machine names ***********/

enum ClientState {
    clientNoInit = -1,
    clientStart = 0,
    clientWaitForAuthReply,
    clientV5Command,
    clientUserNameRequest,
    clientGssApiAuthRequest,
    clientDone,
    clientError
};

enum ServerState {
    serverNoInit = -1,
    serverStart = 0,
    serverInitReply,
    serverCommandReply,
    serverUserReply,
    serverGssApiReply,
    serverBindReply,
    serverDone,
    serverError
};

typedef struct {
    int in_socks_dissector_flag;
    enum ClientState client;
    enum ServerState server;
} sock_state_t;

typedef struct {
    enum ClientState clientState;
    enum ServerState serverState;
    int     version;
    int     command;
    int     authentication_method;
    guint32 server_port;
    guint32 port;
    guint32 udp_port;
    guint32 udp_remote_port;
    address dst_addr;

    guint32 start_done_frame;
}socks_hash_entry_t;


static const value_string address_type_table[] = {
    {1, "IPv4"},
    {3, "Domain Name"},
    {4, "IPv6"},
    {0, NULL}
};

/* String table for the V4 reply status messages */

static const value_string reply_table_v4[] = {
    {90, "Granted"},
    {91, "Rejected or Failed"},
    {92, "Rejected because SOCKS server cannot connect to identd on the client"},
    {93, "Rejected because the client program and identd report different user-ids"},
    {0, NULL}
};

/* String table for the V5 reply status messages */

static const value_string reply_table_v5[] = {
    {0, "Succeeded"},
    {1, "General SOCKS server failure"},
    {2, "Connection not allowed by ruleset"},
    {3, "Network unreachable"},
    {4, "Host unreachable"},
    {5, "Connection refused"},
    {6, "TTL expired"},
    {7, "Command not supported"},
    {8, "Address type not supported"},
    {0, NULL},
};

static const value_string cmd_strings[] = {
    {CONNECT_COMMAND,       "Connect"},
    {BIND_COMMAND,          "Bind"},
    {UDP_ASSOCIATE_COMMAND, "UdpAssociate"},
    {PING_COMMAND,          "Ping"},
    {TRACERT_COMMAND,       "Traceroute"},
    {0, NULL}
};

static const value_string gssapi_command_table[] = {
    { 1,    "Authentication" },
    { 0xFF, "Failure" },
    { 0, NULL }
};


/************************* Support routines ***************************/

static const char *get_auth_method_name( guint Number){

/* return the name of the authentication method */

    if ( Number == 0) return "No authentication";
    if ( Number == 1) return "GSSAPI";
    if ( Number == 2) return "Username/Password";
    if ( Number == 3) return "Chap";
    if (( Number >= 4) && ( Number <= 0x7f))return "IANA assigned";
    if (( Number >= 0x80) && ( Number <= 0xfe)) return "private method";
    if ( Number == 0xff) return "no acceptable method";

    /* shouldn't reach here */

    return "Bad method number (not 0-0xff)";
}

static int display_address(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree) {

/* decode and display the v5 address, return offset of next byte */

    int a_type = tvb_get_guint8(tvb, offset);

    proto_tree_add_item( tree, hf_socks_address_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    switch (a_type)
    {
    case 1: /* IPv4 address */
        proto_tree_add_item( tree, hf_socks_ip_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 3: /* domain name address */
        {
        guint8 len;
        gchar* str;

        len = tvb_get_guint8(tvb, offset);
        str = tvb_get_string_enc(pinfo->pool, tvb, offset+1, len, ENC_ASCII);
        proto_tree_add_string(tree, hf_socks_remote_name, tvb, offset, len+1, str);
        offset += (len+1);
        }
        break;
    case 4: /* IPv6 address */
        proto_tree_add_item( tree, hf_socks_ip6_dst, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;
    }

    return offset;
}


static int get_address_v5(tvbuff_t *tvb, int offset,
    socks_hash_entry_t *hash_info) {

    /* decode the v5 address and return offset of next byte */
    int     a_type;
    address addr;

    a_type = tvb_get_guint8(tvb, offset);
    offset += 1;

    switch(a_type)
    {
    case 1: /* IPv4 address */
        if ( hash_info) {
            set_address_tvb(&addr, AT_IPv4, 4, tvb, offset);
            copy_address_wmem(wmem_file_scope(), &hash_info->dst_addr, &addr);
        }
        offset += 4;
        break;

    case 4: /* IPv6 address */
        if ( hash_info) {
            set_address_tvb(&addr, AT_IPv6, 16, tvb, offset);
            copy_address_wmem(wmem_file_scope(), &hash_info->dst_addr, &addr);
        }
        offset += 16;
        break;

    case 3: /* domain name address */
        offset += tvb_get_guint8(tvb, offset) + 1;
        break;
    }

    return offset;
}


/********************* V5 UDP Associate handlers ***********************/

static int
socks_udp_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {

/* Conversation dissector called from UDP dissector. Decode and display */
/* the socks header, the pass the rest of the data to the udp port  */
/* decode routine to  handle the payload.               */

    int                 offset = 0;
    guint32            *ptr;
    socks_hash_entry_t *hash_info;
    conversation_t     *conversation;
    proto_tree         *socks_tree;
    proto_item         *ti;

    conversation = find_conversation_pinfo( pinfo, 0);

    DISSECTOR_ASSERT( conversation);    /* should always find a conversation */

    hash_info = (socks_hash_entry_t *)conversation_get_proto_data(conversation, proto_socks);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Socks");
    col_set_str(pinfo->cinfo, COL_INFO, "Version: 5, UDP Associated packet");

    if ( tree) {
        ti = proto_tree_add_protocol_format( tree, proto_socks, tvb, offset, -1, "Socks" );

        socks_tree = proto_item_add_subtree(ti, ett_socks);

        proto_tree_add_item(socks_tree, hf_socks_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(socks_tree, hf_socks_fragment_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        offset = display_address(pinfo, tvb, offset, socks_tree);
        hash_info->udp_remote_port = tvb_get_ntohs(tvb, offset);

        proto_tree_add_uint( socks_tree, hf_socks_dstport, tvb,
            offset, 2, hash_info->udp_remote_port);

        offset += 2;
    }
    else {      /* no tree, skip past the socks header */
        offset += 3;
        offset = get_address_v5( tvb, offset, 0) + 2;
    }

    /* set pi src/dst port and call the udp sub-dissector lookup */

    if ( pinfo->srcport == hash_info->port)
        ptr = &pinfo->destport;
    else
        ptr = &pinfo->srcport;

    *ptr = hash_info->udp_remote_port;

    decode_udp_ports( tvb, offset, pinfo, tree, pinfo->srcport, pinfo->destport, -1);

    *ptr = hash_info->udp_port;
    return tvb_captured_length(tvb);
}


static void
new_udp_conversation( socks_hash_entry_t *hash_info, packet_info *pinfo){

    conversation_t *conversation = conversation_new( pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_UDP,
            hash_info->udp_port, hash_info->port, 0);

    DISSECTOR_ASSERT( conversation);

    conversation_add_proto_data(conversation, proto_socks, hash_info);
    conversation_set_dissector(conversation, socks_udp_handle);
}

static void
save_client_state(packet_info *pinfo, enum ClientState state)
{
    sock_state_t* state_info = (sock_state_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_socks, 0);
    if ((state_info != NULL) && (state_info->client == clientNoInit)) {
        state_info->client = state;
    }
}

static void
save_server_state(packet_info *pinfo, enum ServerState state)
{
    sock_state_t* state_info = (sock_state_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_socks, 0);
    if ((state_info != NULL) && (state_info->server == serverNoInit)) {
        state_info->server = state;
    }
}


/**************** Protocol Tree Display routines  ******************/

static void
display_socks_v4(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, socks_hash_entry_t *hash_info, sock_state_t* state_info) {


/* Display the protocol tree for the V4 version. This routine uses the  */
/* stored frame information to decide what to do with the row.  */

    unsigned char ipaddr[4];
    guint         str_len;

    /* Either there is an error, or we're done with the state machine
      (so there's nothing to display) */
    if (state_info == NULL)
        return;

    if (hash_info->server_port == pinfo->destport) {
        /* Client side */
        switch (state_info->client)
        {
        case clientStart:
            proto_tree_add_item( tree, hf_socks_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item( tree, hf_socks_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            /* Do remote port */
            proto_tree_add_item( tree, hf_socks_dstport, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Do destination address */
            tvb_memcpy(tvb, ipaddr, offset, 4);
            proto_tree_add_item( tree, hf_socks_ip_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* display user name */
            str_len = tvb_strsize(tvb, offset);
            proto_tree_add_item( tree, hf_socks_username, tvb, offset, str_len, ENC_ASCII);
            offset += str_len;

            if ( ipaddr[0] == 0 && ipaddr[1] == 0 &&
                 ipaddr[2] == 0 && ipaddr[3] != 0) {
                /* 0.0.0.x , where x!=0 means v4a support */
                str_len = tvb_strsize(tvb, offset);
                proto_tree_add_item( tree, hf_v4a_dns_name, tvb, offset, str_len, ENC_ASCII);
            }
            break;
        default:
            break;
        }
    } else {
        /* Server side */
        switch (state_info->server)
        {
        case serverStart:
            proto_tree_add_item( tree, hf_socks_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
                            /* Do results code */
            proto_tree_add_item( tree, hf_socks_results_4, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

                            /* Do remote port */
            proto_tree_add_item( tree, hf_socks_dstport, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
                            /* Do remote address */
            proto_tree_add_item( tree, hf_socks_ip_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
        default:
            break;
        }
    }
}

static void
client_display_socks_v5(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, socks_hash_entry_t *hash_info, sock_state_t* state_info) {

/* Display the protocol tree for the version. This routine uses the */
/* stored conversation information to decide what to do with the row.   */
/* Per packet information would have been better to do this, but we */
/* didn't have that when I wrote this. And I didn't expect this to get  */
/* so messy.                                */

    unsigned int  i;
    const char   *AuthMethodStr;
    sock_state_t  new_state_info;
    proto_item *ti;

    /* Either there is an error, or we're done with the state machine
      (so there's nothing to display) */
    if (state_info == NULL)
        return;

    if (state_info->client == clientStart)
    {
        proto_tree      *AuthTree;
        guint8 num_auth_methods, auth;

        col_append_str(pinfo->cinfo, COL_INFO, " Connect to server request");

        proto_tree_add_item( tree, hf_socks_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        AuthTree = proto_tree_add_subtree( tree, tvb, offset, -1, ett_socks_auth, &ti, "Client Authentication Methods");

        num_auth_methods = tvb_get_guint8(tvb, offset);
        proto_item_set_len(ti, num_auth_methods+1);

        proto_tree_add_item( AuthTree, hf_client_auth_method_count, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        for( i = 0; i  < num_auth_methods; ++i) {
            auth = tvb_get_guint8( tvb, offset);
            AuthMethodStr = get_auth_method_name(auth);

            proto_tree_add_uint_format(AuthTree, hf_client_auth_method, tvb, offset, 1, auth,
                                        "Method[%u]: %u (%s)", i, auth, AuthMethodStr);
            offset += 1;
        }

        if ((num_auth_methods == 1) &&
            (tvb_bytes_exist(tvb, offset + 2, 1)) &&
            (tvb_get_guint8(tvb, offset + 2) == 0) &&
            (tvb_reported_length_remaining(tvb, offset + 2 + num_auth_methods) > 0)) {
                new_state_info.client = clientV5Command;
                client_display_socks_v5(tvb, offset, pinfo, tree, hash_info, &new_state_info);
        }
    }
    else if (state_info->client == clientV5Command) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Command Request - %s",
                val_to_str_const(hash_info->command, cmd_strings, "Unknown"));

        proto_tree_add_item( tree, hf_socks_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item( tree, hf_socks_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item( tree, hf_socks_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        offset = display_address(pinfo, tvb, offset, tree);
        proto_tree_add_item( tree, hf_client_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
    else if ((state_info->client == clientWaitForAuthReply) &&
             (state_info->server == serverInitReply)) {
        guint16 len;
        gchar* str;

        ti = proto_tree_add_uint( tree, hf_socks_ver, tvb, offset, 0, 5);
        proto_item_set_generated(ti);

        proto_tree_add_item( tree, hf_socks_subnegotiation_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        switch(hash_info->authentication_method)
        {
        case NO_AUTHENTICATION:
            break;
        case USER_NAME_AUTHENTICATION:
            col_append_str(pinfo->cinfo, COL_INFO, " User authentication request");

            /* process user name */
            len = tvb_get_guint8(tvb, offset);
            str = tvb_get_string_enc(pinfo->pool, tvb, offset+1, len, ENC_ASCII);
            proto_tree_add_string(tree, hf_socks_username, tvb, offset, len+1, str);
            offset += (len+1);

            len = tvb_get_guint8(tvb, offset);
            str = tvb_get_string_enc(pinfo->pool, tvb, offset+1, len, ENC_ASCII);
            proto_tree_add_string(tree, hf_socks_password, tvb, offset, len+1, str);
            /* offset += (len+1); */
            break;
        case GSS_API_AUTHENTICATION:
            col_append_str(pinfo->cinfo, COL_INFO, " GSSAPI authentication request");

            proto_tree_add_item( tree, hf_gssapi_command, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item( tree, hf_gssapi_length, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            len = tvb_get_ntohs(tvb, offset+1);
            if (len > 0)
                proto_tree_add_item( tree, hf_gssapi_payload, tvb, offset+3, len, ENC_NA);
            break;
        default:
            break;
        }
    }
    else {
        if (hash_info->port != 0)
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Remote Port: %u",
                hash_info->port);
    }
}

static void
server_display_socks_v5(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, socks_hash_entry_t *hash_info _U_, sock_state_t* state_info) {

/* Display the protocol tree for the version. This routine uses the */
/* stored conversation information to decide what to do with the row.   */
/* Per packet information would have been better to do this, but we */
/* didn't have that when I wrote this. And I didn't expect this to get  */
/* so messy.                                */

    const char *AuthMethodStr;
    guint8      auth, auth_status;
    proto_item *ti;

    /* Either there is an error, or we're done with the state machine
      (so there's nothing to display) */
    if (state_info == NULL)
        return;

    switch(state_info->server)
    {
    case serverStart:
        col_append_str(pinfo->cinfo, COL_INFO, " Connect to server response");

        proto_tree_add_item( tree, hf_socks_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        auth = tvb_get_guint8( tvb, offset);
        AuthMethodStr = get_auth_method_name(auth);

        proto_tree_add_uint_format_value(tree, hf_server_accepted_auth_method, tvb, offset, 1, auth,
                                        "0x%0x (%s)", auth, AuthMethodStr);
        break;

    case serverUserReply:
        col_append_str(pinfo->cinfo, COL_INFO, " User authentication reply");

        ti = proto_tree_add_uint( tree, hf_socks_ver, tvb, offset, 0, 5);
        proto_item_set_generated(ti);

        proto_tree_add_item( tree, hf_socks_subnegotiation_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        auth_status = tvb_get_guint8(tvb, offset);
        ti = proto_tree_add_item(tree, hf_server_auth_status, tvb, offset, 1, ENC_BIG_ENDIAN);
        if(auth_status != 0)
            proto_item_append_text(ti, " (failure)");
        else
            proto_item_append_text(ti, " (success)");
        break;

    case serverGssApiReply:
        col_append_str(pinfo->cinfo, COL_INFO, " GSSAPI authentication reply");

        ti = proto_tree_add_uint( tree, hf_socks_ver, tvb, offset, 0, 5);
        proto_item_set_generated(ti);

        proto_tree_add_item( tree, hf_socks_subnegotiation_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        auth_status = tvb_get_guint8(tvb, offset);
        proto_tree_add_item( tree, hf_gssapi_command, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (auth_status != 0xFF) {
            guint16 len;

            proto_tree_add_item( tree, hf_gssapi_length, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            len = tvb_get_ntohs(tvb, offset+1);
            if (len > 0)
                proto_tree_add_item( tree, hf_gssapi_payload, tvb, offset+3, len, ENC_NA);
        }
        break;

    case serverCommandReply:
        col_append_fstr(pinfo->cinfo, COL_INFO, " Command Response - %s",
                val_to_str_const(hash_info->command, cmd_strings, "Unknown"));

        proto_tree_add_item( tree, hf_socks_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item( tree, hf_socks_results_5, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item( tree, hf_socks_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        offset = display_address(pinfo, tvb, offset, tree);
        proto_tree_add_item( tree, hf_client_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;

    case serverBindReply:
        col_append_str(pinfo->cinfo, COL_INFO, " Command Response: Bind remote host info");

        proto_tree_add_item( tree, hf_socks_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item( tree, hf_socks_results_5, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item( tree, hf_socks_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        offset = display_address(pinfo, tvb, offset, tree);
        proto_tree_add_item( tree, hf_server_remote_host_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;

    default:
        if ( hash_info->port != 0)
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Remote Port: %u",
                hash_info->port);

        break;
    }
}


/**************** Decoder State Machines ******************/


static void
state_machine_v4( socks_hash_entry_t *hash_info, tvbuff_t *tvb,
    int offset, packet_info *pinfo) {

/* Decode V4 protocol.  This is done on the first pass through the  */
/* list.  Based upon the current state, decode the packet and determine */
/* what the next state should be.  */
    address addr;

    if (hash_info->clientState != clientDone)
        save_client_state(pinfo, hash_info->clientState);

    if (hash_info->serverState != serverDone)
        save_server_state(pinfo, hash_info->serverState);

    if (hash_info->server_port == pinfo->destport) {
        /* Client side, only a single request */
        col_append_str(pinfo->cinfo, COL_INFO, " Connect to server request");

        hash_info->command = tvb_get_guint8(tvb, offset + 1);

        /* get remote port */
        if ( hash_info->command == CONNECT_COMMAND)
            hash_info->port =  tvb_get_ntohs(tvb, offset + 2);

        /* get remote address */
        set_address_tvb(&addr, AT_IPv4, 4, tvb, offset);
        copy_address_wmem(wmem_file_scope(), &hash_info->dst_addr, &addr);

        hash_info->clientState = clientDone;
    }
    else {
        col_append_str(pinfo->cinfo, COL_INFO, " Connect Response");

        if (tvb_get_guint8(tvb, offset + 1) == 90)
            hash_info->serverState = serverDone;
        else
            hash_info->serverState = serverError;
    }
}

static void
client_state_machine_v5( socks_hash_entry_t *hash_info, tvbuff_t *tvb,
    int offset, packet_info *pinfo, gboolean start_of_frame) {

/* Decode client side of V5 protocol.  This is done on the first pass through the   */
/* list.  Based upon the current state, decode the packet and determine */
/* what the next state should be. */

    if (start_of_frame) {
        save_client_state(pinfo, hash_info->clientState);
        save_server_state(pinfo, hash_info->serverState);
    }

    if (hash_info->clientState == clientStart)
    {
        guint8 num_auth_methods;

        num_auth_methods = tvb_get_guint8(tvb, offset + 1);
                        /* skip past auth methods */

        if ((num_auth_methods == 0) ||
            ((num_auth_methods == 1) &&
             (tvb_get_guint8(tvb, offset + 2) == 0))) {
            /* No authentication needed */
            hash_info->clientState = clientV5Command;
            if (tvb_reported_length_remaining(tvb, offset + 2 + num_auth_methods) > 0) {
                client_state_machine_v5(hash_info, tvb, offset + 2 + num_auth_methods, pinfo, FALSE);
            }
        } else {
            hash_info->clientState = clientWaitForAuthReply;
        }
    } else if ((hash_info->clientState == clientWaitForAuthReply) &&
               (hash_info->serverState == serverInitReply)) {

        switch(hash_info->authentication_method)
        {
        case NO_AUTHENTICATION:
            hash_info->clientState = clientV5Command;
            hash_info->serverState = serverCommandReply;
            break;
        case USER_NAME_AUTHENTICATION:
            hash_info->clientState = clientV5Command;
            hash_info->serverState = serverUserReply;
            break;
        case GSS_API_AUTHENTICATION:
            hash_info->clientState = clientV5Command;
            hash_info->serverState = serverGssApiReply;
            break;
        default:
            hash_info->clientState = clientError;   /*Auth failed or error*/
            break;
        }
    } else if (hash_info->clientState == clientV5Command) {
        hash_info->command = tvb_get_guint8(tvb, offset + 1); /* get command */

        offset += 3;            /* skip to address type */

        offset = get_address_v5(tvb, offset, hash_info);

        /** temp = tvb_get_guint8(tvb, offset);  XX: what was this for ? **/

        if (( hash_info->command == CONNECT_COMMAND) ||
            ( hash_info->command == UDP_ASSOCIATE_COMMAND))
                        /* get remote port  */
            hash_info->port =  tvb_get_ntohs(tvb, offset);

        hash_info->clientState = clientDone;
    }
}

static void
server_state_machine_v5( socks_hash_entry_t *hash_info, tvbuff_t *tvb,
    int offset, packet_info *pinfo, gboolean start_of_frame) {

/* Decode server side of V5 protocol.  This is done on the first pass through the   */
/* list.  Based upon the current state, decode the packet and determine */
/* what the next state should be. */

    if (start_of_frame)
        save_server_state(pinfo, hash_info->serverState);

    switch (hash_info->serverState) {
    case serverStart:
        hash_info->authentication_method = tvb_get_guint8(tvb, offset + 1);
        switch (hash_info->authentication_method)
        {
        case NO_AUTHENTICATION:
            /* If there is no authentication, client should expect command immediately */
            hash_info->serverState = serverCommandReply;
            hash_info->clientState = clientV5Command;
            break;
        case USER_NAME_AUTHENTICATION:
            hash_info->serverState = serverInitReply;
            break;
        case GSS_API_AUTHENTICATION:
            hash_info->serverState = serverInitReply;
            break;
        default:
            hash_info->serverState = serverError;
            break;
        }
        break;
    case serverUserReply:
        hash_info->serverState = serverCommandReply;
        break;
    case serverGssApiReply:
        if (tvb_get_guint8(tvb, offset+1) == 0xFF) {
            hash_info->serverState = serverError;
        } else {
            if (tvb_get_ntohs(tvb, offset+2) == 0)
                hash_info->serverState = serverCommandReply;
        }
        break;
    case serverCommandReply:
        switch(hash_info->command)
        {
        case CONNECT_COMMAND:
        case PING_COMMAND:
        case TRACERT_COMMAND:
            hash_info->serverState = serverDone;
            break;

        case BIND_COMMAND:
            hash_info->serverState = serverBindReply;
            if ((tvb_get_guint8(tvb, offset + 2) == 0) &&
                (tvb_reported_length_remaining(tvb, offset) > 5)) {
                    offset = display_address(pinfo, tvb, offset, NULL);
                    client_state_machine_v5(hash_info, tvb, offset, pinfo, FALSE);
            }
            break;

        case UDP_ASSOCIATE_COMMAND:
            offset += 3;        /* skip to address type */
            offset = get_address_v5(tvb, offset, hash_info);

            /* save server udp port and create udp conversation */
            hash_info->udp_port =  tvb_get_ntohs(tvb, offset);

            if (!pinfo->fd->visited)
                new_udp_conversation( hash_info, pinfo);

            break;
        }
        break;
    case serverBindReply:
        break;
    default:
        break;
    }
}


static void
display_ping_and_tracert(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, socks_hash_entry_t *hash_info) {

/* Display the ping/trace_route conversation */

    const guchar *data, *dataend;
    const guchar *lineend, *eol;
    int           linelen;

                /* handle the end command */
    if ( pinfo->destport == TCP_PORT_SOCKS){
        col_append_str(pinfo->cinfo, COL_INFO, ", Terminate Request");

        proto_tree_add_item(tree, (hash_info->command  == PING_COMMAND) ? hf_socks_ping_end_command : hf_socks_traceroute_end_command, tvb, offset, 1, ENC_NA);
    }
    else {      /* display the PING or Traceroute results */
        col_append_str(pinfo->cinfo, COL_INFO, ", Results");

        if ( tree){
            proto_tree_add_item(tree, (hash_info->command  == PING_COMMAND) ? hf_socks_ping_results : hf_socks_traceroute_results, tvb, offset, -1, ENC_NA);

            data = tvb_get_ptr(tvb, offset, -1);
            dataend = data + tvb_captured_length_remaining(tvb, offset);

            while (data < dataend) {

                lineend = find_line_end(data, dataend, &eol);
                linelen = (int)(lineend - data);

                proto_tree_add_format_text( tree, tvb, offset, linelen);
                offset += linelen;
                data = lineend;
            }
        }
    }
}

static void clear_in_socks_dissector_flag(void *s)
{
    sock_state_t* state_info = (sock_state_t*)s;
    state_info->in_socks_dissector_flag = 0; /* avoid recursive overflow */
}

static void call_next_dissector(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, proto_tree *socks_tree,
    socks_hash_entry_t *hash_info, sock_state_t* state_info, struct tcpinfo *tcpinfo)
{

/* Display the results for PING and TRACERT extensions or       */
/* Call TCP dissector for the port that was passed during the           */
/* connect process                                  */
/* Load pointer to pinfo->XXXport depending upon the direction,     */
/* change pinfo port to the remote port, call next dissector to decode  */
/* the payload, and restore the pinfo port after that is done.      */

    guint32 *ptr;
    guint16 save_can_desegment;
    struct tcp_analysis *tcpd=NULL;


    if (( hash_info->command  == PING_COMMAND) ||
        ( hash_info->command  == TRACERT_COMMAND))

        display_ping_and_tracert(tvb, offset, pinfo, tree, hash_info);

    else {      /* call the tcp port decoder to handle the payload */

/*XXX may want to load dest address here */

        if (pinfo->destport == TCP_PORT_SOCKS) {
            ptr = &pinfo->destport;
        } else {
            ptr = &pinfo->srcport;
        }

        *ptr = hash_info->port;

        tcpd = get_tcp_conversation_data(NULL, pinfo);
/* 2003-09-18 JCFoster Fixed problem with socks tunnel in socks tunnel */

        state_info->in_socks_dissector_flag = 1; /* avoid recursive overflow */
        CLEANUP_PUSH(clear_in_socks_dissector_flag, state_info);

        save_can_desegment = pinfo->can_desegment;
        pinfo->can_desegment = pinfo->saved_can_desegment;
        dissect_tcp_payload(tvb, pinfo, offset, tcpinfo->seq,
            tcpinfo->nxtseq, pinfo->srcport, pinfo->destport,
            tree, socks_tree, tcpd, tcpinfo);
        pinfo->can_desegment = save_can_desegment;

        CLEANUP_CALL_AND_POP;

        *ptr = TCP_PORT_SOCKS;
    }
}



static int
dissect_socks(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {

    int                 offset     = 0;
    proto_tree         *socks_tree = NULL;
    proto_item         *ti;
    socks_hash_entry_t *hash_info;
    conversation_t     *conversation;
    sock_state_t*       state_info;
    guint8              version;
    struct tcpinfo     *tcpinfo    = (struct tcpinfo*)data;

    state_info = (sock_state_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_socks, 0);
    if (state_info == NULL) {
        state_info = wmem_new(wmem_file_scope(), sock_state_t);
        state_info->in_socks_dissector_flag = 0;
        state_info->client = clientNoInit;
        state_info->server = serverNoInit;

        p_add_proto_data(wmem_file_scope(), pinfo, proto_socks, 0, state_info);
    }

    /* avoid recursive overflow */
    if (state_info->in_socks_dissector_flag)
        return 0;

    conversation = find_conversation_pinfo(pinfo, 0);
    if (conversation == NULL) {
        /* If we don't already have a conversation, make sure the first
           byte is a valid version number */
        version = tvb_get_guint8(tvb, offset);
        if ((version != 4) && (version != 5))
            return 0;

        conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst,
                                        conversation_pt_to_conversation_type(pinfo->ptype), pinfo->srcport, pinfo->destport, 0);
    }

    hash_info = (socks_hash_entry_t *)conversation_get_proto_data(conversation,proto_socks);
    if (hash_info == NULL){
        hash_info = wmem_new0(wmem_file_scope(), socks_hash_entry_t);
        hash_info->start_done_frame = G_MAXINT;
        hash_info->clientState = clientStart;
        hash_info->serverState = serverStart;

        hash_info->server_port = pinfo->destport;
        hash_info->port = 0;
        hash_info->version = tvb_get_guint8(tvb, offset); /* get version*/

        conversation_add_proto_data(conversation, proto_socks, hash_info);

                        /* set dissector for now */
        if (conversation_get_dissector(conversation, pinfo->num) != NULL) {
            conversation_set_dissector(conversation, socks_handle);
        }
    }

    /* display summary window information  */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Socks");

    if (( hash_info->version == 4) || ( hash_info->version == 5)){
        col_add_fstr(pinfo->cinfo, COL_INFO, "Version: %d",
            hash_info->version);
    }
    else            /* unknown version display error */
        col_set_str(pinfo->cinfo, COL_INFO, "Unknown");


    if ( hash_info->command == PING_COMMAND)
        col_append_str(pinfo->cinfo, COL_INFO, ", Ping Req");
    if ( hash_info->command == TRACERT_COMMAND)
        col_append_str(pinfo->cinfo, COL_INFO, ", Traceroute Req");

    /* run state machine if needed */
    if ((!pinfo->fd->visited) &&
        (!((hash_info->clientState == clientDone) &&
           (hash_info->serverState == serverDone)))) {

        if (hash_info->server_port == pinfo->destport) {
            if ((hash_info->clientState != clientError) &&
                (hash_info->clientState != clientDone))
            {
                if ( hash_info->version == 4) {
                    state_machine_v4( hash_info, tvb, offset, pinfo);
                } else if ( hash_info->version == 5) {
                    client_state_machine_v5( hash_info, tvb, offset, pinfo, TRUE);
                }
            }
        } else {
            if ((hash_info->serverState != serverError) &&
                (hash_info->serverState != serverDone)) {
                if ( hash_info->version == 4) {
                    state_machine_v4( hash_info, tvb, offset, pinfo);
                } else if ( hash_info->version == 5) {
                    server_state_machine_v5( hash_info, tvb, offset, pinfo, TRUE);
                }
            }
        }

        if ((hash_info->clientState == clientDone) &&
            (hash_info->serverState == serverDone)) {   /* if done now  */
            hash_info->start_done_frame = pinfo->num;
        }
    }

    /* if proto tree, decode and display */
    if (tree) {
        ti = proto_tree_add_item( tree, proto_socks, tvb, offset, -1, ENC_NA );
        socks_tree = proto_item_add_subtree(ti, ett_socks);

        /* if past startup, add the faked stuff */
        if ( pinfo->num > hash_info->start_done_frame){
                        /*  add info to tree */
            ti = proto_tree_add_uint( socks_tree, hf_socks_ver, tvb, offset, 0, hash_info->version);
            proto_item_set_generated(ti);

            ti = proto_tree_add_uint( socks_tree, hf_socks_cmd, tvb, offset, 0, hash_info->command);
            proto_item_set_generated(ti);

            if (hash_info->dst_addr.type == AT_IPv4) {
                ti = proto_tree_add_ipv4( socks_tree, hf_socks_ip_dst, tvb,
                    offset, 0, *((const guint32*)hash_info->dst_addr.data));
                proto_item_set_generated(ti);
            } else if (hash_info->dst_addr.type == AT_IPv6) {
                ti = proto_tree_add_ipv6( socks_tree, hf_socks_ip6_dst, tvb,
                    offset, 0, (const ws_in6_addr *)hash_info->dst_addr.data);
                proto_item_set_generated(ti);
            }

                /* no fake address for ping & traceroute */

            if (( hash_info->command != PING_COMMAND) &&
                ( hash_info->command != TRACERT_COMMAND)){
                ti = proto_tree_add_uint( socks_tree, hf_socks_dstport, tvb, offset, 0, hash_info->port);
                proto_item_set_generated(ti);
            }
        } else {
            if (hash_info->server_port == pinfo->destport) {
                if ( hash_info->version == 4) {
                    display_socks_v4(tvb, offset, pinfo, socks_tree, hash_info, state_info);
                } else if ( hash_info->version == 5) {
                    client_display_socks_v5(tvb, offset, pinfo, socks_tree, hash_info, state_info);
                }
            } else {
                if ( hash_info->version == 4) {
                    display_socks_v4(tvb, offset, pinfo, socks_tree, hash_info, state_info);
                } else if ( hash_info->version == 5) {
                    server_display_socks_v5(tvb, offset, pinfo, socks_tree, hash_info, state_info);
                }
            }
        }

    }


    /* call next dissector if ready */
    if ( pinfo->num > hash_info->start_done_frame){
        call_next_dissector(tvb, offset, pinfo, tree, socks_tree,
            hash_info, state_info, tcpinfo);
    }

    return tvb_reported_length(tvb);
}


static int
dissect_socks_tls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    if (data != NULL) {
        return dissect_socks(tvb, pinfo, tree, data);
    } else {
        /* lets fake a tcpinfo, which TLS does not give us */
        struct tcpinfo tmp;
        tmp.flags = 0;
        tmp.is_reassembled = FALSE;
        tmp.lastackseq = 0;
        tmp.nxtseq = 0;
        tmp.seq = 0;
        tmp.urgent_pointer = 0;
        return dissect_socks(tvb, pinfo, tree, &tmp);
    }
}

void
proto_register_socks( void){

    static gint *ett[] = {
        &ett_socks,
        &ett_socks_auth,
        &ett_socks_name
    };

    static hf_register_info hf[] = {


        { &hf_socks_ver,
            { "Version", "socks.version", FT_UINT8, BASE_DEC, NULL,
                0x0, NULL, HFILL
            }
        },
        { &hf_socks_ip_dst,
            { "Remote Address", "socks.dst", FT_IPv4, BASE_NONE, NULL,
                0x0, NULL, HFILL
            }
        },
        { &hf_socks_ip6_dst,
            { "Remote Address(ipv6)", "socks.dstV6", FT_IPv6, BASE_NONE, NULL,
                0x0, NULL, HFILL
            }
        },
        { &hf_gssapi_payload,
            { "GSSAPI data", "socks.gssapi.data", FT_BYTES, BASE_NONE, NULL,
                0x0, NULL, HFILL
            }
        },
        { &hf_gssapi_command,
            { "SOCKS/GSSAPI command", "socks.gssapi.command", FT_UINT8, BASE_DEC,
                VALS(gssapi_command_table), 0x0, NULL, HFILL
            }
        },
        { &hf_gssapi_length,
            { "SOCKS/GSSAPI data length", "socks.gssapi.length", FT_UINT16, BASE_DEC, NULL,
                0x0, NULL, HFILL
            }
        },
        { &hf_v4a_dns_name,
            { "SOCKS v4a Remote Domain Name", "socks.v4a_dns_name", FT_STRINGZ, BASE_NONE,
                NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_dstport,
            { "Remote Port", "socks.dstport", FT_UINT16,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_cmd,
            { "Command", "socks.command", FT_UINT8,
                BASE_DEC,  VALS(cmd_strings), 0x0, NULL, HFILL
            }
        },
        { &hf_socks_results_4,
            { "Results(V4)", "socks.results", FT_UINT8,
                BASE_DEC, VALS(reply_table_v4), 0x0, NULL, HFILL
            }
        },
        { &hf_socks_results_5,
            { "Results(V5)", "socks.results", FT_UINT8,
                BASE_DEC, VALS(reply_table_v5), 0x0, NULL, HFILL
            }
        },
        { &hf_client_auth_method_count,
            { "Authentication Method Count", "socks.auth_method_count", FT_UINT8,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_client_auth_method,
            { "Method", "socks.auth_method", FT_UINT8,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_reserved,
            { "Reserved", "socks.reserved", FT_UINT8,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_reserved2,
            { "Reserved", "socks.reserved", FT_UINT16,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_client_port,
            { "Port", "socks.port", FT_UINT16,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_server_accepted_auth_method,
            { "Accepted Auth Method", "socks.auth_accepted_method", FT_UINT8,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_server_auth_status,
            { "Status", "socks.auth_status", FT_UINT8,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_server_remote_host_port,
            { "Remote Host Port", "socks.remote_host_port", FT_UINT16,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_subnegotiation_version,
            { "Subnegotiation Version", "socks.subnegotiation_version", FT_UINT8, BASE_DEC, NULL,
                0x0, NULL, HFILL
            }
        },
        { &hf_socks_username,
            { "User name", "socks.username", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_password,
            { "Password", "socks.password", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_remote_name,
            { "Remote name", "socks.remote_name", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_address_type,
            { "Address Type", "socks.address_type", FT_UINT8,
                BASE_DEC, VALS(address_type_table), 0x0, NULL, HFILL
            }
        },
        { &hf_socks_fragment_number,
            { "Fragment Number", "socks.fragment_number", FT_UINT8,
                BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_ping_end_command,
            { "Ping: End command", "socks.ping_end_command", FT_NONE,
                BASE_NONE, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_ping_results,
            { "Ping Results", "socks.ping_results", FT_NONE,
                BASE_NONE, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_traceroute_end_command,
            { "Traceroute: End command", "socks.traceroute_end_command", FT_NONE,
                BASE_NONE, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_socks_traceroute_results,
            { "Traceroute Results", "socks.traceroute_results", FT_NONE,
                BASE_NONE, NULL, 0x0, NULL, HFILL
            }
        },
    };

    proto_socks = proto_register_protocol ( "Socks Protocol", "Socks", "socks");

    proto_register_field_array(proto_socks, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_socks(void) {

    /* dissector install routine */
    socks_udp_handle = create_dissector_handle(socks_udp_dissector, proto_socks);
    socks_handle = create_dissector_handle(dissect_socks, proto_socks);
    socks_handle_tls = register_dissector("SOCKS over TLS", dissect_socks_tls, proto_socks);

    dissector_add_uint_with_preference("tcp.port", TCP_PORT_SOCKS, socks_handle);

    ssl_dissector_add(0, socks_handle_tls);
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
