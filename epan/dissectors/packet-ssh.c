/* packet-ssh.c
 * Routines for ssh packet dissection
 *
 * Huagang XIE <huagang@intruvert.com>
 * Kees Cook <kees@outflux.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-mysql.c
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
 *
 *
 * Note:  support SSH v1 and v2  now.
 *
 */

/* SSH version 2 is defined in:
 *
 * RFC 4250: The Secure Shell (SSH) Protocol Assigned Numbers
 * RFC 4251: The Secure Shell (SSH) Protocol Architecture
 * RFC 4252: The Secure Shell (SSH) Authentication Protocol
 * RFC 4253: The Secure Shell (SSH) Transport Layer Protocol
 * RFC 4254: The Secure Shell (SSH) Connection Protocol
 *
 * SSH versions under 2 were never officially standardized.
 *
 * Diffie-Hellman Group Exchange is defined in:
 *
 * RFC 4419: Diffie-Hellman Group Exchange for
 *   the Secure Shell (SSH) Transport Layer Protocol
 */

/* "SSH" prefixes are for version 2, whereas "SSH1" is for version 1 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/sctpppids.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-tcp.h"

void proto_register_ssh(void);
void proto_reg_handoff_ssh(void);

/* SSH Version 1 definition , from openssh ssh1.h */
#define SSH1_MSG_NONE           0   /* no message */
#define SSH1_MSG_DISCONNECT     1   /* cause (string) */
#define SSH1_SMSG_PUBLIC_KEY    2   /* ck,msk,srvk,hostk */
#define SSH1_CMSG_SESSION_KEY   3   /* key (BIGNUM) */
#define SSH1_CMSG_USER          4   /* user (string) */


#define SSH_VERSION_UNKNOWN     0
#define SSH_VERSION_1           1
#define SSH_VERSION_2           2

/* proto data */

struct ssh_peer_data {
    guint   counter;

    guint32 frame_version_start;
    guint32 frame_version_end;

    guint32 frame_key_start;
    guint32 frame_key_end;
    int frame_key_end_offset;

    gchar*  kex_proposal;

    /* For all subsequent proposals,
       [0] is client-to-server and [1] is server-to-client. */
#define CLIENT_TO_SERVER_PROPOSAL 0
#define SERVER_TO_CLIENT_PROPOSAL 1

    gchar*  mac_proposals[2];
    gchar*  mac;
    gint    mac_length;

    gchar*  enc_proposals[2];
    gchar*  enc;

    gchar*  comp_proposals[2];
    gchar*  comp;

    gint    length_is_plaintext;
};

struct ssh_flow_data {
    guint   version;

    gchar*  kex;
    int   (*kex_specific_dissector)(guint8 msg_code, tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);

    /* [0] is client's, [1] is server's */
#define CLIENT_PEER_DATA 0
#define SERVER_PEER_DATA 1
    struct ssh_peer_data peer_data[2];
};

static int proto_ssh = -1;
static int hf_ssh_packet_length= -1;
static int hf_ssh_packet_length_encrypted= -1;
static int hf_ssh_padding_length= -1;
static int hf_ssh_payload= -1;
static int hf_ssh_protocol= -1;
static int hf_ssh_dh_gex_min= -1;
static int hf_ssh_dh_gex_nbits= -1;
static int hf_ssh_dh_gex_max= -1;
static int hf_ssh_encrypted_packet= -1;
static int hf_ssh_padding_string= -1;
static int hf_ssh_mac_string= -1;
static int hf_ssh_msg_code = -1;
static int hf_ssh2_msg_code = -1;
static int hf_ssh2_kex_dh_msg_code = -1;
static int hf_ssh2_kex_dh_gex_msg_code = -1;
static int hf_ssh_cookie = -1;
static int hf_ssh_mpint_g= -1;
static int hf_ssh_mpint_p= -1;
static int hf_ssh_mpint_e= -1;
static int hf_ssh_mpint_f= -1;
static int hf_ssh_mpint_length= -1;
static int hf_ssh_kexdh_host_key= -1;
static int hf_ssh_hostkey_length= -1;
static int hf_ssh_hostkey_type= -1;
static int hf_ssh_hostkey_data= -1;
static int hf_ssh_hostkey_rsa_n= -1;
static int hf_ssh_hostkey_rsa_e= -1;
static int hf_ssh_kexdh_h_sig= -1;
static int hf_ssh_kexdh_h_sig_length= -1;
static int hf_ssh_kex_algorithms = -1;
static int hf_ssh_server_host_key_algorithms = -1;
static int hf_ssh_encryption_algorithms_client_to_server = -1;
static int hf_ssh_encryption_algorithms_server_to_client = -1;
static int hf_ssh_mac_algorithms_client_to_server=-1;
static int hf_ssh_mac_algorithms_server_to_client=-1;
static int hf_ssh_compression_algorithms_client_to_server=-1;
static int hf_ssh_compression_algorithms_server_to_client=-1;
static int hf_ssh_languages_client_to_server=-1;
static int hf_ssh_languages_server_to_client=-1;
static int hf_ssh_kex_algorithms_length= -1;
static int hf_ssh_server_host_key_algorithms_length= -1;
static int hf_ssh_encryption_algorithms_client_to_server_length= -1;
static int hf_ssh_encryption_algorithms_server_to_client_length= -1;
static int hf_ssh_mac_algorithms_client_to_server_length= -1;
static int hf_ssh_mac_algorithms_server_to_client_length= -1;
static int hf_ssh_compression_algorithms_client_to_server_length= -1;
static int hf_ssh_compression_algorithms_server_to_client_length= -1;
static int hf_ssh_languages_client_to_server_length= -1;
static int hf_ssh_languages_server_to_client_length= -1;
static int hf_ssh_kex_first_packet_follows = -1;
static int hf_ssh_kex_reserved = -1;

static gint ett_ssh = -1;
static gint ett_key_exchange = -1;
static gint ett_key_exchange_host_key = -1;
static gint ett_key_init = -1;
static gint ett_ssh1 = -1;
static gint ett_ssh2 = -1;

static expert_field ei_ssh_packet_length = EI_INIT;

static gboolean ssh_desegment = TRUE;

static dissector_handle_t ssh_handle;

#define TCP_PORT_SSH  22
#define SCTP_PORT_SSH 22

/* Message Numbers (from RFC 4250) (1-255) */

/* Transport layer protocol: generic (1-19) */
#define SSH_MSG_DISCONNECT          1
#define SSH_MSG_IGNORE              2
#define SSH_MSG_UNIMPLEMENTED       3
#define SSH_MSG_DEBUG               4
#define SSH_MSG_SERVICE_REQUEST     5
#define SSH_MSG_SERVICE_ACCEPT      6

/* Transport layer protocol: Algorithm negotiation (20-29) */
#define SSH_MSG_KEXINIT             20
#define SSH_MSG_NEWKEYS             21

/* Transport layer: Key exchange method specific (reusable) (30-49) */
#define SSH_MSG_KEXDH_INIT          30
#define SSH_MSG_KEXDH_REPLY         31

#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD  30
#define SSH_MSG_KEX_DH_GEX_GROUP        31
#define SSH_MSG_KEX_DH_GEX_INIT         32
#define SSH_MSG_KEX_DH_GEX_REPLY        33
#define SSH_MSG_KEX_DH_GEX_REQUEST      34

/* User authentication protocol: generic (50-59) */
#define SSH_MSG_USERAUTH_REQUEST    50
#define SSH_MSG_USERAUTH_FAILURE    51
#define SSH_MSG_USERAUTH_SUCCESS    52
#define SSH_MSG_USERAUTH_BANNER     53

/* User authentication protocol: method specific (reusable) (50-79) */

/* Connection protocol: generic (80-89) */
#define SSH_MSG_GLOBAL_REQUEST          80
#define SSH_MSG_REQUEST_SUCCESS         81
#define SSH_MSG_REQUEST_FAILURE         82

/* Connection protocol: channel related messages (90-127) */
#define SSH_MSG_CHANNEL_OPEN                90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION   91
#define SSH_MSG_CHANNEL_OPEN_FAILURE        92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST       93
#define SSH_MSG_CHANNEL_DATA                94
#define SSH_MSG_CHANNEL_EXTENDED_DATA       95
#define SSH_MSG_CHANNEL_EOF                 96
#define SSH_MSG_CHANNEL_CLOSE               97
#define SSH_MSG_CHANNEL_REQUEST             98
#define SSH_MSG_CHANNEL_SUCCESS             99
#define SSH_MSG_CHANNEL_FAILURE             100

/* 128-191 reserved for client protocols */
/* 192-255 local extensions */

static const value_string ssh2_msg_vals[] = {
    { SSH_MSG_DISCONNECT,                "Disconnect" },
    { SSH_MSG_IGNORE,                    "Ignore" },
    { SSH_MSG_UNIMPLEMENTED,             "Unimplemented" },
    { SSH_MSG_DEBUG,                     "Debug" },
    { SSH_MSG_SERVICE_REQUEST,           "Service Request" },
    { SSH_MSG_SERVICE_ACCEPT,            "Service Accept" },
    { SSH_MSG_KEXINIT,                   "Key Exchange Init" },
    { SSH_MSG_NEWKEYS,                   "New Keys" },
    { SSH_MSG_USERAUTH_REQUEST,          "User Authentication Request" },
    { SSH_MSG_USERAUTH_FAILURE,          "User Authentication Failure" },
    { SSH_MSG_USERAUTH_SUCCESS,          "User Authentication Success" },
    { SSH_MSG_USERAUTH_BANNER,           "User Authentication Banner" },
    { SSH_MSG_GLOBAL_REQUEST,            "Global Request" },
    { SSH_MSG_REQUEST_SUCCESS,           "Request Success" },
    { SSH_MSG_REQUEST_FAILURE,           "Request Failure" },
    { SSH_MSG_CHANNEL_OPEN,              "Channel Open" },
    { SSH_MSG_CHANNEL_OPEN_CONFIRMATION, "Channel Open Confirmation" },
    { SSH_MSG_CHANNEL_OPEN_FAILURE,      "Channel Open Failure" },
    { SSH_MSG_CHANNEL_WINDOW_ADJUST,     "Window Adjust" },
    { SSH_MSG_CHANNEL_DATA,              "Channel Data" },
    { SSH_MSG_CHANNEL_EXTENDED_DATA,     "Channel Extended Data" },
    { SSH_MSG_CHANNEL_EOF,               "Channel EOF" },
    { SSH_MSG_CHANNEL_CLOSE,             "Channel Close" },
    { SSH_MSG_CHANNEL_REQUEST,           "Channel Request" },
    { SSH_MSG_CHANNEL_SUCCESS,           "Channel Success" },
    { SSH_MSG_CHANNEL_FAILURE,           "Channel Failure" },
    { 0, NULL }
};

static const value_string ssh2_kex_dh_msg_vals[] = {
    { SSH_MSG_KEXDH_INIT,                "Diffie-Hellman Key Exchange Init" },
    { SSH_MSG_KEXDH_REPLY,               "Diffie-Hellman Key Exchange Reply" },
    { 0, NULL }
};

static const value_string ssh2_kex_dh_gex_msg_vals[] = {
    { SSH_MSG_KEX_DH_GEX_REQUEST_OLD,    "Diffie-Hellman Group Exchange Request (Old)" },
    { SSH_MSG_KEX_DH_GEX_GROUP,          "Diffie-Hellman Group Exchange Group" },
    { SSH_MSG_KEX_DH_GEX_INIT,           "Diffie-Hellman Group Exchange Init" },
    { SSH_MSG_KEX_DH_GEX_REPLY,          "Diffie-Hellman Group Exchange Reply" },
    { SSH_MSG_KEX_DH_GEX_REQUEST,        "Diffie-Hellman Group Exchange Request" },
    { 0, NULL }
};

static const value_string ssh1_msg_vals[] = {
    {SSH1_MSG_NONE,                      "No Message"},
    {SSH1_MSG_DISCONNECT,                "Disconnect"},
    {SSH1_SMSG_PUBLIC_KEY,               "Public Key"},
    {SSH1_CMSG_SESSION_KEY,              "Session Key"},
    {SSH1_CMSG_USER,                     "User"},
    {0, NULL}
};

static int ssh_dissect_key_init(tvbuff_t *tvb, int offset, proto_tree *tree,
        int is_response,
        struct ssh_flow_data *global_data);
static int ssh_dissect_proposal(tvbuff_t *tvb, int offset, proto_tree *tree,
        int hf_index_length, int hf_index_value, gchar **store);
static int ssh_dissect_ssh1(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation);
static int ssh_dissect_ssh2(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation);
static int ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation);
static int ssh_dissect_kex_dh(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree);
static int ssh_dissect_kex_dh_gex(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree);
static int ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response, guint *version,
        gboolean *need_desegmentation);
static int ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data,
        int offset, proto_tree *tree);
static void ssh_choose_algo(gchar *client, gchar *server, gchar **result);
static void ssh_set_mac_length(struct ssh_peer_data *peer_data);
static void ssh_set_kex_specific_dissector(struct ssh_flow_data *global_data);


static int
dissect_ssh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree  *ssh_tree;
    proto_item  *ti;
    conversation_t *conversation;
    int     last_offset, offset = 0;

    gboolean    is_response = (pinfo->destport != pinfo->match_uint),
                need_desegmentation;
    guint       version;

    struct ssh_flow_data *global_data=NULL;
    struct ssh_peer_data *peer_data;

    conversation = find_or_create_conversation(pinfo);

    global_data = (struct ssh_flow_data *)conversation_get_proto_data(conversation, proto_ssh);
    if (!global_data) {
        global_data = (struct ssh_flow_data *)wmem_alloc0(wmem_file_scope(), sizeof(struct ssh_flow_data));
        global_data->version=SSH_VERSION_UNKNOWN;
        global_data->kex_specific_dissector=ssh_dissect_kex_dh;
        global_data->peer_data[CLIENT_PEER_DATA].mac_length=-1;
        global_data->peer_data[SERVER_PEER_DATA].mac_length=-1;

        conversation_add_proto_data(conversation, proto_ssh, global_data);
    }

    peer_data = &global_data->peer_data[is_response];

    ti = proto_tree_add_item(tree, proto_ssh, tvb, offset, -1, ENC_NA);
    ssh_tree = proto_item_add_subtree(ti, ett_ssh);

    version = global_data->version;

    switch(version) {
    case SSH_VERSION_UNKNOWN:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSH");
        break;
    case SSH_VERSION_1:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSHv1");
        break;
    case SSH_VERSION_2:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSHv2");
        break;

    }

    col_clear(pinfo->cinfo, COL_INFO);

    while(tvb_reported_length_remaining(tvb, offset)> 0) {
        gboolean after_version_start = (peer_data->frame_version_start == 0 ||
            pinfo->num >= peer_data->frame_version_start);
        gboolean before_version_end = (peer_data->frame_version_end == 0 ||
            pinfo->num <= peer_data->frame_version_end);

        need_desegmentation = FALSE;
        last_offset = offset;

        peer_data->counter++;

        if (after_version_start && before_version_end &&
              (tvb_strncaseeql(tvb, offset, "SSH-", 4) == 0)) {
            if (peer_data->frame_version_start == 0)
                peer_data->frame_version_start = pinfo->num;

            offset = ssh_dissect_protocol(tvb, pinfo,
                    global_data,
                    offset, ssh_tree, is_response,
                    &version, &need_desegmentation);

            if (!need_desegmentation) {
                peer_data->frame_version_end = pinfo->num;
                global_data->version = version;
            }
        } else {
            switch(version) {

            case SSH_VERSION_UNKNOWN:
                offset = ssh_dissect_encrypted_packet(tvb, pinfo,
                        &global_data->peer_data[is_response], offset, ssh_tree);
                break;

            case SSH_VERSION_1:
                offset = ssh_dissect_ssh1(tvb, pinfo, global_data,
                        offset, ssh_tree, is_response,
                        &need_desegmentation);
                break;

            case SSH_VERSION_2:
                offset = ssh_dissect_ssh2(tvb, pinfo, global_data,
                        offset, ssh_tree, is_response,
                        &need_desegmentation);
                break;
            }
        }

        if (need_desegmentation)
            return tvb_captured_length(tvb);
        if (offset <= last_offset) {
            /* XXX - add an expert info in the function
               that decrements offset */
            break;
        }
    }

    col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s: ", is_response ? "Server" : "Client");
    return tvb_captured_length(tvb);
}

static int
ssh_dissect_ssh2(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation)
{
    proto_item *ssh2_tree=NULL;
    int last_offset=offset;

    struct ssh_peer_data *peer_data = &global_data->peer_data[is_response];

    if (tree) {
        wmem_strbuf_t *title=wmem_strbuf_new(wmem_packet_scope(), "SSH Version 2");

        if (peer_data->enc || peer_data->mac || peer_data->comp) {
            wmem_strbuf_append_printf(title, " (");
            if (peer_data->enc)
                wmem_strbuf_append_printf(title, "encryption:%s%s",
                    peer_data->enc,
                    peer_data->mac || peer_data->comp
                        ? " " : "");
            if (peer_data->mac)
                wmem_strbuf_append_printf(title, "mac:%s%s",
                    peer_data->mac,
                    peer_data->comp ? " " : "");
            if (peer_data->comp)
                wmem_strbuf_append_printf(title, "compression:%s",
                    peer_data->comp);
            wmem_strbuf_append_printf(title, ")");
        }

        ssh2_tree=proto_tree_add_subtree(tree, tvb, offset, -1, ett_ssh2, NULL, wmem_strbuf_get_str(title));
    }

    if ((peer_data->frame_key_start == 0) ||
        ((peer_data->frame_key_start <= pinfo->num) &&
        ((peer_data->frame_key_end == 0) || (pinfo->num < peer_data->frame_key_end) ||
                ((pinfo->num == peer_data->frame_key_end) && (offset < peer_data->frame_key_end_offset))))) {
        offset = ssh_dissect_key_exchange(tvb, pinfo, global_data,
            offset, ssh2_tree, is_response,
            need_desegmentation);
    } else {
        offset = ssh_dissect_encrypted_packet(tvb, pinfo,
                &global_data->peer_data[is_response], offset, ssh2_tree);
    }

    if (ssh2_tree) {
        proto_item_set_len(ssh2_tree, offset - last_offset);
    }

    return offset;
}
static int
ssh_dissect_ssh1(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation)
{
    guint   plen, padding_length, len;
    guint8  msg_code;
    guint   remain_length;

    proto_item *ssh1_tree;

    struct ssh_peer_data *peer_data = &global_data->peer_data[is_response];

    ssh1_tree=proto_tree_add_subtree(tree, tvb, offset, -1, ett_ssh1, NULL, "SSH Version 1");

    /*
     * We use "tvb_ensure_captured_length_remaining()" to make sure there
     * actually *is* data remaining.
     *
     * This means we're guaranteed that "remain_length" is positive.
     */
    remain_length = tvb_ensure_captured_length_remaining(tvb, offset);
    /*
     * Can we do reassembly?
     */
    if (ssh_desegment && pinfo->can_desegment) {
        /*
         * Yes - would an SSH header starting at this offset be split
         * across segment boundaries?
         */
        if (remain_length < 4) {
            /*
             * Yes.  Tell the TCP dissector where the data for
             * this message starts in the data it handed us and
             * that we need "some more data."  Don't tell it
             * exactly how many bytes we need because if/when we
             * ask for even more (after the header) that will
             * break reassembly.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    plen = tvb_get_ntohl(tvb, offset) ;
    padding_length  = 8 - plen%8;


    if (ssh_desegment && pinfo->can_desegment) {
        if (plen+4+padding_length >  remain_length) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = plen+padding_length - remain_length;
            *need_desegmentation = TRUE;
            return offset;
        }
    }

    if (plen >= 0xffff) {
        if (ssh1_tree && plen > 0) {
              proto_tree_add_uint_format(ssh1_tree, hf_ssh_packet_length, tvb,
                offset, 4, plen, "Overly large length %x", plen);
        }
        plen = remain_length-4-padding_length;
    } else {
        if (ssh1_tree && plen > 0) {
              proto_tree_add_uint(ssh1_tree, hf_ssh_packet_length, tvb,
                offset, 4, plen);
        }
    }
    offset+=4;
/* padding length */

    proto_tree_add_uint(ssh1_tree, hf_ssh_padding_length, tvb,
            offset, padding_length, padding_length);
    offset += padding_length;

    /* msg_code */
    if ((peer_data->frame_key_start == 0) ||
        ((peer_data->frame_key_start >= pinfo->num) && (pinfo->num <= peer_data->frame_key_end))) {
        msg_code = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(ssh1_tree, hf_ssh_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
            val_to_str(msg_code, ssh1_msg_vals, "Unknown (%u)"));
        offset += 1;
        len = plen -1;
        if (!pinfo->fd->flags.visited) {
            if (peer_data->frame_key_start == 0)
                peer_data->frame_key_start = pinfo->num;
            peer_data->frame_key_end = pinfo->num;
        }
    } else {
        len = plen;
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Encrypted packet (len=%d)", len);
    }
    /* payload */
    if (ssh1_tree) {
        proto_tree_add_item(ssh1_tree, hf_ssh_payload,
            tvb, offset, len, ENC_NA);
    }
    offset+=len;

    return offset;
}

static int
ssh_tree_add_mpint(tvbuff_t *tvb, int offset, proto_tree *tree,
    int hf_ssh_mpint_selection)
{
    guint len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_mpint_length, tvb,
            offset, 4, len);
    offset+=4;
    proto_tree_add_item(tree, hf_ssh_mpint_selection,
            tvb, offset, len, ENC_NA);
    return 4+len;
}

static int
ssh_tree_add_string(tvbuff_t *tvb, int offset, proto_tree *tree,
    int hf_ssh_string, int hf_ssh_string_length)
{
    guint len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_string_length, tvb,
            offset, 4, len);
    offset+=4;
    proto_tree_add_item(tree, hf_ssh_string,
            tvb, offset, len, ENC_NA);
    return 4+len;
}

static int
ssh_tree_add_hostkey(tvbuff_t *tvb, int offset, proto_tree *parent_tree, const char *tree_name,
                     int ett_idx)
{
    proto_tree *tree = NULL;
    int last_offset;
    int remaining_len;
    guint key_len, type_len;
    guint8* key_type;
    gchar *tree_title;

    last_offset = offset;

    key_len = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* Read the key type before creating the tree so we can append it as info. */
    type_len = tvb_get_ntohl(tvb, offset);
    offset += 4;
    key_type = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, type_len, ENC_ASCII|ENC_NA);

    tree_title = wmem_strdup_printf(wmem_packet_scope(), "%s (type: %s)", tree_name, key_type);
    tree = proto_tree_add_subtree(parent_tree, tvb, last_offset, key_len, ett_idx, NULL,
                                  tree_title);

    proto_tree_add_uint(tree, hf_ssh_hostkey_length, tvb, last_offset, 4, key_len);
    proto_tree_add_string(tree, hf_ssh_hostkey_type, tvb, offset, type_len, key_type);
    offset += type_len;

    if (0 == strcmp(key_type, "ssh-rsa")) {
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_rsa_e);
        ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_rsa_n);
    } else {
        remaining_len = key_len - (type_len + 4);
        proto_tree_add_item(tree, hf_ssh_hostkey_data, tvb, offset, remaining_len, ENC_NA);
    }

    return 4+key_len;
}

static int
ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation)
{
    guint   plen, len;
    guint8  padding_length;
    guint   remain_length;
    int     last_offset=offset;
    guint   msg_code;

    proto_item *ti;
    proto_item *key_ex_tree =NULL;

    struct ssh_peer_data *peer_data = &global_data->peer_data[is_response];

    /*
     * We use "tvb_ensure_captured_length_remaining()" to make sure there
     * actually *is* data remaining.
     *
     * This means we're guaranteed that "remain_length" is positive.
     */
    remain_length = tvb_ensure_captured_length_remaining(tvb, offset);
    /*
     * Can we do reassembly?
     */
    if (ssh_desegment && pinfo->can_desegment) {
        /*
         * Yes - would an SSH header starting at this offset
         * be split across segment boundaries?
         */
        if (remain_length < 4) {
            /*
             * Yes.  Tell the TCP dissector where the data for
             * this message starts in the data it handed us and
             * that we need "some more data."  Don't tell it
             * exactly how many bytes we need because if/when we
             * ask for even more (after the header) that will
             * break reassembly.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    plen = tvb_get_ntohl(tvb, offset) ;

    if (ssh_desegment && pinfo->can_desegment) {
        if (plen +4 >  remain_length) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = plen+4 - remain_length;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    /*
     * Need to check plen > 0x80000000 here
     */

    ti = proto_tree_add_uint(tree, hf_ssh_packet_length, tvb,
                    offset, 4, plen);
    if (plen >= 0xffff) {
        expert_add_info_format(pinfo, ti, &ei_ssh_packet_length, "Overly large number %d", plen);
        plen = remain_length-4;
    }
    offset+=4;

    /* padding length */
    padding_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_padding_length, tvb, offset, 1, padding_length);
    offset += 1;

    key_ex_tree=proto_tree_add_subtree(tree, tvb, offset, plen-1, ett_key_exchange, NULL, "Key Exchange");

    /* msg_code */
    msg_code = tvb_get_guint8(tvb, offset);

    if (msg_code >= 30 && msg_code < 40) {
        offset = global_data->kex_specific_dissector(msg_code, tvb, pinfo, offset, key_ex_tree);
    } else {
        proto_tree_add_item(key_ex_tree, hf_ssh2_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
            val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));

        /* 16 bytes cookie  */
        switch(msg_code)
        {
        case SSH_MSG_KEXINIT:
            if ((peer_data->frame_key_start == 0) || (peer_data->frame_key_start == pinfo->num)) {
                offset = ssh_dissect_key_init(tvb, offset, key_ex_tree, is_response, global_data);
                peer_data->frame_key_start = pinfo->num;
            }
            break;
        case SSH_MSG_NEWKEYS:
            if (peer_data->frame_key_end == 0) {
                peer_data->frame_key_end = pinfo->num;
                peer_data->frame_key_end_offset = offset;
                ssh_choose_algo(global_data->peer_data[CLIENT_PEER_DATA].enc_proposals[is_response],
                                global_data->peer_data[SERVER_PEER_DATA].enc_proposals[is_response],
                                &peer_data->enc);

                /* some ciphers have their own MAC so the "negotiated" one is meaningless */
                if(peer_data->enc && (0 == strcmp(peer_data->enc, "aes128-gcm@openssh.com") ||
                                      0 == strcmp(peer_data->enc, "aes256-gcm@openssh.com"))) {
                    peer_data->mac = wmem_strdup(wmem_file_scope(), (const gchar *)"<implicit>");
                    peer_data->mac_length = 16;
                    peer_data->length_is_plaintext = 1;
                }
                else if(peer_data->enc && 0 == strcmp(peer_data->enc, "chacha20-poly1305@openssh.com")) {
                    peer_data->mac = wmem_strdup(wmem_file_scope(), (const gchar *)"<implicit>");
                    peer_data->mac_length = 16;
                }
                else {
                    ssh_choose_algo(global_data->peer_data[CLIENT_PEER_DATA].mac_proposals[is_response],
                                    global_data->peer_data[SERVER_PEER_DATA].mac_proposals[is_response],
                                    &peer_data->mac);
                    ssh_set_mac_length(peer_data);
                }

                ssh_choose_algo(global_data->peer_data[CLIENT_PEER_DATA].comp_proposals[is_response],
                                global_data->peer_data[SERVER_PEER_DATA].comp_proposals[is_response],
                                &peer_data->comp);
            }
            break;
        }
    }

    len = plen+4-padding_length-(offset-last_offset);
    if (len > 0) {
        proto_tree_add_item(key_ex_tree, hf_ssh_payload, tvb, offset, len, ENC_NA);
    }
    offset +=len;

    /* padding */
    proto_tree_add_item(key_ex_tree, hf_ssh_padding_string, tvb, offset, padding_length, ENC_NA);
    offset+= padding_length;

    return offset;
}

static int ssh_dissect_kex_dh(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ssh2_kex_dh_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
        val_to_str(msg_code, ssh2_kex_dh_msg_vals, "Unknown (%u)"));

    switch (msg_code) {
    case SSH_MSG_KEXDH_INIT:
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_mpint_e);
        break;

    case SSH_MSG_KEXDH_REPLY:
        offset += ssh_tree_add_hostkey(tvb, offset, tree, "KEX DH host key", ett_key_exchange_host_key);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_mpint_f);
        offset += ssh_tree_add_string(tvb, offset, tree, hf_ssh_kexdh_h_sig, hf_ssh_kexdh_h_sig_length);
        break;
    }

    return offset;
}

static int ssh_dissect_kex_dh_gex(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ssh2_kex_dh_gex_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
        val_to_str(msg_code, ssh2_kex_dh_gex_msg_vals, "Unknown (%u)"));

    switch (msg_code) {
    case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
        proto_tree_add_item(tree, hf_ssh_dh_gex_nbits, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case SSH_MSG_KEX_DH_GEX_GROUP:
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_mpint_p);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_mpint_g);
        break;

    case SSH_MSG_KEX_DH_GEX_INIT:
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_mpint_e);
        break;

    case SSH_MSG_KEX_DH_GEX_REPLY:
        offset += ssh_tree_add_string(tvb, offset, tree, hf_ssh_kexdh_host_key, hf_ssh_hostkey_length);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_mpint_f);
        offset += ssh_tree_add_string(tvb, offset, tree, hf_ssh_kexdh_h_sig, hf_ssh_kexdh_h_sig_length);
        break;

    case SSH_MSG_KEX_DH_GEX_REQUEST:
        proto_tree_add_item(tree, hf_ssh_dh_gex_min, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_ssh_dh_gex_nbits, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_ssh_dh_gex_max, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    }

    return offset;
}

static int
ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data,
        int offset, proto_tree *tree)
{
    gint len;
    guint plen;

    len = tvb_reported_length_remaining(tvb, offset);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Encrypted packet (len=%d)", len);

    if (tree) {
        gint encrypted_len = len;

        if (len > 4 && peer_data->length_is_plaintext) {
            plen = tvb_get_ntohl(tvb, offset) ;
            proto_tree_add_uint(tree, hf_ssh_packet_length, tvb, offset, 4, plen);
            encrypted_len -= 4;
        }
        else if (len > 4) {
            proto_tree_add_item(tree, hf_ssh_packet_length_encrypted, tvb, offset, 4, ENC_NA);
            encrypted_len -= 4;
        }

        if (peer_data->mac_length>0)
            encrypted_len -= peer_data->mac_length;

        proto_tree_add_item(tree, hf_ssh_encrypted_packet,
                    tvb, offset+4, encrypted_len, ENC_NA);

        if (peer_data->mac_length>0)
            proto_tree_add_item(tree, hf_ssh_mac_string,
                tvb, offset+4+encrypted_len,
                peer_data->mac_length, ENC_NA);
    }
    offset+=len;
    return offset;
}

static int
ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response, guint * version,
        gboolean *need_desegmentation)
{
    guint   remain_length;
    gint    linelen, protolen;

    /*
     *  If the first packet do not contain the banner,
     *  it is dump in the middle of a flow or not a ssh at all
     */
    if (tvb_strncaseeql(tvb, offset, "SSH-", 4) != 0) {
        offset = ssh_dissect_encrypted_packet(tvb, pinfo,
            &global_data->peer_data[is_response], offset, tree);
        return offset;
    }

    if (!is_response) {
        if (tvb_strncaseeql(tvb, offset, "SSH-2.", 6) == 0) {
            *(version) = SSH_VERSION_2;
        } else if (tvb_strncaseeql(tvb, offset, "SSH-1.99-", 9) == 0) {
            *(version) = SSH_VERSION_2;
        } else if (tvb_strncaseeql(tvb, offset, "SSH-1.", 6) == 0) {
            *(version) = SSH_VERSION_1;
        }
    }

    /*
     * We use "tvb_ensure_captured_length_remaining()" to make sure there
     * actually *is* data remaining.
     *
     * This means we're guaranteed that "remain_length" is positive.
     */
    remain_length = tvb_ensure_captured_length_remaining(tvb, offset);
    /*linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
     */
    linelen = tvb_find_guint8(tvb, offset, -1, '\n');

    if (ssh_desegment && pinfo->can_desegment) {
        if (linelen == -1 || remain_length < (guint)linelen-offset) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = linelen-remain_length;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    if (linelen == -1) {
        /* XXX - reassemble across segment boundaries? */
        linelen = remain_length;
        protolen = linelen;
    } else {
        linelen = linelen - offset + 1;

        if (linelen > 1 && tvb_get_guint8(tvb, offset + linelen - 2) == '\r')
            protolen = linelen - 2;
        else
            protolen = linelen - 1;
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Protocol (%s)",
            tvb_format_text(tvb, offset, protolen));

    proto_tree_add_item(tree, hf_ssh_protocol,
                    tvb, offset, linelen, ENC_ASCII|ENC_NA);
    offset+=linelen;
    return offset;
}

static void
ssh_set_mac_length(struct ssh_peer_data *peer_data)
{
    char *size_str;
    guint size=0;
    char *mac_name = peer_data->mac;
    char *strip;

    if (!mac_name)
        return;

    /* wmem_strdup() never returns NULL */
    mac_name = wmem_strdup(NULL, (const gchar *)mac_name);

    /* strip trailing "-etm@openssh.com" or "@openssh.com" */
    strip = strstr(mac_name, "-etm@openssh.com");
    if (strip) {
        peer_data->length_is_plaintext = 1;
        *strip = '\0';
    }
    else {
        strip = strstr(mac_name, "@openssh.com");
        if (strip) *strip = '\0';
    }

    if ((size_str=g_strrstr(mac_name, "-")) && ((size=atoi(size_str+1)))) {
        peer_data->mac_length = (size > 0) ? size / 8 : 0;
    }
    else if (strcmp(mac_name, "hmac-sha1") == 0) {
        peer_data->mac_length = 20;
    }
    else if (strcmp(mac_name, "hmac-md5") == 0) {
        peer_data->mac_length = 16;
    }
    else if (strcmp(mac_name, "hmac-ripemd160") == 0) {
        peer_data->mac_length = 20;
    }
    else if (strcmp(mac_name, "none") == 0) {
        peer_data->mac_length = 0;
    }

    wmem_free(NULL, mac_name);
}

static void ssh_set_kex_specific_dissector(struct ssh_flow_data *global_data)
{
    const char *kex_name = global_data->kex;

    if (!kex_name) return;

    if (strcmp(kex_name, "diffie-hellman-group-exchange-sha1") == 0 ||
        strcmp(kex_name, "diffie-hellman-group-exchange-sha256") == 0)
    {
        global_data->kex_specific_dissector = ssh_dissect_kex_dh_gex;
    }
}

static gint
ssh_gslist_compare_strings(gconstpointer a, gconstpointer b)
{
    if (a == NULL && b == NULL)
        return 0;
    if (a == NULL)
        return -1;
    if (b == NULL)
        return 1;
    return strcmp((const char*)a, (const char*)b);
}

/* expects that *result is NULL */
static void
ssh_choose_algo(gchar *client, gchar *server, gchar **result)
{
    gchar **server_strings=NULL;
    gchar **client_strings=NULL;
    gchar **step;
    GSList *server_list = NULL;

    if (!client || !server || !result || *result)
        return;

    server_strings = g_strsplit(server, ",", 0);
    for (step = server_strings; *step; step++) {
        server_list = g_slist_append(server_list, *step);
    }

    client_strings = g_strsplit(client, ",", 0);
    for (step = client_strings; *step; step++) {
        GSList *agreed;
        if ((agreed=g_slist_find_custom(server_list, *step, ssh_gslist_compare_strings))) {
            *result = wmem_strdup(wmem_file_scope(), (const gchar *)agreed->data);
            break;
        }
    }

    g_strfreev(client_strings);
    g_slist_free(server_list);
    g_strfreev(server_strings);
}

static int
ssh_dissect_key_init(tvbuff_t *tvb, int offset, proto_tree *tree,
        int is_response, struct ssh_flow_data *global_data)
{
    int start_offset = offset;

    proto_item *tf;
    proto_tree *key_init_tree;

    struct ssh_peer_data *peer_data = &global_data->peer_data[is_response];

    key_init_tree=proto_tree_add_subtree(tree, tvb, offset, -1, ett_key_init, &tf, "Algorithms");
    proto_tree_add_item(key_init_tree, hf_ssh_cookie,
                    tvb, offset, 16, ENC_NA);
    offset += 16;

    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_kex_algorithms_length, hf_ssh_kex_algorithms,
        &peer_data->kex_proposal);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_server_host_key_algorithms_length,
        hf_ssh_server_host_key_algorithms, NULL);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_encryption_algorithms_client_to_server_length,
        hf_ssh_encryption_algorithms_client_to_server,
        &peer_data->enc_proposals[CLIENT_TO_SERVER_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_encryption_algorithms_server_to_client_length,
        hf_ssh_encryption_algorithms_server_to_client,
        &peer_data->enc_proposals[SERVER_TO_CLIENT_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_mac_algorithms_client_to_server_length,
        hf_ssh_mac_algorithms_client_to_server,
        &peer_data->mac_proposals[CLIENT_TO_SERVER_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_mac_algorithms_server_to_client_length,
        hf_ssh_mac_algorithms_server_to_client,
        &peer_data->mac_proposals[SERVER_TO_CLIENT_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_compression_algorithms_client_to_server_length,
        hf_ssh_compression_algorithms_client_to_server,
        &peer_data->comp_proposals[CLIENT_TO_SERVER_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_compression_algorithms_server_to_client_length,
        hf_ssh_compression_algorithms_server_to_client,
        &peer_data->comp_proposals[SERVER_TO_CLIENT_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_languages_client_to_server_length,
        hf_ssh_languages_client_to_server, NULL);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_languages_server_to_client_length,
        hf_ssh_languages_server_to_client, NULL);

    proto_tree_add_item(key_init_tree, hf_ssh_kex_first_packet_follows,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    proto_tree_add_item(key_init_tree, hf_ssh_kex_reserved,
        tvb, offset, 4, ENC_NA);
    offset+=4;

    if (global_data->peer_data[CLIENT_PEER_DATA].kex_proposal &&
        global_data->peer_data[SERVER_PEER_DATA].kex_proposal &&
        !global_data->kex)
    {
        /* Note: we're ignoring first_kex_packet_follows. */
        ssh_choose_algo(
            global_data->peer_data[CLIENT_PEER_DATA].kex_proposal,
            global_data->peer_data[SERVER_PEER_DATA].kex_proposal,
            &global_data->kex);
        ssh_set_kex_specific_dissector(global_data);
    }

    if (tf != NULL) {
        proto_item_set_len(tf, offset-start_offset);
    }

    return offset;
}

static int
ssh_dissect_proposal(tvbuff_t *tvb, int offset, proto_tree *tree,
             int hf_index_length, int hf_index_value, gchar **store)
{
    guint32 len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_index_length, tvb, offset, 4, len);
    offset += 4;

    proto_tree_add_item(tree, hf_index_value, tvb, offset, len,
                ENC_ASCII);
    if (store)
        *store = tvb_get_string_enc(wmem_file_scope(), tvb, offset, len, ENC_ASCII);
    offset += len;

    return offset;
}


void
proto_register_ssh(void)
{
    static hf_register_info hf[] = {
        { &hf_ssh_packet_length,
          { "Packet Length",      "ssh.packet_length",
            FT_UINT32, BASE_DEC, NULL,  0x0,
            "SSH packet length", HFILL }},

        { &hf_ssh_packet_length_encrypted,
          { "Packet Length (encrypted)",      "ssh.packet_length_encrypted",
            FT_BYTES, BASE_NONE, NULL,  0x0,
            "SSH packet length (encrypted)", HFILL }},

        { &hf_ssh_padding_length,
          { "Padding Length",  "ssh.padding_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "SSH Packet Number", HFILL }},

        { &hf_ssh_msg_code,
          { "Message Code",  "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh1_msg_vals), 0x0,
            "SSH Message Code", HFILL }},

        { &hf_ssh2_msg_code,
          { "Message Code",  "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_msg_vals), 0x0,
            "SSH Message Code", HFILL }},

        { &hf_ssh2_kex_dh_msg_code,
          { "Message Code",  "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_kex_dh_msg_vals), 0x0,
            "SSH Message Code", HFILL }},

        { &hf_ssh2_kex_dh_gex_msg_code,
          { "Message Code",  "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_kex_dh_gex_msg_vals), 0x0,
            "SSH Message Code", HFILL }},

        { &hf_ssh_mpint_g,
          { "DH base (G)",  "ssh.dh.g",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH DH base (G)", HFILL }},

        { &hf_ssh_mpint_p,
          { "DH modulus (P)",  "ssh.dh.p",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH DH modulus (P)", HFILL }},

        { &hf_ssh_mpint_e,
          { "DH client e",  "ssh.dh.e",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH DH client e", HFILL }},

        { &hf_ssh_mpint_f,
          { "DH server f",  "ssh.dh.f",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH DH server f", HFILL }},

        { &hf_ssh_mpint_length,
          { "Multi Precision Integer Length",      "ssh.mpint_length",
            FT_UINT32, BASE_DEC, NULL,  0x0,
            "SSH mpint length", HFILL }},

        { &hf_ssh_kexdh_host_key,
          { "KEX DH host key",         "ssh.kexdh.host_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH KEX DH host key", HFILL }},

        { &hf_ssh_kexdh_h_sig,
          { "KEX DH H signature",         "ssh.kexdh.h_sig",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH KEX DH H signature", HFILL }},

        { &hf_ssh_hostkey_length,
          { "Host key length",         "ssh.host_key.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_type,
          { "Host key type",         "ssh.host_key.type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_data,
          { "Host key data",         "ssh.host_key.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_rsa_n,
          { "RSA modulus (N)",         "ssh.host_key.rsa.n",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_rsa_e,
          { "RSA public exponent (e)",         "ssh.host_key.rsa.e",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kexdh_h_sig_length,
          { "KEX DH H signature length",         "ssh.kexdh.h_sig_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH KEX DH H signature length", HFILL }},

        { &hf_ssh_encrypted_packet,
          { "Encrypted Packet",  "ssh.encrypted_packet",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH Protocol Packet", HFILL }},

        { &hf_ssh_protocol,
          { "Protocol",  "ssh.protocol",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "SSH Protocol", HFILL }},

        { &hf_ssh_cookie,
          { "Cookie",  "ssh.cookie",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH Cookie", HFILL }},

        { &hf_ssh_kex_first_packet_follows,
          { "KEX First Packet Follows",      "ssh.kex.first_packet_follows",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "SSH KEX Fist Packet Follows", HFILL }},

        { &hf_ssh_kex_reserved,
          { "Reserved",  "ssh.kex.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH Protocol KEX Reserved", HFILL }},

        { &hf_ssh_dh_gex_min,
          { "DH GEX Min",  "ssh.dh_gex.min",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH DH GEX Minimum", HFILL }},

        { &hf_ssh_dh_gex_nbits,
          { "DH GEX Number of Bits",  "ssh.dh_gex.nbits",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH DH GEX Number of Bits", HFILL }},

        { &hf_ssh_dh_gex_max,
          { "DH GEX Max",  "ssh.dh_gex.max",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH DH GEX Maximum", HFILL }},

        { &hf_ssh_payload,
          { "Payload",  "ssh.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH Payload", HFILL }},

        { &hf_ssh_padding_string,
          { "Padding String",  "ssh.padding_string",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH Padding String", HFILL }},

        { &hf_ssh_mac_string,
          { "MAC",  "ssh.mac",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SSH Protocol Packet MAC", HFILL }},

        { &hf_ssh_kex_algorithms,
          { "kex_algorithms string",         "ssh.kex_algorithms",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "SSH kex_algorithms string", HFILL }},

        { &hf_ssh_server_host_key_algorithms,
          { "server_host_key_algorithms string",         "ssh.server_host_key_algorithms",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "SSH server_host_key_algorithms string", HFILL }},

        { &hf_ssh_encryption_algorithms_client_to_server,
          { "encryption_algorithms_client_to_server string",         "ssh.encryption_algorithms_client_to_server",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "SSH encryption_algorithms_client_to_server string", HFILL }},

        { &hf_ssh_encryption_algorithms_server_to_client,
          { "encryption_algorithms_server_to_client string",         "ssh.encryption_algorithms_server_to_client",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "SSH encryption_algorithms_server_to_client string", HFILL }},

        { &hf_ssh_mac_algorithms_client_to_server,
          { "mac_algorithms_client_to_server string",         "ssh.mac_algorithms_client_to_server",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "SSH mac_algorithms_client_to_server string", HFILL }},

        { &hf_ssh_mac_algorithms_server_to_client,
          { "mac_algorithms_server_to_client string",         "ssh.mac_algorithms_server_to_client",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "SSH mac_algorithms_server_to_client string", HFILL }},

        { &hf_ssh_compression_algorithms_client_to_server,
          { "compression_algorithms_client_to_server string",         "ssh.compression_algorithms_client_to_server",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "SSH compression_algorithms_client_to_server string", HFILL }},

        { &hf_ssh_compression_algorithms_server_to_client,
          { "compression_algorithms_server_to_client string",         "ssh.compression_algorithms_server_to_client",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "SSH compression_algorithms_server_to_client string", HFILL }},

        { &hf_ssh_languages_client_to_server,
          { "languages_client_to_server string",         "ssh.languages_client_to_server",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "SSH languages_client_to_server string", HFILL }},

        { &hf_ssh_languages_server_to_client,
          { "languages_server_to_client string",         "ssh.languages_server_to_client",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "SSH languages_server_to_client string", HFILL }},

        { &hf_ssh_kex_algorithms_length,
          { "kex_algorithms length",         "ssh.kex_algorithms_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH kex_algorithms length", HFILL }},

        { &hf_ssh_server_host_key_algorithms_length,
          { "server_host_key_algorithms length",         "ssh.server_host_key_algorithms_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH server_host_key_algorithms length", HFILL }},

        { &hf_ssh_encryption_algorithms_client_to_server_length,
          { "encryption_algorithms_client_to_server length",         "ssh.encryption_algorithms_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH encryption_algorithms_client_to_server length", HFILL }},

        { &hf_ssh_encryption_algorithms_server_to_client_length,
          { "encryption_algorithms_server_to_client length",         "ssh.encryption_algorithms_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH encryption_algorithms_server_to_client length", HFILL }},

        { &hf_ssh_mac_algorithms_client_to_server_length,
          { "mac_algorithms_client_to_server length",         "ssh.mac_algorithms_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH mac_algorithms_client_to_server length", HFILL }},

        { &hf_ssh_mac_algorithms_server_to_client_length,
          { "mac_algorithms_server_to_client length",         "ssh.mac_algorithms_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH mac_algorithms_server_to_client length", HFILL }},

        { &hf_ssh_compression_algorithms_client_to_server_length,
          { "compression_algorithms_client_to_server length",         "ssh.compression_algorithms_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH compression_algorithms_client_to_server length", HFILL }},

        { &hf_ssh_compression_algorithms_server_to_client_length,
          { "compression_algorithms_server_to_client length",         "ssh.compression_algorithms_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH compression_algorithms_server_to_client length", HFILL }},

        { &hf_ssh_languages_client_to_server_length,
          { "languages_client_to_server length",         "ssh.languages_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH languages_client_to_server length", HFILL }},

        { &hf_ssh_languages_server_to_client_length,
          { "languages_server_to_client length",         "ssh.languages_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SSH languages_server_to_client length", HFILL }},
    };

    static gint *ett[] = {
        &ett_ssh,
        &ett_key_exchange,
        &ett_key_exchange_host_key,
        &ett_ssh1,
        &ett_ssh2,
        &ett_key_init
    };

    static ei_register_info ei[] = {
        { &ei_ssh_packet_length, { "ssh.packet_length.error", PI_PROTOCOL, PI_WARN, "Overly large number", EXPFILL }},
    };

    module_t *ssh_module;
    expert_module_t *expert_ssh;

    proto_ssh = proto_register_protocol("SSH Protocol", "SSH", "ssh");
    proto_register_field_array(proto_ssh, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ssh = expert_register_protocol(proto_ssh);
    expert_register_field_array(expert_ssh, ei, array_length(ei));

    ssh_module = prefs_register_protocol(proto_ssh, NULL);
    prefs_register_bool_preference(ssh_module, "desegment_buffers",
                       "Reassemble SSH buffers spanning multiple TCP segments",
                       "Whether the SSH dissector should reassemble SSH buffers spanning multiple TCP segments. "
                       "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                       &ssh_desegment);

    ssh_handle = register_dissector("ssh", dissect_ssh, proto_ssh);
}

void
proto_reg_handoff_ssh(void)
{
    dissector_add_uint("tcp.port", TCP_PORT_SSH, ssh_handle);
    dissector_add_uint("sctp.port", SCTP_PORT_SSH, ssh_handle);
    dissector_add_uint("sctp.ppi", SSH_PAYLOAD_PROTOCOL_ID, ssh_handle);
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
