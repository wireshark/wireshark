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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
#define WS_LOG_DOMAIN "packet-ssh"

// Define this to get hex dumps more similar to what you get in openssh. If not defined, dumps look more like what you get with other dissectors.
#define OPENSSH_STYLE

#include <errno.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/sctpppids.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <wsutil/strtoi.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/curve25519.h>
#include <wsutil/pint.h>
#include <wsutil/wslog.h>
#include <ui/version_info.h>
#include <epan/secrets.h>
#include <wiretap/secrets-types.h>

#if defined(HAVE_LIBGNUTLS)
#include <gnutls/abstract.h>
#endif

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

typedef struct {
    guint8  *data;
    guint   length;
} ssh_bignum;

#define SSH_KEX_CURVE25519 0x00010000

#define SSH_KEX_HASH_SHA256 2

#define DIGEST_MAX_SIZE 48

typedef struct _ssh_message_info_t {
    guint32 sequence_number;
    guint32 offset;
    guchar *plain_data;     /**< Decrypted data. */
    guint   data_len;       /**< Length of decrypted data. */
    gint    id;             /**< Identifies the exact message within a frame
                                 (there can be multiple records in a frame). */
    struct _ssh_message_info_t* next;
    guint8  calc_mac[DIGEST_MAX_SIZE];
} ssh_message_info_t;

typedef struct {
    gboolean from_server;
    ssh_message_info_t * messages;
} ssh_packet_info_t;

typedef struct _ssh_channel_info_t {
    guint  client_channel_number;
    guint  server_channel_number;
    dissector_handle_t subdissector_handle;
    struct _ssh_channel_info_t* next;
} ssh_channel_info_t;

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

    // see libgcrypt source, gcrypt.h:gcry_cipher_algos
    guint            cipher_id;
    guint            mac_id;
    // chacha20 needs two cipher handles
    gcry_cipher_hd_t cipher, cipher_2;
    guint            sequence_number;
    guint32          seq_num_kex_init;
// union ??? -- begin
    guint32          seq_num_gex_req;
    guint32          seq_num_gex_grp;
    guint32          seq_num_gex_ini;
    guint32          seq_num_gex_rep;
// --
    guint32          seq_num_ecdh_ini;
    guint32          seq_num_ecdh_rep;
// --
    guint32          seq_num_dh_ini;
    guint32          seq_num_dh_rep;
// union ??? -- end
    guint32          seq_num_new_key;
    ssh_bignum      *bn_cookie;
    guint8           iv[12];
    guint8           hmac_iv[DIGEST_MAX_SIZE];
    guint            hmac_iv_len;
    struct ssh_flow_data * global_data;
};

struct ssh_flow_data {
    guint   version;

    gchar*  kex;
    int   (*kex_specific_dissector)(guint8 msg_code, tvbuff_t *tvb,
            packet_info *pinfo, int offset, proto_tree *tree,
            struct ssh_flow_data *global_data, guint *seq_num);

    /* [0] is client's, [1] is server's */
#define CLIENT_PEER_DATA 0
#define SERVER_PEER_DATA 1
    struct ssh_peer_data peer_data[2];

    gchar           *session_id;
    guint           session_id_length;
    ssh_bignum      *kex_e;
    ssh_bignum      *kex_f;
    ssh_bignum      *secret;
    wmem_array_t    *kex_client_version;
    wmem_array_t    *kex_server_version;
    wmem_array_t    *kex_client_key_exchange_init;
    wmem_array_t    *kex_server_key_exchange_init;
    wmem_array_t    *kex_server_host_key_blob;
    wmem_array_t    *kex_shared_secret;
    gboolean        do_decrypt;
    ssh_bignum      new_keys[6];
    ssh_channel_info_t *channel_info;
};

static GHashTable * ssh_master_key_map = NULL;

static int proto_ssh = -1;

/* Version exchange */
static int hf_ssh_protocol = -1;

/* Framing */
static int hf_ssh_packet_length = -1;
static int hf_ssh_packet_length_encrypted = -1;
static int hf_ssh_padding_length = -1;
static int hf_ssh_payload = -1;
static int hf_ssh_encrypted_packet = -1;
static int hf_ssh_padding_string = -1;
static int hf_ssh_mac_string = -1;
static int hf_ssh_mac_status = -1;
static int hf_ssh_seq_num = -1;
static int hf_ssh_direction = -1;

/* Message codes */
static int hf_ssh_msg_code = -1;
static int hf_ssh2_msg_code = -1;
static int hf_ssh2_kex_dh_msg_code = -1;
static int hf_ssh2_kex_dh_gex_msg_code = -1;
static int hf_ssh2_kex_ecdh_msg_code = -1;

/* Algorithm negotiation */
static int hf_ssh_cookie = -1;
static int hf_ssh_kex_algorithms = -1;
static int hf_ssh_server_host_key_algorithms = -1;
static int hf_ssh_encryption_algorithms_client_to_server = -1;
static int hf_ssh_encryption_algorithms_server_to_client = -1;
static int hf_ssh_mac_algorithms_client_to_server = -1;
static int hf_ssh_mac_algorithms_server_to_client = -1;
static int hf_ssh_compression_algorithms_client_to_server = -1;
static int hf_ssh_compression_algorithms_server_to_client = -1;
static int hf_ssh_languages_client_to_server = -1;
static int hf_ssh_languages_server_to_client = -1;
static int hf_ssh_kex_algorithms_length = -1;
static int hf_ssh_server_host_key_algorithms_length = -1;
static int hf_ssh_encryption_algorithms_client_to_server_length = -1;
static int hf_ssh_encryption_algorithms_server_to_client_length = -1;
static int hf_ssh_mac_algorithms_client_to_server_length = -1;
static int hf_ssh_mac_algorithms_server_to_client_length = -1;
static int hf_ssh_compression_algorithms_client_to_server_length = -1;
static int hf_ssh_compression_algorithms_server_to_client_length = -1;
static int hf_ssh_languages_client_to_server_length = -1;
static int hf_ssh_languages_server_to_client_length = -1;
static int hf_ssh_first_kex_packet_follows = -1;
static int hf_ssh_kex_reserved = -1;
static int hf_ssh_kex_hassh_algo = -1;
static int hf_ssh_kex_hassh = -1;
static int hf_ssh_kex_hasshserver_algo = -1;
static int hf_ssh_kex_hasshserver = -1;

/* Key exchange common elements */
static int hf_ssh_hostkey_length = -1;
static int hf_ssh_hostkey_type_length = -1;
static int hf_ssh_hostkey_type = -1;
static int hf_ssh_hostkey_data = -1;
static int hf_ssh_hostkey_rsa_n = -1;
static int hf_ssh_hostkey_rsa_e = -1;
static int hf_ssh_hostkey_dsa_p = -1;
static int hf_ssh_hostkey_dsa_q = -1;
static int hf_ssh_hostkey_dsa_g = -1;
static int hf_ssh_hostkey_dsa_y = -1;
static int hf_ssh_hostkey_ecdsa_curve_id = -1;
static int hf_ssh_hostkey_ecdsa_curve_id_length = -1;
static int hf_ssh_hostkey_ecdsa_q = -1;
static int hf_ssh_hostkey_ecdsa_q_length = -1;
static int hf_ssh_hostkey_eddsa_key = -1;
static int hf_ssh_hostkey_eddsa_key_length = -1;
static int hf_ssh_hostsig_length = -1;
static int hf_ssh_hostsig_type_length = -1;
static int hf_ssh_hostsig_type = -1;
static int hf_ssh_hostsig_rsa = -1;
static int hf_ssh_hostsig_dsa = -1;
static int hf_ssh_hostsig_data = -1;

/* Key exchange: Diffie-Hellman */
static int hf_ssh_dh_e = -1;
static int hf_ssh_dh_f = -1;

/* Key exchange: Diffie-Hellman Group Exchange */
static int hf_ssh_dh_gex_min = -1;
static int hf_ssh_dh_gex_nbits = -1;
static int hf_ssh_dh_gex_max = -1;
static int hf_ssh_dh_gex_p = -1;
static int hf_ssh_dh_gex_g = -1;

/* Key exchange: Elliptic Curve Diffie-Hellman */
static int hf_ssh_ecdh_q_c = -1;
static int hf_ssh_ecdh_q_c_length = -1;
static int hf_ssh_ecdh_q_s = -1;
static int hf_ssh_ecdh_q_s_length = -1;

/* Miscellaneous */
static int hf_ssh_mpint_length = -1;

static int hf_ssh_ignore_data_length = -1;
static int hf_ssh_ignore_data = -1;
static int hf_ssh_debug_always_display = -1;
static int hf_ssh_debug_message_length = -1;
static int hf_ssh_debug_message = -1;
static int hf_ssh_service_name_length = -1;
static int hf_ssh_service_name = -1;
static int hf_ssh_userauth_user_name_length = -1;
static int hf_ssh_userauth_user_name = -1;
static int hf_ssh_userauth_change_password = -1;
static int hf_ssh_userauth_service_name_length = -1;
static int hf_ssh_userauth_service_name = -1;
static int hf_ssh_userauth_method_name_length = -1;
static int hf_ssh_userauth_method_name = -1;
static int hf_ssh_userauth_have_signature = -1;
static int hf_ssh_userauth_password_length = -1;
static int hf_ssh_userauth_password = -1;
static int hf_ssh_userauth_new_password_length = -1;
static int hf_ssh_userauth_new_password = -1;
static int hf_ssh_auth_failure_list_length = -1;
static int hf_ssh_auth_failure_list = -1;
static int hf_ssh_userauth_partial_success = -1;
static int hf_ssh_userauth_pka_name_len = -1;
static int hf_ssh_userauth_pka_name = -1;
static int hf_ssh_pk_blob_name_length = -1;
static int hf_ssh_pk_blob_name = -1;
static int hf_ssh_blob_length = -1;
static int hf_ssh_signature_length = -1;
static int hf_ssh_pk_sig_blob_name_length = -1;
static int hf_ssh_pk_sig_blob_name = -1;
static int hf_ssh_connection_type_name_len = -1;
static int hf_ssh_connection_type_name = -1;
static int hf_ssh_connection_sender_channel = -1;
static int hf_ssh_connection_recipient_channel = -1;
static int hf_ssh_connection_initial_window = -1;
static int hf_ssh_connection_maximum_packet_size = -1;
static int hf_ssh_global_request_name_len = -1;
static int hf_ssh_global_request_name = -1;
static int hf_ssh_global_request_want_reply = -1;
static int hf_ssh_global_request_hostkeys_array_len = -1;
static int hf_ssh_channel_request_name_len = -1;
static int hf_ssh_channel_request_name = -1;
static int hf_ssh_channel_request_want_reply = -1;
static int hf_ssh_subsystem_name_len = -1;
static int hf_ssh_subsystem_name = -1;
static int hf_ssh_channel_window_adjust = -1;
static int hf_ssh_channel_data_len = -1;
static int hf_ssh_exit_status = -1;
static int hf_ssh_disconnect_reason = -1;
static int hf_ssh_disconnect_description_length = -1;
static int hf_ssh_disconnect_description = -1;
static int hf_ssh_lang_tag_length = -1;
static int hf_ssh_lang_tag = -1;

static int hf_ssh_blob_p = -1;
static int hf_ssh_blob_e = -1;

static int hf_ssh_pk_sig_s_length = -1;
static int hf_ssh_pk_sig_s = -1;

static gint ett_ssh = -1;
static gint ett_key_exchange = -1;
static gint ett_key_exchange_host_key = -1;
static gint ett_key_exchange_host_sig = -1;
static gint ett_userauth_pk_blob = -1;
static gint ett_userauth_pk_signautre = -1;
static gint ett_key_init = -1;
static gint ett_ssh1 = -1;
static gint ett_ssh2 = -1;

static expert_field ei_ssh_packet_length = EI_INIT;
static expert_field ei_ssh_packet_decode = EI_INIT;
static expert_field ei_ssh_invalid_keylen = EI_INIT;
static expert_field ei_ssh_mac_bad = EI_INIT;

static gboolean ssh_desegment = TRUE;

static dissector_handle_t ssh_handle;
static dissector_handle_t sftp_handle=NULL;

static const char   *pref_keylog_file;
static FILE         *ssh_keylog_file;

#define SSH_DECRYPT_DEBUG

#ifdef SSH_DECRYPT_DEBUG
static const gchar *ssh_debug_file_name     = NULL;
#endif

// 29418/tcp: Gerrit Code Review
#define TCP_RANGE_SSH  "22,29418"
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

#define SSH_MSG_KEX_ECDH_INIT       30
#define SSH_MSG_KEX_ECDH_REPLY      31

/* User authentication protocol: generic (50-59) */
#define SSH_MSG_USERAUTH_REQUEST    50
#define SSH_MSG_USERAUTH_FAILURE    51
#define SSH_MSG_USERAUTH_SUCCESS    52
#define SSH_MSG_USERAUTH_BANNER     53

/* User authentication protocol: method specific (reusable) (50-79) */
#define SSH_MSG_USERAUTH_PK_OK      60

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

#define CIPHER_AES128_CBC               0x00020001
#define CIPHER_AES192_CBC               0x00020002
#define CIPHER_AES256_CBC               0x00020004
#define CIPHER_AES128_GCM               0x00040001
//#define CIPHER_AES192_GCM               0x00040002	-- does not exist
#define CIPHER_AES256_GCM               0x00040004

#define CIPHER_MAC_SHA2_256             0x00020001

static const value_string ssh_direction_vals[] = {
    { CLIENT_TO_SERVER_PROPOSAL, "client-to-server" },
    { SERVER_TO_CLIENT_PROPOSAL, "server-to-client" },
    { 0, NULL }
};

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
    { SSH_MSG_USERAUTH_PK_OK,            "Public Key algorithm accepted" },
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

static const value_string ssh2_kex_ecdh_msg_vals[] = {
    { SSH_MSG_KEX_ECDH_INIT,             "Elliptic Curve Diffie-Hellman Key Exchange Init" },
    { SSH_MSG_KEX_ECDH_REPLY,            "Elliptic Curve Diffie-Hellman Key Exchange Reply" },
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

static int ssh_dissect_key_init(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
        int is_response,
        struct ssh_flow_data *global_data);
static int ssh_dissect_proposal(tvbuff_t *tvb, int offset, proto_tree *tree,
        int hf_index_length, int hf_index_value, char **store);
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
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, guint *seq_num);
static int ssh_dissect_kex_dh_gex(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, guint *seq_num);
static int ssh_dissect_kex_ecdh(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, guint *seq_num);
static int ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response, guint *version,
        gboolean *need_desegmentation);
static int ssh_try_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *tree);
static int ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data,
        int offset, proto_tree *tree);
static void ssh_choose_algo(gchar *client, gchar *server, gchar **result);
static void ssh_set_mac_length(struct ssh_peer_data *peer_data);
static void ssh_set_kex_specific_dissector(struct ssh_flow_data *global_data);

static void ssh_keylog_read_file(void);
static void ssh_keylog_process_line(const char *line);
static void ssh_keylog_process_lines(const guint8 *data, guint datalen);
static void ssh_keylog_reset(void);
static ssh_bignum *ssh_kex_make_bignum(const guint8 *data, guint length);
static gboolean ssh_read_e(tvbuff_t *tvb, int offset,
        struct ssh_flow_data *global_data);
static gboolean ssh_read_f(tvbuff_t *tvb, int offset,
        struct ssh_flow_data *global_data);
static void ssh_keylog_hash_write_secret(struct ssh_flow_data *global_data);
static ssh_bignum *ssh_kex_shared_secret(gint kex_type, ssh_bignum *pub, ssh_bignum *priv);
static void ssh_hash_buffer_put_string(wmem_array_t *buffer, const gchar *string,
        guint len);
static gchar *ssh_string(const gchar *string, guint len);
static void ssh_derive_symmetric_keys(ssh_bignum *shared_secret,
        gchar *exchange_hash, guint hash_length,
        struct ssh_flow_data *global_data);
static void ssh_derive_symmetric_key(ssh_bignum *shared_secret,
        gchar *exchange_hash, guint hash_length, gchar id,
        ssh_bignum *result_key, struct ssh_flow_data *global_data);

static void ssh_decryption_set_cipher_id(struct ssh_peer_data *peer);
static void ssh_decryption_setup_cipher(struct ssh_peer_data *peer,
        ssh_bignum *iv, ssh_bignum *key);
static void ssh_decryption_set_mac_id(struct ssh_peer_data *peer);
static void ssh_decryption_setup_mac(struct ssh_peer_data *peer,
        ssh_bignum *iv);
static void ssh_increment_message_number(packet_info *pinfo,
        struct ssh_flow_data *global_data, gboolean is_response);
static guint ssh_decrypt_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *tree);
static gboolean ssh_decrypt_chacha20(gcry_cipher_hd_t hd, guint32 seqnr,
        guint32 counter, const guchar *ctext, guint ctext_len,
        guchar *plain, guint plain_len);
static proto_item * ssh_tree_add_mac(proto_tree *tree, tvbuff_t *tvb, const guint offset, const guint mac_len,
        const int hf_mac, const int hf_mac_status, struct expert_field* bad_checksum_expert,
        packet_info *pinfo, const guint8 * calc_mac, const guint flags);

static int ssh_dissect_decrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, proto_tree *tree,
        gchar *plaintext, guint plaintext_len);
static int ssh_dissect_transport_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code);
static int ssh_dissect_userauth_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code);
static int ssh_dissect_userauth_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code);
static int ssh_dissect_connection_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_item *msg_type_tree,
        guint msg_code);
static int ssh_dissect_connection_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code);
static int ssh_dissect_public_key_blob(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree);
static int ssh_dissect_public_key_signature(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree);

static dissector_handle_t get_subdissector_for_channel(struct ssh_peer_data *peer_data, guint uiNumChannel);
static void set_subdissector_for_channel(struct ssh_peer_data *peer_data, guint uiNumChannel, guint8* subsystem_name);

#define SSH_DEBUG_USE_STDERR "-"

#ifdef SSH_DECRYPT_DEBUG
static void
ssh_debug_printf(const gchar* fmt,...) G_GNUC_PRINTF(1,2);
static void
ssh_print_data(const gchar* name, const guchar* data, size_t len);
static void
ssh_set_debug(const gchar* name);
static void
ssh_debug_flush(void);
#else

/* No debug: nullify debug operation*/
static inline void G_GNUC_PRINTF(1,2)
ssh_debug_printf(const gchar* fmt _U_,...)
{
}
#define ssh_print_data(a, b, c)
#define ssh_print_string(a, b)
#define ssh_set_debug(name)
#define ssh_debug_flush()

#endif /* SSH_DECRYPT_DEBUG */

static int
dissect_ssh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree  *ssh_tree;
    proto_item  *ti;
    conversation_t *conversation;
    int         last_offset, offset = 0;

    gboolean    is_response = (pinfo->destport != pinfo->match_uint),
                need_desegmentation;
    guint       version;

    struct ssh_flow_data *global_data = NULL;
    struct ssh_peer_data *peer_data;

    ssh_debug_printf("\ndissect_ssh enter frame #%u (%s)\n", pinfo->num, (pinfo->fd->visited)?"already visited":"first time");

    conversation = find_or_create_conversation(pinfo);

    global_data = (struct ssh_flow_data *)conversation_get_proto_data(conversation, proto_ssh);
    if (!global_data) {
        global_data = wmem_new0(wmem_file_scope(), struct ssh_flow_data);
        global_data->version = SSH_VERSION_UNKNOWN;
        global_data->kex_specific_dissector = ssh_dissect_kex_dh;
        global_data->peer_data[CLIENT_PEER_DATA].mac_length = -1;
        global_data->peer_data[SERVER_PEER_DATA].mac_length = -1;
        global_data->peer_data[CLIENT_PEER_DATA].sequence_number = 0;
        global_data->peer_data[SERVER_PEER_DATA].sequence_number = 0;
        global_data->peer_data[CLIENT_PEER_DATA].seq_num_kex_init = 0;
        global_data->peer_data[SERVER_PEER_DATA].seq_num_kex_init = 0;
        global_data->peer_data[CLIENT_PEER_DATA].seq_num_gex_req = 0;
        global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_req = 0;
        global_data->peer_data[CLIENT_PEER_DATA].seq_num_gex_grp = 0;
        global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_grp = 0;
        global_data->peer_data[CLIENT_PEER_DATA].seq_num_gex_ini = 0;
        global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_ini = 0;
        global_data->peer_data[CLIENT_PEER_DATA].seq_num_gex_rep = 0;
        global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_rep = 0;
        global_data->peer_data[CLIENT_PEER_DATA].seq_num_ecdh_ini = 0;
        global_data->peer_data[SERVER_PEER_DATA].seq_num_ecdh_ini = 0;
        global_data->peer_data[CLIENT_PEER_DATA].seq_num_ecdh_rep = 0;
        global_data->peer_data[SERVER_PEER_DATA].seq_num_ecdh_rep = 0;
        global_data->peer_data[CLIENT_PEER_DATA].seq_num_dh_ini = 0;
        global_data->peer_data[SERVER_PEER_DATA].seq_num_dh_ini = 0;
        global_data->peer_data[CLIENT_PEER_DATA].seq_num_dh_rep = 0;
        global_data->peer_data[SERVER_PEER_DATA].seq_num_dh_rep = 0;
        global_data->peer_data[CLIENT_PEER_DATA].seq_num_new_key = 0;
        global_data->peer_data[SERVER_PEER_DATA].seq_num_new_key = 0;
        global_data->peer_data[CLIENT_PEER_DATA].bn_cookie = NULL;
        global_data->peer_data[SERVER_PEER_DATA].bn_cookie = NULL;
        global_data->peer_data[CLIENT_PEER_DATA].global_data = global_data;
        global_data->peer_data[SERVER_PEER_DATA].global_data = global_data;
        global_data->channel_info = NULL;
        global_data->kex_client_version = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_server_version = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_client_key_exchange_init = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_server_key_exchange_init = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_server_host_key_blob = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_shared_secret = wmem_array_new(wmem_file_scope(), 1);
        global_data->do_decrypt      = TRUE;

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
                offset = ssh_try_dissect_encrypted_packet(tvb, pinfo,
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
    ti = proto_tree_add_boolean_format_value(ssh_tree, hf_ssh_direction, tvb, 0, 0, is_response, "%s",
        try_val_to_str(is_response, ssh_direction_vals));
    proto_item_set_generated(ti);

    ssh_debug_flush();

    return tvb_captured_length(tvb);
}

static int
ssh_dissect_ssh2(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation)
{
    proto_item *ssh2_tree = NULL;
    gint remain_length;

    struct ssh_peer_data *peer_data = &global_data->peer_data[is_response];

    remain_length = tvb_captured_length_remaining(tvb, offset);

    while(remain_length>0){
        int last_offset = offset;
        if (tree) {
            wmem_strbuf_t *title = wmem_strbuf_new(wmem_packet_scope(), "SSH Version 2");

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

            ssh2_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_ssh2, NULL, wmem_strbuf_get_str(title));
        }
        ws_noisy("....ssh_dissect_ssh2[%c]: frame_key_start=%d, pinfo->num=%d, frame_key_end=%d, offset=%d, frame_key_end_offset=%d ", is_response==SERVER_PEER_DATA?'S':'C', peer_data->frame_key_start, pinfo->num, peer_data->frame_key_end, offset, peer_data->frame_key_end_offset);
        if ((peer_data->frame_key_start == 0) ||
            ((peer_data->frame_key_start <= pinfo->num) &&
            ((peer_data->frame_key_end == 0) || (pinfo->num < peer_data->frame_key_end) ||
                    ((pinfo->num == peer_data->frame_key_end) && (offset < peer_data->frame_key_end_offset))))) {
            offset = ssh_dissect_key_exchange(tvb, pinfo, global_data,
                offset, ssh2_tree, is_response,
                need_desegmentation);

            if (!*need_desegmentation) {
                ssh_increment_message_number(pinfo, global_data, is_response);
            }else{
                break;
            }
        } else {
            if(!*need_desegmentation){
                offset = ssh_try_dissect_encrypted_packet(tvb, pinfo,
                        &global_data->peer_data[is_response], offset, ssh2_tree);
            }else{
                break;
            }
        }

        if (ssh2_tree) {
            proto_item_set_len(ssh2_tree, offset - last_offset);
        }

        remain_length = tvb_captured_length_remaining(tvb, offset);
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

    ssh1_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_ssh1, NULL, "SSH Version 1");

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
        if (!pinfo->fd->visited) {
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
    offset += len;

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

static guint
ssh_tree_add_hostkey(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                     const char *tree_name, int ett_idx,
                     struct ssh_flow_data *global_data)
{
    proto_tree *tree = NULL;
    int last_offset;
    int remaining_len;
    guint key_len, type_len;
    char* key_type;
    gchar *tree_title;

    last_offset = offset;

    key_len = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* Read the key type before creating the tree so we can append it as info. */
    type_len = tvb_get_ntohl(tvb, offset);
    offset += 4;
    key_type = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, offset, type_len, ENC_ASCII|ENC_NA);

    tree_title = wmem_strdup_printf(wmem_packet_scope(), "%s (type: %s)", tree_name, key_type);
    tree = proto_tree_add_subtree(parent_tree, tvb, last_offset, key_len + 4, ett_idx, NULL,
                                  tree_title);

    proto_tree_add_uint(tree, hf_ssh_hostkey_length, tvb, last_offset, 4, key_len);

    // server host key (K_S / Q)
    gchar *data = (gchar *)tvb_memdup(wmem_packet_scope(), tvb, last_offset + 4, key_len);
    ssh_hash_buffer_put_string(global_data->kex_server_host_key_blob, data, key_len);

    last_offset += 4;
    proto_tree_add_uint(tree, hf_ssh_hostkey_type_length, tvb, last_offset, 4, type_len);
    proto_tree_add_string(tree, hf_ssh_hostkey_type, tvb, offset, type_len, key_type);
    offset += type_len;

    if (0 == strcmp(key_type, "ssh-rsa")) {
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_rsa_e);
        ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_rsa_n);
    } else if (0 == strcmp(key_type, "ssh-dss")) {
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_dsa_p);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_dsa_q);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_dsa_g);
        ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_dsa_y);
    } else if (g_str_has_prefix(key_type, "ecdsa-sha2-")) {
        offset += ssh_tree_add_string(tvb, offset, tree,
                                      hf_ssh_hostkey_ecdsa_curve_id, hf_ssh_hostkey_ecdsa_curve_id_length);
        ssh_tree_add_string(tvb, offset, tree,
                            hf_ssh_hostkey_ecdsa_q, hf_ssh_hostkey_ecdsa_q_length);
    } else if (g_str_has_prefix(key_type, "ssh-ed")) {
        ssh_tree_add_string(tvb, offset, tree,
                            hf_ssh_hostkey_eddsa_key, hf_ssh_hostkey_eddsa_key_length);
    } else {
        remaining_len = key_len - (type_len + 4);
        proto_tree_add_item(tree, hf_ssh_hostkey_data, tvb, offset, remaining_len, ENC_NA);
    }

    return 4+key_len;
}

static guint
ssh_tree_add_hostsignature(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *parent_tree,
                     const char *tree_name, int ett_idx,
                     struct ssh_flow_data *global_data)
{
    (void)global_data;
    proto_tree *tree = NULL;
    proto_item* ti = NULL;
    int last_offset;
    int offset0 = offset;
    int remaining_len;
    guint sig_len, type_len;
    guint8* sig_type;
    gchar *tree_title;

    last_offset = offset;

    sig_len = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* Read the signature type before creating the tree so we can append it as info. */
    type_len = tvb_get_ntohl(tvb, offset);
    offset += 4;
    sig_type = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, type_len, ENC_ASCII|ENC_NA);

    tree_title = wmem_strdup_printf(wmem_packet_scope(), "%s (type: %s)", tree_name, sig_type);
    tree = proto_tree_add_subtree(parent_tree, tvb, last_offset, sig_len + 4, ett_idx, NULL,
                                  tree_title);

    ti = proto_tree_add_uint(tree, hf_ssh_hostsig_length, tvb, last_offset, 4, sig_len);

    last_offset += 4;
    proto_tree_add_uint(tree, hf_ssh_hostsig_type_length, tvb, last_offset, 4, type_len);
    proto_tree_add_string(tree, hf_ssh_hostsig_type, tvb, offset, type_len, sig_type);
    offset += type_len;

    if (0 == strcmp(sig_type, "ssh-rsa")) {
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostsig_rsa);
    } else if (0 == strcmp(sig_type, "ssh-dss")) {
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostsig_dsa);
    } else if (g_str_has_prefix(sig_type, "ecdsa-sha2-")) {
//        offset += ssh_tree_add_string(tvb, offset, tree,
//                                      hf_ssh_hostkey_ecdsa_curve_id, hf_ssh_hostkey_ecdsa_curve_id_length);
//        ssh_tree_add_string(tvb, offset, tree,
//                            hf_ssh_hostkey_ecdsa_q, hf_ssh_hostkey_ecdsa_q_length);
    } else if (g_str_has_prefix(sig_type, "ssh-ed")) {
//        ssh_tree_add_string(tvb, offset, tree,
//                            hf_ssh_hostkey_eddsa_key, hf_ssh_hostkey_eddsa_key_length);
    } else {
        remaining_len = sig_len - (type_len + 4);
        proto_tree_add_item(tree, hf_ssh_hostsig_data, tvb, offset, remaining_len, ENC_NA);
    }

    if(offset-offset0!=(int)(4+sig_len)){
        expert_add_info_format(pinfo, ti, &ei_ssh_packet_decode, "Decoded %d bytes, but packet legnth is %d bytes", offset-offset0, sig_len);
    }

    return 4+sig_len;
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
    int     last_offset = offset;
    guint   msg_code;
    guint   seq_num = 0;

    proto_item *ti;
    proto_item *key_ex_tree = NULL;
    const gchar *key_ex_title = "Key Exchange";

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

    if (global_data->kex)
        key_ex_title = wmem_strdup_printf(wmem_packet_scope(), "%s (method:%s)", key_ex_title, global_data->kex);
    key_ex_tree = proto_tree_add_subtree(tree, tvb, offset, plen-1, ett_key_exchange, NULL, key_ex_title);

    /* msg_code */
    msg_code = tvb_get_guint8(tvb, offset);

    if (msg_code >= 30 && msg_code < 40) {
        offset = global_data->kex_specific_dissector(msg_code, tvb, pinfo,
                offset, key_ex_tree, global_data, &seq_num);
    } else {
        proto_tree_add_item(key_ex_tree, hf_ssh2_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
            val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));

        /* 16 bytes cookie  */
        switch(msg_code)
        {
        case SSH_MSG_KEXINIT:
            offset = ssh_dissect_key_init(tvb, pinfo, offset, key_ex_tree, is_response, global_data);
            if ((peer_data->frame_key_start == 0) || (peer_data->frame_key_start == pinfo->num)) {
                if (!PINFO_FD_VISITED(pinfo)) {
                    peer_data->frame_key_start = pinfo->num;
                    if(global_data->peer_data[is_response].seq_num_kex_init == 0){
                        global_data->peer_data[is_response].seq_num_kex_init = global_data->peer_data[is_response].sequence_number;
                        global_data->peer_data[is_response].sequence_number++;
                        ssh_debug_printf("%s->sequence_number{SSH_MSG_KEXINIT=%d}++ > %d\n", is_response?"server":"client", global_data->peer_data[is_response].seq_num_kex_init, global_data->peer_data[is_response].sequence_number);
                    }
                }
            }
            seq_num = global_data->peer_data[is_response].seq_num_kex_init;
            break;
        case SSH_MSG_NEWKEYS:
            if (peer_data->frame_key_end == 0) {
                peer_data->frame_key_end = pinfo->num;
                peer_data->frame_key_end_offset = offset;
                ssh_choose_algo(global_data->peer_data[CLIENT_PEER_DATA].enc_proposals[is_response],
                                global_data->peer_data[SERVER_PEER_DATA].enc_proposals[is_response],
                                &peer_data->enc);

                if(global_data->peer_data[is_response].seq_num_new_key == 0){
                    global_data->peer_data[is_response].seq_num_new_key = global_data->peer_data[is_response].sequence_number;
                    global_data->peer_data[is_response].sequence_number++;
                    ssh_debug_printf("%s->sequence_number{SSH_MSG_NEWKEYS=%d}++ > %d\n", is_response?"server":"client", global_data->peer_data[is_response].seq_num_new_key, global_data->peer_data[is_response].sequence_number);
                }

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

                // the client sent SSH_MSG_NEWKEYS
                if (!is_response) {
                    ssh_decryption_set_cipher_id(&global_data->peer_data[CLIENT_PEER_DATA]);
                    ssh_decryption_set_mac_id(&global_data->peer_data[CLIENT_PEER_DATA]);
                    ssh_debug_printf("Activating new keys for CLIENT => SERVER\n");
                    ssh_decryption_setup_cipher(&global_data->peer_data[CLIENT_PEER_DATA], &global_data->new_keys[0], &global_data->new_keys[2]);
                    ssh_decryption_setup_mac(&global_data->peer_data[CLIENT_PEER_DATA], &global_data->new_keys[4]);
                }else{
                    ssh_decryption_set_cipher_id(&global_data->peer_data[SERVER_PEER_DATA]);
                    ssh_decryption_set_mac_id(&global_data->peer_data[SERVER_PEER_DATA]);
                    ssh_debug_printf("Activating new keys for SERVER => CLIENT\n");
                    ssh_decryption_setup_cipher(&global_data->peer_data[SERVER_PEER_DATA], &global_data->new_keys[1], &global_data->new_keys[3]);
                    ssh_decryption_setup_mac(&global_data->peer_data[SERVER_PEER_DATA], &global_data->new_keys[5]);
                }
            }
            seq_num = global_data->peer_data[is_response].seq_num_new_key;

            break;
        }
    }

    len = plen+4-padding_length-(offset-last_offset);
    if (len > 0) {
        proto_tree_add_item(key_ex_tree, hf_ssh_payload, tvb, offset, len, ENC_NA);
    }
    offset += len;

    /* padding */
    proto_tree_add_item(tree, hf_ssh_padding_string, tvb, offset, padding_length, ENC_NA);
    offset+= padding_length;
    proto_tree_add_uint(tree, hf_ssh_seq_num, tvb, offset, 0, seq_num);

    return offset;
}

static int ssh_dissect_kex_dh(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, guint *seq_num)
{
    *seq_num = 0;
    proto_tree_add_item(tree, hf_ssh2_kex_dh_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
        val_to_str(msg_code, ssh2_kex_dh_msg_vals, "Unknown (%u)"));

    switch (msg_code) {
    case SSH_MSG_KEXDH_INIT:
        // e (client ephemeral key public part)
        if (!ssh_read_e(tvb, offset, global_data)) {
            proto_tree_add_expert_format(tree, pinfo, &ei_ssh_invalid_keylen, tvb, offset, 2,
                "Invalid key length: %u", tvb_get_ntohl(tvb, offset));
        }

        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_e);
        if(global_data->peer_data[CLIENT_PEER_DATA].seq_num_dh_ini == 0){
            global_data->peer_data[CLIENT_PEER_DATA].sequence_number++;
            global_data->peer_data[CLIENT_PEER_DATA].seq_num_dh_ini = global_data->peer_data[CLIENT_PEER_DATA].sequence_number;
            ssh_debug_printf("%s->sequence_number{SSH_MSG_KEXDH_INIT}++ > %d\n", CLIENT_PEER_DATA?"serveur":"client", global_data->peer_data[CLIENT_PEER_DATA].sequence_number);
        }
        *seq_num = global_data->peer_data[CLIENT_PEER_DATA].seq_num_dh_ini;
        break;

    case SSH_MSG_KEXDH_REPLY:
        offset += ssh_tree_add_hostkey(tvb, offset, tree, "KEX host key",
                ett_key_exchange_host_key, global_data);

        // f (server ephemeral key public part), K_S (host key)
        if (!ssh_read_f(tvb, offset, global_data)) {
            proto_tree_add_expert_format(tree, pinfo, &ei_ssh_invalid_keylen, tvb, offset, 2,
                "Invalid key length: %u", tvb_get_ntohl(tvb, offset));
        }
        ssh_keylog_hash_write_secret(global_data);

        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_f);
        offset += ssh_tree_add_hostsignature(tvb, pinfo, offset, tree, "KEX host signature",
                ett_key_exchange_host_sig, global_data);
        if(global_data->peer_data[SERVER_PEER_DATA].seq_num_dh_rep == 0){
            global_data->peer_data[SERVER_PEER_DATA].sequence_number++;
            global_data->peer_data[SERVER_PEER_DATA].seq_num_dh_rep = global_data->peer_data[SERVER_PEER_DATA].sequence_number;
            ssh_debug_printf("%s->sequence_number{SSH_MSG_KEXDH_REPLY}++ > %d\n", SERVER_PEER_DATA?"serveur":"client", global_data->peer_data[SERVER_PEER_DATA].sequence_number);
        }
        *seq_num = global_data->peer_data[SERVER_PEER_DATA].seq_num_dh_rep;
        break;
    }

    return offset;
}

static int ssh_dissect_kex_dh_gex(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, guint *seq_num)
{
    *seq_num = 0;
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
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_gex_p);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_gex_g);
        if(global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_grp == 0){
            global_data->peer_data[SERVER_PEER_DATA].sequence_number++;
            global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_grp = global_data->peer_data[SERVER_PEER_DATA].sequence_number;
            ssh_debug_printf("%s->sequence_number{SSH_MSG_KEX_DH_GEX_GROUP}++ > %d\n", SERVER_PEER_DATA?"serveur":"client", global_data->peer_data[SERVER_PEER_DATA].sequence_number);
        }
        *seq_num = global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_grp;
        break;

    case SSH_MSG_KEX_DH_GEX_INIT:
        // TODO allow decryption with this key exchange method
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_e);
        if(global_data->peer_data[CLIENT_PEER_DATA].seq_num_gex_ini == 0){
            global_data->peer_data[CLIENT_PEER_DATA].sequence_number++;
            global_data->peer_data[CLIENT_PEER_DATA].seq_num_gex_ini = global_data->peer_data[CLIENT_PEER_DATA].sequence_number;
            ssh_debug_printf("%s->sequence_number{SSH_MSG_KEX_DH_GEX_INIT}++ > %d\n", CLIENT_PEER_DATA?"serveur":"client", global_data->peer_data[CLIENT_PEER_DATA].sequence_number);
        }
        *seq_num = global_data->peer_data[CLIENT_PEER_DATA].seq_num_gex_ini;
        break;

    case SSH_MSG_KEX_DH_GEX_REPLY:
        offset += ssh_tree_add_hostkey(tvb, offset, tree, "KEX host key",
                ett_key_exchange_host_key, global_data);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_f);
        offset += ssh_tree_add_hostsignature(tvb, pinfo, offset, tree, "KEX host signature",
                ett_key_exchange_host_sig, global_data);
        if(global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_rep == 0){
            global_data->peer_data[SERVER_PEER_DATA].sequence_number++;
            global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_rep = global_data->peer_data[SERVER_PEER_DATA].sequence_number;
            ssh_debug_printf("%s->sequence_number{SSH_MSG_KEX_DH_GEX_REPLY}++ > %d\n", SERVER_PEER_DATA?"serveur":"client", global_data->peer_data[SERVER_PEER_DATA].sequence_number);
        }
        *seq_num = global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_rep;
        break;

    case SSH_MSG_KEX_DH_GEX_REQUEST:
        proto_tree_add_item(tree, hf_ssh_dh_gex_min, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_ssh_dh_gex_nbits, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_ssh_dh_gex_max, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        if(global_data->peer_data[CLIENT_PEER_DATA].seq_num_gex_req == 0){
            global_data->peer_data[CLIENT_PEER_DATA].sequence_number++;
            global_data->peer_data[CLIENT_PEER_DATA].seq_num_gex_req = global_data->peer_data[CLIENT_PEER_DATA].sequence_number;
            ssh_debug_printf("%s->sequence_number{SSH_MSG_KEX_DH_GEX_REQUEST}++ > %d\n", CLIENT_PEER_DATA?"serveur":"client", global_data->peer_data[CLIENT_PEER_DATA].sequence_number);
        }
        *seq_num = global_data->peer_data[CLIENT_PEER_DATA].seq_num_gex_req;
        break;
    }

    return offset;
}

static int
ssh_dissect_kex_ecdh(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, guint *seq_num)
{
    proto_tree_add_item(tree, hf_ssh2_kex_ecdh_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
        val_to_str(msg_code, ssh2_kex_ecdh_msg_vals, "Unknown (%u)"));

    switch (msg_code) {
    case SSH_MSG_KEX_ECDH_INIT:
        if (!ssh_read_e(tvb, offset, global_data)) {
            proto_tree_add_expert_format(tree, pinfo, &ei_ssh_invalid_keylen, tvb, offset, 2,
                "Invalid key length: %u", tvb_get_ntohl(tvb, offset));
        }

        if (!PINFO_FD_VISITED(pinfo)) {
            if(global_data->peer_data[CLIENT_PEER_DATA].seq_num_ecdh_ini == 0){
                global_data->peer_data[CLIENT_PEER_DATA].seq_num_ecdh_ini = global_data->peer_data[CLIENT_PEER_DATA].sequence_number;
                global_data->peer_data[CLIENT_PEER_DATA].sequence_number++;
                ssh_debug_printf("%s->sequence_number{SSH_MSG_KEX_ECDH_INIT=%d}++ > %d\n", CLIENT_PEER_DATA?"server":"client", global_data->peer_data[CLIENT_PEER_DATA].seq_num_ecdh_ini, global_data->peer_data[CLIENT_PEER_DATA].sequence_number);
            }
        }
        *seq_num = global_data->peer_data[CLIENT_PEER_DATA].seq_num_ecdh_ini;

        offset += ssh_tree_add_string(tvb, offset, tree, hf_ssh_ecdh_q_c, hf_ssh_ecdh_q_c_length);
        break;

    case SSH_MSG_KEX_ECDH_REPLY:
        offset += ssh_tree_add_hostkey(tvb, offset, tree, "KEX host key",
                ett_key_exchange_host_key, global_data);

        if (!ssh_read_f(tvb, offset, global_data)){
            proto_tree_add_expert_format(tree, pinfo, &ei_ssh_invalid_keylen, tvb, offset, 2,
                "Invalid key length: %u", tvb_get_ntohl(tvb, offset));
        }

        ssh_keylog_hash_write_secret(global_data);
        if(global_data->peer_data[SERVER_PEER_DATA].seq_num_ecdh_rep == 0){
            global_data->peer_data[SERVER_PEER_DATA].seq_num_ecdh_rep = global_data->peer_data[SERVER_PEER_DATA].sequence_number;
            global_data->peer_data[SERVER_PEER_DATA].sequence_number++;
            ssh_debug_printf("%s->sequence_number{SSH_MSG_KEX_ECDH_REPLY=%d}++ > %d\n", SERVER_PEER_DATA?"server":"client", global_data->peer_data[SERVER_PEER_DATA].seq_num_ecdh_rep, global_data->peer_data[SERVER_PEER_DATA].sequence_number);
        }
        *seq_num = global_data->peer_data[SERVER_PEER_DATA].seq_num_ecdh_rep;

        offset += ssh_tree_add_string(tvb, offset, tree, hf_ssh_ecdh_q_s, hf_ssh_ecdh_q_s_length);
        offset += ssh_tree_add_hostsignature(tvb, pinfo, offset, tree, "KEX host signature",
                ett_key_exchange_host_sig, global_data);
        break;
    }

    return offset;
}

static int
ssh_try_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *tree)
{
    gboolean can_decrypt = peer_data->cipher != NULL;

    if (can_decrypt) {
        return ssh_decrypt_packet(tvb, pinfo, peer_data, offset, tree);
    }

    return ssh_dissect_encrypted_packet(tvb, pinfo, peer_data, offset, tree);
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
    offset += len;
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
            tvb_format_text(pinfo->pool, tvb, offset, protolen));

    // V_C / V_S (client and server identification strings) RFC4253 4.2
    // format: SSH-protoversion-softwareversion SP comments [CR LF not incl.]
    if (!PINFO_FD_VISITED(pinfo)) {
        gchar *data = (gchar *)tvb_memdup(wmem_packet_scope(), tvb, offset, protolen);
        if(!is_response){
            ssh_hash_buffer_put_string(global_data->kex_client_version, data, protolen);
        }else{
            ssh_hash_buffer_put_string(global_data->kex_server_version, data, protolen);
        }
    }

    proto_tree_add_item(tree, hf_ssh_protocol,
                    tvb, offset, protolen, ENC_ASCII);
    offset += linelen;
    return offset;
}

static void
ssh_set_mac_length(struct ssh_peer_data *peer_data)
{
    char *size_str;
    guint32 size = 0;
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

    size_str = g_strrstr(mac_name, "-");
    if (size_str && ws_strtou32(size_str + 1, NULL, &size) && size > 0 && size % 8 == 0) {
        peer_data->mac_length = size / 8;
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
    else if (g_str_has_prefix(kex_name, "ecdh-sha2-") ||
        strcmp(kex_name, "curve25519-sha256@libssh.org") == 0 ||
        strcmp(kex_name, "curve25519-sha256") == 0 ||
        strcmp(kex_name, "curve448-sha512") == 0)
    {
        global_data->kex_specific_dissector = ssh_dissect_kex_ecdh;
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
    gchar **server_strings = NULL;
    gchar **client_strings = NULL;
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
        if ((agreed = g_slist_find_custom(server_list, *step, ssh_gslist_compare_strings))) {
            *result = wmem_strdup(wmem_file_scope(), (const gchar *)agreed->data);
            break;
        }
    }

    g_strfreev(client_strings);
    g_slist_free(server_list);
    g_strfreev(server_strings);
}

static int
ssh_dissect_key_init(tvbuff_t *tvb, packet_info *pinfo, int offset,
        proto_tree *tree, int is_response, struct ssh_flow_data *global_data)
{
    int start_offset = offset;
    int payload_length;
    wmem_strbuf_t *hassh_algo;
    gchar  *hassh;

    proto_item *tf, *ti;
    proto_tree *key_init_tree;

    struct ssh_peer_data *peer_data = &global_data->peer_data[is_response];

    key_init_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_key_init, &tf, "Algorithms");
    if (!PINFO_FD_VISITED(pinfo)) {
        peer_data->bn_cookie = ssh_kex_make_bignum(tvb_get_ptr(tvb, offset, 16), 16);
    }
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

    proto_tree_add_item(key_init_tree, hf_ssh_first_kex_packet_follows,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    proto_tree_add_item(key_init_tree, hf_ssh_kex_reserved,
        tvb, offset, 4, ENC_NA);
    offset+=4;

    hassh_algo = wmem_strbuf_new(wmem_packet_scope(), "");
    if(!is_response) {
        wmem_strbuf_append_printf(hassh_algo, "%s;%s;%s;%s", peer_data->kex_proposal, peer_data->enc_proposals[CLIENT_TO_SERVER_PROPOSAL],
                peer_data->mac_proposals[CLIENT_TO_SERVER_PROPOSAL], peer_data->comp_proposals[CLIENT_TO_SERVER_PROPOSAL]);
        hassh = g_compute_checksum_for_string(G_CHECKSUM_MD5, wmem_strbuf_get_str(hassh_algo), wmem_strbuf_get_len(hassh_algo));
        ti = proto_tree_add_string(key_init_tree, hf_ssh_kex_hassh_algo, tvb, offset, 0, wmem_strbuf_get_str(hassh_algo));
        proto_item_set_generated(ti);
        ti = proto_tree_add_string(key_init_tree, hf_ssh_kex_hassh, tvb, offset, 0, hassh);
        proto_item_set_generated(ti);
        g_free(hassh);
    } else {
        wmem_strbuf_append_printf(hassh_algo, "%s;%s;%s;%s", peer_data->kex_proposal, peer_data->enc_proposals[SERVER_TO_CLIENT_PROPOSAL],
                peer_data->mac_proposals[SERVER_TO_CLIENT_PROPOSAL], peer_data->comp_proposals[SERVER_TO_CLIENT_PROPOSAL]);
        hassh = g_compute_checksum_for_string(G_CHECKSUM_MD5, wmem_strbuf_get_str(hassh_algo), wmem_strbuf_get_len(hassh_algo));
        ti = proto_tree_add_string(key_init_tree, hf_ssh_kex_hasshserver_algo, tvb, offset, 0, wmem_strbuf_get_str(hassh_algo));
        proto_item_set_generated(ti);
        ti = proto_tree_add_string(key_init_tree, hf_ssh_kex_hasshserver, tvb, offset, 0, hassh);
        proto_item_set_generated(ti);
        g_free(hassh);
    }

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

    payload_length = offset - start_offset;

    if (tf != NULL) {
        proto_item_set_len(tf, payload_length);
    }

    // I_C / I_S (client and server SSH_MSG_KEXINIT payload) RFC4253 4.2
    if (!PINFO_FD_VISITED(pinfo)) {
        gchar *data = (gchar *)wmem_alloc(wmem_packet_scope(), payload_length + 1);
        tvb_memcpy(tvb, data + 1, start_offset, payload_length);
        data[0] = SSH_MSG_KEXINIT;
        if(is_response){
            ssh_hash_buffer_put_string(global_data->kex_server_key_exchange_init, data, payload_length + 1);
        }else{
            ssh_hash_buffer_put_string(global_data->kex_client_key_exchange_init, data, payload_length + 1);
        }
    }

    return offset;
}

static int
ssh_dissect_proposal(tvbuff_t *tvb, int offset, proto_tree *tree,
             int hf_index_length, int hf_index_value, char **store)
{
    guint32 len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_index_length, tvb, offset, 4, len);
    offset += 4;

    proto_tree_add_item(tree, hf_index_value, tvb, offset, len,
                ENC_ASCII);
    if (store)
        *store = (char *) tvb_get_string_enc(wmem_file_scope(), tvb, offset, len, ENC_ASCII);
    offset += len;

    return offset;
}

static void
ssh_keylog_read_file(void)
{
    if (!pref_keylog_file || !*pref_keylog_file) {
        ws_debug("no keylog file preference set");
        return;
    }

    if (ssh_keylog_file && file_needs_reopen(ws_fileno(ssh_keylog_file),
                pref_keylog_file)) {
        ssh_keylog_reset();
    }

    if (!ssh_keylog_file) {
        ssh_keylog_file = ws_fopen(pref_keylog_file, "r");
        if (!ssh_keylog_file) {
            ws_debug("ssh: failed to open key log file %s: %s",
                    pref_keylog_file, g_strerror(errno));
            return;
        }
    }

    /* File format: each line follows the format "<cookie> <key>".
     * <cookie> is the hex-encoded (client or server) 16 bytes cookie
     * (32 characters) found in the SSH_MSG_KEXINIT of the endpoint whose
     * private random is disclosed.
     * <key> is the private random number that is used to generate the DH
     * negotiation (length depends on algorithm). In RFC4253 it is called
     * x for the client and y for the server.
     * For openssh and DH group exchange, it can be retrieved using
     * DH_get0_key(kex->dh, NULL, &server_random)
     * for groupN in file kexdh.c function kex_dh_compute_key
     * for custom group in file kexgexs.c function input_kex_dh_gex_init
     * For openssh and curve25519, it can be found in function kex_c25519_enc
     * in variable server_key.
     *
     * Example:
     *  90d886612f9c35903db5bb30d11f23c2 DEF830C22F6C927E31972FFB20B46C96D0A5F2D5E7BE5A3A8804D6BFC431619ED10AF589EEDFF4750DEA00EFD7AFDB814B6F3528729692B1F2482041521AE9DC
     */
    for (;;) {
        char buf[512];
        buf[0] = 0;

        if (!fgets(buf, sizeof(buf), ssh_keylog_file)) {
            if (ferror(ssh_keylog_file)) {
                ws_debug("Error while reading %s, closing it.", pref_keylog_file);
                ssh_keylog_reset();
            }
            break;
        }

        size_t len = strlen(buf);
        while(len>0 && (buf[len-1]=='\r' || buf[len-1]=='\n')){len-=1;buf[len]=0;}

        ssh_keylog_process_line(buf);
    }
}

static void
ssh_keylog_process_lines(const guint8 *data, guint datalen)
{
    const char *next_line = (const char *)data;
    const char *line_end = next_line + datalen;
    while (next_line && next_line < line_end) {
        const char *line = next_line;
        next_line = (const char *)memchr(line, '\n', line_end - line);
        gssize linelen;

        if (next_line) {
            linelen = next_line - line;
            next_line++;    /* drop LF */
        } else {
            linelen = (gssize)(line_end - line);
        }
        if (linelen > 0 && line[linelen - 1] == '\r') {
            linelen--;      /* drop CR */
        }

        ssh_debug_printf("  checking keylog line: %.*s\n", (int)linelen, line);

        gchar * strippedline = g_strndup(line, linelen);
        ssh_keylog_process_line(strippedline);
        g_free(strippedline);
    }
}

static void
ssh_keylog_process_line(const char *line)
{
    ws_debug("ssh: process line: %s", line);

    gchar **split = g_strsplit(line, " ", 2);
    gchar *cookie, *key;
    size_t cookie_len, key_len;

    if (g_strv_length(split) != 2) {
        ws_debug("ssh keylog: invalid format");
        g_strfreev(split);
        return;
    }

// [cookie of corresponding key] [key]
    cookie = split[0];
    key = split[1];

    key_len = strlen(key);
    cookie_len = strlen(cookie);
    if(key_len & 1){
        ws_debug("ssh keylog: invalid format (key could at least be even!)");
        g_strfreev(split);
        return;
    }
    if(cookie_len & 1){
        ws_debug("ssh keylog: invalid format (cookie could at least be even!)");
        g_strfreev(split);
        return;
    }
    ssh_bignum * bn_cookie = ssh_kex_make_bignum(NULL, (guint)(cookie_len/2));
    ssh_bignum * bn_priv   = ssh_kex_make_bignum(NULL, (guint)(key_len/2));
    guint8 c;
    for (size_t i = 0; i < key_len/2; i ++) {
        gchar v0 = key[i * 2];
        gint8 h0 = (v0>='0' && v0<='9')?v0-'0':(v0>='a' && v0<='f')?v0-'a'+10:(v0>='A' && v0<='F')?v0-'A'+10:-1;
        gchar v1 = key[i * 2 + 1];
        gint8 h1 = (v1>='0' && v1<='9')?v1-'0':(v1>='a' && v1<='f')?v1-'a'+10:(v1>='A' && v1<='F')?v1-'A'+10:-1;

        if (h0==-1 || h1==-1) {
            ws_debug("ssh: can't process key, invalid hex number: %c%c", v0, v1);
            g_strfreev(split);
            return;
        }

        c = (h0 << 4) | h1;

        bn_priv->data[i] = c;
    }

    for (size_t i = 0; i < cookie_len/2; i ++) {
        gchar v0 = cookie[i * 2];
        gint8 h0 = (v0>='0' && v0<='9')?v0-'0':(v0>='a' && v0<='f')?v0-'a'+10:(v0>='A' && v0<='F')?v0-'A'+10:-1;
        gchar v1 = cookie[i * 2 + 1];
        gint8 h1 = (v1>='0' && v1<='9')?v1-'0':(v1>='a' && v1<='f')?v1-'a'+10:(v1>='A' && v1<='F')?v1-'A'+10:-1;

        if (h0==-1 || h1==-1) {
            ws_debug("ssh: can't process cookie, invalid hex number: %c%c", v0, v1);
            g_strfreev(split);
            return;
        }

        c = (h0 << 4) | h1;

        bn_cookie->data[i] = c;
    }

    g_hash_table_insert(ssh_master_key_map, bn_cookie, bn_priv);
    g_strfreev(split);
}

static void
ssh_keylog_reset(void)
{
    if (ssh_keylog_file) {
        fclose(ssh_keylog_file);
        ssh_keylog_file = NULL;
    }
}

static guint
ssh_kex_type(gchar *type)
{
    if (type) {
        if (g_str_has_prefix(type, "curve25519")) {
            return SSH_KEX_CURVE25519;
        }
    }

    return 0;
}

static guint
ssh_kex_hash_type(gchar *type_string)
{
    if (type_string && g_str_has_suffix(type_string, "sha256")) {
        return SSH_KEX_HASH_SHA256;
    } else {
        ws_debug("hash type %s not supported", type_string);
        return 0;
    }
}

static ssh_bignum *
ssh_kex_make_bignum(const guint8 *data, guint length)
{
    // 512 bytes (4096 bits) is the maximum bignum size we're supporting
    if (length == 0 || length > 512) {
        return NULL;
    }

    ssh_bignum *bn = wmem_new0(wmem_file_scope(), ssh_bignum);
    bn->data = (guint8 *)wmem_alloc0(wmem_file_scope(), length);

    if (data) {
        memcpy(bn->data, data, length);
    }

    bn->length = length;
    return bn;
}

static gboolean
ssh_read_e(tvbuff_t *tvb, int offset, struct ssh_flow_data *global_data)
{
    // store the client's public part (e) for later usage
    guint32 length = tvb_get_ntohl(tvb, offset);
    global_data->kex_e = ssh_kex_make_bignum(NULL, length);
    if (!global_data->kex_e) {
        return false;
    }
    tvb_memcpy(tvb, global_data->kex_e->data, offset + 4, length);
    return true;
}

static gboolean
ssh_read_f(tvbuff_t *tvb, int offset, struct ssh_flow_data *global_data)
{
    // store the server's public part (f) for later usage
    guint32 length = tvb_get_ntohl(tvb, offset);
    global_data->kex_f = ssh_kex_make_bignum(NULL, length);
    if (!global_data->kex_f) {
        return false;
    }
    tvb_memcpy(tvb, global_data->kex_f->data, offset + 4, length);
    return true;
}

static void
ssh_keylog_hash_write_secret(struct ssh_flow_data *global_data)
{
    /*
     * This computation is defined differently for each key exchange method:
     * https://tools.ietf.org/html/rfc4253#page-23
     * https://tools.ietf.org/html/rfc5656#page-8
     * https://tools.ietf.org/html/rfc4419#page-4
     * All key exchange methods:
     * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-16
     */

    gcry_md_hd_t hd;
    ssh_bignum *secret = NULL, *priv;
    int length;

    ssh_keylog_read_file();

    guint kex_type = ssh_kex_type(global_data->kex);
    guint kex_hash_type = ssh_kex_hash_type(global_data->kex);

    priv = (ssh_bignum *)g_hash_table_lookup(ssh_master_key_map, global_data->peer_data[SERVER_PEER_DATA].bn_cookie);
    if(priv){
        secret = ssh_kex_shared_secret(kex_type, global_data->kex_e, priv);
    }else{
        priv = (ssh_bignum *)g_hash_table_lookup(ssh_master_key_map, global_data->peer_data[CLIENT_PEER_DATA].bn_cookie);
        if(priv){
            secret = ssh_kex_shared_secret(kex_type, global_data->kex_f, priv);
        }
    }

    if (!secret) {
        ws_debug("ssh decryption: no private key for this session");
        global_data->do_decrypt = FALSE;
        return;
    }

    // shared secret data needs to be written as an mpint, and we need it later
    if (secret->data[0] & 0x80) {         // Stored in Big endian
        length = secret->length + 1;
        gchar *tmp = (gchar *)wmem_alloc0(wmem_packet_scope(), length);
        memcpy(tmp + 1, secret->data, secret->length);
        tmp[0] = 0;
        secret->data = tmp;
        secret->length = length;
    }
    ssh_hash_buffer_put_string(global_data->kex_shared_secret, secret->data, secret->length);

    wmem_array_t    * kex_e = wmem_array_new(wmem_packet_scope(), 1);
    if(global_data->kex_e){ssh_hash_buffer_put_string(kex_e, global_data->kex_e->data, global_data->kex_e->length);}
    wmem_array_t    * kex_f = wmem_array_new(wmem_packet_scope(), 1);
    if(global_data->kex_f){ssh_hash_buffer_put_string(kex_f, global_data->kex_f->data, global_data->kex_f->length);}

    wmem_array_t    * kex_hash_buffer = wmem_array_new(wmem_packet_scope(), 1);
    ssh_print_data("client_version", (const guchar *)wmem_array_get_raw(global_data->kex_client_version), wmem_array_get_count(global_data->kex_client_version));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_client_version), wmem_array_get_count(global_data->kex_client_version));
    ssh_print_data("server_version", (const guchar *)wmem_array_get_raw(global_data->kex_server_version), wmem_array_get_count(global_data->kex_server_version));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_server_version), wmem_array_get_count(global_data->kex_server_version));
    ssh_print_data("client_key_exchange_init", (const guchar *)wmem_array_get_raw(global_data->kex_client_key_exchange_init), wmem_array_get_count(global_data->kex_client_key_exchange_init));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_client_key_exchange_init), wmem_array_get_count(global_data->kex_client_key_exchange_init));
    ssh_print_data("server_key_exchange_init", (const guchar *)wmem_array_get_raw(global_data->kex_server_key_exchange_init), wmem_array_get_count(global_data->kex_server_key_exchange_init));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_server_key_exchange_init), wmem_array_get_count(global_data->kex_server_key_exchange_init));
    ssh_print_data("kex_server_host_key_blob", (const guchar *)wmem_array_get_raw(global_data->kex_server_host_key_blob), wmem_array_get_count(global_data->kex_server_host_key_blob));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_server_host_key_blob), wmem_array_get_count(global_data->kex_server_host_key_blob));
    if(kex_type==SSH_KEX_CURVE25519){
        ssh_print_data("key client  (Q_C)", (const guchar *)wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        ssh_print_data("key server (Q_S)", (const guchar *)wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
    }
    ssh_print_data("shared secret", (const guchar *)wmem_array_get_raw(global_data->kex_shared_secret), wmem_array_get_count(global_data->kex_shared_secret));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_shared_secret), wmem_array_get_count(global_data->kex_shared_secret));

    ssh_print_data("exchange", (const guchar *)wmem_array_get_raw(kex_hash_buffer), wmem_array_get_count(kex_hash_buffer));

    guint hash_len = 32;
    if(kex_hash_type==SSH_KEX_HASH_SHA256){
        gcry_md_open(&hd, GCRY_MD_SHA256, 0);
        hash_len = 32;
    } else {
        ws_debug("kex_hash_type type %d not supported", kex_hash_type);
        return;
    }
    gchar *exchange_hash = (gchar *)wmem_alloc0(wmem_file_scope(), hash_len);
    gcry_md_write(hd, wmem_array_get_raw(kex_hash_buffer), wmem_array_get_count(kex_hash_buffer));
    memcpy(exchange_hash, gcry_md_read(hd, 0), hash_len);
    gcry_md_close(hd);
    ssh_print_data("hash", exchange_hash, hash_len);
    global_data->secret = secret;
    ssh_derive_symmetric_keys(secret, exchange_hash, hash_len, global_data);
}

// the purpose of this function is to deal with all different kex methods
static ssh_bignum *
ssh_kex_shared_secret(gint kex_type, ssh_bignum *pub, ssh_bignum *priv)
{
    DISSECTOR_ASSERT(pub != NULL);
    DISSECTOR_ASSERT(priv != NULL);

    ssh_bignum *secret = ssh_kex_make_bignum(NULL, pub->length);
    if (!secret) {
        ws_debug("invalid key length %u", pub->length);
        return NULL;
    }

    if(kex_type==SSH_KEX_CURVE25519){
        if (crypto_scalarmult_curve25519(secret->data, priv->data, pub->data)) {
            ws_debug("curve25519: can't compute shared secret");
            return NULL;
        }
    } else {
        ws_debug("kex_type type %d not supported", kex_type);
        return 0;
    }

    return secret;
}

static gchar *
ssh_string(const gchar *string, guint length)
{
    gchar *ssh_string = (gchar *)wmem_alloc(wmem_packet_scope(), length + 4);
    ssh_string[0] = (length >> 24) & 0xff;
    ssh_string[1] = (length >> 16) & 0xff;
    ssh_string[2] = (length >> 8) & 0xff;
    ssh_string[3] = length & 0xff;
    memcpy(ssh_string + 4, string, length);
    return ssh_string;
}

static void
ssh_hash_buffer_put_string(wmem_array_t *buffer, const gchar *string,
        guint length)
{
    if (!buffer) {
        return;
    }

    gchar *string_with_length = ssh_string(string, length);
    wmem_array_append(buffer, string_with_length, length + 4);
}

static void ssh_derive_symmetric_keys(ssh_bignum *secret, gchar *exchange_hash,
        guint hash_length, struct ssh_flow_data *global_data)
{
    if (!global_data->session_id) {
        global_data->session_id = exchange_hash;
        global_data->session_id_length = hash_length;
    }

    for (int i = 0; i < 6; i ++) {
        ssh_derive_symmetric_key(secret, exchange_hash, hash_length,
                'A' + i, &global_data->new_keys[i], global_data);
        if(i==0){       ssh_print_data("Initial IV client to server", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }else if(i==1){ ssh_print_data("Initial IV server to client", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }else if(i==2){ ssh_print_data("Encryption key client to server", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }else if(i==3){ ssh_print_data("Encryption key server to client", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }else if(i==4){ ssh_print_data("Integrity key client to server", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }else if(i==5){ ssh_print_data("Integrity key server to client", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }
    }
}

static void ssh_derive_symmetric_key(ssh_bignum *secret, gchar *exchange_hash,
        guint hash_length, gchar id, ssh_bignum *result_key,
        struct ssh_flow_data *global_data)
{
    gcry_md_hd_t hd;
    guint len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);

    // required size of key depends on cipher used. chacha20 wants 64 bytes
    guint need = 64;
    result_key->data = (guchar *)wmem_alloc(wmem_file_scope(), need);

    gchar *secret_with_length = ssh_string(secret->data, secret->length);

    if (gcry_md_open(&hd, GCRY_MD_SHA256, 0) == 0) {
        gcry_md_write(hd, secret_with_length, secret->length + 4);
        gcry_md_write(hd, exchange_hash, hash_length);
        gcry_md_putc(hd, id);
        gcry_md_write(hd, global_data->session_id, hash_length);
        memcpy(result_key->data, gcry_md_read(hd, 0), len);
        gcry_md_close(hd);
    }

    // expand key
    for (guint have = len; have < need; have += len) {
        if (gcry_md_open(&hd, GCRY_MD_SHA256, 0) == 0) {
            gcry_md_write(hd, secret_with_length, secret->length + 4);
            gcry_md_write(hd, exchange_hash, hash_length);
            gcry_md_write(hd, result_key->data, len);
            guint add_length = MIN(len, need - have);
            memcpy(result_key->data+have, gcry_md_read(hd, 0), add_length);
            gcry_md_close(hd);
        }
    }

    result_key->length = need;
}

static void
ssh_decryption_set_cipher_id(struct ssh_peer_data *peer)
{
    gchar *cipher_name = peer->enc;

    if (!cipher_name) {
        peer->cipher = NULL;
        ws_debug("ERROR: cipher_name is NULL");
    } else if (0 == strcmp(cipher_name, "chacha20-poly1305@openssh.com")) {
        peer->cipher_id = GCRY_CIPHER_CHACHA20;
    } else if (0 == strcmp(cipher_name, "aes128-gcm@openssh.com")) {
        peer->cipher_id = CIPHER_AES128_GCM;
    } else if (0 == strcmp(cipher_name, "aes128-gcm")) {
        peer->cipher_id = CIPHER_AES128_GCM;
    } else if (0 == strcmp(cipher_name, "aes256-gcm@openssh.com")) {
        peer->cipher_id = CIPHER_AES256_GCM;
    } else if (0 == strcmp(cipher_name, "aes256-gcm")) {
        peer->cipher_id = CIPHER_AES256_GCM;
    } else if (0 == strcmp(cipher_name, "aes128-cbc")) {
        peer->cipher_id = CIPHER_AES128_CBC;
    } else if (0 == strcmp(cipher_name, "aes192-cbc")) {
        peer->cipher_id = CIPHER_AES192_CBC;
    } else if (0 == strcmp(cipher_name, "aes256-cbc")) {
        peer->cipher_id = CIPHER_AES256_CBC;
    } else {
        peer->cipher = NULL;
        ws_debug("decryption not supported: %s", cipher_name);
    }
}

static void
ssh_decryption_set_mac_id(struct ssh_peer_data *peer)
{
    gchar *mac_name = peer->mac;

    if (!mac_name) {
        peer->mac = NULL;
        g_debug("ERROR: mac_name is NULL");
    } else if (0 == strcmp(mac_name, "hmac-sha2-256")) {
        peer->mac_id = CIPHER_MAC_SHA2_256;
    } else {
        peer->mac = NULL;
        g_debug("decryption MAC not supported: %s", mac_name);
    }
}

static void
ssh_decryption_setup_cipher(struct ssh_peer_data *peer_data,
        ssh_bignum *iv, ssh_bignum *key)
{
    (void)iv;           // Used for algorithms other than chacha20

    gcry_error_t err;
    gcry_cipher_hd_t *hd1, *hd2;

    hd1 = &peer_data->cipher;
    hd2 = &peer_data->cipher_2;

    if (GCRY_CIPHER_CHACHA20 == peer_data->cipher_id) {
        if (gcry_cipher_open(hd1, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0) ||
            gcry_cipher_open(hd2, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0)) {
            gcry_cipher_close(*hd1);
            gcry_cipher_close(*hd2);
            ws_debug("ssh: can't open chacha20 cipher handles");
            return;
        }

        gchar k1[32];
        gchar k2[32];
        if(key->data){
            memcpy(k1, key->data, 32);
            memcpy(k2, key->data + 32, 32);
        }else{
            memset(k1, 0, 32);
            memset(k2, 0, 32);
        }

        ssh_debug_printf("ssh: cipher is chacha20\n");
        ssh_print_data("key 1", k1, 32);
        ssh_print_data("key 2", k2, 32);

        if ((err = gcry_cipher_setkey(*hd1, k1, 32))) {
            gcry_cipher_close(*hd1);
            ws_debug("ssh: can't set chacha20 cipher key %s", gcry_strerror(err));
            return;
        }

        if ((err = gcry_cipher_setkey(*hd2, k2, 32))) {
            gcry_cipher_close(*hd1);
            gcry_cipher_close(*hd2);
            ws_debug("ssh: can't set chacha20 cipher key %s", gcry_strerror(err));
            return;
        }
    } else if (CIPHER_AES128_CBC == peer_data->cipher_id  || CIPHER_AES192_CBC == peer_data->cipher_id || CIPHER_AES256_CBC == peer_data->cipher_id) {
        gint iKeyLen = CIPHER_AES128_CBC == peer_data->cipher_id?16:CIPHER_AES192_CBC == peer_data->cipher_id?24:32;
        if (gcry_cipher_open(hd1, CIPHER_AES128_CBC == peer_data->cipher_id?GCRY_CIPHER_AES128:CIPHER_AES192_CBC == peer_data->cipher_id?GCRY_CIPHER_AES192:GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS)) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't open aes%d cipher handle", iKeyLen*8);
            return;
        }
        gchar k1[32], iv1[16];
        if(key->data){
            memcpy(k1, key->data, iKeyLen);
        }else{
            memset(k1, 0, iKeyLen);
        }
        if(iv->data){
            memcpy(iv1, iv->data, 16);
        }else{
            memset(iv1, 0, 16);
        }

        ssh_debug_printf("ssh: cipher is aes%d-cbc\n", iKeyLen*8);
        ssh_print_data("key", k1, iKeyLen);
        ssh_print_data("iv", iv1, 16);

        if ((err = gcry_cipher_setkey(*hd1, k1, iKeyLen))) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't set aes%d cipher key", iKeyLen*8);
            return;
        }

        if ((err = gcry_cipher_setiv(*hd1, iv1, 16))) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't set aes%d cipher iv", iKeyLen*8);
            g_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
            return;
        }

    } else if (CIPHER_AES128_GCM == peer_data->cipher_id  || CIPHER_AES256_GCM == peer_data->cipher_id) {
        gint iKeyLen = CIPHER_AES128_GCM == peer_data->cipher_id?16:32;
        if (gcry_cipher_open(hd1, CIPHER_AES128_GCM == peer_data->cipher_id?GCRY_CIPHER_AES128:GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0)) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't open aes%d cipher handle", iKeyLen*8);
            return;
        }

        gchar k1[32], iv2[12];
        if(key->data){
            memcpy(k1, key->data, iKeyLen);
        }else{
            memset(k1, 0, iKeyLen);
        }
        if(iv->data){
            memcpy(peer_data->iv, iv->data, 12);
        }else{
            memset(iv2, 0, 12);
        }

        ssh_print_data("key", k1, iKeyLen);
        ssh_print_data("iv", peer_data->iv, 12);

        if ((err = gcry_cipher_setkey(*hd1, k1, iKeyLen))) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't set aes%d cipher key", iKeyLen*8);
            return;
        }

    }
}

static void
ssh_decryption_setup_mac(struct ssh_peer_data *peer_data,
        ssh_bignum *iv)
{
    if(peer_data->mac_id == CIPHER_MAC_SHA2_256){
        if(iv->data){
            memcpy(peer_data->hmac_iv, iv->data, 32);
        }else{
            memset(peer_data->hmac_iv, 0, 32);
        }
        peer_data->hmac_iv_len = 32;
        ssh_debug_printf("ssh: mac is hmac-sha2-256\n");
        ssh_print_data("iv", peer_data->hmac_iv, peer_data->hmac_iv_len);
    }else{
        g_debug("ssh: unsupported MAC");
    }
}

/* libgcrypt wrappers for HMAC/message digest operations {{{ */
/* hmac abstraction layer */
#define SSH_HMAC gcry_md_hd_t

static inline gint
ssh_hmac_init(SSH_HMAC* md, const void * key, gint len, gint algo)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;

    err = gcry_md_open(md,algo, GCRY_MD_FLAG_HMAC);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssh_debug_printf("ssh_hmac_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    gcry_md_setkey (*(md), key, len);
    return 0;
}

static inline void
ssh_hmac_update(SSH_HMAC* md, const void* data, gint len)
{
    gcry_md_write(*(md), data, len);
}

static inline void
ssh_hmac_final(SSH_HMAC* md, guchar* data, guint* datalen)
{
    gint  algo;
    guint len;

    algo = gcry_md_get_algo (*(md));
    len  = gcry_md_get_algo_dlen(algo);
    DISSECTOR_ASSERT(len <= *datalen);
    memcpy(data, gcry_md_read(*(md), algo), len);
    *datalen = len;
}

static inline void
ssh_hmac_cleanup(SSH_HMAC* md)
{
    gcry_md_close(*(md));
}
/* libgcrypt wrappers for HMAC/message digest operations }}} */

/* Decryption integrity check {{{ */

static gint
ssh_get_digest_by_id(guint mac_id)
{
    if(mac_id==CIPHER_MAC_SHA2_256){
        return GCRY_MD_SHA256;
    }
    return -1;
}

static void
ssh_calc_mac(struct ssh_peer_data *peer_data, guint32 seqnr, guint8* data, guint32 datalen, guint8* calc_mac)
{
    SSH_HMAC hm;
    gint     md;
    guint32  len;
    guint8   buf[DIGEST_MAX_SIZE];

    md=ssh_get_digest_by_id(peer_data->mac_id);
//    ssl_debug_printf("ssh_check_mac mac type:%s md %d\n",
//        ssl_cipher_suite_dig(decoder->cipher_suite)->name, md);

    memset(calc_mac, 0, DIGEST_MAX_SIZE);

    if (ssh_hmac_init(&hm, peer_data->hmac_iv, peer_data->hmac_iv_len,md) != 0)
        return;

    /* hash sequence number */
    phton32(buf, seqnr);

    ssh_print_data("Mac IV", peer_data->hmac_iv, peer_data->hmac_iv_len);
    ssh_print_data("Mac seq", buf, 4);
    ssh_print_data("Mac data", data, datalen);

    ssh_hmac_update(&hm,buf,4);

    ssh_hmac_update(&hm,data,datalen);

    /* get digest and digest len*/
    len = sizeof(buf);
    ssh_hmac_final(&hm,buf,&len);
    ssh_hmac_cleanup(&hm);
    ssh_print_data("Mac", buf, len);
    memcpy(calc_mac, buf, len);

    return;
}
/* Decryption integrity check }}} */

static void
ssh_increment_message_number(packet_info *pinfo, struct ssh_flow_data *global_data,
        gboolean is_response)
{
    if (!PINFO_FD_VISITED(pinfo)) {
        ssh_packet_info_t * packet = (ssh_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ssh, 0);
        if(!packet){
            packet = wmem_new0(wmem_file_scope(), ssh_packet_info_t);
            packet->from_server = is_response;
            packet->messages = NULL;
            p_add_proto_data(wmem_file_scope(), pinfo, proto_ssh, 0, packet);
        }
        (void)global_data;
    }
}

static guint
ssh_decrypt_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *tree)
{
    gboolean    is_response = (pinfo->destport != pinfo->match_uint);
    ssh_packet_info_t *packet = (ssh_packet_info_t *)p_get_proto_data(
            wmem_file_scope(), pinfo, proto_ssh, 0);
    if(!packet){
        packet = wmem_new0(wmem_file_scope(), ssh_packet_info_t);
        packet->from_server = is_response;
        packet->messages = NULL;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_ssh, 0, packet);
    }

    gint record_id = tvb_raw_offset(tvb)+offset;
    ssh_message_info_t *message = NULL;
    ssh_message_info_t **pmessage = &packet->messages;
    while(*pmessage){
        if ((*pmessage)->id == record_id) {
            message = *pmessage;
            break;
        }
        pmessage = &(*pmessage)->next;
    }
    if(!message){
        message = wmem_new(wmem_file_scope(), ssh_message_info_t);
        message->plain_data = NULL;
        message->data_len = 0;
        message->id = record_id;
        message->next = NULL;
        message->sequence_number = peer_data->sequence_number;
        peer_data->sequence_number++;
        ssh_debug_printf("%s->sequence_number++ > %d\n", is_response?"server":"client", peer_data->sequence_number);
        *pmessage = message;
    }

    guint message_length = 0, seqnr;
    gchar *plain = NULL, *mac;
    guint mac_len;

    seqnr = message->sequence_number;

    if (GCRY_CIPHER_CHACHA20 == peer_data->cipher_id) {
        const gchar *ctext = (const gchar *)tvb_get_ptr(tvb, offset, 4);
        guint8 plain_length_buf[4];

        if (!ssh_decrypt_chacha20(peer_data->cipher_2, seqnr, 0, ctext, 4,
                    plain_length_buf, 4)) {
            ws_debug("ERROR: could not decrypt packet len");
            return tvb_captured_length(tvb);
        }

        message_length = pntoh32(plain_length_buf);

        ssh_debug_printf("chachapoly_crypt seqnr=%d [%u]\n", seqnr, message_length);

        ssh_debug_printf("%s plain for seq = %d len = %u\n", is_response?"s2c":"c2s", seqnr, message_length);
        if(message_length>32768){
            ws_debug("ssh: unreasonable message length %u", message_length);
            return tvb_captured_length(tvb);
        }

        plain = (gchar *)wmem_alloc0(pinfo->pool, message_length+4);
        plain[0] = plain_length_buf[0]; plain[1] = plain_length_buf[1]; plain[2] = plain_length_buf[2]; plain[3] = plain_length_buf[3];
        const gchar *ctext2 = (const gchar *)tvb_get_ptr(tvb, offset+4,
                message_length);

        if (!ssh_decrypt_chacha20(peer_data->cipher, seqnr, 1, ctext2,
                    message_length, plain+4, message_length)) {
            ws_debug("ERROR: could not decrypt packet payload");
            return tvb_captured_length(tvb);
        }

        mac_len = 16;
        mac = (gchar *)tvb_get_ptr(tvb, offset + 4 + message_length, mac_len);
        gchar poly_key[32], iv[16];

        memset(poly_key, 0, 32);
        memset(iv, 0, 8);
        phton64(iv+8, (guint64)seqnr);
        gcry_cipher_setiv(peer_data->cipher, iv, mac_len);
        gcry_cipher_encrypt(peer_data->cipher, poly_key, 32, poly_key, 32);

        gcry_mac_hd_t mac_hd;
        gcry_mac_open(&mac_hd, GCRY_MAC_POLY1305, 0, NULL);
        gcry_mac_setkey(mac_hd, poly_key, 32);
        gcry_mac_write(mac_hd, ctext, 4);
        gcry_mac_write(mac_hd, ctext2, message_length);
        if (gcry_mac_verify(mac_hd, mac, mac_len)) {
            ws_debug("ssh: MAC does not match");
        }
        size_t buflen = DIGEST_MAX_SIZE;
        gcry_mac_read(mac_hd, message->calc_mac, &buflen);

        message->plain_data = plain;
        message->data_len   = message_length + 4;

//        ssh_print_data(is_response?"s2c encrypted":"c2s encrypted", ctext2, message_length+4+mac_len);
        ssh_debug_printf("%s plain text seq=%d", is_response?"s2c":"c2s",seqnr);
        ssh_print_data("", plain, message_length+4);
    } else if (CIPHER_AES128_GCM == peer_data->cipher_id || CIPHER_AES256_GCM == peer_data->cipher_id) {

        mac_len = peer_data->mac_length;
        message_length = tvb_reported_length_remaining(tvb, offset) - 4 - mac_len;

        const gchar *plain_buf = (const gchar *)tvb_get_ptr(tvb, offset, 4);
        message_length = pntoh32(plain_buf);
        guint remaining = tvb_reported_length_remaining(tvb, offset);
        ssh_debug_printf("length: %d, remaining: %d\n", message_length, remaining);

        if(message->plain_data && message->data_len){
            message_length = message->data_len - 4;
        }else{

            const gchar *ctl = (const gchar *)tvb_get_ptr(tvb, offset,
                    message_length+4);
            const gchar *ctext = ctl + 4;
            plain = (gchar *)wmem_alloc(wmem_file_scope(), message_length+4);
            plain[0] = message_length >> 24; plain[1] = message_length >> 16; plain[2] = message_length >>  8; plain[3] = message_length >>  0;

            gcry_error_t err;
            /* gcry_cipher_setiv(peer_data->cipher, iv, 12); */
            if ((err = gcry_cipher_setiv(peer_data->cipher, peer_data->iv, 12))) {
                gcry_cipher_close(peer_data->cipher);
// TODO: temporary work-around as long as a Windows python bug is triggered by automated tests
#ifndef _WIN32
                ws_debug("ssh: can't set aes128 cipher iv");
                ws_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
#endif	//ndef _WIN32
                return offset;
            }
            int idx = 12;
            do{
                idx -= 1;
                peer_data->iv[idx] += 1;
            }while(idx>4 && peer_data->iv[idx]==0);

            if ((err = gcry_cipher_authenticate(peer_data->cipher, plain, 4))) {
// TODO: temporary work-around as long as a Windows python bug is triggered by automated tests
#ifndef _WIN32
                ws_debug("can't authenticate using aes128-gcm: %s\n", gpg_strerror(err));
#endif	//ndef _WIN32
                return offset;
            }

            guint offs = 0;
            if(remaining>message_length+4){remaining=message_length;}
            while(offs<remaining){
                if (gcry_cipher_decrypt(peer_data->cipher, plain+4+offs, 16,
                        ctext+offs, 16))
                {
// TODO: temporary work-around as long as a Windows python bug is triggered by automated tests
#ifndef _WIN32
                    ws_debug("can\'t decrypt aes128");
#endif	//ndef _WIN32
                    return offset;
                }
                offs += 16;
            }

            if (gcry_cipher_gettag (peer_data->cipher, message->calc_mac, 16)) {
// TODO: temporary work-around as long as a Windows python bug is triggered by automated tests
#ifndef _WIN32
                ws_debug ("aes128-gcm, gcry_cipher_gettag() failed\n");
#endif	//ndef _WIN32
                return offset;
            }

            if ((err = gcry_cipher_reset(peer_data->cipher))) {
// TODO: temporary work-around as long as a Windows python bug is triggered by automated tests
#ifndef _WIN32
                ws_debug("aes-gcm, gcry_cipher_reset failed: %s\n", gpg_strerror (err));
#endif	//ndef _WIN32
                return offset;
            }

            message->plain_data = plain;
            message->data_len   = message_length + 4;

//            ssh_print_data(is_response?"s2c encrypted":"c2s encrypted", ctl, message_length+4+mac_len);
            ssh_debug_printf("%s plain text seq=%d", is_response?"s2c":"c2s",seqnr);
            ssh_print_data("", plain, message_length+4);
        }

        plain = message->plain_data;
        message_length = message->data_len - 4;
        mac = (gchar *)tvb_get_ptr(tvb, offset + 4 + message_length, mac_len);


    } else if (CIPHER_AES128_CBC == peer_data->cipher_id ||
        CIPHER_AES192_CBC == peer_data->cipher_id ||
        CIPHER_AES256_CBC == peer_data->cipher_id) {

        mac_len = peer_data->mac_length;
        message_length = tvb_reported_length_remaining(tvb, offset) - 4 - mac_len;

        if(message->plain_data && message->data_len){
            message_length = message->data_len - 4;
        }else{
// TODO: see how to handle fragmentation...
//            const gchar *ctext = NULL;
            g_debug("Getting raw bytes of length %d", tvb_reported_length_remaining(tvb, offset));
            const gchar *cypher_buf0 = (const gchar *)tvb_get_ptr(tvb, offset, tvb_reported_length_remaining(tvb, offset));

            gchar   plain0[16];
            if (gcry_cipher_decrypt(peer_data->cipher, plain0, 16, cypher_buf0, 16))
            {
                g_debug("can\'t decrypt aes128");
                return offset;
            }
//            ctext = cypher_buf0;
            plain = plain0;
            guint message_length_decrypted = pntoh32(plain0);
            guint remaining = tvb_reported_length_remaining(tvb, offset);

            if(message_length_decrypted>32768){
                g_debug("ssh: unreasonable message length %u/%u", message_length_decrypted, message_length);
                offset += remaining;
                return tvb_captured_length(tvb);
            }else{

                message_length = message_length_decrypted;
                message->plain_data = (gchar *)wmem_alloc(wmem_file_scope(), message_length+4);
                memcpy(message->plain_data, plain0, 16);
                plain = message->plain_data;

                guint offs = 16;
                if(remaining>message_length+4){remaining=message_length+4;}
                while(offs<remaining){
                    gchar *ct = (gchar *)tvb_get_ptr(tvb, offset+offs, 16);
                    if (gcry_cipher_decrypt(peer_data->cipher, plain+offs, 16, ct, 16))
                    {
                        g_debug("can\'t decrypt aes128");
                        return offset;
                    }
                    offs += 16;
                }

                if(message_length_decrypted>remaining){
                    // Need desegmentation
                    g_debug("  need_desegmentation: offset = %d, reported_length_remaining = %d\n",
                                    offset, tvb_reported_length_remaining(tvb, offset));
                    /* Make data available to ssh_follow_tap_listener */
                    return tvb_captured_length(tvb);
                }

//                ssh_print_data(is_response?"s2c encrypted":"c2s encrypted", ctext, message_length+4+mac_len);
                ssh_debug_printf("%s plain text seq=%d", is_response?"s2c":"c2s",seqnr);
                ssh_print_data("", plain, message_length+4);

// TODO: process fragments
                message->plain_data = plain;
                message->data_len   = message_length + 4;

                ssh_calc_mac(peer_data, message->sequence_number, message->plain_data, message->data_len, message->calc_mac);
            }
        }
        plain = message->plain_data;
        message_length = message->data_len - 4;
        mac = (gchar *)tvb_get_ptr(tvb, offset + 4 + message_length, mac_len);
        if(!memcmp(mac, message->calc_mac, mac_len)){g_debug("MAC OK");}else{g_debug("MAC ERR");}
    }

    if(plain){
        ssh_dissect_decrypted_packet(tvb, pinfo, peer_data, tree, plain, message_length+4);
        ssh_tree_add_mac(tree, tvb, offset + 4 + message_length, mac_len, hf_ssh_mac_string, hf_ssh_mac_status, &ei_ssh_mac_bad, pinfo, message->calc_mac,
                                               PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
        proto_tree_add_uint(tree, hf_ssh_seq_num, tvb, offset + 4 + message_length, mac_len, message->sequence_number);
    }

    offset += message_length + peer_data->mac_length + 4;
    return offset;
}

proto_item *
ssh_tree_add_mac(proto_tree *tree, tvbuff_t *tvb, const guint offset, const guint mac_len,
                const int hf_mac, const int hf_mac_status, struct expert_field* bad_checksum_expert,
                packet_info *pinfo, const guint8 * calc_mac, const guint flags)
{
//    header_field_info *hfinfo = proto_registrar_get_nth(hf_checksum);
    proto_item* ti = NULL;
    proto_item* ti2;
    gboolean incorrect_mac = TRUE;
    gchar *mac;

//    DISSECTOR_ASSERT_HINT(hfinfo != NULL, "Not passed hfi!");
/*
    if (flags & PROTO_CHECKSUM_NOT_PRESENT) {
        ti = proto_tree_add_uint_format_value(tree, hf_checksum, tvb, offset, len, 0, "[missing]");
        proto_item_set_generated(ti);
        if (hf_checksum_status != -1) {
            ti2 = proto_tree_add_uint(tree, hf_checksum_status, tvb, offset, len, PROTO_CHECKSUM_E_NOT_PRESENT);
            proto_item_set_generated(ti2);
        }
        return ti;
    }
*/
    mac = (gchar *)tvb_get_ptr(tvb, offset, mac_len);
    if (flags & PROTO_CHECKSUM_GENERATED) {
//        ti = proto_tree_add_uint(tree, hf_checksum, tvb, offset, len, computed_checksum);
//        proto_item_set_generated(ti);
    } else {
        ti = proto_tree_add_item(tree, hf_mac, tvb, offset, mac_len, ENC_NA);
        if (flags & PROTO_CHECKSUM_VERIFY) {
            if (flags & (PROTO_CHECKSUM_IN_CKSUM|PROTO_CHECKSUM_ZERO)) {
                if (!memcmp(mac, calc_mac, mac_len)) {
                    proto_item_append_text(ti, " [correct]");
                    if (hf_mac_status != -1) {
                        ti2 = proto_tree_add_uint(tree, hf_mac_status, tvb, offset, 0, PROTO_CHECKSUM_E_GOOD);
                        proto_item_set_generated(ti2);
                    }
                    incorrect_mac = FALSE;
                } else if (flags & PROTO_CHECKSUM_IN_CKSUM) {
//                    computed_checksum = in_cksum_shouldbe(checksum, computed_checksum);
                }
            } else {
                if (!memcmp(mac, calc_mac, mac_len)) {
                    proto_item_append_text(ti, " [correct]");
                    if (hf_mac_status != -1) {
                        ti2 = proto_tree_add_uint(tree, hf_mac_status, tvb, offset, 0, PROTO_CHECKSUM_E_GOOD);
                        proto_item_set_generated(ti2);
                    }
                    incorrect_mac = FALSE;
                }
            }

            if (incorrect_mac) {
                if (hf_mac_status != -1) {
                    ti2 = proto_tree_add_uint(tree, hf_mac_status, tvb, offset, 0, PROTO_CHECKSUM_E_BAD);
                    proto_item_set_generated(ti2);
                }
                if (flags & PROTO_CHECKSUM_ZERO) {
                    proto_item_append_text(ti, " [incorrect]");
                    if (bad_checksum_expert != NULL)
                        expert_add_info_format(pinfo, ti, bad_checksum_expert, "%s", expert_get_summary(bad_checksum_expert));
                } else {
                    gchar *data = (gchar *)wmem_alloc(wmem_packet_scope(), mac_len*2 + 1);
//                    proto_item_append_text(ti, " incorrect, should be TODO");
                    static const char h2a[] = "0123456789abcdef";
                    for(guint macCnt=0;macCnt<mac_len;macCnt++){
                        data[macCnt*2+0] = h2a[(calc_mac[macCnt] >> 4) & 0xF];
                        data[macCnt*2+1] = h2a[(calc_mac[macCnt] >> 0) & 0xF];
                    }
                    data[mac_len*2] = 0;
                    proto_item_append_text(ti, " incorrect, computed %s", data);
                    if (bad_checksum_expert != NULL)
                        expert_add_info_format(pinfo, ti, bad_checksum_expert, "%s", expert_get_summary(bad_checksum_expert));
                }
            }
        } else {
            if (hf_mac_status != -1) {
                proto_item_append_text(ti, " [unverified]");
                ti2 = proto_tree_add_uint(tree, hf_mac_status, tvb, offset, 0, PROTO_CHECKSUM_E_UNVERIFIED);
                proto_item_set_generated(ti2);
            }
        }
    }

    return ti;
}

static gboolean
ssh_decrypt_chacha20(gcry_cipher_hd_t hd,
        guint32 seqnr, guint32 counter, const guchar *ctext, guint ctext_len,
        guchar *plain, guint plain_len)
{
    guchar seq[8];
    guchar iv[16];

    phton64(seq, (guint64)seqnr);

    // chacha20 uses a different cipher handle for the packet payload & length
    // the payload uses a block counter
    if (counter) {
        guchar ctr[8] = {1,0,0,0,0,0,0,0};
        memcpy(iv, ctr, 8);
        memcpy(iv+8, seq, 8);
    }

    return ((!counter && gcry_cipher_setiv(hd, seq, 8) == 0) ||
            (counter && gcry_cipher_setiv(hd, iv, 16) == 0)) &&
            gcry_cipher_decrypt(hd, plain, plain_len, ctext, ctext_len) == 0;
}

static int
ssh_dissect_decrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, proto_tree *tree,
        gchar *plaintext, guint plaintext_len)
{
    int offset = 0;      // TODO:
    int dissected_len = 0;

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Encrypted packet (plaintext_len=%d)", plaintext_len);

    tvbuff_t *packet_tvb = tvb_new_child_real_data(tvb, plaintext, plaintext_len, plaintext_len);
    add_new_data_source(pinfo, packet_tvb, "Decrypted Packet");

    guint   plen, len;
    guint8  padding_length;
    guint   remain_length;
    int     last_offset=offset;
    guint   msg_code;

    proto_item *ti;
    proto_item *msg_type_tree = NULL;

    /*
     * We use "tvb_ensure_captured_length_remaining()" to make sure there
     * actually *is* data remaining.
     *
     * This means we're guaranteed that "remain_length" is positive.
     */
    remain_length = tvb_ensure_captured_length_remaining(packet_tvb, offset);
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
            return offset;
        }
    }
    plen = tvb_get_ntohl(packet_tvb, offset) ;

    if (ssh_desegment && pinfo->can_desegment) {
        if (plen +4 >  remain_length) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = plen+4 - remain_length;
            return offset;
        }
    }
    /*
     * Need to check plen > 0x80000000 here
     */

    ti = proto_tree_add_uint(tree, hf_ssh_packet_length, packet_tvb,
                    offset, 4, plen);
    if (plen >= 0xffff) {
        expert_add_info_format(pinfo, ti, &ei_ssh_packet_length, "Overly large number %d", plen);
        plen = remain_length-4;
    }
    offset+=4;

    /* padding length */
    padding_length = tvb_get_guint8(packet_tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_padding_length, packet_tvb, offset, 1, padding_length);
    offset += 1;

    /* msg_code */
    msg_code = tvb_get_guint8(packet_tvb, offset);

    /* Transport layer protocol */
    /* Generic (1-19) */
    if(msg_code >= 1 && msg_code <= 19) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Transport (generic)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        dissected_len = ssh_dissect_transport_generic(packet_tvb, pinfo, offset, msg_type_tree, msg_code) - offset;
        // offset = ssh_dissect_transport_generic(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
    }
    /* Algorithm negotiation (20-29) */
    else if(msg_code >=20 && msg_code <= 29) {
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Transport (algorithm negotiation)");
//TODO: See if the complete dissector should be refactored to always got through here first        offset = ssh_dissect_transport_algorithm_negotiation(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
    }
    /* Key exchange method specific (reusable) (30-49) */
    else if (msg_code >=30 && msg_code <= 49) {
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Transport (key exchange method specific)");
//TODO: See if the complete dissector should be refactored to always got through here first                offset = global_data->kex_specific_dissector(msg_code, packet_tvb, pinfo, offset, msg_type_tree);
    }

    /* User authentication protocol */
    /* Generic (50-59) */
    else if (msg_code >= 50 && msg_code <= 59) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: User Authentication (generic)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        dissected_len = ssh_dissect_userauth_generic(packet_tvb, pinfo, offset+1, msg_type_tree, msg_code) - offset;
        // TODO: offset = ssh_dissect_userauth_generic(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
    }
    /* User authentication method specific (reusable) (60-79) */
    else if (msg_code >= 60 && msg_code <= 79) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: User Authentication: (method specific)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        // TODO: offset = ssh_dissect_userauth_specific(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
        dissected_len = ssh_dissect_userauth_specific(packet_tvb, pinfo, offset+1, msg_type_tree, msg_code) - offset;
    }

    /* Connection protocol */
    /* Generic (80-89) */
    else if (msg_code >= 80 && msg_code <= 89) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Connection (generic)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        // TODO: offset = ssh_dissect_connection_generic(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
        dissected_len = ssh_dissect_connection_generic(packet_tvb, pinfo, offset+1, msg_type_tree, msg_code) - offset;
    }
    /* Channel related messages (90-127) */
    else if (msg_code >= 90 && msg_code <= 127) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Connection: (channel related message)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        // TODO: offset = ssh_dissect_connection_channel(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
        dissected_len = ssh_dissect_connection_specific(packet_tvb, pinfo, peer_data, offset+1, msg_type_tree, msg_code) - offset;
    }

    /* Reserved for client protocols (128-191) */
    else if (msg_code >= 128 && msg_code <= 191) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Client protocol");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        // TODO: offset = ssh_dissect_client(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
    }

    /* Local extensions (192-255) */
    else if (msg_code >= 192 && msg_code <= 255) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Local extension");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        // TODO: offset = ssh_dissect_local_extention(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
    }

    len = plen+4-padding_length-(offset-last_offset);
    if (len > 0) {
        proto_tree_add_item(msg_type_tree, hf_ssh_payload, packet_tvb, offset, len, ENC_NA);
    }
    if(dissected_len!=(int)len){
//        expert_add_info_format(pinfo, ti, &ei_ssh_packet_decode, "Decoded %d bytes, but packet legnth is %d bytes", dissected_len, len);
        expert_add_info_format(pinfo, ti, &ei_ssh_packet_decode, "Decoded %d bytes, but packet legnth is %d bytes [%d]", dissected_len, len, msg_code);
    }
    offset +=len;

    /* padding */
    proto_tree_add_item(tree, hf_ssh_padding_string, packet_tvb, offset, padding_length, ENC_NA);
    offset+= padding_length;

    return offset;
}

static int
ssh_dissect_transport_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_DISCONNECT){
                proto_tree_add_item(msg_type_tree, hf_ssh_disconnect_reason, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint   nlen;
                nlen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_disconnect_description_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_disconnect_description, packet_tvb, offset, nlen, ENC_ASCII);
                offset += nlen;
                nlen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_lang_tag_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_lang_tag, packet_tvb, offset, nlen, ENC_ASCII);
                offset += nlen;
        }else if(msg_code==SSH_MSG_IGNORE){
                offset += ssh_tree_add_string(packet_tvb, offset, msg_type_tree, hf_ssh_ignore_data, hf_ssh_ignore_data_length);
        }else if(msg_code==SSH_MSG_DEBUG){
                guint   slen;
                proto_tree_add_item(msg_type_tree, hf_ssh_debug_always_display, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_debug_message_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_debug_message, packet_tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_lang_tag_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_lang_tag, packet_tvb, offset, slen, ENC_ASCII);
                offset += slen;
        }else if(msg_code==SSH_MSG_SERVICE_REQUEST){
                guint   nlen;
                nlen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name, packet_tvb, offset, nlen, ENC_ASCII);
                offset += nlen;
        }else if(msg_code==SSH_MSG_SERVICE_ACCEPT){
                guint   nlen;
                nlen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name, packet_tvb, offset, nlen, ENC_ASCII);
                offset += nlen;
        }
        return offset;
}

static int
ssh_dissect_userauth_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_USERAUTH_REQUEST){
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_user_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_user_name, packet_tvb, offset, slen, ENC_ASCII);
                offset += slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_service_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_service_name, packet_tvb, offset, slen, ENC_ASCII);
                offset += slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_method_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_method_name, packet_tvb, offset, slen, ENC_ASCII);

                guint8* key_type;
                key_type = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset, slen, ENC_ASCII|ENC_NA);
                offset += slen;
                if (0 == strcmp(key_type, "none")) {
                }else if (0 == strcmp(key_type, "publickey")) {
                        guint8 bHaveSignature = tvb_get_guint8(packet_tvb, offset);
                        int dissected_len = 0;
                        proto_tree_add_item(msg_type_tree, hf_ssh_userauth_have_signature, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        slen = tvb_get_ntohl(packet_tvb, offset) ;
                        proto_tree_add_item(msg_type_tree, hf_ssh_userauth_pka_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(msg_type_tree, hf_ssh_userauth_pka_name, packet_tvb, offset, slen, ENC_ASCII);
                        offset += slen;
                        proto_item *blob_tree = NULL;
                        slen = tvb_get_ntohl(packet_tvb, offset) ;
                        proto_tree_add_item(msg_type_tree, hf_ssh_blob_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        blob_tree = proto_tree_add_subtree(msg_type_tree, packet_tvb, offset, slen, ett_userauth_pk_blob, NULL, "Public key blob");
//        proto_tree_add_item(blob_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                        dissected_len = ssh_dissect_public_key_blob(packet_tvb, pinfo, offset, blob_tree) - offset;
                        if(dissected_len!=(int)slen){
                            expert_add_info_format(pinfo, blob_tree, &ei_ssh_packet_decode, "Decoded %d bytes, but packet legnth is %d bytes", dissected_len, slen);
                        }
                        offset += slen;
                        if(bHaveSignature){
                                slen = tvb_get_ntohl(packet_tvb, offset) ;
                                proto_tree_add_item(msg_type_tree, hf_ssh_signature_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                                offset += 4;
                                proto_item *signature_tree = NULL;
                                signature_tree = proto_tree_add_subtree(msg_type_tree, packet_tvb, offset, slen, ett_userauth_pk_signautre, NULL, "Public key signature");
                                dissected_len = ssh_dissect_public_key_signature(packet_tvb, pinfo, offset, signature_tree) - offset;
                                if(dissected_len!=(int)slen){
                                    expert_add_info_format(pinfo, signature_tree, &ei_ssh_packet_decode, "Decoded %d bytes, but packet legnth is %d bytes", dissected_len, slen);
                                }
                                offset += slen;
                        }
                }else if (0 == strcmp(key_type, "password")) {
                        guint8 bChangePassword = tvb_get_guint8(packet_tvb, offset);
                        proto_tree_add_item(msg_type_tree, hf_ssh_userauth_change_password, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        slen = tvb_get_ntohl(packet_tvb, offset) ;
                        proto_tree_add_item(msg_type_tree, hf_ssh_userauth_password_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(msg_type_tree, hf_ssh_userauth_password, packet_tvb, offset, slen, ENC_ASCII);
                        offset += slen;
                        if(bChangePassword){
                            slen = tvb_get_ntohl(packet_tvb, offset) ;
                            proto_tree_add_item(msg_type_tree, hf_ssh_userauth_new_password_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            proto_tree_add_item(msg_type_tree, hf_ssh_userauth_new_password, packet_tvb, offset, slen, ENC_ASCII);
                            offset += slen;
                        }
                }else{
                }

        }else if(msg_code==SSH_MSG_USERAUTH_FAILURE){
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_auth_failure_list_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_auth_failure_list, packet_tvb, offset, slen, ENC_ASCII);
                offset += slen;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_partial_success, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
        }
        return offset;
}

static int
ssh_dissect_userauth_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_USERAUTH_PK_OK){
                proto_item *ti;
                int dissected_len = 0;
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_pka_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_pka_name, packet_tvb, offset, slen, ENC_ASCII);
                offset += slen;
                proto_item *blob_tree = NULL;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                ti = proto_tree_add_item(msg_type_tree, hf_ssh_blob_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                blob_tree = proto_tree_add_subtree(msg_type_tree, packet_tvb, offset, slen, ett_userauth_pk_blob, NULL, "Public key blob");
                dissected_len = ssh_dissect_public_key_blob(packet_tvb, pinfo, offset, blob_tree) - offset;
                if(dissected_len!=(int)slen){
                    expert_add_info_format(pinfo, ti, &ei_ssh_packet_decode, "Decoded %d bytes, but packet legnth is %d bytes", dissected_len, slen);
                }
                offset += slen;
        }
        return offset;
}

static int
ssh_dissect_connection_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_item *msg_type_tree,
        guint msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_CHANNEL_OPEN){
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_type_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_type_name, packet_tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_sender_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_initial_window, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_maximum_packet_size, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_OPEN_CONFIRMATION){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_sender_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_initial_window, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_maximum_packet_size, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_WINDOW_ADJUST){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_window_adjust, packet_tvb, offset, 4, ENC_BIG_ENDIAN);         // TODO: maintain count of transfered bytes and window size
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_DATA){
                guint   uiNumChannel;
                uiNumChannel = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
// TODO: process according to the type of channel
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_data_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                tvbuff_t *next_tvb = tvb_new_subset_remaining(packet_tvb, offset);
                dissector_handle_t subdissector_handle = get_subdissector_for_channel(peer_data, uiNumChannel);
                if(subdissector_handle){
                        call_dissector(subdissector_handle, next_tvb, pinfo, msg_type_tree);
                }
                offset += slen;
        }else if(msg_code==SSH_MSG_CHANNEL_EOF){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_CLOSE){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_REQUEST){
                guint   uiNumChannel;
                uiNumChannel = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8* request_name;
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_request_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                request_name = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset, slen, ENC_ASCII|ENC_NA);
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_request_name, packet_tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_request_want_reply, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                if (0 == strcmp(request_name, "subsystem")) {
                        slen = tvb_get_ntohl(packet_tvb, offset) ;
                        proto_tree_add_item(msg_type_tree, hf_ssh_subsystem_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        guint8* subsystem_name = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset, slen, ENC_ASCII|ENC_NA);
                        set_subdissector_for_channel(peer_data, uiNumChannel, subsystem_name);
                        proto_tree_add_item(msg_type_tree, hf_ssh_subsystem_name, packet_tvb, offset, slen, ENC_UTF_8);
                        offset += slen;
                }else if (0 == strcmp(request_name, "exit-status")) {
                        proto_tree_add_item(msg_type_tree, hf_ssh_exit_status, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                }
        }else if(msg_code==SSH_MSG_CHANNEL_SUCCESS){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }
	return offset;
}

static dissector_handle_t
get_subdissector_for_channel(struct ssh_peer_data *peer_data, guint uiNumChannel)
{
        ssh_channel_info_t *ci = peer_data->global_data->channel_info;
        while(ci){
            guint channel_number = &peer_data->global_data->peer_data[SERVER_PEER_DATA]==peer_data?ci->client_channel_number:ci->server_channel_number;
            if(channel_number==uiNumChannel){return ci->subdissector_handle;}
            ci = ci->next;
        }
        ws_debug("Error lookin up channel %d", uiNumChannel);
        return NULL;
}

static void
set_subdissector_for_channel(struct ssh_peer_data *peer_data, guint uiNumChannel, guint8* subsystem_name)
{
        ssh_channel_info_t *ci = NULL;
        ssh_channel_info_t **pci = &peer_data->global_data->channel_info;
        int is_server = &peer_data->global_data->peer_data[SERVER_PEER_DATA]==peer_data;
        while(*pci){
            guint channel_number = is_server?(*pci)->client_channel_number:(*pci)->server_channel_number;
            if (channel_number == uiNumChannel) {
                ci = *pci;
                break;
            }
            pci = &(*pci)->next;
        }
        if(!ci){
            ci = wmem_new(wmem_file_scope(), ssh_channel_info_t);
            *pci = ci;
        }
        if(0 == strcmp(subsystem_name, "sftp")) {
            ci->subdissector_handle = sftp_handle;
        } else {
            ci->subdissector_handle = NULL;
        }
}

static int
ssh_dissect_connection_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_GLOBAL_REQUEST){
                guint8* request_name;
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_global_request_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                request_name = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset, slen, ENC_ASCII|ENC_NA);
                proto_tree_add_item(msg_type_tree, hf_ssh_global_request_name, packet_tvb, offset, slen, ENC_ASCII);
                offset += slen;
                proto_tree_add_item(msg_type_tree, hf_ssh_global_request_want_reply, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                if (0 == strcmp(request_name, "hostkeys-00@openssh.com")) {
                    guint   alen;
                    proto_item *ti;
                    int dissected_len = 0;
                    alen = tvb_get_ntohl(packet_tvb, offset) ;
                    ti = proto_tree_add_item(msg_type_tree, hf_ssh_global_request_hostkeys_array_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_item *blob_tree = NULL;
                    blob_tree = proto_tree_add_subtree(msg_type_tree, packet_tvb, offset, alen, ett_userauth_pk_blob, NULL, "Public key blob");
                    dissected_len = ssh_dissect_public_key_blob(packet_tvb, pinfo, offset, blob_tree) - offset;
                    if(dissected_len!=(int)alen){
                        expert_add_info_format(pinfo, ti, &ei_ssh_packet_decode, "Decoded %d bytes, but packet legnth is %d bytes", dissected_len, alen);
                    }
                    offset += alen;
                }
        }
        return offset;
}

static int
ssh_dissect_public_key_blob(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree)
{
        (void)pinfo;
        guint   slen;
        slen = tvb_get_ntohl(packet_tvb, offset) ;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_blob_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_blob_name, packet_tvb, offset, slen, ENC_ASCII);
        offset += slen;
        offset += ssh_tree_add_mpint(packet_tvb, offset, msg_type_tree, hf_ssh_blob_e);
        offset += ssh_tree_add_mpint(packet_tvb, offset, msg_type_tree, hf_ssh_blob_p);
        return offset;
}

static int
ssh_dissect_public_key_signature(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree)
{
        (void)pinfo;
        guint   slen;
        slen = tvb_get_ntohl(packet_tvb, offset) ;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_sig_blob_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_sig_blob_name, packet_tvb, offset, slen, ENC_ASCII);
        offset += slen;
        slen = tvb_get_ntohl(packet_tvb, offset) ;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_sig_s_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_sig_s, packet_tvb, offset, slen, ENC_NA);
        offset += slen;
        return offset;
}

#ifdef SSH_DECRYPT_DEBUG /* {{{ */

static FILE* ssh_debug_file=NULL;

static void
ssh_prefs_apply_cb(void)
{
    ssh_set_debug(ssh_debug_file_name);
}

static void
ssh_set_debug(const gchar* name)
{
    static gint debug_file_must_be_closed;
    gint        use_stderr;

    use_stderr                = name?(strcmp(name, SSH_DEBUG_USE_STDERR) == 0):0;

    if (debug_file_must_be_closed)
        fclose(ssh_debug_file);

    if (use_stderr)
        ssh_debug_file = stderr;
    else if (!name || (strcmp(name, "") ==0))
        ssh_debug_file = NULL;
    else
        ssh_debug_file = ws_fopen(name, "w");

    if (!use_stderr && ssh_debug_file)
        debug_file_must_be_closed = 1;
    else
        debug_file_must_be_closed = 0;

    ssh_debug_printf("Wireshark SSH debug log \n\n");
#ifdef HAVE_LIBGNUTLS
    ssh_debug_printf("GnuTLS version:    %s\n", gnutls_check_version(NULL));
#endif
    ssh_debug_printf("Libgcrypt version: %s\n", gcry_check_version(NULL));
    ssh_debug_printf("\n");
}

static void
ssh_debug_flush(void)
{
    if (ssh_debug_file)
        fflush(ssh_debug_file);
}

static void
ssh_debug_printf(const gchar* fmt, ...)
{
    va_list ap;

    if (!ssh_debug_file)
        return;

    va_start(ap, fmt);
    vfprintf(ssh_debug_file, fmt, ap);
    va_end(ap);
}

static void
ssh_print_data(const gchar* name, const guchar* data, size_t len)
{
    size_t i, j, k;
    if (!ssh_debug_file)
        return;
#ifdef OPENSSH_STYLE
    fprintf(ssh_debug_file,"%s[%d]\n",name, (int) len);
#else
    fprintf(ssh_debug_file,"%s[%d]:\n",name, (int) len);
#endif
    for (i=0; i<len; i+=16) {
#ifdef OPENSSH_STYLE
        fprintf(ssh_debug_file,"%04u: ", (unsigned int)i);
#else
        fprintf(ssh_debug_file,"| ");
#endif
        for (j=i, k=0; k<16 && j<len; ++j, ++k)
            fprintf(ssh_debug_file,"%.2x ",data[j]);
        for (; k<16; ++k)
            fprintf(ssh_debug_file,"   ");
#ifdef OPENSSH_STYLE
        fputc(' ', ssh_debug_file);
#else
        fputc('|', ssh_debug_file);
#endif
        for (j=i, k=0; k<16 && j<len; ++j, ++k) {
            guchar c = data[j];
            if (!g_ascii_isprint(c) || (c=='\t')) c = '.';
            fputc(c, ssh_debug_file);
        }
#ifdef OPENSSH_STYLE
        fprintf(ssh_debug_file,"\n");
#else
        for (; k<16; ++k)
            fputc(' ', ssh_debug_file);
        fprintf(ssh_debug_file,"|\n");
#endif
    }
}

#endif /* SSH_DECRYPT_DEBUG }}} */

static void
ssh_secrets_block_callback(const void *secrets, guint size)
{
    ssh_keylog_process_lines((const guint8 *)secrets, size);
}

/* Functions for SSH random hashtables. {{{ */
static gint
ssh_equal (gconstpointer v, gconstpointer v2)
{
    if (v == NULL || v2 == NULL) {
        return 0;
    }

    const ssh_bignum *val1;
    const ssh_bignum *val2;
    val1 = (const ssh_bignum *)v;
    val2 = (const ssh_bignum *)v2;

    if (val1->length == val2->length &&
        !memcmp(val1->data, val2->data, val2->length)) {
        return 1;
    }
    return 0;
}

static guint
ssh_hash  (gconstpointer v)
{
    guint l,hash;
    const ssh_bignum* id;
    const guint* cur;

    if (v == NULL) {
        return 0;
    }

    hash = 0;
    id = (const ssh_bignum*) v;

    /*  id and id->data are mallocated in ssh_save_master_key().  As such 'data'
     *  should be aligned for any kind of access (for example as a guint as
     *  is done below).  The intermediate void* cast is to prevent "cast
     *  increases required alignment of target type" warnings on CPUs (such
     *  as SPARCs) that do not allow misaligned memory accesses.
     */
    cur = (const guint*)(void*) id->data;

    for (l=4; (l < id->length); l+=4, cur++)
        hash = hash ^ (*cur);

    return hash;
}
/* Functions for SSH random hashtables. }}} */

void
proto_register_ssh(void)
{
    static hf_register_info hf[] = {
        { &hf_ssh_protocol,
          { "Protocol", "ssh.protocol",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_packet_length,
          { "Packet Length", "ssh.packet_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_packet_length_encrypted,
          { "Packet Length (encrypted)", "ssh.packet_length_encrypted",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_padding_length,
          { "Padding Length", "ssh.padding_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_payload,
          { "Payload", "ssh.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_encrypted_packet,
          { "Encrypted Packet", "ssh.encrypted_packet",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_padding_string,
          { "Padding String", "ssh.padding_string",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_seq_num,
          { "Sequence number", "ssh.seq_num",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mac_string,
          { "MAC", "ssh.mac",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Message authentication code", HFILL }},

        { &hf_ssh_mac_status,
          { "MAC Status", "ssh.mac.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh_direction,
          { "Direction", "ssh.direction",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Message direction", HFILL }},

        { &hf_ssh_msg_code,
          { "Message Code", "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh1_msg_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh2_msg_code,
          { "Message Code", "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_msg_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh2_kex_dh_msg_code,
          { "Message Code", "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_kex_dh_msg_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh2_kex_dh_gex_msg_code,
          { "Message Code", "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_kex_dh_gex_msg_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh2_kex_ecdh_msg_code,
          { "Message Code", "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_kex_ecdh_msg_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh_cookie,
          { "Cookie", "ssh.cookie",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_algorithms,
          { "kex_algorithms string", "ssh.kex_algorithms",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_server_host_key_algorithms,
          { "server_host_key_algorithms string", "ssh.server_host_key_algorithms",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_encryption_algorithms_client_to_server,
          { "encryption_algorithms_client_to_server string", "ssh.encryption_algorithms_client_to_server",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_encryption_algorithms_server_to_client,
          { "encryption_algorithms_server_to_client string", "ssh.encryption_algorithms_server_to_client",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mac_algorithms_client_to_server,
          { "mac_algorithms_client_to_server string", "ssh.mac_algorithms_client_to_server",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mac_algorithms_server_to_client,
          { "mac_algorithms_server_to_client string", "ssh.mac_algorithms_server_to_client",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_compression_algorithms_client_to_server,
          { "compression_algorithms_client_to_server string", "ssh.compression_algorithms_client_to_server",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_compression_algorithms_server_to_client,
          { "compression_algorithms_server_to_client string", "ssh.compression_algorithms_server_to_client",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_languages_client_to_server,
          { "languages_client_to_server string", "ssh.languages_client_to_server",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_languages_server_to_client,
          { "languages_server_to_client string", "ssh.languages_server_to_client",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_algorithms_length,
          { "kex_algorithms length", "ssh.kex_algorithms_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_server_host_key_algorithms_length,
          { "server_host_key_algorithms length", "ssh.server_host_key_algorithms_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_encryption_algorithms_client_to_server_length,
          { "encryption_algorithms_client_to_server length", "ssh.encryption_algorithms_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_encryption_algorithms_server_to_client_length,
          { "encryption_algorithms_server_to_client length", "ssh.encryption_algorithms_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mac_algorithms_client_to_server_length,
          { "mac_algorithms_client_to_server length", "ssh.mac_algorithms_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mac_algorithms_server_to_client_length,
          { "mac_algorithms_server_to_client length", "ssh.mac_algorithms_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_compression_algorithms_client_to_server_length,
          { "compression_algorithms_client_to_server length", "ssh.compression_algorithms_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_compression_algorithms_server_to_client_length,
          { "compression_algorithms_server_to_client length", "ssh.compression_algorithms_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_languages_client_to_server_length,
          { "languages_client_to_server length", "ssh.languages_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_languages_server_to_client_length,
          { "languages_server_to_client length", "ssh.languages_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_first_kex_packet_follows,
          { "First KEX Packet Follows", "ssh.first_kex_packet_follows",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_reserved,
          { "Reserved", "ssh.kex.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_hassh_algo,
          { "hasshAlgorithms", "ssh.kex.hassh_algorithms",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_hassh,
          { "hassh", "ssh.kex.hassh",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_hasshserver_algo,
          { "hasshServerAlgorithms", "ssh.kex.hasshserver_algorithms",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_hasshserver,
          { "hasshServer", "ssh.kex.hasshserver",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_length,
          { "Host key length", "ssh.host_key.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_type_length,
          { "Host key type length", "ssh.host_key.type_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_type,
          { "Host key type", "ssh.host_key.type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_data,
          { "Host key data", "ssh.host_key.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_rsa_n,
          { "RSA modulus (N)", "ssh.host_key.rsa.n",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_rsa_e,
          { "RSA public exponent (e)", "ssh.host_key.rsa.e",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_dsa_p,
          { "DSA prime modulus (p)", "ssh.host_key.dsa.p",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_dsa_q,
          { "DSA prime divisor (q)", "ssh.host_key.dsa.q",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_dsa_g,
          { "DSA subgroup generator (g)", "ssh.host_key.dsa.g",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_dsa_y,
          { "DSA public key (y)", "ssh.host_key.dsa.y",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_ecdsa_curve_id,
          { "ECDSA elliptic curve identifier", "ssh.host_key.ecdsa.id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_ecdsa_curve_id_length,
          { "ECDSA elliptic curve identifier length", "ssh.host_key.ecdsa.id_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_ecdsa_q,
          { "ECDSA public key (Q)", "ssh.host_key.ecdsa.q",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_ecdsa_q_length,
          { "ECDSA public key length", "ssh.host_key.ecdsa.q_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_eddsa_key,
          { "EdDSA public key", "ssh.host_key.eddsa.key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_eddsa_key_length,
          { "EdDSA public key length", "ssh.host_key.eddsa.key_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostsig_length,
          { "Host signature length", "ssh.host_sig.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostsig_type_length,
          { "Host signature type length", "ssh.host_sig.type_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostsig_type,
          { "Host signature type", "ssh.host_sig.type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostsig_data,
          { "Host signature data", "ssh.host_sig.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostsig_rsa,
          { "RSA signature", "ssh.host_sig.rsa",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostsig_dsa,
          { "DSA signature", "ssh.host_sig.dsa",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_dh_e,
          { "DH client e", "ssh.dh.e",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_dh_f,
          { "DH server f", "ssh.dh.f",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_dh_gex_min,
          { "DH GEX Min", "ssh.dh_gex.min",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Minimal acceptable group size", HFILL }},

        { &hf_ssh_dh_gex_nbits,
          { "DH GEX Number of Bits", "ssh.dh_gex.nbits",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Preferred group size", HFILL }},

        { &hf_ssh_dh_gex_max,
          { "DH GEX Max", "ssh.dh_gex.max",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Maximal acceptable group size", HFILL }},

        { &hf_ssh_dh_gex_p,
          { "DH GEX modulus (P)", "ssh.dh_gex.p",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_dh_gex_g,
          { "DH GEX base (G)", "ssh.dh_gex.g",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ecdh_q_c,
          { "ECDH client's ephemeral public key (Q_C)", "ssh.ecdh.q_c",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ecdh_q_c_length,
          { "ECDH client's ephemeral public key length", "ssh.ecdh.q_c_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ecdh_q_s,
          { "ECDH server's ephemeral public key (Q_S)", "ssh.ecdh.q_s",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ecdh_q_s_length,
          { "ECDH server's ephemeral public key length", "ssh.ecdh.q_s_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mpint_length,
          { "Multi Precision Integer Length", "ssh.mpint_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ignore_data_length,
          { "Debug message length", "ssh.ignore_data_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ignore_data,
          { "Ignore data", "ssh.ignore_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_debug_always_display,
          { "Always Display", "ssh.debug_always_display",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_debug_message_length,
          { "Debug message length", "ssh.debug_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_debug_message,
          { "Debug message", "ssh.debug_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_service_name_length,
          { "Service Name length", "ssh.service_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_service_name,
          { "Service Name", "ssh.service_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_disconnect_reason,
          { "Disconnect reason", "ssh.disconnect_reason",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_disconnect_description_length,
          { "Disconnect description length", "ssh.disconnect_description_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_disconnect_description,
          { "Disconnect description", "ssh.disconnect_description",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_lang_tag_length,
          { "Language tag length", "ssh.lang_tag_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_lang_tag,
          { "Language tag", "ssh.lang_tag",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_user_name_length,
          { "User Name length", "ssh.userauth_user_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_user_name,
          { "User Name", "ssh.userauth_user_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_change_password,
          { "Change password", "ssh.userauth.change_password",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_service_name_length,
          { "Service Name length", "ssh.userauth_service_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_service_name,
          { "Service Name", "ssh.userauth_service_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_method_name_length,
          { "Method Name length", "ssh.userauth_method_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_method_name,
          { "Method Name", "ssh.userauth_method_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_have_signature,
          { "Have signature", "ssh.userauth.have_signature",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_password_length,
          { "Password length", "ssh.userauth_password_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_password,
          { "Password", "ssh.userauth_password",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_new_password_length,
          { "New password length", "ssh.userauth_new_password_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_new_password,
          { "New password", "ssh.userauth_new_password",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_auth_failure_list_length,
          { "Authentications that can continue list len", "ssh.auth_failure_cont_list_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_auth_failure_list,
          { "Authentications that can continue list", "ssh.auth_failure_cont_list",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_partial_success,
          { "Partial success", "ssh.userauth.partial_success",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_pka_name_len,
          { "Public key algorithm name length", "ssh.userauth_pka_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_pka_name,
          { "Public key algorithm name", "ssh.userauth_pka_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_blob_name_length,
          { "Public key blob algorithm name length", "ssh.pk_blob_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_blob_name,
          { "Public key blob algorithm name", "ssh.pk_blob_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_blob_length,
          { "Public key blob length", "ssh.pk_blob_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_blob_p,
          { "ssh-rsa modulus (n)", "ssh.blob.ssh-rsa.n",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_blob_e,
          { "ssh-rsa public exponent (e)", "ssh.blob.ssh-rsa.e",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_signature_length,
          { "Public key signature blob length", "ssh.pk_sig_blob_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_sig_blob_name_length,
          { "Public key signature blob algorithm name length", "ssh.pk_sig_blob_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_sig_blob_name,
          { "Public key signature blob algorithm name", "ssh.pk_sig_blob_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_sig_s_length,
          { "ssh-rsa signature length", "ssh.sig.ssh-rsa.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_sig_s,
          { "ssh-rsa signature (s)", "ssh.sig.ssh-rsa.s",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_type_name_len,
          { "Channel type name length", "ssh.connection_type_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_type_name,
          { "Channel type name", "ssh.connection_type_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_sender_channel,
          { "Sender channel", "ssh.connection_sender_channel",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_recipient_channel,
          { "Recipient channel", "ssh.connection_recipient_channel",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_initial_window,
          { "Initial window size", "ssh.connection_initial_window_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_maximum_packet_size,
          { "Maximum packet size", "ssh.userauth_maximum_packet_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_global_request_name_len,
          { "Global request name length", "ssh.global_request_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_global_request_name,
          { "Global request name", "ssh.global_request_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_global_request_want_reply,
          { "Global request want reply", "ssh.global_request_want_reply",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_global_request_hostkeys_array_len,
          { "Host keys array length", "ssh.global_request_hostkeys",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_request_name_len,
          { "Channel request name length", "ssh.global_request_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_request_name,
          { "Channel request name", "ssh.global_request_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_request_want_reply,
          { "Channel request want reply", "ssh.channel_request_want_reply",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_subsystem_name_len,
          { "Subsystem name length", "ssh.subsystem_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_subsystem_name,
          { "Subsystem name", "ssh.subsystem_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_exit_status,
          { "Exit status", "ssh.exit_status",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_window_adjust,
          { "Bytes to add", "ssh.channel_window_adjust",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_data_len,
          { "Data length", "ssh.channel_data_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

    };

    static gint *ett[] = {
        &ett_ssh,
        &ett_key_exchange,
        &ett_key_exchange_host_key,
        &ett_key_exchange_host_sig,
        &ett_userauth_pk_blob,
        &ett_userauth_pk_signautre,
        &ett_ssh1,
        &ett_ssh2,
        &ett_key_init
    };

    static ei_register_info ei[] = {
        { &ei_ssh_packet_length,  { "ssh.packet_length.error", PI_PROTOCOL, PI_WARN, "Overly large number", EXPFILL }},
        { &ei_ssh_packet_decode,  { "ssh.packet_decode.error", PI_PROTOCOL, PI_WARN, "Packet decoded length not equal to packet length", EXPFILL }},
        { &ei_ssh_invalid_keylen, { "ssh.key_length.error", PI_PROTOCOL, PI_ERROR, "Invalid key length", EXPFILL }},
        { &ei_ssh_mac_bad,        { "ssh.mac_bad.expert", PI_CHECKSUM, PI_ERROR, "Bad MAC", EXPFILL }},
    };

    module_t *ssh_module;
    expert_module_t *expert_ssh;

    proto_ssh = proto_register_protocol("SSH Protocol", "SSH", "ssh");
    proto_register_field_array(proto_ssh, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ssh = expert_register_protocol(proto_ssh);
    expert_register_field_array(expert_ssh, ei, array_length(ei));

#ifdef SSH_DECRYPT_DEBUG
    ssh_module = prefs_register_protocol(proto_ssh, ssh_prefs_apply_cb);
#else
    ssh_module = prefs_register_protocol(proto_ssh, NULL);
#endif
    prefs_register_bool_preference(ssh_module, "desegment_buffers",
                       "Reassemble SSH buffers spanning multiple TCP segments",
                       "Whether the SSH dissector should reassemble SSH buffers spanning multiple TCP segments. "
                       "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                       &ssh_desegment);

    ssh_master_key_map = g_hash_table_new(ssh_hash, ssh_equal);
    prefs_register_filename_preference(ssh_module, "keylog_file", "Key log filename",
            "The path to the file which contains a list of key exchange secrets in the following format:\n"
            "\"<hex-encoded-cookie> <hex-encoded-key>\" (without quotes or leading spaces).\n",
            &pref_keylog_file, FALSE);

    prefs_register_filename_preference(ssh_module, "debug_file", "SSH debug file",
        "Redirect SSH debug to the file specified. Leave empty to disable debugging "
        "or use \"" SSH_DEBUG_USE_STDERR "\" to redirect output to stderr.",
        &ssh_debug_file_name, TRUE);

    secrets_register_type(SECRETS_TYPE_SSH, ssh_secrets_block_callback);

    ssh_handle = register_dissector("ssh", dissect_ssh, proto_ssh);
}

void
proto_reg_handoff_ssh(void)
{
#ifdef SSH_DECRYPT_DEBUG
    ssh_set_debug(ssh_debug_file_name);
#endif
    dissector_add_uint_range_with_preference("tcp.port", TCP_RANGE_SSH, ssh_handle);
    dissector_add_uint("sctp.port", SCTP_PORT_SSH, ssh_handle);
    dissector_add_uint("sctp.ppi", SSH_PAYLOAD_PROTOCOL_ID, ssh_handle);
    sftp_handle = find_dissector("sftp");
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
