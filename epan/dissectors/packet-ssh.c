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
/* Start with WIRESHARK_LOG_DOMAINS=packet-ssh and WIRESHARK_LOG_LEVEL=debug to see messages. */
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
#include <wsutil/to_str.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/curve25519.h>
#include <wsutil/pint.h>
#include <wsutil/str_util.h>
#include <wsutil/wslog.h>
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
    uint8_t *data;
    unsigned   length;
} ssh_bignum;

#define SSH_KEX_CURVE25519 0x00010000
#define SSH_KEX_DH_GEX     0x00020000
#define SSH_KEX_DH_GROUP1  0x00030001
#define SSH_KEX_DH_GROUP14 0x00030014
#define SSH_KEX_DH_GROUP16 0x00030016
#define SSH_KEX_DH_GROUP18 0x00030018

#define SSH_KEX_HASH_SHA1   1
#define SSH_KEX_HASH_SHA256 2
#define SSH_KEX_HASH_SHA512 4

#define DIGEST_MAX_SIZE 48

typedef struct _ssh_message_info_t {
    uint32_t sequence_number;
    unsigned char *plain_data;     /**< Decrypted data. */
    unsigned   data_len;       /**< Length of decrypted data. */
    int     id;             /**< Identifies the exact message within a frame
                                 (there can be multiple records in a frame). */
    uint32_t byte_seq;
    uint32_t next_byte_seq;
    struct _ssh_message_info_t* next;
    uint8_t calc_mac[DIGEST_MAX_SIZE];
} ssh_message_info_t;

typedef struct {
    bool from_server;
    ssh_message_info_t * messages;
} ssh_packet_info_t;

typedef struct _ssh_channel_info_t {
    uint32_t byte_seq;
    uint16_t flags;
    wmem_tree_t *multisegment_pdus;
    dissector_handle_t handle;
} ssh_channel_info_t;

struct ssh_peer_data {
    unsigned   counter;

    uint32_t frame_version_start;
    uint32_t frame_version_end;

    uint32_t frame_key_start;
    uint32_t frame_key_end;
    int frame_key_end_offset;

    char*  kex_proposal;

    /* For all subsequent proposals,
       [0] is client-to-server and [1] is server-to-client. */
#define CLIENT_TO_SERVER_PROPOSAL 0
#define SERVER_TO_CLIENT_PROPOSAL 1

    char*  mac_proposals[2];
    char*  mac;
    int     mac_length;

    char*  enc_proposals[2];
    char*  enc;

    char*  comp_proposals[2];
    char*  comp;

    int     length_is_plaintext;

    // see libgcrypt source, gcrypt.h:gcry_cipher_algos
    unsigned         cipher_id;
    unsigned         mac_id;
    // chacha20 needs two cipher handles
    gcry_cipher_hd_t cipher, cipher_2;
    unsigned         sequence_number;
    uint32_t         seq_num_kex_init;
// union ??? -- begin
    uint32_t         seq_num_gex_req;
    uint32_t         seq_num_gex_grp;
    uint32_t         seq_num_gex_ini;
    uint32_t         seq_num_gex_rep;
// --
    uint32_t         seq_num_ecdh_ini;
    uint32_t         seq_num_ecdh_rep;
// --
    uint32_t         seq_num_dh_ini;
    uint32_t         seq_num_dh_rep;
// union ??? -- end
    uint32_t         seq_num_new_key;
    ssh_bignum      *bn_cookie;
    uint8_t          iv[12];
    uint8_t          hmac_iv[DIGEST_MAX_SIZE];
    unsigned         hmac_iv_len;

    wmem_map_t      *channel_info; /**< Map of sender channel numbers to recipient numbers. */
    wmem_map_t      *channel_handles; /**< Map of recipient channel numbers to subdissector handles. */
    struct ssh_flow_data * global_data;
};

struct ssh_flow_data {
    unsigned   version;

    char*  kex;
    int   (*kex_specific_dissector)(uint8_t msg_code, tvbuff_t *tvb,
            packet_info *pinfo, int offset, proto_tree *tree,
            struct ssh_flow_data *global_data, unsigned *seq_num);

    /* [0] is client's, [1] is server's */
#define CLIENT_PEER_DATA 0
#define SERVER_PEER_DATA 1
    struct ssh_peer_data peer_data[2];

    char            *session_id;
    unsigned        session_id_length;
    ssh_bignum      *kex_e;
    ssh_bignum      *kex_f;
    ssh_bignum      *kex_gex_p;                 // Group modulo
    ssh_bignum      *kex_gex_g;                 // Group generator
    ssh_bignum      *secret;
    wmem_array_t    *kex_client_version;
    wmem_array_t    *kex_server_version;
    wmem_array_t    *kex_client_key_exchange_init;
    wmem_array_t    *kex_server_key_exchange_init;
    wmem_array_t    *kex_server_host_key_blob;
    wmem_array_t    *kex_gex_bits_min;
    wmem_array_t    *kex_gex_bits_req;
    wmem_array_t    *kex_gex_bits_max;
    wmem_array_t    *kex_shared_secret;
    bool            do_decrypt;
    bool            ext_ping_openssh_offered;
    ssh_bignum      new_keys[6];
};

typedef struct {
    char       *type;
    ssh_bignum *key_material;
} ssh_key_map_entry_t;

static GHashTable * ssh_master_key_map;

static int proto_ssh;

/* Version exchange */
static int hf_ssh_protocol;

/* Framing */
static int hf_ssh_packet_length;
static int hf_ssh_packet_length_encrypted;
static int hf_ssh_padding_length;
static int hf_ssh_payload;
static int hf_ssh_encrypted_packet;
static int hf_ssh_padding_string;
static int hf_ssh_mac_string;
static int hf_ssh_mac_status;
static int hf_ssh_seq_num;
static int hf_ssh_direction;

/* Message codes */
static int hf_ssh_msg_code;
static int hf_ssh2_msg_code;
static int hf_ssh2_kex_dh_msg_code;
static int hf_ssh2_kex_dh_gex_msg_code;
static int hf_ssh2_kex_ecdh_msg_code;
static int hf_ssh2_ext_ping_msg_code;

/* Algorithm negotiation */
static int hf_ssh_cookie;
static int hf_ssh_kex_algorithms;
static int hf_ssh_server_host_key_algorithms;
static int hf_ssh_encryption_algorithms_client_to_server;
static int hf_ssh_encryption_algorithms_server_to_client;
static int hf_ssh_mac_algorithms_client_to_server;
static int hf_ssh_mac_algorithms_server_to_client;
static int hf_ssh_compression_algorithms_client_to_server;
static int hf_ssh_compression_algorithms_server_to_client;
static int hf_ssh_languages_client_to_server;
static int hf_ssh_languages_server_to_client;
static int hf_ssh_kex_algorithms_length;
static int hf_ssh_server_host_key_algorithms_length;
static int hf_ssh_encryption_algorithms_client_to_server_length;
static int hf_ssh_encryption_algorithms_server_to_client_length;
static int hf_ssh_mac_algorithms_client_to_server_length;
static int hf_ssh_mac_algorithms_server_to_client_length;
static int hf_ssh_compression_algorithms_client_to_server_length;
static int hf_ssh_compression_algorithms_server_to_client_length;
static int hf_ssh_languages_client_to_server_length;
static int hf_ssh_languages_server_to_client_length;
static int hf_ssh_first_kex_packet_follows;
static int hf_ssh_kex_reserved;
static int hf_ssh_kex_hassh_algo;
static int hf_ssh_kex_hassh;
static int hf_ssh_kex_hasshserver_algo;
static int hf_ssh_kex_hasshserver;

/* Key exchange common elements */
static int hf_ssh_hostkey_length;
static int hf_ssh_hostkey_type_length;
static int hf_ssh_hostkey_type;
static int hf_ssh_hostkey_data;
static int hf_ssh_hostkey_rsa_n;
static int hf_ssh_hostkey_rsa_e;
static int hf_ssh_hostkey_dsa_p;
static int hf_ssh_hostkey_dsa_q;
static int hf_ssh_hostkey_dsa_g;
static int hf_ssh_hostkey_dsa_y;
static int hf_ssh_hostkey_ecdsa_curve_id;
static int hf_ssh_hostkey_ecdsa_curve_id_length;
static int hf_ssh_hostkey_ecdsa_q;
static int hf_ssh_hostkey_ecdsa_q_length;
static int hf_ssh_hostkey_eddsa_key;
static int hf_ssh_hostkey_eddsa_key_length;
static int hf_ssh_hostsig_length;
static int hf_ssh_hostsig_type_length;
static int hf_ssh_hostsig_type;
static int hf_ssh_hostsig_rsa;
static int hf_ssh_hostsig_dsa;
static int hf_ssh_hostsig_data;

/* Key exchange: Diffie-Hellman */
static int hf_ssh_dh_e;
static int hf_ssh_dh_f;

/* Key exchange: Diffie-Hellman Group Exchange */
static int hf_ssh_dh_gex_min;
static int hf_ssh_dh_gex_nbits;
static int hf_ssh_dh_gex_max;
static int hf_ssh_dh_gex_p;
static int hf_ssh_dh_gex_g;

/* Key exchange: Elliptic Curve Diffie-Hellman */
static int hf_ssh_ecdh_q_c;
static int hf_ssh_ecdh_q_c_length;
static int hf_ssh_ecdh_q_s;
static int hf_ssh_ecdh_q_s_length;

/* Extension negotiation */
static int hf_ssh_ext_count;
static int hf_ssh_ext_name_length;
static int hf_ssh_ext_name;
static int hf_ssh_ext_value_length;
static int hf_ssh_ext_value;
static int hf_ssh_ext_server_sig_algs_algorithms;
static int hf_ssh_ext_delay_compression_algorithms_client_to_server_length;
static int hf_ssh_ext_delay_compression_algorithms_client_to_server;
static int hf_ssh_ext_delay_compression_algorithms_server_to_client_length;
static int hf_ssh_ext_delay_compression_algorithms_server_to_client;
static int hf_ssh_ext_no_flow_control_value;
static int hf_ssh_ext_elevation_value;
static int hf_ssh_ext_prop_publickey_algorithms_algorithms;

/* Miscellaneous */
static int hf_ssh_mpint_length;

static int hf_ssh_ignore_data_length;
static int hf_ssh_ignore_data;
static int hf_ssh_debug_always_display;
static int hf_ssh_debug_message_length;
static int hf_ssh_debug_message;
static int hf_ssh_service_name_length;
static int hf_ssh_service_name;
static int hf_ssh_userauth_user_name_length;
static int hf_ssh_userauth_user_name;
static int hf_ssh_userauth_change_password;
static int hf_ssh_userauth_service_name_length;
static int hf_ssh_userauth_service_name;
static int hf_ssh_userauth_method_name_length;
static int hf_ssh_userauth_method_name;
static int hf_ssh_userauth_have_signature;
static int hf_ssh_userauth_password_length;
static int hf_ssh_userauth_password;
static int hf_ssh_userauth_new_password_length;
static int hf_ssh_userauth_new_password;
static int hf_ssh_auth_failure_list_length;
static int hf_ssh_auth_failure_list;
static int hf_ssh_userauth_partial_success;
static int hf_ssh_userauth_pka_name_len;
static int hf_ssh_userauth_pka_name;
static int hf_ssh_pk_blob_name_length;
static int hf_ssh_pk_blob_name;
static int hf_ssh_blob_length;
static int hf_ssh_signature_length;
static int hf_ssh_pk_sig_blob_name_length;
static int hf_ssh_pk_sig_blob_name;
static int hf_ssh_connection_type_name_len;
static int hf_ssh_connection_type_name;
static int hf_ssh_connection_sender_channel;
static int hf_ssh_connection_recipient_channel;
static int hf_ssh_connection_initial_window;
static int hf_ssh_connection_maximum_packet_size;
static int hf_ssh_global_request_name_len;
static int hf_ssh_global_request_name;
static int hf_ssh_global_request_want_reply;
static int hf_ssh_global_request_hostkeys_array_len;
static int hf_ssh_channel_request_name_len;
static int hf_ssh_channel_request_name;
static int hf_ssh_channel_request_want_reply;
static int hf_ssh_subsystem_name_len;
static int hf_ssh_subsystem_name;
static int hf_ssh_channel_window_adjust;
static int hf_ssh_channel_data_len;
static int hf_ssh_exit_status;
static int hf_ssh_disconnect_reason;
static int hf_ssh_disconnect_description_length;
static int hf_ssh_disconnect_description;
static int hf_ssh_lang_tag_length;
static int hf_ssh_lang_tag;
static int hf_ssh_ping_data_length;
static int hf_ssh_ping_data;
static int hf_ssh_pong_data_length;
static int hf_ssh_pong_data;

static int hf_ssh_blob_p;
static int hf_ssh_blob_e;

static int hf_ssh_pk_sig_s_length;
static int hf_ssh_pk_sig_s;

static int hf_ssh_reassembled_in;
static int hf_ssh_reassembled_length;
static int hf_ssh_reassembled_data;
static int hf_ssh_segments;
static int hf_ssh_segment;
static int hf_ssh_segment_overlap;
static int hf_ssh_segment_overlap_conflict;
static int hf_ssh_segment_multiple_tails;
static int hf_ssh_segment_too_long_fragment;
static int hf_ssh_segment_error;
static int hf_ssh_segment_count;
static int hf_ssh_segment_data;

static int ett_ssh;
static int ett_key_exchange;
static int ett_key_exchange_host_key;
static int ett_key_exchange_host_sig;
static int ett_extension;
static int ett_userauth_pk_blob;
static int ett_userauth_pk_signautre;
static int ett_key_init;
static int ett_ssh1;
static int ett_ssh2;
static int ett_ssh_segments;
static int ett_ssh_segment;

static expert_field ei_ssh_packet_length;
static expert_field ei_ssh_packet_decode;
static expert_field ei_ssh_channel_number;
static expert_field ei_ssh_invalid_keylen;
static expert_field ei_ssh_mac_bad;

static bool ssh_desegment = true;

static dissector_handle_t ssh_handle;
static dissector_handle_t sftp_handle;

static const char   *pref_keylog_file;
static FILE         *ssh_keylog_file;

static reassembly_table ssh_reassembly_table;

static const fragment_items ssh_segment_items = {
    &ett_ssh_segment,
    &ett_ssh_segments,
    &hf_ssh_segments,
    &hf_ssh_segment,
    &hf_ssh_segment_overlap,
    &hf_ssh_segment_overlap_conflict,
    &hf_ssh_segment_multiple_tails,
    &hf_ssh_segment_too_long_fragment,
    &hf_ssh_segment_error,
    &hf_ssh_segment_count,
    &hf_ssh_reassembled_in,
    &hf_ssh_reassembled_length,
    &hf_ssh_reassembled_data,
    "Segments"
};

#define SSH_DECRYPT_DEBUG

#ifdef SSH_DECRYPT_DEBUG
static const char *ssh_debug_file_name;
#endif

#define TCP_RANGE_SSH  "22"
#define SCTP_PORT_SSH 22

/* Message Numbers (from RFC 4250) (1-255) */

/* Transport layer protocol: generic (1-19) */
#define SSH_MSG_DISCONNECT          1
#define SSH_MSG_IGNORE              2
#define SSH_MSG_UNIMPLEMENTED       3
#define SSH_MSG_DEBUG               4
#define SSH_MSG_SERVICE_REQUEST     5
#define SSH_MSG_SERVICE_ACCEPT      6
#define SSH_MSG_EXT_INFO            7
#define SSH_MSG_NEWCOMPRESS         8

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
#define SSH_MSG_PING                        192
#define SSH_MSG_PONG                        193

#define CIPHER_AES128_CTR               0x00010001
#define CIPHER_AES192_CTR               0x00010003
#define CIPHER_AES256_CTR               0x00010004
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
    { SSH_MSG_EXT_INFO,                  "Extension Information" },
    { SSH_MSG_NEWCOMPRESS,               "New Compression" },
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

static const value_string ssh2_ext_ping_msg_vals[] = {
    { SSH_MSG_PING,                     "Ping" },
    { SSH_MSG_PONG,                     "Pong" },
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
        bool *need_desegmentation);
static int ssh_dissect_ssh2(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        bool *need_desegmentation);
static int ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        bool *need_desegmentation);
static int ssh_dissect_kex_dh(uint8_t msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, unsigned *seq_num);
static int ssh_dissect_kex_dh_gex(uint8_t msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, unsigned *seq_num);
static int ssh_dissect_kex_ecdh(uint8_t msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, unsigned *seq_num);
static int ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response, unsigned *version,
        bool *need_desegmentation);
static int ssh_try_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *tree);
static int ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data,
        int offset, proto_tree *tree);
static void ssh_choose_algo(char *client, char *server, char **result);
static void ssh_set_mac_length(struct ssh_peer_data *peer_data);
static void ssh_set_kex_specific_dissector(struct ssh_flow_data *global_data);

static void ssh_keylog_read_file(void);
static void ssh_keylog_process_line(const char *line);
static void ssh_keylog_process_lines(const uint8_t *data, unsigned datalen);
static void ssh_keylog_reset(void);
static ssh_bignum *ssh_kex_make_bignum(const uint8_t *data, unsigned length);
static bool ssh_read_e(tvbuff_t *tvb, int offset,
        struct ssh_flow_data *global_data);
static bool ssh_read_f(tvbuff_t *tvb, int offset,
        struct ssh_flow_data *global_data);
static ssh_bignum * ssh_read_mpint(tvbuff_t *tvb, int offset);
static void ssh_keylog_hash_write_secret(struct ssh_flow_data *global_data);
static ssh_bignum *ssh_kex_shared_secret(int kex_type, ssh_bignum *pub, ssh_bignum *priv, ssh_bignum *modulo);
static void ssh_hash_buffer_put_string(wmem_array_t *buffer, const char *string,
        unsigned len);
static void ssh_hash_buffer_put_uint32(wmem_array_t *buffer, unsigned val);
static char *ssh_string(const char *string, unsigned len);
static void ssh_derive_symmetric_keys(ssh_bignum *shared_secret,
        char *exchange_hash, unsigned hash_length,
        struct ssh_flow_data *global_data);
static void ssh_derive_symmetric_key(ssh_bignum *shared_secret,
        char *exchange_hash, unsigned hash_length, char id,
        ssh_bignum *result_key, struct ssh_flow_data *global_data, unsigned we_need);

static void ssh_choose_enc_mac(struct ssh_flow_data *global_data);
static void ssh_decryption_set_cipher_id(struct ssh_peer_data *peer);
static void ssh_decryption_setup_cipher(struct ssh_peer_data *peer,
        ssh_bignum *iv, ssh_bignum *key);
static void ssh_decryption_set_mac_id(struct ssh_peer_data *peer);
static void ssh_decryption_setup_mac(struct ssh_peer_data *peer,
        ssh_bignum *iv);
static void ssh_increment_message_number(packet_info *pinfo,
        struct ssh_flow_data *global_data, bool is_response);
static unsigned ssh_decrypt_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset);
static bool ssh_decrypt_chacha20(gcry_cipher_hd_t hd, uint32_t seqnr,
        uint32_t counter, const unsigned char *ctext, unsigned ctext_len,
        unsigned char *plain, unsigned plain_len);
static proto_item * ssh_tree_add_mac(proto_tree *tree, tvbuff_t *tvb, const unsigned offset, const unsigned mac_len,
        const int hf_mac, const int hf_mac_status, struct expert_field* bad_checksum_expert,
        packet_info *pinfo, const uint8_t * calc_mac, const unsigned flags);

static int ssh_dissect_decrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, proto_tree *tree,
        ssh_message_info_t *message);
static int ssh_dissect_transport_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, struct ssh_peer_data *peer_data, proto_item *msg_type_tree, unsigned msg_code);
static int ssh_dissect_rfc8308_extension(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, struct ssh_peer_data *peer_data, proto_item *msg_type_tree);
static int ssh_dissect_userauth_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, unsigned msg_code);
static int ssh_dissect_userauth_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, unsigned msg_code);
static int ssh_dissect_connection_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_item *msg_type_tree,
        unsigned msg_code, ssh_message_info_t *message);
static int ssh_dissect_connection_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, unsigned msg_code);
static int ssh_dissect_local_extension(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, struct ssh_peer_data *peer_data, proto_item *msg_type_tree, unsigned msg_code);
static int ssh_dissect_public_key_blob(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree);
static int ssh_dissect_public_key_signature(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree);

static void create_channel(struct ssh_peer_data *peer_data, uint32_t recipient_channel, uint32_t sender_channel);
static ssh_channel_info_t* get_channel_info_for_channel(struct ssh_peer_data *peer_data, uint32_t recipient_channel);
static void set_subdissector_for_channel(struct ssh_peer_data *peer_data, uint32_t recipient_channel, const uint8_t* subsystem_name);

#define SSH_DEBUG_USE_STDERR "-"

#ifdef SSH_DECRYPT_DEBUG
static void
ssh_debug_printf(const char* fmt,...) G_GNUC_PRINTF(1,2);
static void
ssh_print_data(const char* name, const unsigned char* data, size_t len);
static void
ssh_set_debug(const char* name);
static void
ssh_debug_flush(void);
#else

/* No debug: nullify debug operation*/
static inline void G_GNUC_PRINTF(1,2)
ssh_debug_printf(const char* fmt _U_,...)
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

    bool        is_response = (pinfo->destport != pinfo->match_uint),
                need_desegmentation;
    unsigned    version;

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
        global_data->kex_client_version = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_server_version = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_client_key_exchange_init = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_server_key_exchange_init = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_server_host_key_blob = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_gex_bits_min = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_gex_bits_req = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_gex_bits_max = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_shared_secret = wmem_array_new(wmem_file_scope(), 1);
        global_data->do_decrypt      = true;
        global_data->ext_ping_openssh_offered = false;

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
        bool after_version_start = (peer_data->frame_version_start == 0 ||
            pinfo->num >= peer_data->frame_version_start);
        bool before_version_end = (peer_data->frame_version_end == 0 ||
            pinfo->num <= peer_data->frame_version_end);

        need_desegmentation = false;
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
        bool *need_desegmentation)
{
    proto_item *ssh2_tree = NULL;
    int remain_length;

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
        bool *need_desegmentation)
{
    unsigned   plen, padding_length, len;
    uint8_t msg_code;
    unsigned   remain_length;

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
            *need_desegmentation = true;
            return offset;
        }
    }
    plen = tvb_get_ntohl(tvb, offset) ;
    padding_length  = 8 - plen%8;


    if (ssh_desegment && pinfo->can_desegment) {
        if (plen+4+padding_length >  remain_length) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = plen+padding_length - remain_length;
            *need_desegmentation = true;
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
        msg_code = tvb_get_uint8(tvb, offset);

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
    unsigned len = tvb_get_ntohl(tvb, offset);
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
    unsigned len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_string_length, tvb,
            offset, 4, len);
    offset+=4;
    proto_tree_add_item(tree, hf_ssh_string,
            tvb, offset, len, ENC_NA);
    return 4+len;
}

static unsigned
ssh_tree_add_hostkey(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                     const char *tree_name, int ett_idx,
                     struct ssh_flow_data *global_data)
{
    proto_tree *tree = NULL;
    int last_offset;
    int remaining_len;
    unsigned key_len, type_len;
    char* key_type;
    char *tree_title;

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
    char *data = (char *)tvb_memdup(wmem_packet_scope(), tvb, last_offset + 4, key_len);
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

static unsigned
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
    unsigned sig_len, type_len;
    uint8_t* sig_type;
    char *tree_title;

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
//    } else if (g_str_has_prefix(sig_type, "ecdsa-sha2-")) {
//        offset += ssh_tree_add_string(tvb, offset, tree,
//                                      hf_ssh_hostkey_ecdsa_curve_id, hf_ssh_hostkey_ecdsa_curve_id_length);
//        ssh_tree_add_string(tvb, offset, tree,
//                            hf_ssh_hostkey_ecdsa_q, hf_ssh_hostkey_ecdsa_q_length);
//    } else if (g_str_has_prefix(sig_type, "ssh-ed")) {
//        ssh_tree_add_string(tvb, offset, tree,
//                            hf_ssh_hostkey_eddsa_key, hf_ssh_hostkey_eddsa_key_length);
    } else {
        remaining_len = sig_len - (type_len + 4);
        proto_tree_add_item(tree, hf_ssh_hostsig_data, tvb, offset, remaining_len, ENC_NA);
        offset += remaining_len;
    }

    if(offset-offset0!=(int)(4+sig_len)){
        expert_add_info_format(pinfo, ti, &ei_ssh_packet_decode, "Decoded %d bytes, but packet length is %d bytes", offset-offset0, sig_len);
    }

    return 4+sig_len;
}

static int
ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        bool *need_desegmentation)
{
    unsigned   plen, len;
    uint8_t padding_length;
    unsigned   remain_length;
    int     last_offset = offset;
    unsigned   msg_code;
    unsigned   seq_num = 0;

    proto_item *ti;
    proto_item *key_ex_tree = NULL;
    const char *key_ex_title = "Key Exchange";

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
            *need_desegmentation = true;
            return offset;
        }
    }
    plen = tvb_get_ntohl(tvb, offset) ;

    if (ssh_desegment && pinfo->can_desegment) {
        if (plen +4 >  remain_length) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = plen+4 - remain_length;
            *need_desegmentation = true;
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
    padding_length = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_padding_length, tvb, offset, 1, padding_length);
    offset += 1;

    if (global_data->kex)
        key_ex_title = wmem_strdup_printf(wmem_packet_scope(), "%s (method:%s)", key_ex_title, global_data->kex);
    key_ex_tree = proto_tree_add_subtree(tree, tvb, offset, plen-1, ett_key_exchange, NULL, key_ex_title);

    /* msg_code */
    msg_code = tvb_get_uint8(tvb, offset);

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

                if(global_data->peer_data[is_response].seq_num_new_key == 0){
                    global_data->peer_data[is_response].seq_num_new_key = global_data->peer_data[is_response].sequence_number;
                    global_data->peer_data[is_response].sequence_number++;
                    ssh_debug_printf("%s->sequence_number{SSH_MSG_NEWKEYS=%d}++ > %d\n", is_response?"server":"client", global_data->peer_data[is_response].seq_num_new_key, global_data->peer_data[is_response].sequence_number);
                }

                // the client sent SSH_MSG_NEWKEYS
                if (!is_response) {
                    ssh_debug_printf("Activating new keys for CLIENT => SERVER\n");
                    ssh_decryption_setup_cipher(&global_data->peer_data[CLIENT_PEER_DATA], &global_data->new_keys[0], &global_data->new_keys[2]);
                    ssh_decryption_setup_mac(&global_data->peer_data[CLIENT_PEER_DATA], &global_data->new_keys[4]);
                }else{
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
    ti = proto_tree_add_uint(tree, hf_ssh_seq_num, tvb, offset, 0, seq_num);
    proto_item_set_generated(ti);

    return offset;
}

static int ssh_dissect_kex_dh(uint8_t msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, unsigned *seq_num)
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
        ssh_choose_enc_mac(global_data);
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

static int ssh_dissect_kex_dh_gex(uint8_t msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, unsigned *seq_num)
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
        // p (Group modulo)
        global_data->kex_gex_p = ssh_read_mpint(tvb, offset);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_gex_p);
        // g (Group generator)
        global_data->kex_gex_g = ssh_read_mpint(tvb, offset);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_gex_g);
        if(global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_grp == 0){
            global_data->peer_data[SERVER_PEER_DATA].sequence_number++;
            global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_grp = global_data->peer_data[SERVER_PEER_DATA].sequence_number;
            ssh_debug_printf("%s->sequence_number{SSH_MSG_KEX_DH_GEX_GROUP}++ > %d\n", SERVER_PEER_DATA?"serveur":"client", global_data->peer_data[SERVER_PEER_DATA].sequence_number);
        }
        *seq_num = global_data->peer_data[SERVER_PEER_DATA].seq_num_gex_grp;
        break;

    case SSH_MSG_KEX_DH_GEX_INIT:
        // e (Client public key)
        if (!ssh_read_e(tvb, offset, global_data)) {
            proto_tree_add_expert_format(tree, pinfo, &ei_ssh_invalid_keylen, tvb, offset, 2,
                "Invalid key length: %u", tvb_get_ntohl(tvb, offset));
        }
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
        if (!PINFO_FD_VISITED(pinfo)) {
            ssh_read_f(tvb, offset, global_data);
            // f (server ephemeral key public part), K_S (host key)
            ssh_choose_enc_mac(global_data);
            ssh_keylog_hash_write_secret(global_data);
        }
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

    case SSH_MSG_KEX_DH_GEX_REQUEST:{

        if (!PINFO_FD_VISITED(pinfo)) {
            ssh_hash_buffer_put_uint32(global_data->kex_gex_bits_min, tvb_get_ntohl(tvb, offset));
        }
        proto_tree_add_item(tree, hf_ssh_dh_gex_min, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        if (!PINFO_FD_VISITED(pinfo)) {
            ssh_hash_buffer_put_uint32(global_data->kex_gex_bits_req, tvb_get_ntohl(tvb, offset));
        }
        proto_tree_add_item(tree, hf_ssh_dh_gex_nbits, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        if (!PINFO_FD_VISITED(pinfo)) {
            ssh_hash_buffer_put_uint32(global_data->kex_gex_bits_max, tvb_get_ntohl(tvb, offset));
        }
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
    }

    return offset;
}

static int
ssh_dissect_kex_ecdh(uint8_t msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data, unsigned *seq_num)
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

        ssh_choose_enc_mac(global_data);
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

static ssh_message_info_t*
ssh_get_message(packet_info *pinfo, int record_id)
{
    ssh_packet_info_t *packet = (ssh_packet_info_t *)p_get_proto_data(
            wmem_file_scope(), pinfo, proto_ssh, 0);

    if (!packet) {
        return NULL;
    }

    ssh_message_info_t *message = NULL;
    for (message = packet->messages; message; message = message->next) {
        ws_debug("%u:looking for message %d now %d", pinfo->num, record_id, message->id);
        if (message->id == record_id) {
            return message;
        }
    }

    return NULL;
}

static int
ssh_try_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *tree)
{
    bool can_decrypt = peer_data->cipher != NULL;
    ssh_message_info_t *message = NULL;

    if (can_decrypt) {
        if (!PINFO_FD_VISITED(pinfo)) {
            ssh_decrypt_packet(tvb, pinfo, peer_data, offset);
        }

        int record_id = tvb_raw_offset(tvb) + offset;
        message = ssh_get_message(pinfo, record_id);

        if (message) {
            offset += ssh_dissect_decrypted_packet(tvb_new_subset_remaining(tvb, offset), pinfo, peer_data, tree, message);
            return offset;
        }
    }

    return ssh_dissect_encrypted_packet(tvb, pinfo, peer_data, offset, tree);
}

static int
ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data,
        int offset, proto_tree *tree)
{
    int len;
    unsigned plen;

    len = tvb_reported_length_remaining(tvb, offset);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Encrypted packet (len=%d)", len);

    if (tree) {
        int encrypted_len = len;

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
        int offset, proto_tree *tree, int is_response, unsigned * version,
        bool *need_desegmentation)
{
    unsigned   remain_length;
    int     linelen, protolen;

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
    /*linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, false);
     */
    linelen = tvb_find_guint8(tvb, offset, -1, '\n');

    if (ssh_desegment && pinfo->can_desegment) {
        if (linelen == -1 || remain_length < (unsigned)linelen-offset) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = linelen-remain_length;
            *need_desegmentation = true;
            return offset;
        }
    }
    if (linelen == -1) {
        /* XXX - reassemble across segment boundaries? */
        linelen = remain_length;
        protolen = linelen;
    } else {
        linelen = linelen - offset + 1;

        if (linelen > 1 && tvb_get_uint8(tvb, offset + linelen - 2) == '\r')
            protolen = linelen - 2;
        else
            protolen = linelen - 1;
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Protocol (%s)",
            tvb_format_text(pinfo->pool, tvb, offset, protolen));

    // V_C / V_S (client and server identification strings) RFC4253 4.2
    // format: SSH-protoversion-softwareversion SP comments [CR LF not incl.]
    if (!PINFO_FD_VISITED(pinfo)) {
        char *data = (char *)tvb_memdup(wmem_packet_scope(), tvb, offset, protolen);
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
    uint32_t size = 0;
    char *mac_name = peer_data->mac;
    char *strip;

    if (!mac_name)
        return;

    /* wmem_strdup() never returns NULL */
    mac_name = wmem_strdup(NULL, (const char *)mac_name);

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
    else if (strcmp(kex_name, "diffie-hellman-group14-sha256") == 0 ||
        strcmp(kex_name, "diffie-hellman-group16-sha512") == 0 ||
        strcmp(kex_name, "diffie-hellman-group18-sha512") == 0 ||
        strcmp(kex_name, "diffie-hellman-group1-sha1") == 0 ||
        strcmp(kex_name, "diffie-hellman-group14-sha1") == 0)
    {
        global_data->kex_specific_dissector = ssh_dissect_kex_dh;
    }
}

static int
ssh_gslist_compare_strings(const void *a, const void *b)
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
ssh_choose_algo(char *client, char *server, char **result)
{
    char **server_strings = NULL;
    char **client_strings = NULL;
    char **step;
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
            *result = wmem_strdup(wmem_file_scope(), (const char *)agreed->data);
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
    char   *hassh;

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
        char *data = (char *)wmem_alloc(wmem_packet_scope(), payload_length + 1);
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
    uint32_t len = tvb_get_ntohl(tvb, offset);
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
        g_hash_table_remove_all(ssh_master_key_map);
    }

    if (!ssh_keylog_file) {
        ssh_keylog_file = ws_fopen(pref_keylog_file, "r");
        if (!ssh_keylog_file) {
            ws_debug("ssh: failed to open key log file %s: %s",
                    pref_keylog_file, g_strerror(errno));
            return;
        }
    }

    /* File format: each line follows the format "<cookie> <type> <key>".
     * <cookie> is the hex-encoded (client or server) 16 bytes cookie
     * (32 characters) found in the SSH_MSG_KEXINIT of the endpoint whose
     * private random is disclosed.
     * <type> is either SHARED_SECRET or PRIVATE_KEY depending on the
     * type of key provided. PRIVAT_KEY is only supported for DH,
     * DH group exchange, and ECDH (including Curve25519) key exchanges.
     * <key> is the private random number that is used to generate the DH
     * negotiation (length depends on algorithm). In RFC4253 it is called
     * x for the client and y for the server.
     * For openssh and DH group exchange, it can be retrieved using
     * DH_get0_key(kex->dh, NULL, &server_random)
     * for groupN in file kexdh.c function kex_dh_compute_key
     * for custom group in file kexgexs.c function input_kex_dh_gex_init
     * For openssh and curve25519, it can be found in function kex_c25519_enc
     * in variable server_key. One may also provide the shared secret
     * directly if <type> is set to SHARED_SECRET.
     *
     * Example:
     *  90d886612f9c35903db5bb30d11f23c2 PRIVATE_KEY DEF830C22F6C927E31972FFB20B46C96D0A5F2D5E7BE5A3A8804D6BFC431619ED10AF589EEDFF4750DEA00EFD7AFDB814B6F3528729692B1F2482041521AE9DC
     */
    for (;;) {
        char buf[512];
        buf[0] = 0;

        if (!fgets(buf, sizeof(buf), ssh_keylog_file)) {
            if (ferror(ssh_keylog_file)) {
                ws_debug("Error while reading %s, closing it.", pref_keylog_file);
                ssh_keylog_reset();
                g_hash_table_remove_all(ssh_master_key_map);
            }
            break;
        }

        size_t len = strlen(buf);
        while(len>0 && (buf[len-1]=='\r' || buf[len-1]=='\n')){len-=1;buf[len]=0;}

        ssh_keylog_process_line(buf);
    }
}

static void
ssh_keylog_process_lines(const uint8_t *data, unsigned datalen)
{
    const char *next_line = (const char *)data;
    const char *line_end = next_line + datalen;
    while (next_line && next_line < line_end) {
        const char *line = next_line;
        next_line = (const char *)memchr(line, '\n', line_end - line);
        ssize_t linelen;

        if (next_line) {
            linelen = next_line - line;
            next_line++;    /* drop LF */
        } else {
            linelen = (ssize_t)(line_end - line);
        }
        if (linelen > 0 && line[linelen - 1] == '\r') {
            linelen--;      /* drop CR */
        }

        ssh_debug_printf("  checking keylog line: %.*s\n", (int)linelen, line);

        char * strippedline = g_strndup(line, linelen);
        ssh_keylog_process_line(strippedline);
        g_free(strippedline);
    }
}

static void
ssh_keylog_process_line(const char *line)
{
    ws_noisy("ssh: process line: %s", line);

    char **split = g_strsplit(line, " ", 3);
    char *cookie, *type, *key;
    size_t cookie_len, key_len;

    if (g_strv_length(split) == 3) {
        // New format: [hex-encoded cookie] [key type] [hex-encoded key material]
        cookie = split[0];
        type = split[1];
        key = split[2];
    } else if (g_strv_length(split) == 2) {
        // Old format: [hex-encoded cookie] [hex-encoded private key]
        ws_debug("ssh keylog: detected old keylog format without explicit key type");
        type = "PRIVATE_KEY";
        cookie = split[0];
        key = split[1];
    } else {
        ws_debug("ssh keylog: invalid format");
        g_strfreev(split);
        return;
    }

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
    ssh_bignum * bn_cookie = ssh_kex_make_bignum(NULL, (unsigned)(cookie_len/2));
    ssh_bignum * bn_priv   = ssh_kex_make_bignum(NULL, (unsigned)(key_len/2));
    uint8_t c;
    for (size_t i = 0; i < key_len/2; i ++) {
        char v0 = key[i * 2];
        int8_t h0 = (v0>='0' && v0<='9')?v0-'0':(v0>='a' && v0<='f')?v0-'a'+10:(v0>='A' && v0<='F')?v0-'A'+10:-1;
        char v1 = key[i * 2 + 1];
        int8_t h1 = (v1>='0' && v1<='9')?v1-'0':(v1>='a' && v1<='f')?v1-'a'+10:(v1>='A' && v1<='F')?v1-'A'+10:-1;

        if (h0==-1 || h1==-1) {
            ws_debug("ssh: can't process key, invalid hex number: %c%c", v0, v1);
            g_strfreev(split);
            return;
        }

        c = (h0 << 4) | h1;

        bn_priv->data[i] = c;
    }
    for (size_t i = 0; i < cookie_len/2; i ++) {
        char v0 = cookie[i * 2];
        int8_t h0 = (v0>='0' && v0<='9')?v0-'0':(v0>='a' && v0<='f')?v0-'a'+10:(v0>='A' && v0<='F')?v0-'A'+10:-1;
        char v1 = cookie[i * 2 + 1];
        int8_t h1 = (v1>='0' && v1<='9')?v1-'0':(v1>='a' && v1<='f')?v1-'a'+10:(v1>='A' && v1<='F')?v1-'A'+10:-1;

        if (h0==-1 || h1==-1) {
            ws_debug("ssh: can't process cookie, invalid hex number: %c%c", v0, v1);
            g_strfreev(split);
            return;
        }

        c = (h0 << 4) | h1;

        bn_cookie->data[i] = c;
    }
    ssh_bignum * bn_priv_ht = g_new(ssh_bignum, 1);
    bn_priv_ht->length = bn_priv->length;
    bn_priv_ht->data = (uint8_t *) g_memdup2(bn_priv->data, bn_priv->length);
    ssh_bignum * bn_cookie_ht = g_new(ssh_bignum, 1);
    bn_cookie_ht->length = bn_cookie->length;
    bn_cookie_ht->data = (uint8_t *) g_memdup2(bn_cookie->data, bn_cookie->length);

    char * type_ht = (char *) g_memdup2(type, strlen(type) + 1);
    ssh_key_map_entry_t * entry_ht = g_new(ssh_key_map_entry_t, 1);
    entry_ht->type = type_ht;
    entry_ht->key_material = bn_priv_ht;
    g_hash_table_insert(ssh_master_key_map, bn_cookie_ht, entry_ht);
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

static unsigned
ssh_kex_type(char *type)
{
    if (type) {
        if (g_str_has_prefix(type, "curve25519")) {
            return SSH_KEX_CURVE25519;
        }else if (g_str_has_prefix(type, "diffie-hellman-group-exchange")) {
            return SSH_KEX_DH_GEX;
        }else if (g_str_has_prefix(type, "diffie-hellman-group14")) {
            return SSH_KEX_DH_GROUP14;
        }else if (g_str_has_prefix(type, "diffie-hellman-group16")) {
            return SSH_KEX_DH_GROUP16;
        }else if (g_str_has_prefix(type, "diffie-hellman-group18")) {
            return SSH_KEX_DH_GROUP18;
        }else if (g_str_has_prefix(type, "diffie-hellman-group1")) {
            return SSH_KEX_DH_GROUP1;
        }
    }

    return 0;
}

static unsigned
ssh_kex_hash_type(char *type_string)
{
    if (type_string && g_str_has_suffix(type_string, "sha1")) {
        return SSH_KEX_HASH_SHA1;
    }else if (type_string && g_str_has_suffix(type_string, "sha256")) {
        return SSH_KEX_HASH_SHA256;
    }else if (type_string && g_str_has_suffix(type_string, "sha256@libssh.org")) {
        return SSH_KEX_HASH_SHA256;
    }else if (type_string && g_str_has_suffix(type_string, "sha512")) {
        return SSH_KEX_HASH_SHA512;
    } else {
        ws_debug("hash type %s not supported", type_string);
        return 0;
    }
}

static ssh_bignum *
ssh_kex_make_bignum(const uint8_t *data, unsigned length)
{
    // 512 bytes (4096 bits) is the maximum bignum size we're supporting
    // Actually we need 513 bytes, to make provision for signed values
    // Diffie-Hellman group 18 has 8192 bits
    if (length == 0 || length > 1025) {
        return NULL;
    }

    ssh_bignum *bn = wmem_new0(wmem_file_scope(), ssh_bignum);
    bn->data = (uint8_t *)wmem_alloc0(wmem_file_scope(), length);

    if (data) {
        memcpy(bn->data, data, length);
    }

    bn->length = length;
    return bn;
}

static bool
ssh_read_e(tvbuff_t *tvb, int offset, struct ssh_flow_data *global_data)
{
    // store the client's public part (e) for later usage
    uint32_t length = tvb_get_ntohl(tvb, offset);
    global_data->kex_e = ssh_kex_make_bignum(NULL, length);
    if (!global_data->kex_e) {
        return false;
    }
    tvb_memcpy(tvb, global_data->kex_e->data, offset + 4, length);
    return true;
}

static bool
ssh_read_f(tvbuff_t *tvb, int offset, struct ssh_flow_data *global_data)
{
    // store the server's public part (f) for later usage
    uint32_t length = tvb_get_ntohl(tvb, offset);
    global_data->kex_f = ssh_kex_make_bignum(NULL, length);
    if (!global_data->kex_f) {
        return false;
    }
    tvb_memcpy(tvb, global_data->kex_f->data, offset + 4, length);
    return true;
}

static ssh_bignum *
ssh_read_mpint(tvbuff_t *tvb, int offset)
{
    // store the DH group modulo (p) for later usage
    int length = tvb_get_ntohl(tvb, offset);
    ssh_bignum * bn = ssh_kex_make_bignum(NULL, length);
    if (!bn) {
        ws_debug("invalid bignum length %u", length);
        return NULL;
    }
    tvb_memcpy(tvb, bn->data, offset + 4, length);
    return bn;
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
    ssh_key_map_entry_t *entry;
    ssh_bignum *secret = NULL;
    int length;
    bool client_cookie = false;

    ssh_keylog_read_file();

    unsigned kex_type = ssh_kex_type(global_data->kex);
    unsigned kex_hash_type = ssh_kex_hash_type(global_data->kex);

    entry = (ssh_key_map_entry_t *)g_hash_table_lookup(ssh_master_key_map, global_data->peer_data[SERVER_PEER_DATA].bn_cookie);
    if (!entry) {
        entry = (ssh_key_map_entry_t *)g_hash_table_lookup(ssh_master_key_map, global_data->peer_data[CLIENT_PEER_DATA].bn_cookie);
        client_cookie = true;
    }
    if (!entry) {
        ws_debug("ssh decryption: no entry in keylog file for this session");
        global_data->do_decrypt = false;
        return;
    }

    if (!strcmp(entry->type, "PRIVATE_KEY")) {
        if (client_cookie) {
            secret = ssh_kex_shared_secret(kex_type, global_data->kex_f, entry->key_material, global_data->kex_gex_p);
        } else {
            secret = ssh_kex_shared_secret(kex_type, global_data->kex_e, entry->key_material, global_data->kex_gex_p);
        }
    } else if (!strcmp(entry->type, "SHARED_SECRET")) {
        secret = ssh_kex_make_bignum(entry->key_material->data, entry->key_material->length);
    } else {
        ws_debug("ssh decryption: unknown key type in keylog file");
        global_data->do_decrypt = false;
        return;
    }

    if (!secret) {
        ws_debug("ssh decryption: no key material for this session");
        global_data->do_decrypt = false;
        return;
    }

    // shared secret data needs to be written as an mpint, and we need it later
    if (secret->data[0] & 0x80) {         // Stored in Big endian
        length = secret->length + 1;
        char *tmp = (char *)wmem_alloc0(wmem_packet_scope(), length);
        memcpy(tmp + 1, secret->data, secret->length);
        tmp[0] = 0;
        secret->data = tmp;
        secret->length = length;
    }
    ssh_hash_buffer_put_string(global_data->kex_shared_secret, secret->data, secret->length);

    wmem_array_t    * kex_gex_p = wmem_array_new(wmem_packet_scope(), 1);
    if(global_data->kex_gex_p){ssh_hash_buffer_put_string(kex_gex_p, global_data->kex_gex_p->data, global_data->kex_gex_p->length);}
    wmem_array_t    * kex_gex_g = wmem_array_new(wmem_packet_scope(), 1);
    if(global_data->kex_gex_g){ssh_hash_buffer_put_string(kex_gex_g, global_data->kex_gex_g->data, global_data->kex_gex_g->length);}
    wmem_array_t    * kex_e = wmem_array_new(wmem_packet_scope(), 1);
    if(global_data->kex_e){ssh_hash_buffer_put_string(kex_e, global_data->kex_e->data, global_data->kex_e->length);}
    wmem_array_t    * kex_f = wmem_array_new(wmem_packet_scope(), 1);
    if(global_data->kex_f){ssh_hash_buffer_put_string(kex_f, global_data->kex_f->data, global_data->kex_f->length);}

    wmem_array_t    * kex_hash_buffer = wmem_array_new(wmem_packet_scope(), 1);
    ssh_print_data("client_version", (const unsigned char *)wmem_array_get_raw(global_data->kex_client_version), wmem_array_get_count(global_data->kex_client_version));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_client_version), wmem_array_get_count(global_data->kex_client_version));
    ssh_print_data("server_version", (const unsigned char *)wmem_array_get_raw(global_data->kex_server_version), wmem_array_get_count(global_data->kex_server_version));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_server_version), wmem_array_get_count(global_data->kex_server_version));
    ssh_print_data("client_key_exchange_init", (const unsigned char *)wmem_array_get_raw(global_data->kex_client_key_exchange_init), wmem_array_get_count(global_data->kex_client_key_exchange_init));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_client_key_exchange_init), wmem_array_get_count(global_data->kex_client_key_exchange_init));
    ssh_print_data("server_key_exchange_init", (const unsigned char *)wmem_array_get_raw(global_data->kex_server_key_exchange_init), wmem_array_get_count(global_data->kex_server_key_exchange_init));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_server_key_exchange_init), wmem_array_get_count(global_data->kex_server_key_exchange_init));
    ssh_print_data("kex_server_host_key_blob", (const unsigned char *)wmem_array_get_raw(global_data->kex_server_host_key_blob), wmem_array_get_count(global_data->kex_server_host_key_blob));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_server_host_key_blob), wmem_array_get_count(global_data->kex_server_host_key_blob));
    if(kex_type==SSH_KEX_DH_GEX){
        ssh_print_data("kex_gex_bits_min", (const unsigned char *)wmem_array_get_raw(global_data->kex_gex_bits_min), wmem_array_get_count(global_data->kex_gex_bits_min));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_gex_bits_min), wmem_array_get_count(global_data->kex_gex_bits_min));
        ssh_print_data("kex_gex_bits_req", (const unsigned char *)wmem_array_get_raw(global_data->kex_gex_bits_req), wmem_array_get_count(global_data->kex_gex_bits_req));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_gex_bits_req), wmem_array_get_count(global_data->kex_gex_bits_req));
        ssh_print_data("kex_gex_bits_max", (const unsigned char *)wmem_array_get_raw(global_data->kex_gex_bits_max), wmem_array_get_count(global_data->kex_gex_bits_max));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_gex_bits_max), wmem_array_get_count(global_data->kex_gex_bits_max));
        ssh_print_data("key modulo  (p)", (const unsigned char *)wmem_array_get_raw(kex_gex_p), wmem_array_get_count(kex_gex_p));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_gex_p), wmem_array_get_count(kex_gex_p));
        ssh_print_data("key base    (g)", (const unsigned char *)wmem_array_get_raw(kex_gex_g), wmem_array_get_count(kex_gex_g));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_gex_g), wmem_array_get_count(kex_gex_g));
        ssh_print_data("key client  (e)", (const unsigned char *)wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        ssh_print_data("key server  (f)", (const unsigned char *)wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
    }
    if(kex_type==SSH_KEX_DH_GROUP1 || kex_type==SSH_KEX_DH_GROUP14 || kex_type==SSH_KEX_DH_GROUP16 || kex_type==SSH_KEX_DH_GROUP18){
        ssh_print_data("key client  (e)", (const unsigned char *)wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        ssh_print_data("key server (f)", (const unsigned char *)wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
    }
    if(kex_type==SSH_KEX_CURVE25519){
        ssh_print_data("key client  (Q_C)", (const unsigned char *)wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        ssh_print_data("key server (Q_S)", (const unsigned char *)wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
    }
    ssh_print_data("shared secret", (const unsigned char *)wmem_array_get_raw(global_data->kex_shared_secret), wmem_array_get_count(global_data->kex_shared_secret));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_shared_secret), wmem_array_get_count(global_data->kex_shared_secret));

    ssh_print_data("exchange", (const unsigned char *)wmem_array_get_raw(kex_hash_buffer), wmem_array_get_count(kex_hash_buffer));

    unsigned hash_len = 32;
    if(kex_hash_type==SSH_KEX_HASH_SHA1) {
        gcry_md_open(&hd, GCRY_MD_SHA1, 0);
        hash_len = 20;
    } else if(kex_hash_type==SSH_KEX_HASH_SHA256) {
        gcry_md_open(&hd, GCRY_MD_SHA256, 0);
        hash_len = 32;
    } else if(kex_hash_type==SSH_KEX_HASH_SHA512) {
        gcry_md_open(&hd, GCRY_MD_SHA512, 0);
        hash_len = 64;
    } else {
        ws_debug("kex_hash_type type %d not supported", kex_hash_type);
        return;
    }
    char *exchange_hash = (char *)wmem_alloc0(wmem_file_scope(), hash_len);
    gcry_md_write(hd, wmem_array_get_raw(kex_hash_buffer), wmem_array_get_count(kex_hash_buffer));
    memcpy(exchange_hash, gcry_md_read(hd, 0), hash_len);
    gcry_md_close(hd);
    ssh_print_data("hash", exchange_hash, hash_len);
    global_data->secret = secret;
    ssh_derive_symmetric_keys(secret, exchange_hash, hash_len, global_data);
}

// the purpose of this function is to deal with all different kex methods
static ssh_bignum *
ssh_kex_shared_secret(int kex_type, ssh_bignum *pub, ssh_bignum *priv, ssh_bignum *modulo)
{
    DISSECTOR_ASSERT(pub != NULL);
    DISSECTOR_ASSERT(priv != NULL);

    ssh_bignum *secret = ssh_kex_make_bignum(NULL, pub->length);
    if (!secret) {
        ws_debug("invalid key length %u", pub->length);
        return NULL;
    }

    if(kex_type==SSH_KEX_DH_GEX){
        gcry_mpi_t b = NULL;
        gcry_mpi_scan(&b, GCRYMPI_FMT_USG, pub->data, pub->length, NULL);
        gcry_mpi_t d = NULL, e = NULL, m = NULL;
        size_t result_len = 0;
        d = gcry_mpi_new(pub->length*8);
        gcry_mpi_scan(&e, GCRYMPI_FMT_USG, priv->data, priv->length, NULL);
        gcry_mpi_scan(&m, GCRYMPI_FMT_USG, modulo->data, modulo->length, NULL);
        gcry_mpi_powm(d, b, e, m);                 // gcry_mpi_powm(d, b, e, m)    => d = b^e % m
        gcry_mpi_print(GCRYMPI_FMT_USG, secret->data, secret->length, &result_len, d);
        secret->length = (unsigned)result_len;        // Should not be larger than what fits in a 32-bit unsigned integer...
        gcry_mpi_release(d);
        gcry_mpi_release(b);
        gcry_mpi_release(e);
        gcry_mpi_release(m);

    }else if(kex_type==SSH_KEX_DH_GROUP1 || kex_type==SSH_KEX_DH_GROUP14 || kex_type==SSH_KEX_DH_GROUP16 || kex_type==SSH_KEX_DH_GROUP18){
        gcry_mpi_t m = NULL;
        if(kex_type==SSH_KEX_DH_GROUP1){
            static const uint8_t p[] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
                    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
                    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
                    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
                    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
                    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
                    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
                    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,};
            gcry_mpi_scan(&m, GCRYMPI_FMT_USG, p, sizeof(p), NULL);
        }else if(kex_type==SSH_KEX_DH_GROUP14){
//p:FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            static const uint8_t p[] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
                    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
                    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
                    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
                    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
                    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
                    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
                    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
                    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
                    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
                    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
                    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
                    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
                    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
                    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
                    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            gcry_mpi_scan(&m, GCRYMPI_FMT_USG, p, sizeof(p), NULL);
        }else if(kex_type==SSH_KEX_DH_GROUP16){
//p:FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
            static const uint8_t p[] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
                    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
                    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
                    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
                    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
                    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
                    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
                    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
                    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
                    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
                    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
                    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
                    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
                    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
                    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
                    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
                    0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
                    0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
                    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
                    0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
                    0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
                    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
                    0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
                    0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
                    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
                    0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA, 0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8,
                    0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
                    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2,
                    0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED, 0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF,
                    0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
                    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F,
                    0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,};
            gcry_mpi_scan(&m, GCRYMPI_FMT_USG, p, sizeof(p), NULL);
        }else if(kex_type==SSH_KEX_DH_GROUP18){
//p:FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
            static const uint8_t p[] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
                    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
                    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
                    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
                    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
                    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
                    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
                    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
                    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
                    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
                    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
                    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
                    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
                    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
                    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
                    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
                    0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
                    0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
                    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
                    0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
                    0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
                    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
                    0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
                    0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
                    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
                    0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA, 0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8,
                    0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
                    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2,
                    0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED, 0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF,
                    0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
                    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F,
                    0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92, 0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26,
                    0xC1, 0xD4, 0xDC, 0xB2, 0x60, 0x26, 0x46, 0xDE, 0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD,
                    0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E, 0xE5, 0xDB, 0x38, 0x2F, 0x41, 0x30, 0x01, 0xAE,
                    0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31, 0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18,
                    0xDA, 0x3E, 0xDB, 0xEB, 0xCF, 0x9B, 0x14, 0xED, 0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B,
                    0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B, 0x33, 0x20, 0x51, 0x51, 0x2B, 0xD7, 0xAF, 0x42,
                    0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF, 0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC,
                    0xF0, 0x32, 0xEA, 0x15, 0xD1, 0x72, 0x1D, 0x03, 0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6,
                    0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82, 0xB5, 0xA8, 0x40, 0x31, 0x90, 0x0B, 0x1C, 0x9E,
                    0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3, 0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE,
                    0x0F, 0x1D, 0x45, 0xB7, 0xFF, 0x58, 0x5A, 0xC5, 0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA,
                    0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8, 0x14, 0xCC, 0x5E, 0xD2, 0x0F, 0x80, 0x37, 0xE0,
                    0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28, 0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76,
                    0xF5, 0x50, 0xAA, 0x3D, 0x8A, 0x1F, 0xBF, 0xF0, 0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C,
                    0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32, 0x38, 0x7F, 0xE8, 0xD7, 0x6E, 0x3C, 0x04, 0x68,
                    0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE, 0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6,
                    0xE6, 0x94, 0xF9, 0x1E, 0x6D, 0xBE, 0x11, 0x59, 0x74, 0xA3, 0x92, 0x6F, 0x12, 0xFE, 0xE5, 0xE4,
                    0x38, 0x77, 0x7C, 0xB6, 0xA9, 0x32, 0xDF, 0x8C, 0xD8, 0xBE, 0xC4, 0xD0, 0x73, 0xB9, 0x31, 0xBA,
                    0x3B, 0xC8, 0x32, 0xB6, 0x8D, 0x9D, 0xD3, 0x00, 0x74, 0x1F, 0xA7, 0xBF, 0x8A, 0xFC, 0x47, 0xED,
                    0x25, 0x76, 0xF6, 0x93, 0x6B, 0xA4, 0x24, 0x66, 0x3A, 0xAB, 0x63, 0x9C, 0x5A, 0xE4, 0xF5, 0x68,
                    0x34, 0x23, 0xB4, 0x74, 0x2B, 0xF1, 0xC9, 0x78, 0x23, 0x8F, 0x16, 0xCB, 0xE3, 0x9D, 0x65, 0x2D,
                    0xE3, 0xFD, 0xB8, 0xBE, 0xFC, 0x84, 0x8A, 0xD9, 0x22, 0x22, 0x2E, 0x04, 0xA4, 0x03, 0x7C, 0x07,
                    0x13, 0xEB, 0x57, 0xA8, 0x1A, 0x23, 0xF0, 0xC7, 0x34, 0x73, 0xFC, 0x64, 0x6C, 0xEA, 0x30, 0x6B,
                    0x4B, 0xCB, 0xC8, 0x86, 0x2F, 0x83, 0x85, 0xDD, 0xFA, 0x9D, 0x4B, 0x7F, 0xA2, 0xC0, 0x87, 0xE8,
                    0x79, 0x68, 0x33, 0x03, 0xED, 0x5B, 0xDD, 0x3A, 0x06, 0x2B, 0x3C, 0xF5, 0xB3, 0xA2, 0x78, 0xA6,
                    0x6D, 0x2A, 0x13, 0xF8, 0x3F, 0x44, 0xF8, 0x2D, 0xDF, 0x31, 0x0E, 0xE0, 0x74, 0xAB, 0x6A, 0x36,
                    0x45, 0x97, 0xE8, 0x99, 0xA0, 0x25, 0x5D, 0xC1, 0x64, 0xF3, 0x1C, 0xC5, 0x08, 0x46, 0x85, 0x1D,
                    0xF9, 0xAB, 0x48, 0x19, 0x5D, 0xED, 0x7E, 0xA1, 0xB1, 0xD5, 0x10, 0xBD, 0x7E, 0xE7, 0x4D, 0x73,
                    0xFA, 0xF3, 0x6B, 0xC3, 0x1E, 0xCF, 0xA2, 0x68, 0x35, 0x90, 0x46, 0xF4, 0xEB, 0x87, 0x9F, 0x92,
                    0x40, 0x09, 0x43, 0x8B, 0x48, 0x1C, 0x6C, 0xD7, 0x88, 0x9A, 0x00, 0x2E, 0xD5, 0xEE, 0x38, 0x2B,
                    0xC9, 0x19, 0x0D, 0xA6, 0xFC, 0x02, 0x6E, 0x47, 0x95, 0x58, 0xE4, 0x47, 0x56, 0x77, 0xE9, 0xAA,
                    0x9E, 0x30, 0x50, 0xE2, 0x76, 0x56, 0x94, 0xDF, 0xC8, 0x1F, 0x56, 0xE8, 0x80, 0xB9, 0x6E, 0x71,
                    0x60, 0xC9, 0x80, 0xDD, 0x98, 0xED, 0xD3, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,};
            gcry_mpi_scan(&m, GCRYMPI_FMT_USG, p, sizeof(p), NULL);
        }

        gcry_mpi_t b = NULL;
        gcry_mpi_scan(&b, GCRYMPI_FMT_USG, pub->data, pub->length, NULL);
        gcry_mpi_t d = NULL, e = NULL;
        size_t result_len = 0;
        d = gcry_mpi_new(pub->length*8);
        gcry_mpi_scan(&e, GCRYMPI_FMT_USG, priv->data, priv->length, NULL);
        gcry_mpi_powm(d, b, e, m);                 // gcry_mpi_powm(d, b, e, m)    => d = b^e % m
        gcry_mpi_print(GCRYMPI_FMT_USG, secret->data, secret->length, &result_len, d);
        secret->length = (unsigned)result_len;        // Should not be larger than what fits in a 32-bit unsigned integer...
        gcry_mpi_release(d);
        gcry_mpi_release(b);
        gcry_mpi_release(e);
        gcry_mpi_release(m);
    }else if(kex_type==SSH_KEX_CURVE25519){
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

static char *
ssh_string(const char *string, unsigned length)
{
    char *ssh_string = (char *)wmem_alloc(wmem_packet_scope(), length + 4);
    ssh_string[0] = (length >> 24) & 0xff;
    ssh_string[1] = (length >> 16) & 0xff;
    ssh_string[2] = (length >> 8) & 0xff;
    ssh_string[3] = length & 0xff;
    memcpy(ssh_string + 4, string, length);
    return ssh_string;
}

static void
ssh_hash_buffer_put_string(wmem_array_t *buffer, const char *string,
        unsigned length)
{
    if (!buffer) {
        return;
    }

    char *string_with_length = ssh_string(string, length);
    wmem_array_append(buffer, string_with_length, length + 4);
}

static void
ssh_hash_buffer_put_uint32(wmem_array_t *buffer, unsigned val)
{
    if (!buffer) {
        return;
    }

    char buf[4];
    buf[0] = (val >> 24); buf[1] = (val >> 16); buf[2] = (val >>  8); buf[3] = (val >>  0);
    wmem_array_append(buffer, buf, 4);
}

static void ssh_derive_symmetric_keys(ssh_bignum *secret, char *exchange_hash,
        unsigned hash_length, struct ssh_flow_data *global_data)
{
    if (!global_data->session_id) {
        global_data->session_id = exchange_hash;
        global_data->session_id_length = hash_length;
    }

    unsigned int we_need = 0;
    for(int peer_cnt=0;peer_cnt<2;peer_cnt++){
        struct ssh_peer_data * peer_data = &global_data->peer_data[peer_cnt];
        // required size of key depends on cipher used. chacha20 wants 64 bytes
        unsigned need = 0;
        if (GCRY_CIPHER_CHACHA20 == peer_data->cipher_id) {
            need = 64;
        } else if (CIPHER_AES128_CBC == peer_data->cipher_id || CIPHER_AES128_CTR == peer_data->cipher_id || CIPHER_AES128_GCM == peer_data->cipher_id) {
            need = 16;
        } else if (CIPHER_AES192_CBC == peer_data->cipher_id || CIPHER_AES192_CTR == peer_data->cipher_id) {
            need = 24;
        } else if (CIPHER_AES256_CBC == peer_data->cipher_id || CIPHER_AES256_CTR == peer_data->cipher_id || CIPHER_AES256_GCM == peer_data->cipher_id) {
            need = 32;
        } else {
            ssh_debug_printf("ssh: cipher (%d) is unknown or not set\n", peer_data->cipher_id);
            ssh_debug_flush();
        }
        if(peer_data->mac_id == CIPHER_MAC_SHA2_256){
            need = 32;
        }else{
            ssh_debug_printf("ssh: MAC (%d) is unknown or not set\n", peer_data->mac_id);
            ssh_debug_flush();
        }
        if (we_need<need) {
            we_need = need;
        }
    }

    for (int i = 0; i < 6; i ++) {
        ssh_derive_symmetric_key(secret, exchange_hash, hash_length,
                'A' + i, &global_data->new_keys[i], global_data, we_need);
        if(i==0){       ssh_print_data("Initial IV client to server", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }else if(i==1){ ssh_print_data("Initial IV server to client", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }else if(i==2){ ssh_print_data("Encryption key client to server", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }else if(i==3){ ssh_print_data("Encryption key server to client", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }else if(i==4){ ssh_print_data("Integrity key client to server", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }else if(i==5){ ssh_print_data("Integrity key server to client", global_data->new_keys[i].data, global_data->new_keys[i].length);
        }
    }
}

static void ssh_derive_symmetric_key(ssh_bignum *secret, char *exchange_hash,
        unsigned hash_length, char id, ssh_bignum *result_key,
        struct ssh_flow_data *global_data, unsigned we_need)
{
    gcry_md_hd_t hd;

    unsigned kex_hash_type = ssh_kex_hash_type(global_data->kex);
    int algo = GCRY_MD_SHA256;
    if(kex_hash_type==SSH_KEX_HASH_SHA1){
        algo = GCRY_MD_SHA1;
    }else if(kex_hash_type==SSH_KEX_HASH_SHA256){
        algo = GCRY_MD_SHA256;
    }else if(kex_hash_type==SSH_KEX_HASH_SHA512){
        algo = GCRY_MD_SHA512;
    }
    unsigned len = gcry_md_get_algo_dlen(algo);

    result_key->data = (unsigned char *)wmem_alloc(wmem_file_scope(), we_need);

    char *secret_with_length = ssh_string(secret->data, secret->length);

    if (gcry_md_open(&hd, algo, 0) == 0) {
        gcry_md_write(hd, secret_with_length, secret->length + 4);
        gcry_md_write(hd, exchange_hash, hash_length);
        gcry_md_putc(hd, id);
        gcry_md_write(hd, global_data->session_id, hash_length);
        unsigned add_length = MIN(len, we_need);
        memcpy(result_key->data, gcry_md_read(hd, 0), add_length);
        gcry_md_close(hd);
    }

    // expand key
    for (unsigned have = len; have < we_need; have += len) {
        if (gcry_md_open(&hd, algo, 0) == 0) {
            gcry_md_write(hd, secret_with_length, secret->length + 4);
            gcry_md_write(hd, exchange_hash, hash_length);
            gcry_md_write(hd, result_key->data+have-len, len);
            unsigned add_length = MIN(len, we_need - have);
            memcpy(result_key->data+have, gcry_md_read(hd, 0), add_length);
            gcry_md_close(hd);
        }
    }

    result_key->length = we_need;
}

static void
ssh_choose_enc_mac(struct ssh_flow_data *global_data)
{
    for(int peer_cnt=0;peer_cnt<2;peer_cnt++){
        struct ssh_peer_data * peer_data = &global_data->peer_data[peer_cnt];
        ssh_choose_algo(global_data->peer_data[CLIENT_PEER_DATA].enc_proposals[peer_cnt],
                        global_data->peer_data[SERVER_PEER_DATA].enc_proposals[peer_cnt],
                        &peer_data->enc);
        /* some ciphers have their own MAC so the "negotiated" one is meaningless */
        if(peer_data->enc && (0 == strcmp(peer_data->enc, "aes128-gcm@openssh.com") ||
                              0 == strcmp(peer_data->enc, "aes256-gcm@openssh.com"))) {
            peer_data->mac = wmem_strdup(wmem_file_scope(), (const char *)"<implicit>");
            peer_data->mac_length = 16;
            peer_data->length_is_plaintext = 1;
        }
        else if(peer_data->enc && 0 == strcmp(peer_data->enc, "chacha20-poly1305@openssh.com")) {
            peer_data->mac = wmem_strdup(wmem_file_scope(), (const char *)"<implicit>");
            peer_data->mac_length = 16;
        }
        else {
            ssh_choose_algo(global_data->peer_data[CLIENT_PEER_DATA].mac_proposals[peer_cnt],
                            global_data->peer_data[SERVER_PEER_DATA].mac_proposals[peer_cnt],
                            &peer_data->mac);
            ssh_set_mac_length(peer_data);
        }
        ssh_choose_algo(global_data->peer_data[CLIENT_PEER_DATA].comp_proposals[peer_cnt],
                        global_data->peer_data[SERVER_PEER_DATA].comp_proposals[peer_cnt],
                        &peer_data->comp);
    }

    ssh_decryption_set_cipher_id(&global_data->peer_data[CLIENT_PEER_DATA]);
    ssh_decryption_set_mac_id(&global_data->peer_data[CLIENT_PEER_DATA]);
    ssh_decryption_set_cipher_id(&global_data->peer_data[SERVER_PEER_DATA]);
    ssh_decryption_set_mac_id(&global_data->peer_data[SERVER_PEER_DATA]);
}

static void
ssh_decryption_set_cipher_id(struct ssh_peer_data *peer)
{
    char *cipher_name = peer->enc;

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
    } else if (0 == strcmp(cipher_name, "aes128-ctr")) {
        peer->cipher_id = CIPHER_AES128_CTR;
    } else if (0 == strcmp(cipher_name, "aes192-ctr")) {
        peer->cipher_id = CIPHER_AES192_CTR;
    } else if (0 == strcmp(cipher_name, "aes256-ctr")) {
        peer->cipher_id = CIPHER_AES256_CTR;
    } else {
        peer->cipher = NULL;
        ws_debug("decryption not supported: %s", cipher_name);
    }
}

static void
ssh_decryption_set_mac_id(struct ssh_peer_data *peer)
{
    char *mac_name = peer->mac;

    if (!mac_name) {
        peer->mac = NULL;
        ws_debug("ERROR: mac_name is NULL");
    } else if (0 == strcmp(mac_name, "hmac-sha2-256")) {
        peer->mac_id = CIPHER_MAC_SHA2_256;
    } else {
        ws_debug("decryption MAC not supported: %s", mac_name);
    }
}

static bool
gcry_cipher_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data)
{
    gcry_cipher_hd_t hd = (gcry_cipher_hd_t)user_data;

    gcry_cipher_close(hd);

    return false;
}

static void
ssh_decryption_setup_cipher(struct ssh_peer_data *peer_data,
        ssh_bignum *iv, ssh_bignum *key)
{
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

        char k1[32];
        char k2[32];
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

        wmem_register_callback(wmem_file_scope(), gcry_cipher_destroy_cb, *hd1);
        wmem_register_callback(wmem_file_scope(), gcry_cipher_destroy_cb, *hd2);

    } else if (CIPHER_AES128_CBC == peer_data->cipher_id  || CIPHER_AES192_CBC == peer_data->cipher_id || CIPHER_AES256_CBC == peer_data->cipher_id) {
        int iKeyLen = CIPHER_AES128_CBC == peer_data->cipher_id?16:CIPHER_AES192_CBC == peer_data->cipher_id?24:32;
        if (gcry_cipher_open(hd1, CIPHER_AES128_CBC == peer_data->cipher_id?GCRY_CIPHER_AES128:CIPHER_AES192_CBC == peer_data->cipher_id?GCRY_CIPHER_AES192:GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0)) {
            gcry_cipher_close(*hd1);
            ws_debug("ssh: can't open aes%d cipher handle", iKeyLen*8);
            return;
        }
        char k1[32], iv1[16];
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
            ws_debug("ssh: can't set aes%d cipher key", iKeyLen*8);
            ws_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
            return;
        }

        if ((err = gcry_cipher_setiv(*hd1, iv1, 16))) {
            gcry_cipher_close(*hd1);
            ws_debug("ssh: can't set aes%d cipher iv", iKeyLen*8);
            ws_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
            return;
        }

        wmem_register_callback(wmem_file_scope(), gcry_cipher_destroy_cb, *hd1);

    } else if (CIPHER_AES128_CTR == peer_data->cipher_id  || CIPHER_AES192_CTR == peer_data->cipher_id || CIPHER_AES256_CTR == peer_data->cipher_id) {
        int iKeyLen = CIPHER_AES128_CTR == peer_data->cipher_id?16:CIPHER_AES192_CTR == peer_data->cipher_id?24:32;
        if (gcry_cipher_open(hd1, CIPHER_AES128_CTR == peer_data->cipher_id?GCRY_CIPHER_AES128:CIPHER_AES192_CTR == peer_data->cipher_id?GCRY_CIPHER_AES192:GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0)) {
            gcry_cipher_close(*hd1);
            ws_debug("ssh: can't open aes%d cipher handle", iKeyLen*8);
            return;
        }
        char k1[32], iv1[16];
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

        ssh_debug_printf("ssh: cipher is aes%d-ctr\n", iKeyLen*8);
        ssh_print_data("key", k1, iKeyLen);
        ssh_print_data("iv", iv1, 16);

        if ((err = gcry_cipher_setkey(*hd1, k1, iKeyLen))) {
            gcry_cipher_close(*hd1);
            ws_debug("ssh: can't set aes%d cipher key", iKeyLen*8);
            ws_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
            return;
        }

        if ((err = gcry_cipher_setctr(*hd1, iv1, 16))) {
            gcry_cipher_close(*hd1);
            ws_debug("ssh: can't set aes%d cipher iv", iKeyLen*8);
            ws_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
            return;
        }

        wmem_register_callback(wmem_file_scope(), gcry_cipher_destroy_cb, *hd1);

    } else if (CIPHER_AES128_GCM == peer_data->cipher_id  || CIPHER_AES256_GCM == peer_data->cipher_id) {
        int iKeyLen = CIPHER_AES128_GCM == peer_data->cipher_id?16:32;
        if (gcry_cipher_open(hd1, CIPHER_AES128_GCM == peer_data->cipher_id?GCRY_CIPHER_AES128:GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0)) {
            gcry_cipher_close(*hd1);
            ws_debug("ssh: can't open aes%d cipher handle", iKeyLen*8);
            return;
        }

        char k1[32], iv2[12];
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

        ssh_debug_printf("ssh: cipher is aes%d-gcm\n", iKeyLen*8);
        ssh_print_data("key", k1, iKeyLen);
        ssh_print_data("iv", peer_data->iv, 12);

        if ((err = gcry_cipher_setkey(*hd1, k1, iKeyLen))) {
            gcry_cipher_close(*hd1);
            ws_debug("ssh: can't set aes%d cipher key", iKeyLen*8);
            ws_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
            return;
        }

        wmem_register_callback(wmem_file_scope(), gcry_cipher_destroy_cb, *hd1);

    } else {
        ssh_debug_printf("ssh: cipher (%d) is unknown or not set\n", peer_data->cipher_id);
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
        ws_debug("ssh: unsupported MAC");
    }
}

/* libgcrypt wrappers for HMAC/message digest operations {{{ */
/* hmac abstraction layer */
#define SSH_HMAC gcry_md_hd_t

static inline int
ssh_hmac_init(SSH_HMAC* md, const void * key, int len, int algo)
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
    err = gcry_md_setkey(*(md), key, len);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssh_debug_printf("ssh_hmac_init(): gcry_md_setkey(..., ..., %d) failed %s/%s", len, err_str, err_src);
        return -1;
    }
    return 0;
}

static inline void
ssh_hmac_update(SSH_HMAC* md, const void* data, int len)
{
    gcry_md_write(*(md), data, len);
}

static inline void
ssh_hmac_final(SSH_HMAC* md, unsigned char* data, unsigned* datalen)
{
    int   algo;
    unsigned len;

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

static int
ssh_get_digest_by_id(unsigned mac_id)
{
    if(mac_id==CIPHER_MAC_SHA2_256){
        return GCRY_MD_SHA256;
    }
    return -1;
}

static void
ssh_calc_mac(struct ssh_peer_data *peer_data, uint32_t seqnr, uint8_t* data, uint32_t datalen, uint8_t* calc_mac)
{
    SSH_HMAC hm;
    int      md;
    uint32_t len;
    uint8_t  buf[DIGEST_MAX_SIZE];

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
        bool is_response)
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

static unsigned
ssh_decrypt_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset)
{
    bool        is_response = (pinfo->destport != pinfo->match_uint);

    gcry_error_t err;
    unsigned message_length = 0, seqnr;
    char *plain = NULL, *mac;
    unsigned mac_len, data_len = 0;
    uint8_t calc_mac[DIGEST_MAX_SIZE];
    memset(calc_mac, 0, DIGEST_MAX_SIZE);

    mac_len = peer_data->mac_length;
    seqnr = peer_data->sequence_number;

    if (GCRY_CIPHER_CHACHA20 == peer_data->cipher_id) {
        const char *ctext = (const char *)tvb_get_ptr(tvb, offset, 4);
        uint8_t plain_length_buf[4];

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

        plain = (char *)wmem_alloc0(pinfo->pool, message_length+4);
        memcpy(plain, plain_length_buf, 4);
        const char *ctext2 = (const char *)tvb_get_ptr(tvb, offset+4,
                message_length);

        if (!ssh_decrypt_chacha20(peer_data->cipher, seqnr, 1, ctext2,
                    message_length, plain+4, message_length)) {
            ws_debug("ERROR: could not decrypt packet payload");
            return tvb_captured_length(tvb);
        }

        mac = (char *)tvb_get_ptr(tvb, offset + 4 + message_length, mac_len);
        char poly_key[32], iv[16];

        memset(poly_key, 0, 32);
        memset(iv, 0, 8);
        phton64(iv+8, (uint64_t)seqnr);
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
        gcry_mac_read(mac_hd, calc_mac, &buflen);
        gcry_mac_close(mac_hd);

        data_len   = message_length + 4;

//        ssh_print_data(is_response?"s2c encrypted":"c2s encrypted", ctext2, message_length+4+mac_len);
        ssh_debug_printf("%s plain text seq=%d", is_response?"s2c":"c2s",seqnr);
        ssh_print_data("", plain, message_length+4);
    } else if (CIPHER_AES128_GCM == peer_data->cipher_id || CIPHER_AES256_GCM == peer_data->cipher_id) {

        /* AES GCM for Secure Shell [RFC 5647] */
        /* The message length is Additional Authenticated Data */
        /* XXX: If there are fewer than 4 octets available, we need to
         * ask the TCP dissector for DESEGMENT_ONE_MORE_SEGMENT instead
         * of throwing an exception here, if we're desegmenting.
         */
        message_length = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
        unsigned remaining = tvb_reported_length_remaining(tvb, offset);
        ssh_debug_printf("length: %d, remaining: %d\n", message_length, remaining);
        /* The minimum size of a packet (not counting mac) is 16. */
        if (message_length < 16) {
            ws_debug("ssh: unreasonable message length %u", message_length);
            return tvb_captured_length(tvb);
        }

        /* SSH requires that the data to be encrypted (not including the AAD,
         * so message_length) be a multiple of the block size, 16 octets */
        if (message_length % 16 != 0) {
            ssh_debug_printf("length not a multiple of block length (16)!\n");
        }

        /* If tvb_reported_length_remaining(tvb, offset + 4) is less
         * than message_length + mac_len, then we should ask the TCP
         * dissector for more data if we're desegmenting. That is
         * simpler than trying to handle fragmentation ourselves.
         */
        const char *ctext = (const char *)tvb_get_ptr(tvb, offset + 4,
                message_length);
        plain = (char *)wmem_alloc(pinfo->pool, message_length+4);
        phton32(plain, message_length);

        /* gcry_cipher_setiv(peer_data->cipher, iv, 12); */
        if ((err = gcry_cipher_setiv(peer_data->cipher, peer_data->iv, 12))) {
            //gcry_cipher_close(peer_data->cipher);
            //Don't close this unless we also remove the wmem callback
// TODO: temporary work-around as long as a Windows python bug is triggered by automated tests
#ifndef _WIN32
            ws_debug("ssh: can't set aes128 cipher iv");
            ws_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
#endif	//ndef _WIN32
            return tvb_captured_length(tvb);
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
            return tvb_captured_length(tvb);
        }

        if ((err = gcry_cipher_decrypt(peer_data->cipher, plain+4, message_length,
                ctext, message_length))) {
// TODO: temporary work-around as long as a Windows python bug is triggered by automated tests
#ifndef _WIN32
            ws_debug("can't decrypt aes-gcm %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));

#endif	//ndef _WIN32
            return tvb_captured_length(tvb);
        }

        if (gcry_cipher_gettag (peer_data->cipher, calc_mac, 16)) {
// TODO: temporary work-around as long as a Windows python bug is triggered by automated tests
#ifndef _WIN32
            ws_debug ("aes128-gcm, gcry_cipher_gettag() failed\n");
#endif	//ndef _WIN32
            return tvb_captured_length(tvb);
        }

        if ((err = gcry_cipher_reset(peer_data->cipher))) {
// TODO: temporary work-around as long as a Windows python bug is triggered by automated tests
#ifndef _WIN32
            ws_debug("aes-gcm, gcry_cipher_reset failed: %s\n", gpg_strerror (err));
#endif	//ndef _WIN32
            return tvb_captured_length(tvb);
        }

        data_len   = message_length + 4;

//            ssh_print_data(is_response?"s2c encrypted":"c2s encrypted", ctl, message_length+4+mac_len);
        ssh_debug_printf("%s plain text seq=%d", is_response?"s2c":"c2s",seqnr);
        ssh_print_data("", plain, message_length+4);

    } else if (CIPHER_AES128_CBC == peer_data->cipher_id || CIPHER_AES128_CTR == peer_data->cipher_id ||
        CIPHER_AES192_CBC == peer_data->cipher_id || CIPHER_AES192_CTR == peer_data->cipher_id ||
        CIPHER_AES256_CBC == peer_data->cipher_id || CIPHER_AES256_CTR == peer_data->cipher_id) {

        message_length = tvb_reported_length_remaining(tvb, offset) - 4 - mac_len;

// TODO: see how to handle fragmentation...
        ws_noisy("Getting raw bytes of length %d", tvb_reported_length_remaining(tvb, offset));
        /* In CBC and CTR mode, the message length is encrypted as well.
         * We need to decrypt one block to get the length.
         * If we have fewer than 16 octets, and we're doing desegmentation,
         * we should tell the TCP dissector we need ONE_MORE_SEGMENT.
         */
        const char *cypher_buf0 = (const char *)tvb_get_ptr(tvb, offset, 16);

        char    plain0[16];
        if (gcry_cipher_decrypt(peer_data->cipher, plain0, 16, cypher_buf0, 16))
        {
            ws_debug("can\'t decrypt aes128");
            return tvb_captured_length(tvb);
        }

        unsigned message_length_decrypted = pntoh32(plain0);
        unsigned remaining = tvb_reported_length_remaining(tvb, offset);

        /* The message_length value doesn't include the length of the
         * message_length field itself, so it must be at least 12 bytes.
         */
        if(message_length_decrypted>32768 || message_length_decrypted < 12){
            ws_debug("ssh: unreasonable message length %u/%u", message_length_decrypted, message_length);
            return tvb_captured_length(tvb);
        }

        message_length = message_length_decrypted;
        /* SSH requires that the data to be encrypted (message_length+4)
         * be a multiple of the block size, 16 octets. */
        if (message_length % 16 != 12) {
            ssh_debug_printf("total length not a multiple of block length (16)!\n");
        }
        plain = (char *)wmem_alloc(pinfo->pool, message_length+4);
        memcpy(plain, plain0, 16);

        /* If we're desegmenting, we want to test if we have enough
         * remaining bytes here. It's easier to have the TCP
         * dissector put together a PDU based on our length.
         */

        if (message_length - 12 > 0) {
            /* All of these functions actually do handle the case where
             * there is no data left, so the check is unnecessary.
             */
            char *ct = (char *)tvb_get_ptr(tvb, offset + 16, message_length - 12);
            if ((err = gcry_cipher_decrypt(peer_data->cipher, plain + 16, message_length - 12, ct, message_length - 12)))
            {
                ws_debug("can't decrypt aes-cbc/ctr %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
                return tvb_captured_length(tvb);
            }
        }

        /* XXX: Need to test if we have enough data above if we're
         * doing desegmentation; the tvb_get_ptr() calls will throw
         * exceptions if there's not enough data before we get here.
         */
        if(message_length_decrypted>remaining){
            // Need desegmentation
            ws_noisy("  need_desegmentation: offset = %d, reported_length_remaining = %d\n",
                            offset, tvb_reported_length_remaining(tvb, offset));
            /* Make data available to ssh_follow_tap_listener */
            return tvb_captured_length(tvb);
        }

//                ssh_print_data(is_response?"s2c encrypted":"c2s encrypted", ctext, message_length+4+mac_len);
        ssh_debug_printf("%s plain text seq=%d", is_response?"s2c":"c2s",seqnr);
        ssh_print_data("", plain, message_length+4);

// TODO: process fragments
        data_len   = message_length + 4;

        ssh_calc_mac(peer_data, seqnr, plain, data_len, calc_mac);
    }

    if (mac_len && data_len) {
        mac = (char *)tvb_get_ptr(tvb, offset + data_len, mac_len);
        if (!memcmp(mac, calc_mac, mac_len)){
            ws_noisy("MAC OK");
        }else{
            ws_debug("MAC ERR");
            /* Bad MAC, just show the packet as encrypted. We can get
             * this for a known encryption type with no keys currently. */
            /* XXX: The TLS dissector has a preference to show the attempt
             * anyway if it failed.
             */
            return tvb_captured_length(tvb);
        }
    }

    if(plain){
        // Save message

        ssh_packet_info_t *packet = (ssh_packet_info_t *)p_get_proto_data(
                wmem_file_scope(), pinfo, proto_ssh, 0);
        if(!packet){
            packet = wmem_new0(wmem_file_scope(), ssh_packet_info_t);
            packet->from_server = is_response;
            packet->messages = NULL;
            p_add_proto_data(wmem_file_scope(), pinfo, proto_ssh, 0, packet);
        }

        int record_id = tvb_raw_offset(tvb)+offset;
        ssh_message_info_t *message;

        message = wmem_new(wmem_file_scope(), ssh_message_info_t);
        message->sequence_number = peer_data->sequence_number++;
        message->plain_data = wmem_memdup(wmem_file_scope(), plain, data_len);
        message->data_len = data_len;
        message->id = record_id;
        message->next = NULL;
        memcpy(message->calc_mac, calc_mac, DIGEST_MAX_SIZE);
        ssh_debug_printf("%s->sequence_number++ > %d\n", is_response?"server":"client", peer_data->sequence_number);

        ssh_message_info_t **pmessage = &packet->messages;
        while(*pmessage){
            pmessage = &(*pmessage)->next;
        }
        *pmessage = message;
    }

    offset += message_length + mac_len + 4;
    return offset;
}

proto_item *
ssh_tree_add_mac(proto_tree *tree, tvbuff_t *tvb, const unsigned offset, const unsigned mac_len,
                const int hf_mac, const int hf_mac_status, struct expert_field* bad_checksum_expert,
                packet_info *pinfo, const uint8_t * calc_mac, const unsigned flags)
{
//    header_field_info *hfinfo = proto_registrar_get_nth(hf_checksum);
    proto_item* ti = NULL;
    proto_item* ti2;
    bool incorrect_mac = true;
    char *mac;

//    DISSECTOR_ASSERT_HINT(hfinfo != NULL, "Not passed hfi!");
/*
    if (flags & PROTO_CHECKSUM_NOT_PRESENT) {
        ti = proto_tree_add_uint_format_value(tree, hf_checksum, tvb, offset, len, 0, "[missing]");
        proto_item_set_generated(ti);
        if (hf_checksum_status > 0) {
            ti2 = proto_tree_add_uint(tree, hf_checksum_status, tvb, offset, len, PROTO_CHECKSUM_E_NOT_PRESENT);
            proto_item_set_generated(ti2);
        }
        return ti;
    }
*/
    mac = (char *)tvb_get_ptr(tvb, offset, mac_len);
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
                    incorrect_mac = false;
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
                    incorrect_mac = false;
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
                    char *data = (char *)wmem_alloc(wmem_packet_scope(), mac_len*2 + 1);
                    *bytes_to_hexstr(data, calc_mac, mac_len) = 0;
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

static bool
ssh_decrypt_chacha20(gcry_cipher_hd_t hd,
        uint32_t seqnr, uint32_t counter, const unsigned char *ctext, unsigned ctext_len,
        unsigned char *plain, unsigned plain_len)
{
    unsigned char seq[8];
    unsigned char iv[16];

    phton64(seq, (uint64_t)seqnr);

    // chacha20 uses a different cipher handle for the packet payload & length
    // the payload uses a block counter
    if (counter) {
        unsigned char ctr[8] = {1,0,0,0,0,0,0,0};
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
        ssh_message_info_t *message)
{
    int offset = 0;      // TODO:
    int dissected_len = 0;

    char* plaintext = message->plain_data;
    unsigned plaintext_len = message->data_len;

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Encrypted packet (plaintext_len=%d)", plaintext_len);

    tvbuff_t *packet_tvb = tvb_new_child_real_data(tvb, plaintext, plaintext_len, plaintext_len);
    add_new_data_source(pinfo, packet_tvb, "Decrypted Packet");

    unsigned   plen, len;
    uint8_t padding_length;
    unsigned   remain_length;
    int     last_offset=offset;
    unsigned   msg_code;

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
    padding_length = tvb_get_uint8(packet_tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_padding_length, packet_tvb, offset, 1, padding_length);
    offset += 1;

    /* msg_code */
    msg_code = tvb_get_uint8(packet_tvb, offset);

    /* Transport layer protocol */
    /* Generic (1-19) */
    if(msg_code >= 1 && msg_code <= 19) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Transport (generic)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        dissected_len = ssh_dissect_transport_generic(packet_tvb, pinfo, offset+1, peer_data, msg_type_tree, msg_code) - offset;
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
        dissected_len = ssh_dissect_connection_specific(packet_tvb, pinfo, peer_data, offset+1, msg_type_tree, msg_code, message) - offset;
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
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Local extension");
        dissected_len = ssh_dissect_local_extension(packet_tvb, pinfo, offset, peer_data, msg_type_tree, msg_code) - offset;
    }

    len = plen+4-padding_length-(offset-last_offset);
    if (len > 0) {
        proto_tree_add_item(msg_type_tree, hf_ssh_payload, packet_tvb, offset, len, ENC_NA);
    }
    if(dissected_len!=(int)len){
//        expert_add_info_format(pinfo, ti, &ei_ssh_packet_decode, "Decoded %d bytes, but packet length is %d bytes", dissected_len, len);
        expert_add_info_format(pinfo, ti, &ei_ssh_packet_decode, "Decoded %d bytes, but packet length is %d bytes [%d]", dissected_len, len, msg_code);
    }
    offset +=len;

    /* padding */
    proto_tree_add_item(tree, hf_ssh_padding_string, packet_tvb, offset, padding_length, ENC_NA);
    offset+= padding_length;

    if (peer_data->mac_length) {
        ssh_tree_add_mac(tree, tvb, offset, peer_data->mac_length, hf_ssh_mac_string, hf_ssh_mac_status, &ei_ssh_mac_bad, pinfo, message->calc_mac,
                                               PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
        offset += peer_data->mac_length;
    }
    ti = proto_tree_add_uint(tree, hf_ssh_seq_num, tvb, offset, 0, message->sequence_number);
    proto_item_set_generated(ti);
    return offset;
}

static int
ssh_dissect_transport_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, struct ssh_peer_data *peer_data, proto_item *msg_type_tree, unsigned msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_DISCONNECT){
                proto_tree_add_item(msg_type_tree, hf_ssh_disconnect_reason, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                unsigned   nlen;
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
                unsigned   slen;
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
                unsigned   nlen;
                nlen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name, packet_tvb, offset, nlen, ENC_ASCII);
                offset += nlen;
        }else if(msg_code==SSH_MSG_SERVICE_ACCEPT){
                unsigned   nlen;
                nlen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name, packet_tvb, offset, nlen, ENC_ASCII);
                offset += nlen;
        }else if(msg_code==SSH_MSG_EXT_INFO){
                unsigned   ext_cnt;
                ext_cnt = tvb_get_ntohl(packet_tvb, offset);
                proto_tree_add_item(msg_type_tree, hf_ssh_ext_count, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                for(unsigned ext_index = 0; ext_index < ext_cnt; ext_index++) {
                    offset = ssh_dissect_rfc8308_extension(packet_tvb, pinfo, offset, peer_data, msg_type_tree);
                }
        }
        return offset;
}

static int
ssh_dissect_rfc8308_extension(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, struct ssh_peer_data *peer_data, proto_item *msg_type_tree)
{
    (void)pinfo;
    unsigned ext_name_slen = tvb_get_ntohl(packet_tvb, offset);
    uint8_t *ext_name = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset + 4, ext_name_slen, ENC_ASCII);
    unsigned ext_value_slen = tvb_get_ntohl(packet_tvb, offset + 4 + ext_name_slen);
    unsigned ext_len = 8 + ext_name_slen + ext_value_slen;
    proto_item *ext_tree = proto_tree_add_subtree_format(msg_type_tree, packet_tvb, offset, ext_len, ett_extension, NULL, "Extension: %s", ext_name);

    proto_tree_add_item(ext_tree, hf_ssh_ext_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ext_tree, hf_ssh_ext_name, packet_tvb, offset, ext_name_slen, ENC_ASCII);
    offset += ext_name_slen;
    proto_tree_add_item(ext_tree, hf_ssh_ext_value_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ext_tree, hf_ssh_ext_value, packet_tvb, offset, ext_value_slen, ENC_NA);

    if (g_str_equal(ext_name, "server-sig-algs")) {
        // server-sig-algs (RFC8308 Sec. 3.1)
        proto_tree_add_item(ext_tree, hf_ssh_ext_server_sig_algs_algorithms, packet_tvb, offset, ext_value_slen, ENC_ASCII);
        offset += ext_value_slen;
    } else if (g_str_equal(ext_name, "delay-compression")) {
        // delay-compression (RFC8308 Sec 3.2)
        unsigned slen;
        slen = tvb_get_ntohl(packet_tvb, offset);
        proto_tree_add_item(ext_tree, hf_ssh_ext_delay_compression_algorithms_client_to_server_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ext_tree, hf_ssh_ext_delay_compression_algorithms_client_to_server, packet_tvb, offset, slen, ENC_ASCII);
        offset += slen;
        slen = tvb_get_ntohl(packet_tvb, offset);
        proto_tree_add_item(ext_tree, hf_ssh_ext_delay_compression_algorithms_server_to_client_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ext_tree, hf_ssh_ext_delay_compression_algorithms_server_to_client, packet_tvb, offset, slen, ENC_ASCII);
        offset += slen;
    } else if (g_str_equal(ext_name, "no-flow-control")) {
        // no-flow-control (RFC 8308 Sec 3.3)
        proto_tree_add_item(ext_tree, hf_ssh_ext_no_flow_control_value, packet_tvb, offset, ext_value_slen, ENC_ASCII);
        offset += ext_value_slen;
    } else if (g_str_equal(ext_name, "elevation")) {
        // elevation (RFC 8308 Sec 3.4)
        proto_tree_add_item(ext_tree, hf_ssh_ext_elevation_value, packet_tvb, offset, ext_value_slen, ENC_ASCII);
        offset += ext_value_slen;
    } else if (g_str_equal(ext_name, "publickey-algorithms@roumenpetrov.info")) {
        // publickey-algorithms@roumenpetrov.info (proprietary)
        proto_tree_add_item(ext_tree, hf_ssh_ext_prop_publickey_algorithms_algorithms, packet_tvb, offset, ext_value_slen, ENC_ASCII);
        offset += ext_value_slen;
    } else if (g_str_equal(ext_name, "ping@openssh.com")) {
        // ping@openssh.com (proprietary w/ primitive extension value)
        peer_data->global_data->ext_ping_openssh_offered = true;
        offset += ext_value_slen;
    } else {
        offset += ext_value_slen;
    }

    // The following extensions do not require advanced dissection:
    //  - global-requests-ok
    //  - ext-auth-info
    //  - publickey-hostbound@openssh.com
    //  - ext-info-in-auth@openssh.com

    return offset;
}

static int
ssh_dissect_userauth_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, unsigned msg_code)
{
        if(msg_code==SSH_MSG_USERAUTH_REQUEST){
                unsigned   slen;
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

                uint8_t* key_type;
                key_type = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset, slen, ENC_ASCII|ENC_NA);
                offset += slen;
                if (0 == strcmp(key_type, "none")) {
                }else if (0 == strcmp(key_type, "publickey")) {
                        uint8_t bHaveSignature = tvb_get_uint8(packet_tvb, offset);
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
                            expert_add_info_format(pinfo, blob_tree, &ei_ssh_packet_decode, "Decoded %d bytes, but packet length is %d bytes", dissected_len, slen);
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
                                    expert_add_info_format(pinfo, signature_tree, &ei_ssh_packet_decode, "Decoded %d bytes, but packet length is %d bytes", dissected_len, slen);
                                }
                                offset += slen;
                        }
                }else if (0 == strcmp(key_type, "password")) {
                        uint8_t bChangePassword = tvb_get_uint8(packet_tvb, offset);
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
                unsigned   slen;
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
        int offset, proto_item *msg_type_tree, unsigned msg_code)
{
        if(msg_code==SSH_MSG_USERAUTH_PK_OK){
                proto_item *ti;
                int dissected_len = 0;
                unsigned   slen;
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
                    expert_add_info_format(pinfo, ti, &ei_ssh_packet_decode, "Decoded %d bytes, but packet length is %d bytes", dissected_len, slen);
                }
                offset += slen;
        }
        return offset;
}

static void
ssh_process_payload(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, ssh_channel_info_t *channel)
{
    tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (channel->handle) {
        call_dissector(channel->handle, next_tvb, pinfo, proto_tree_get_root(tree));
    } else {
        call_data_dissector(next_tvb, pinfo, proto_tree_get_root(tree));
    }
}

static void
print_ssh_fragment_tree(fragment_head *ipfd_head, proto_tree *tree, proto_tree *ssh_tree, packet_info *pinfo, tvbuff_t *next_tvb)
{
    proto_item *ssh_tree_item, *frag_tree_item;

    /*
     * The subdissector thought it was completely
     * desegmented (although the stuff at the
     * end may, in turn, require desegmentation),
     * so we show a tree with all segments.
     */
    show_fragment_tree(ipfd_head, &ssh_segment_items,
                       tree, pinfo, next_tvb, &frag_tree_item);
    /*
     * The toplevel fragment subtree is now
     * behind all desegmented data; move it
     * right behind the SSH tree.
     */
    ssh_tree_item = proto_tree_get_parent(ssh_tree);
    /* The SSH protocol item is up a few levels from the message tree */
    ssh_tree_item = proto_item_get_parent_nth(ssh_tree_item, 2);
    if (frag_tree_item && ssh_tree_item) {
        proto_tree_move_item(tree, ssh_tree_item, frag_tree_item);
    }
}

static uint32_t
ssh_msp_fragment_id(struct tcp_multisegment_pdu *msp)
{
    /*
     * If a frame contains multiple PDUs, then "first_frame" is not
     * sufficient to uniquely identify groups of fragments. Therefore we use
     * the tcp reassembly functions that also test msp->seq (the position of
     * the initial fragment in the SSH channel).
     */
    return msp->first_frame;
}

static void
ssh_proto_tree_add_segment_data(
    proto_tree  *tree,
    tvbuff_t    *tvb,
    int          offset,
    int          length,
    const char *prefix)
{
    proto_tree_add_bytes_format(
        tree,
        hf_ssh_segment_data,
        tvb,
        offset,
        length,
        NULL,
        "%sSSH segment data (%u %s)",
        prefix != NULL ? prefix : "",
        length == -1 ? tvb_reported_length_remaining(tvb, offset) : length,
        plurality(length, "byte", "bytes"));
}

static void
desegment_ssh(tvbuff_t *tvb, packet_info *pinfo, uint32_t seq,
        uint32_t nxtseq, proto_tree *tree, ssh_channel_info_t *channel)
{
    fragment_head *ipfd_head;
    bool           must_desegment;
    bool           called_dissector;
    int            another_pdu_follows;
    bool           another_segment_in_frame = false;
    int            deseg_offset, offset = 0;
    uint32_t       deseg_seq;
    int            nbytes;
    proto_item    *item;
    struct tcp_multisegment_pdu *msp;
    bool           first_pdu = true;

again:
    ipfd_head = NULL;
    must_desegment = false;
    called_dissector = false;
    another_pdu_follows = 0;
    msp = NULL;

    /*
     * Initialize these to assume no desegmentation.
     * If that's not the case, these will be set appropriately
     * by the subdissector.
     */
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

   /*
     * Initialize this to assume that this segment will just be
     * added to the middle of a desegmented chunk of data, so
     * that we should show it all as data.
     * If that's not the case, it will be set appropriately.
     */
    deseg_offset = offset;

    /* If we've seen this segment before (e.g., it's a retransmission),
     * there's nothing for us to do.  Certainly, don't add it to the list
     * of multisegment_pdus (that would cause subsequent lookups to find
     * the retransmission instead of the original transmission, breaking
     * dissection of the desegmented pdu if we'd already seen the end of
     * the pdu).
     */
    if ((msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32(channel->multisegment_pdus, seq))) {
        const char *prefix;
        bool is_retransmission = false;

        if (msp->first_frame == pinfo->num) {
            /* This must be after the first pass. */
            prefix = "";
            if (msp->last_frame == pinfo->num) {
                col_clear(pinfo->cinfo, COL_INFO);
            } else {
                if (first_pdu) {
                    col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[SSH segment of a reassembled PDU]");
                }
            }
        } else {
            prefix = "Retransmitted ";
            is_retransmission = true;
        }

        if (!is_retransmission) {
            ipfd_head = fragment_get(&ssh_reassembly_table, pinfo, msp->first_frame, msp);
            if (ipfd_head != NULL && ipfd_head->reassembled_in !=0 &&
                ipfd_head->reassembled_in != pinfo->num) {
                /* Show what frame this was reassembled in if not this one. */
                item=proto_tree_add_uint(tree, *ssh_segment_items.hf_reassembled_in,
                                         tvb, 0, 0, ipfd_head->reassembled_in);
                proto_item_set_generated(item);
            }
        }
        nbytes = tvb_reported_length_remaining(tvb, offset);
        ssh_proto_tree_add_segment_data(tree, tvb, offset, nbytes, prefix);
        return;
    }

    /* Else, find the most previous PDU starting before this sequence number */
    msp = (struct tcp_multisegment_pdu *)wmem_tree_lookup32_le(channel->multisegment_pdus, seq-1);
    if (msp && msp->seq <= seq && msp->nxtpdu > seq) {
        int len;

        if (!PINFO_FD_VISITED(pinfo)) {
            msp->last_frame = pinfo->num;
            msp->last_frame_time = pinfo->abs_ts;
        }

        /* OK, this PDU was found, which means the segment continues
         * a higher-level PDU and that we must desegment it.
         */
        if (msp->flags & MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            /* The dissector asked for the entire segment */
            len = MAX(0, tvb_reported_length_remaining(tvb, offset));
        } else {
            len = MIN(nxtseq, msp->nxtpdu) - seq;
        }

        ipfd_head = fragment_add(&ssh_reassembly_table, tvb, offset,
                                 pinfo, ssh_msp_fragment_id(msp), msp,
                                 seq - msp->seq,
                                 len, (LT_SEQ (nxtseq,msp->nxtpdu)));

        if (!PINFO_FD_VISITED(pinfo)
        && msp->flags & MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            msp->flags &= (~MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT);

            /* If we consumed the entire segment there is no
             * other pdu starting anywhere inside this segment.
             * So update nxtpdu to point at least to the start
             * of the next segment.
             * (If the subdissector asks for even more data we
             * will advance nxtpdu even further later down in
             * the code.)
             */
            msp->nxtpdu = nxtseq;
        }

        if ( (msp->nxtpdu < nxtseq)
        &&  (msp->nxtpdu >= seq)
        &&  (len > 0)) {
            another_pdu_follows = msp->nxtpdu - seq;
        }
    } else {
        /* This segment was not found in our table, so it doesn't
         * contain a continuation of a higher-level PDU.
         * Call the normal subdissector.
         */
        ssh_process_payload(tvb, offset, pinfo, tree, channel);
        called_dissector = true;

        /* Did the subdissector ask us to desegment some more data
         * before it could handle the packet?
         * If so we have to create some structures in our table but
         * this is something we only do the first time we see this
         * packet.
         */
        if (pinfo->desegment_len) {
            if (!PINFO_FD_VISITED(pinfo))
                must_desegment = true;

            /*
             * Set "deseg_offset" to the offset in "tvb"
             * of the first byte of data that the
             * subdissector didn't process.
             */
            deseg_offset = offset + pinfo->desegment_offset;
        }

        /* Either no desegmentation is necessary, or this is
         * segment contains the beginning but not the end of
         * a higher-level PDU and thus isn't completely
         * desegmented.
         */
        ipfd_head = NULL;
    }

    /* is it completely desegmented? */
    if (ipfd_head && ipfd_head->reassembled_in == pinfo->num) {
        /*
         * Yes, we think it is.
         * We only call subdissector for the last segment.
         * Note that the last segment may include more than what
         * we needed.
         */
        if (nxtseq < msp->nxtpdu) {
            /*
             * This is *not* the last segment. It is part of a PDU in the same
             * frame, so no another PDU can follow this one.
             * Do not reassemble SSH yet, it will be done in the final segment.
             * (If we are reassembling at FIN, we will do that in dissect_ssl()
             * after iterating through all the records.)
             * Clear the Info column and avoid displaying [SSH segment of a
             * reassembled PDU], the payload dissector will typically set it.
             * (This is needed here for the second pass.)
             */
            another_pdu_follows = 0;
            col_clear(pinfo->cinfo, COL_INFO);
            another_segment_in_frame = true;
        } else {
            /*
             * OK, this is the last segment of the PDU and also the
             * last segment in this frame.
             * Let's call the subdissector with the desegmented
             * data.
             */
            tvbuff_t *next_tvb;
            int old_len;

            /*
             * Reset column in case multiple SSH segments form the PDU
             * and this last SSH segment is not in the first TCP segment of
             * this frame.
             * XXX prevent clearing the column if the last layer is not SSH?
             */
            /* Clear column during the first pass. */
            col_clear(pinfo->cinfo, COL_INFO);

            /* create a new TVB structure for desegmented data */
            next_tvb = tvb_new_chain(tvb, ipfd_head->tvb_data);

            /* add desegmented data to the data source list */
            add_new_data_source(pinfo, next_tvb, "Reassembled SSH");

            /* call subdissector */
            ssh_process_payload(next_tvb, 0, pinfo, tree, channel);
            called_dissector = true;

            /*
             * OK, did the subdissector think it was completely
             * desegmented, or does it think we need even more
             * data?
             */
            old_len = (int)(tvb_reported_length(next_tvb) - tvb_reported_length_remaining(tvb, offset));
            if (pinfo->desegment_len && pinfo->desegment_offset <= old_len) {
                /*
                 * "desegment_len" isn't 0, so it needs more
                 * data for something - and "desegment_offset"
                 * is before "old_len", so it needs more data
                 * to dissect the stuff we thought was
                 * completely desegmented (as opposed to the
                 * stuff at the beginning being completely
                 * desegmented, but the stuff at the end
                 * being a new higher-level PDU that also
                 * needs desegmentation).
                 */
                fragment_set_partial_reassembly(&ssh_reassembly_table,
                                                pinfo, ssh_msp_fragment_id(msp), msp);
                /* Update msp->nxtpdu to point to the new next
                 * pdu boundary.
                 */
                if (pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                    /* We want reassembly of at least one
                     * more segment so set the nxtpdu
                     * boundary to one byte into the next
                     * segment.
                     * This means that the next segment
                     * will complete reassembly even if it
                     * is only one single byte in length.
                     */
                    msp->nxtpdu = seq + tvb_reported_length_remaining(tvb, offset) + 1;
                    msp->flags |= MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
                } else if (pinfo->desegment_len == DESEGMENT_UNTIL_FIN) {
                    /* This is not the first segment, and we thought reassembly
                     * would be done now, but now we know we desegment at FIN.
                     * E.g., a HTTP response where the headers were split
                     * across segments (so previous ONE_MORE_SEGMENT) and
                     * also no Content-Length (so now DESEGMENT_UNTIL_FIN).
                     */
                    channel->flags |= TCP_FLOW_REASSEMBLE_UNTIL_FIN;
                    msp->nxtpdu = nxtseq + 0x40000000;
                } else {
                    msp->nxtpdu = seq + tvb_reported_length_remaining(tvb, offset) + pinfo->desegment_len;
                }
                /* Since we need at least some more data
                 * there can be no pdu following in the
                 * tail of this segment.
                 */
                another_pdu_follows = 0;
            } else {
                /*
                 * Show the stuff in this TCP segment as
                 * just raw TCP segment data.
                 */
                nbytes = another_pdu_follows > 0
                    ? another_pdu_follows
                    : tvb_reported_length_remaining(tvb, offset);
                ssh_proto_tree_add_segment_data(tree, tvb, offset, nbytes, NULL);

                /* Show details of the reassembly */
                print_ssh_fragment_tree(ipfd_head, proto_tree_get_root(tree), tree, pinfo, next_tvb);

                /* Did the subdissector ask us to desegment
                 * some more data?  This means that the data
                 * at the beginning of this segment completed
                 * a higher-level PDU, but the data at the
                 * end of this segment started a higher-level
                 * PDU but didn't complete it.
                 *
                 * If so, we have to create some structures
                 * in our table, but this is something we
                 * only do the first time we see this packet.
                 */
                if (pinfo->desegment_len) {
                    if (!PINFO_FD_VISITED(pinfo))
                        must_desegment = true;

                    /* The stuff we couldn't dissect
                     * must have come from this segment,
                     * so it's all in "tvb".
                     *
                     * "pinfo->desegment_offset" is
                     * relative to the beginning of
                     * "next_tvb"; we want an offset
                     * relative to the beginning of "tvb".
                     *
                     * First, compute the offset relative
                     * to the *end* of "next_tvb" - i.e.,
                     * the number of bytes before the end
                     * of "next_tvb" at which the
                     * subdissector stopped.  That's the
                     * length of "next_tvb" minus the
                     * offset, relative to the beginning
                     * of "next_tvb, at which the
                     * subdissector stopped.
                     */
                    deseg_offset = ipfd_head->datalen - pinfo->desegment_offset;

                    /* "tvb" and "next_tvb" end at the
                     * same byte of data, so the offset
                     * relative to the end of "next_tvb"
                     * of the byte at which we stopped
                     * is also the offset relative to
                     * the end of "tvb" of the byte at
                     * which we stopped.
                     *
                     * Convert that back into an offset
                     * relative to the beginning of
                     * "tvb", by taking the length of
                     * "tvb" and subtracting the offset
                     * relative to the end.
                     */
                    deseg_offset = tvb_reported_length(tvb) - deseg_offset;
                }
            }
        }
    }

    if (must_desegment) {
        /* If the dissector requested "reassemble until FIN"
         * just set this flag for the flow and let reassembly
         * proceed at normal.  We will check/pick up these
         * reassembled PDUs later down in dissect_tcp() when checking
         * for the FIN flag.
         */
        if (pinfo->desegment_len == DESEGMENT_UNTIL_FIN) {
            channel->flags |= TCP_FLOW_REASSEMBLE_UNTIL_FIN;
        }
        /*
         * The sequence number at which the stuff to be desegmented
         * starts is the sequence number of the byte at an offset
         * of "deseg_offset" into "tvb".
         *
         * The sequence number of the byte at an offset of "offset"
         * is "seq", i.e. the starting sequence number of this
         * segment, so the sequence number of the byte at
         * "deseg_offset" is "seq + (deseg_offset - offset)".
         */
        deseg_seq = seq + (deseg_offset - offset);

        if (((nxtseq - deseg_seq) <= 1024*1024)
            &&  (!PINFO_FD_VISITED(pinfo))) {
            if (pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                /* The subdissector asked to reassemble using the
                 * entire next segment.
                 * Just ask reassembly for one more byte
                 * but set this msp flag so we can pick it up
                 * above.
                 */
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                    deseg_seq, nxtseq+1, channel->multisegment_pdus);
                msp->flags |= MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
            } else if (pinfo->desegment_len == DESEGMENT_UNTIL_FIN) {
                /* Set nxtseq very large so that reassembly won't happen
                 * until we force it at the end of the stream in dissect_ssl()
                 * outside this function.
                 */
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                    deseg_seq, nxtseq+0x40000000, channel->multisegment_pdus);
            } else {
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                    deseg_seq, nxtseq+pinfo->desegment_len, channel->multisegment_pdus);
            }

            /* add this segment as the first one for this new pdu */
            fragment_add(&ssh_reassembly_table, tvb, deseg_offset,
                         pinfo, ssh_msp_fragment_id(msp), msp,
                         0, nxtseq - deseg_seq,
                         LT_SEQ(nxtseq, msp->nxtpdu));
        }
    }

    if (!called_dissector || pinfo->desegment_len != 0) {
        if (ipfd_head != NULL && ipfd_head->reassembled_in != 0 &&
            ipfd_head->reassembled_in != pinfo->num &&
            !(ipfd_head->flags & FD_PARTIAL_REASSEMBLY)) {
            /*
             * We know what other frame this PDU is reassembled in;
             * let the user know.
             */
            item=proto_tree_add_uint(tree, *ssh_segment_items.hf_reassembled_in,
                                     tvb, 0, 0, ipfd_head->reassembled_in);
            proto_item_set_generated(item);
        }

        /*
         * Either we didn't call the subdissector at all (i.e.,
         * this is a segment that contains the middle of a
         * higher-level PDU, but contains neither the beginning
         * nor the end), or the subdissector couldn't dissect it
         * all, as some data was missing (i.e., it set
         * "pinfo->desegment_len" to the amount of additional
         * data it needs).
         */
        if (!another_segment_in_frame && pinfo->desegment_offset == 0) {
            /*
             * It couldn't, in fact, dissect any of it (the
             * first byte it couldn't dissect is at an offset
             * of "pinfo->desegment_offset" from the beginning
             * of the payload, and that's 0).
             * Just mark this as SSH.
             */

            /* SFTP checks the length before setting the protocol column.
             * If other subdissectors don't do this, we'd want to set the
             * protocol column back - but we want to get the SSH version
             */
            //col_set_str(pinfo->cinfo, COL_PROTOCOL,
            //        val_to_str_const(session->version, ssl_version_short_names, "SSH"));
            if (first_pdu) {
                col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[SSH segment of a reassembled PDU]");
            }
        }

        /*
         * Show what's left in the packet as just raw SSH segment data.
         * XXX - remember what protocol the last subdissector
         * was, and report it as a continuation of that, instead?
         */
        nbytes = tvb_reported_length_remaining(tvb, deseg_offset);
        ssh_proto_tree_add_segment_data(tree, tvb, deseg_offset, nbytes, NULL);
    }
    pinfo->can_desegment = 0;
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    if (another_pdu_follows) {
        /* there was another pdu following this one. */
        pinfo->can_desegment=2;
        /* we also have to prevent the dissector from changing the
         * PROTOCOL and INFO colums since what follows may be an
         * incomplete PDU and we don't want it be changed back from
         *  <Protocol>   to <SSH>
         */
        col_set_fence(pinfo->cinfo, COL_INFO);
        col_set_writable(pinfo->cinfo, COL_PROTOCOL, false);
        first_pdu = false;
        offset += another_pdu_follows;
        seq += another_pdu_follows;
        goto again;
    }
}

static void
ssh_dissect_channel_data(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data _U_, proto_tree *tree,
        ssh_message_info_t *message _U_, ssh_channel_info_t *channel)
{

    uint16_t save_can_desegment = pinfo->can_desegment;

    if (ssh_desegment) {
        pinfo->can_desegment = 2;
        desegment_ssh(tvb, pinfo, message->byte_seq, message->next_byte_seq, tree, channel);
    } else {
        pinfo->can_desegment = 0;
        bool save_fragmented = pinfo->fragmented;
        pinfo->fragmented = true;

        ssh_process_payload(tvb, 0, pinfo, tree, channel);
        pinfo->fragmented = save_fragmented;
    }

    pinfo->can_desegment = save_can_desegment;
}

static int
ssh_dissect_connection_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *msg_type_tree,
        unsigned msg_code, ssh_message_info_t *message)
{
        uint32_t recipient_channel, sender_channel;

        if(msg_code==SSH_MSG_CHANNEL_OPEN){
                uint32_t slen;
                proto_tree_add_item_ret_uint(msg_type_tree, hf_ssh_connection_type_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN, &slen);
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
                proto_tree_add_item_ret_uint(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN, &recipient_channel);
                offset += 4;
                proto_tree_add_item_ret_uint(msg_type_tree, hf_ssh_connection_sender_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN, &sender_channel);
                offset += 4;
                if (!PINFO_FD_VISITED(pinfo)) {
                    create_channel(peer_data, recipient_channel, sender_channel);
                }
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_initial_window, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_maximum_packet_size, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_WINDOW_ADJUST){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_window_adjust, packet_tvb, offset, 4, ENC_BIG_ENDIAN);         // TODO: maintain count of transferred bytes and window size
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_DATA){
                proto_item *ti = proto_tree_add_item_ret_uint(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN, &recipient_channel);
                offset += 4;
// TODO: process according to the type of channel
                uint32_t slen;
                proto_tree_add_item_ret_uint(msg_type_tree, hf_ssh_channel_data_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN, &slen);
                offset += 4;
                tvbuff_t *next_tvb = tvb_new_subset_length(packet_tvb, offset, slen);

                ssh_channel_info_t *channel = get_channel_info_for_channel(peer_data, recipient_channel);
                if (channel) {
                        if (!PINFO_FD_VISITED(pinfo)) {
                            message->byte_seq = channel->byte_seq;
                            channel->byte_seq += slen;
                            message->next_byte_seq = channel->byte_seq;
                        }
                        ssh_dissect_channel_data(next_tvb, pinfo, peer_data, msg_type_tree, message, channel);
                } else {
                        expert_add_info_format(pinfo, ti, &ei_ssh_channel_number, "Could not find configuration for channel %d", recipient_channel);
                }
                offset += slen;
        }else if(msg_code==SSH_MSG_CHANNEL_EOF){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_CLOSE){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_REQUEST){
                proto_tree_add_item_ret_uint(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN, &recipient_channel);
                offset += 4;
                const uint8_t* request_name;
                uint32_t slen;
                proto_tree_add_item_ret_uint(msg_type_tree, hf_ssh_channel_request_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN, &slen);
                offset += 4;
                proto_tree_add_item_ret_string(msg_type_tree, hf_ssh_channel_request_name, packet_tvb, offset, slen, ENC_UTF_8, pinfo->pool, &request_name);
                offset += slen;
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_request_want_reply, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* RFC 4254 6.5: "Only one of these requests ["shell", "exec",
                 * or "subsystem"] can succeed per channel." Set up the
                 * appropriate handler for future CHANNEL_DATA and
                 * CHANNEL_EXTENDED_DATA messages on the channel.
                 */
                if (0 == strcmp(request_name, "subsystem")) {
                        proto_tree_add_item_ret_uint(msg_type_tree, hf_ssh_subsystem_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN, &slen);
                        offset += 4;
                        const uint8_t* subsystem_name;
                        proto_tree_add_item_ret_string(msg_type_tree, hf_ssh_subsystem_name, packet_tvb, offset, slen, ENC_UTF_8, pinfo->pool, &subsystem_name);
                        set_subdissector_for_channel(peer_data, recipient_channel, subsystem_name);
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

/* Channel mapping {{{ */

/* The usual flow:
 * 1. client sends SSH_MSG_CHANNEL_OPEN with its (sender) channel number
 * 2. server responds with SSH_MSG_CHANNEL_OPEN_CONFIRMATION with
 *    its channel number and echoing the client's number, creating
 *    a bijective map
 * 3. client sends SSH_MSG_CHANNEL_REQUEST which has the name of
 *    the shell, command, or subsystem to start. This has the recipient's
 *    channel number (i.e. the server's)
 * 4. server may send back a SSG_MSG_CHANNEL_SUCCESS (or _FAILURE) with
 *    the the recipient (i.e., client) channel number, but this does not
 *    contain the subsystem name or anything identifying the request to
 *    which it responds. It MUST be sent in the same order as the
 *    corresponding request message (RFC 4254 4 Global Requests), so we
 *    could track it that way, but for our purposes we just treat all
 *    requests as successes. (If not, either there won't be data or another
 *    request will supercede it later.)
 *
 * Either side can open a channel (RFC 4254 5 Channel Mechanism). The
 * typical flow is the client opening a channel, but in the case of
 * remote port forwarding (7 TCP/IP Port Forwarding) the directions are
 * swapped. For port forwarding, all the information is contained in the
 * SSH_MSG_CHANNEL_OPEN, there is no SSH_MSG_CHANNEL_REQUEST.
*
 * XXX: Channel numbers can be re-used after being closed (5.3 Closing a
 * Channel), but not necessarily mapped to the same channel number on the
 * other side. If that actually happens, the right way to handle this is
 * to track the state changes over time for random packet access (e.g.,
 * using a multimap with the packet number instead of maps.)
 */

static struct ssh_peer_data*
get_other_peer_data(struct ssh_peer_data *peer_data)
{
    bool is_server = &peer_data->global_data->peer_data[SERVER_PEER_DATA]==peer_data;
    if (is_server) {
        return &peer_data->global_data->peer_data[CLIENT_PEER_DATA];
    } else {
        return &peer_data->global_data->peer_data[SERVER_PEER_DATA];
    }
}

/* Create pairings between a recipient channel and the sender's channel,
 * from a SSH_MSG_CHANNEL_OPEN_CONFIRMATION. */
static void
create_channel(struct ssh_peer_data *peer_data, uint32_t recipient_channel, uint32_t sender_channel)
{
    if (peer_data->channel_info == NULL) {
        peer_data->channel_info = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    }
    wmem_map_insert(peer_data->channel_info, GUINT_TO_POINTER(sender_channel), GUINT_TO_POINTER(recipient_channel));

    if (peer_data->channel_handles == NULL) {
        peer_data->channel_handles = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    }

    ssh_channel_info_t *new_channel = wmem_new0(wmem_file_scope(), ssh_channel_info_t);
    new_channel->multisegment_pdus = wmem_tree_new(wmem_file_scope());
    wmem_map_insert(peer_data->channel_handles, GUINT_TO_POINTER(recipient_channel), new_channel);

    /* If the recipient channel is already configured in the other direction,
     * set the handle. We need this if we eventually handle port forwarding,
     * where all the information to handle the traffic is sent in the
     * SSH_MSG_CHANNEL_OPEN message before the CONFIRMATION. It might also
     * help if the packets are out of order (i.e. we get the client
     * CHANNEL_REQUEST before the CHANNEL_OPEN_CONFIRMATION.)
     */
    struct ssh_peer_data *other_peer_data = get_other_peer_data(peer_data);
    if (other_peer_data->channel_handles) {
        ssh_channel_info_t *peer_channel = wmem_map_lookup(other_peer_data->channel_handles, GUINT_TO_POINTER(sender_channel));
        if (peer_channel) {
            new_channel->handle = peer_channel->handle;
        }
    }
}

static ssh_channel_info_t*
get_channel_info_for_channel(struct ssh_peer_data *peer_data, uint32_t recipient_channel)
{
    if (peer_data->channel_handles == NULL) {
        return NULL;
    }
    ssh_channel_info_t *channel = wmem_map_lookup(peer_data->channel_handles, GUINT_TO_POINTER(recipient_channel));

    return channel;
}

static void
set_subdissector_for_channel(struct ssh_peer_data *peer_data, uint32_t recipient_channel, const uint8_t* subsystem_name)
{
    dissector_handle_t handle = NULL;
    if(0 == strcmp(subsystem_name, "sftp")) {
        handle = sftp_handle;
    }

    if (handle) {
        /* Map this handle to the recipient channel */
        ssh_channel_info_t *channel = NULL;
        if (peer_data->channel_handles == NULL) {
            peer_data->channel_handles = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        } else {
            channel = wmem_map_lookup(peer_data->channel_handles, GUINT_TO_POINTER(recipient_channel));
        }
        if (channel == NULL) {
            channel = wmem_new0(wmem_file_scope(), ssh_channel_info_t);
            channel->multisegment_pdus = wmem_tree_new(wmem_file_scope());
            wmem_map_insert(peer_data->channel_handles, GUINT_TO_POINTER(recipient_channel), channel);
        }
        channel->handle = handle;

        /* This recipient channel is the sender channel for the other side.
         * Do we know what the recipient channel on the other side is?  */
        struct ssh_peer_data *other_peer_data = get_other_peer_data(peer_data);

        wmem_map_t *channel_info = other_peer_data->channel_info;
        if (channel_info) {
            uint32_t sender_channel;
            if (wmem_map_lookup_extended(channel_info, GUINT_TO_POINTER(recipient_channel), NULL, (void**)&sender_channel)) {
                /* Yes. See the handle for the other side too. */
                if (other_peer_data->channel_handles == NULL) {
                    other_peer_data->channel_handles = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
                    channel = NULL;
                } else {
                    channel = wmem_map_lookup(other_peer_data->channel_handles, GUINT_TO_POINTER(sender_channel));
                }
                if (channel == NULL) {
                    channel = wmem_new0(wmem_file_scope(), ssh_channel_info_t);
                    channel->multisegment_pdus = wmem_tree_new(wmem_file_scope());
                    wmem_map_insert(other_peer_data->channel_handles, GUINT_TO_POINTER(sender_channel), channel);
                }
                channel->handle = handle;
            }
        }
    }
}

/* Channel mapping. }}} */

static int
ssh_dissect_connection_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, unsigned msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_GLOBAL_REQUEST){
                uint8_t* request_name;
                unsigned   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_global_request_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                request_name = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset, slen, ENC_ASCII|ENC_NA);
                proto_tree_add_item(msg_type_tree, hf_ssh_global_request_name, packet_tvb, offset, slen, ENC_ASCII);
                offset += slen;
                proto_tree_add_item(msg_type_tree, hf_ssh_global_request_want_reply, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                if (0 == strcmp(request_name, "hostkeys-00@openssh.com")) {
                    unsigned   alen;
                    proto_item *ti;
                    int dissected_len = 0;
                    alen = tvb_get_ntohl(packet_tvb, offset) ;
                    ti = proto_tree_add_item(msg_type_tree, hf_ssh_global_request_hostkeys_array_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_item *blob_tree = NULL;
                    blob_tree = proto_tree_add_subtree(msg_type_tree, packet_tvb, offset, alen, ett_userauth_pk_blob, NULL, "Public key blob");
                    dissected_len = ssh_dissect_public_key_blob(packet_tvb, pinfo, offset, blob_tree) - offset;
                    if(dissected_len!=(int)alen){
                        expert_add_info_format(pinfo, ti, &ei_ssh_packet_decode, "Decoded %d bytes, but packet length is %d bytes", dissected_len, alen);
                    }
                    offset += alen;
                }
        }
        return offset;
}

static int
ssh_dissect_local_extension(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, struct ssh_peer_data *peer_data, proto_item *msg_type_tree, unsigned msg_code) {
    unsigned slen;
    if (peer_data->global_data->ext_ping_openssh_offered && msg_code >= SSH_MSG_PING && msg_code <= SSH_MSG_PONG) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_ext_ping_msg_vals, "Unknown (%u)"));
        proto_tree_add_item(msg_type_tree, hf_ssh2_ext_ping_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        if (msg_code == SSH_MSG_PING) {
            slen = tvb_get_ntohl(packet_tvb, offset) ;
            proto_tree_add_item(msg_type_tree, hf_ssh_ping_data_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(msg_type_tree, hf_ssh_ping_data, packet_tvb, offset, slen, ENC_NA);
            offset += slen;
        } else if (msg_code == SSH_MSG_PONG) {
            slen = tvb_get_ntohl(packet_tvb, offset) ;
            proto_tree_add_item(msg_type_tree, hf_ssh_pong_data_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(msg_type_tree, hf_ssh_pong_data, packet_tvb, offset, slen, ENC_NA);
            offset += slen;
        }
    } else {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    return offset;
}

static int
ssh_dissect_public_key_blob(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree)
{
        (void)pinfo;
        unsigned   slen;
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
        unsigned   slen;
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

static FILE* ssh_debug_file;

static void
ssh_prefs_apply_cb(void)
{
    ssh_set_debug(ssh_debug_file_name);
}

static void
ssh_set_debug(const char* name)
{
    static int debug_file_must_be_closed;
    int         use_stderr;

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
ssh_debug_printf(const char* fmt, ...)
{
    va_list ap;

    if (!ssh_debug_file)
        return;

    va_start(ap, fmt);
    vfprintf(ssh_debug_file, fmt, ap);
    va_end(ap);
}

static void
ssh_print_data(const char* name, const unsigned char* data, size_t len)
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
            unsigned char c = data[j];
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
ssh_secrets_block_callback(const void *secrets, unsigned size)
{
    ssh_keylog_process_lines((const uint8_t *)secrets, size);
}

/* Functions for SSH random hashtables. {{{ */
static int
ssh_equal (const void *v, const void *v2)
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

static unsigned
ssh_hash  (const void *v)
{
    unsigned l,hash;
    const ssh_bignum* id;
    const unsigned* cur;

    if (v == NULL) {
        return 0;
    }

    hash = 0;
    id = (const ssh_bignum*) v;

    /*  id and id->data are mallocated in ssh_save_master_key().  As such 'data'
     *  should be aligned for any kind of access (for example as a unsigned as
     *  is done below).  The intermediate void* cast is to prevent "cast
     *  increases required alignment of target type" warnings on CPUs (such
     *  as SPARCs) that do not allow misaligned memory accesses.
     */
    cur = (const unsigned*)(void*) id->data;

    for (l=4; (l < id->length); l+=4, cur++)
        hash = hash ^ (*cur);

    return hash;
}

static void
ssh_free_glib_allocated_bignum(void *data)
{
    ssh_bignum * bignum;
    if (data == NULL) {
        return;
    }

    bignum = (ssh_bignum *) data;
    g_free(bignum->data);
    g_free(bignum);
}

static void
ssh_free_glib_allocated_entry(void *data)
{
    ssh_key_map_entry_t * entry;
    if (data == NULL) {
        return;
    }

    entry = (ssh_key_map_entry_t *) data;
    g_free(entry->type);
    ssh_free_glib_allocated_bignum(entry->key_material);
    g_free(entry);
}
/* Functions for SSH random hashtables. }}} */

static void
ssh_shutdown(void) {
    g_hash_table_destroy(ssh_master_key_map);
}

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

        { &hf_ssh2_ext_ping_msg_code,
          { "Message Code", "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_ext_ping_msg_vals), 0x0,
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

        { &hf_ssh_ext_count,
          { "Extension count", "ssh.extension.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_name_length,
          { "Extension name length", "ssh.extension.name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_name,
          { "Extension name", "ssh.extension.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_value_length,
          { "Extension value length", "ssh.extension.value_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_value,
          { "Extension value", "ssh.extension.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_server_sig_algs_algorithms,
          { "Accepted signature algorithms", "ssh.extension.server_sig_algs.algorithms",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_delay_compression_algorithms_client_to_server_length,
          { "Compression algorithms (client to server) length", "ssh.extension.delay_compression.compression_algorithms_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_delay_compression_algorithms_client_to_server,
          { "Compression algorithms (client to server)", "ssh.extension.delay_compression.compression_algorithms_client_to_server",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_delay_compression_algorithms_server_to_client_length,
          { "Compression algorithms (server to client) length", "ssh.extension.delay_compression.compression_algorithms_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_delay_compression_algorithms_server_to_client,
          { "Compression algorithms (server to client)", "ssh.extension.delay_compression.compression_algorithms_server_to_client",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_no_flow_control_value,
          { "No flow control flag", "ssh.extension.no_flow_control.value",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_elevation_value,
          { "Elevation flag", "ssh.extension.elevation.value",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ext_prop_publickey_algorithms_algorithms,
          { "Public key algorithms", "ssh.extension.prop_publickey_algorithms.algorithms",
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

        { &hf_ssh_ping_data_length,
          { "Data length", "ssh.ping_data_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ping_data,
          { "Data", "ssh.ping_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pong_data_length,
          { "Data length", "ssh.pong_data_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pong_data,
          { "Data", "ssh.pong_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
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
          { "Channel request name length", "ssh.channel_request_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_request_name,
          { "Channel request name", "ssh.channel_request_name",
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

        { &hf_ssh_reassembled_in,
          { "Reassembled PDU in frame", "ssh.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The PDU that doesn't end in this segment is reassembled in this frame", HFILL }},

        { &hf_ssh_reassembled_length,
          { "Reassembled PDU length", "ssh.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},

        { &hf_ssh_reassembled_data,
          { "Reassembled PDU data", "ssh.reassembled.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "The payload of multiple reassembled SSH segments", HFILL }},

        { &hf_ssh_segments,
          { "Reassembled SSH segments", "ssh.segments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_segment,
          { "SSH segment", "ssh.segment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_segment_overlap,
          { "Segment overlap", "ssh.segment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment overlaps with other segments", HFILL }},

        { &hf_ssh_segment_overlap_conflict,
          { "Conflicting data in segment overlap", "ssh.segment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping segments contained conflicting data", HFILL }},

        { &hf_ssh_segment_multiple_tails,
          { "Multiple tail segments found", "ssh.segment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when reassembling the pdu", HFILL }},

        { &hf_ssh_segment_too_long_fragment,
          { "Segment too long", "ssh.segment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment contained data past end of the pdu", HFILL }},

        { &hf_ssh_segment_error,
          { "Reassembling error", "ssh.segment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Reassembling error due to illegal segments", HFILL }},

        { &hf_ssh_segment_count,
          { "Segment count", "ssh.segment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_segment_data,
          { "SSH segment data", "ssh.segment.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "The payload of a single SSH segment", HFILL }
        },

    };

    static int *ett[] = {
        &ett_ssh,
        &ett_key_exchange,
        &ett_key_exchange_host_key,
        &ett_key_exchange_host_sig,
        &ett_extension,
        &ett_userauth_pk_blob,
        &ett_userauth_pk_signautre,
        &ett_ssh1,
        &ett_ssh2,
        &ett_key_init,
        &ett_ssh_segments,
        &ett_ssh_segment
    };

    static ei_register_info ei[] = {
        { &ei_ssh_packet_length,  { "ssh.packet_length.error", PI_PROTOCOL, PI_WARN, "Overly large number", EXPFILL }},
        { &ei_ssh_packet_decode,  { "ssh.packet_decode.error", PI_PROTOCOL, PI_WARN, "Packet decoded length not equal to packet length", EXPFILL }},
        { &ei_ssh_channel_number, { "ssh.channel_number.error", PI_PROTOCOL, PI_WARN, "Coud not find channel", EXPFILL }},
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

    ssh_master_key_map = g_hash_table_new_full(ssh_hash, ssh_equal, ssh_free_glib_allocated_bignum, ssh_free_glib_allocated_entry);
    prefs_register_filename_preference(ssh_module, "keylog_file", "Key log filename",
            "The path to the file which contains a list of key exchange secrets in the following format:\n"
            "\"<hex-encoded-cookie> <PRIVATE_KEY|SHARED_SECRET> <hex-encoded-key>\" (without quotes or leading spaces).\n",
            &pref_keylog_file, false);

    prefs_register_filename_preference(ssh_module, "debug_file", "SSH debug file",
        "Redirect SSH debug to the file specified. Leave empty to disable debugging "
        "or use \"" SSH_DEBUG_USE_STDERR "\" to redirect output to stderr.",
        &ssh_debug_file_name, true);

    secrets_register_type(SECRETS_TYPE_SSH, ssh_secrets_block_callback);

    ssh_handle = register_dissector("ssh", dissect_ssh, proto_ssh);
    reassembly_table_register(&ssh_reassembly_table, &tcp_reassembly_table_functions);
    register_shutdown_routine(ssh_shutdown);
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
