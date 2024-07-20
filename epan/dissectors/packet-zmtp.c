/* packet-zmtp.c
 * ZeroMQ Message Transport Protocol as described at https://rfc.zeromq.org/spec/23/
 * Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* N.B. this dissector aims to replace the popular lua dissector at
 * https://github.com/whitequark/zmtp-wireshark
 * Tries to support the same backward compatibility and
 * dissector table (TCP port -> protocol) as the Lua dissector, but also has UAT that will override.
 *
 * TODO: would be nice if entries added in the tables were automatically added to TCP port range..
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/uat.h>
#include <tap.h>
#include <ui/tap-credentials.h>

#include "packet-tcp.h"

static int credentials_tap;

static int proto_zmtp;

static int hf_zmtp_flags;
static int hf_zmtp_flags_reserved;
static int hf_zmtp_flags_command;
static int hf_zmtp_flags_long;
static int hf_zmtp_flags_more;
static int hf_zmtp_length;
static int hf_zmtp_data;
static int hf_zmtp_data_text;
static int hf_zmtp_signature;
static int hf_zmtp_padding;
static int hf_zmtp_version;
static int hf_zmtp_version_major;
static int hf_zmtp_version_minor;
static int hf_zmtp_mechanism;
static int hf_zmtp_as_server;
static int hf_zmtp_filler;
static int hf_zmtp_metadata_key;
static int hf_zmtp_metadata_value;
static int hf_zmtp_command_name_length;
static int hf_zmtp_command_name;
static int hf_zmtp_curvezmq_nonce;
static int hf_zmtp_curvezmq_box;
static int hf_zmtp_curvezmq_version;
static int hf_zmtp_curvezmq_version_major;
static int hf_zmtp_curvezmq_version_minor;
static int hf_zmtp_curvezmq_publickey;
static int hf_zmtp_curvezmq_signature;
static int hf_zmtp_curvezmq_cookie;
static int hf_zmtp_username;
static int hf_zmtp_password;
static int hf_zmtp_error_reason;
static int hf_zmtp_ping_ttl;
static int hf_zmtp_ping_context;

/* Subtrees */
static int ett_zmtp;
static int ett_zmtp_flags;
static int ett_zmtp_version;
static int ett_zmtp_curvezmq_version;

static dissector_handle_t zmtp_handle;

/* Forward declarations */
void proto_register_zmtp(void);
void proto_reg_handoff_zmtp(void);

static dissector_table_t zmtp_port_dissector_table;

/* User definable values */
static range_t *global_zmtp_port_range = NULL;


/**************************************************************************/
/* Conversation state                                                     */
/**************************************************************************/

typedef enum
{
    MECH_NULL=0, /* assuming as default */
    MECH_PLAIN,
    MECH_CURVE
} mechanism_type;

static const value_string mechanism_vals[] =
{
    { MECH_NULL,   "NULL" },
    { MECH_PLAIN,  "PLAIN" },
    { MECH_CURVE,  "CURVE" },
    { 0x0,   NULL }
};


typedef struct
{
    mechanism_type mechanism;
    uint32_t       mechanism_frame;
} zmtp_conversation_t;

static const value_string flags_vals[] =
{
    { 0xff,   "Greeting" },
    { 0x00,   "Data" },
    { 0x01,   "Data(+)" },
    { 0x02,   "Data" },
    { 0x03,   "Data(+)" },
    { 0x04,   "Command" },
    { 0x06,   "Command" },
	{ 0x0,   NULL }
};


/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

/* The data payload type of the data on certain TCP ports */
typedef struct {
    range_t  *tcp_port_range; /* dissect data on these tcp ports as protocol */
    char     *protocol;       /* protocol of data on these tcp ports */
} zmtp_tcp_protocol_t;

static zmtp_tcp_protocol_t* zmtp_tcp_protocols = NULL;
static unsigned num_zmtp_tcp_protocols = 0;

static void *
zmtp_tcp_protocols_copy_cb(void* n, const void* o, size_t siz _U_)
{
    zmtp_tcp_protocol_t* new_rec = (zmtp_tcp_protocol_t*)n;
    const zmtp_tcp_protocol_t* old_rec = (const zmtp_tcp_protocol_t*)o;

    /* Cpy interval values like int */
    memcpy(new_rec, old_rec, sizeof(zmtp_tcp_protocol_t));

    if (old_rec->tcp_port_range) {
        new_rec->tcp_port_range = range_copy(NULL, old_rec->tcp_port_range);
    }
    if (old_rec->protocol) {
        new_rec->protocol = g_strdup(old_rec->protocol);
    }

    return new_rec;
}

static bool
zmtp_tcp_protocols_update_cb(void *r, char **err)
{
    zmtp_tcp_protocol_t* rec = (zmtp_tcp_protocol_t*)r;
    static range_t *empty;

    empty = range_empty(NULL);
    if (ranges_are_equal(rec->tcp_port_range, empty)) {
        *err = g_strdup("Must specify TCP port(s) (like 8000 or 8000,8008-8088)");
        wmem_free(NULL, empty);
        return false;
    }

    wmem_free(NULL, empty);
    return true;
}

static void
zmtp_tcp_protocols_free_cb(void*r)
{
    zmtp_tcp_protocol_t* rec = (zmtp_tcp_protocol_t*)r;

    wmem_free(NULL, rec->tcp_port_range);
    g_free(rec->protocol);
}

UAT_RANGE_CB_DEF(zmtp_tcp_protocols, tcp_port_range, zmtp_tcp_protocol_t)
UAT_CSTRING_CB_DEF(zmtp_tcp_protocols, protocol, zmtp_tcp_protocol_t)

/* Try to find matching data dissector name by TCP port */
static const char*
find_data_dissector_by_tcp_port(packet_info *pinfo)
{
    range_t* tcp_port_range;
    const char* protocol;
    unsigned i;
    for (i = 0; i < num_zmtp_tcp_protocols; ++i) {
        tcp_port_range = zmtp_tcp_protocols[i].tcp_port_range;
        if (value_is_in_range(tcp_port_range, pinfo->srcport) ||
            value_is_in_range(tcp_port_range, pinfo->destport)) {

            protocol = zmtp_tcp_protocols[i].protocol;
            if (protocol && strlen(protocol) > 0) {
                return protocol;
            }
        }
    }
    return NULL;
}



/* How long is this message (by checking flags+length). cb for tcp_dissect_pdus()  */
static unsigned
get_zmtp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint8_t flags = tvb_get_uint8(tvb, offset);
    uint64_t length;

    switch (flags) {
        case 0xff:        /* Greeting */
            return 64;

        /* 1-byte length field */
        case 0:           /* data short (last) */
        case 1:           /* data short (and more) */
        case 4:           /* command (short) */
            length = tvb_get_uint8(tvb, offset+1);
            return (unsigned)length + 2;

        /* 8-byte length field */
        case 2:           /* data long (last) */
        case 3:           /* data long (and more) */
        case 6:           /* command (long) */
            if (tvb_captured_length(tvb) < 9) {
                return 0;
            }
            length = tvb_get_ntoh64(tvb, offset+1);
            return (unsigned)length + 9;
    }

    return 0;
}

/* Dissect the payload of a data message */
static void dissect_zmtp_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, uint64_t length,
                              zmtp_conversation_t *p_conv_data)
{
    if (length == 0 || !p_conv_data) {
        return;
    }

    /* Show mechanism value */
    proto_item *mech_ti = proto_tree_add_string(tree, hf_zmtp_mechanism, tvb, 0, 0,
                                                val_to_str_const(p_conv_data->mechanism, mechanism_vals, "Unknown"));
    proto_item_set_generated(mech_ti);

    /* Is data all text? */
    bool all_text = true;
    for (uint64_t n=offset; n < tvb_captured_length(tvb); n++) {
        if (!g_ascii_isprint(tvb_get_uint8(tvb, offset))) {
            all_text = false;
            break;
        }
    }

    /* Add data as raw bytes */
    proto_item *raw_data_ti = proto_tree_add_item(tree, hf_zmtp_data, tvb, offset, -1, ENC_NA);
    /* If all text, prefer to show as text (bytes filter is still there) */
    if (all_text) {
        proto_item_set_hidden(raw_data_ti);
        proto_tree_add_item(tree, hf_zmtp_data_text, tvb, offset, -1, ENC_ASCII);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "(%" PRIu64 " bytes) ", length);

    /* Should only try to make any more sense of data if mechanism is not encrypted.. */
    if (p_conv_data->mechanism == MECH_CURVE) {
        return;
    }

    /* Get data tvb ready */
    tvbuff_t *data_tvb = tvb_new_subset_remaining(tvb, offset);

    /* Look up UAT for dissector to use */
    const char *protocol = find_data_dissector_by_tcp_port(pinfo);
    if (protocol) {
        dissector_handle_t protocol_handle = find_dissector(protocol);
        if (protocol_handle) {
            TRY {
                col_set_writable(pinfo->cinfo, COL_INFO, false);
                call_dissector_only(protocol_handle, data_tvb, pinfo, tree, NULL);
                col_set_writable(pinfo->cinfo, COL_INFO, true);
            }
            CATCH_ALL {
            }
            ENDTRY

            return;
        }
    }

    /* Look up registered dissector table (try both ports) */
    if (dissector_try_uint(zmtp_port_dissector_table, pinfo->destport, data_tvb, pinfo, tree)) {
        return;
    }
    if (dissector_try_uint(zmtp_port_dissector_table, pinfo->srcport, data_tvb, pinfo, tree)) {
        return;
    }

    /* TODO: maybe call simple data dissector? */
}

/* Dissect key=data pairs to end of frame */
static void dissect_zmtp_metadata(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    unsigned length;
    while (tvb_reported_length_remaining(tvb, offset)) {
        /* Key */
        length = tvb_get_uint8(tvb, offset);
        offset++;
        const unsigned char *key;
        proto_tree_add_item_ret_string(tree, hf_zmtp_metadata_key, tvb, offset, length, ENC_ASCII, pinfo->pool, &key);
        offset += length;
        /* Data */
        length = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (length) {
            const unsigned char *value;
            proto_tree_add_item_ret_string(tree, hf_zmtp_metadata_value, tvb, offset, length, ENC_ASCII, pinfo->pool, &value);
            offset += length;
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s=%s", key, value);
        }
        else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", key);
        }
    }
}

/* These command details are largely taken from the Lua dissector */
static int dissect_zmtp_command(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree,
                                 mechanism_type mechanism)
{
    proto_item *len_ti, *mech_ti;

    /* Show mechanism value */
    mech_ti = proto_tree_add_string(tree, hf_zmtp_mechanism, tvb, 0, 0,
                                    val_to_str_const(mechanism, mechanism_vals, "Unknown"));
    proto_item_set_generated(mech_ti);

    /* command-name (len + bytes) */
    uint32_t command_name_length;
    const unsigned char *command_name;
    len_ti = proto_tree_add_item_ret_uint(tree, hf_zmtp_command_name_length, tvb, offset, 1, ENC_BIG_ENDIAN, &command_name_length);
    proto_item_set_hidden(len_ti);
    offset++;
    proto_tree_add_item_ret_string(tree, hf_zmtp_command_name, tvb, offset, command_name_length, ENC_ASCII, pinfo->pool, &command_name);
    col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ", command_name);
    offset += command_name_length;

    /* What comes next depends upon the command and mechanism setting */
    if (strcmp(command_name, "READY") == 0) {
        switch (mechanism) {
            case MECH_CURVE:
                proto_tree_add_item(tree, hf_zmtp_curvezmq_nonce, tvb, offset, 8, ENC_ASCII);
                offset += 8;
                proto_tree_add_item(tree, hf_zmtp_curvezmq_box, tvb, offset, -1, ENC_ASCII);
                break;
            default:
                /* Metadata */
                dissect_zmtp_metadata(tvb, offset, pinfo, tree);
                break;
        }
    }
    else if (strcmp(command_name, "HELLO") == 0) {
        switch (mechanism) {
            case MECH_PLAIN:
            {
                /* TODO: these could be empty. Check and show? */
                uint8_t len;

                /* Username */
                const unsigned char *username;
                len = tvb_get_uint8(tvb, offset);
                offset++;
                proto_item *username_ti = proto_tree_add_item_ret_string(tree, hf_zmtp_username, tvb, offset, len, ENC_ASCII, pinfo->pool, &username);
                offset += len;
                if (len == 0) {
                    proto_item_append_text(username_ti, " (empty)");
                }

                /* Password */
                const unsigned char *password;
                len = tvb_get_uint8(tvb, offset);
                offset++;
                proto_item *password_ti = proto_tree_add_item_ret_string(tree, hf_zmtp_password, tvb, offset, len, ENC_ASCII, pinfo->pool, &password);
                offset += len;
                if (len == 0) {
                    proto_item_append_text(password_ti, " (empty)");
                }

                col_append_fstr(pinfo->cinfo, COL_INFO, "(username=%s, password=%s) ",
                                username, password);
                /* Also tap credentials */
                tap_credential_t* auth = wmem_new0(wmem_packet_scope(), tap_credential_t);
                auth->num = pinfo->num;
                auth->proto = "ZMTP";
                auth->password_hf_id = hf_zmtp_password;
                auth->username = (char*)username;
                auth->username_num = pinfo->num;
                auth->info = wmem_strdup_printf(wmem_packet_scope(), "PLAIN: username/password");
                tap_queue_packet(credentials_tap, pinfo, auth);
                break;
            }
            case MECH_CURVE:
            {
                /* Version */
                uint32_t major, minor;
                /* subtree */
                proto_item *version_ti = proto_tree_add_string_format(tree, hf_zmtp_curvezmq_version, tvb, offset, 2, "", "Version");
                proto_tree *version_tree = proto_item_add_subtree(version_ti, ett_zmtp_curvezmq_version);

                /* major */
                proto_tree_add_item_ret_uint(version_tree, hf_zmtp_curvezmq_version_major, tvb, offset, 1, ENC_NA, &major);
                offset++;
                /* minor */
                proto_tree_add_item_ret_uint(version_tree, hf_zmtp_curvezmq_version_minor, tvb, offset, 1, ENC_NA, &minor);
                offset++;
                proto_item_append_text(version_ti, " (%u.%u)", major, minor);

                /* If 1.0 */
                if (major==1 && minor==0) {
                    /* 70 bytes padding */
                    proto_tree_add_item(tree, hf_zmtp_padding, tvb, offset, 70, ENC_NA);
                    offset += 70;
                    /* 32 bytes publickey */
                    proto_tree_add_item(tree, hf_zmtp_curvezmq_publickey, tvb, offset, 32, ENC_ASCII);
                    offset += 32;
                    /* 8 bytes nonce */
                    proto_tree_add_item(tree, hf_zmtp_curvezmq_nonce, tvb, offset, 8, ENC_ASCII);
                    offset += 8;
                    /* 80 bytes signature */
                    proto_tree_add_item(tree, hf_zmtp_curvezmq_signature, tvb, offset, 80, ENC_ASCII);
                    offset += 80;
                }
                /* Else */
                /*     unsupported version (TODO: expert info?) */
                break;
            }
            default:
                break;
        }
    }
    else if (strcmp(command_name, "WELCOME") == 0) {
        switch (mechanism) {
            case MECH_CURVE:
                /* Nonce (16 bytes) */
                proto_tree_add_item(tree, hf_zmtp_curvezmq_nonce, tvb, offset, 16, ENC_ASCII);
                offset += 16;
                /* Box (128 bytes) */
                proto_tree_add_item(tree, hf_zmtp_curvezmq_box, tvb, offset, 128, ENC_ASCII);
                offset += 128;
                break;
            default:
                break;
        }

    }
    else if (strcmp(command_name, "INITIATE") == 0) {
        switch (mechanism) {
            case MECH_PLAIN:
                /* Metadata */
                dissect_zmtp_metadata(tvb, offset, pinfo, tree);
                break;
            case MECH_CURVE:
                /* cookie (96 bytes) */
                proto_tree_add_item(tree, hf_zmtp_curvezmq_cookie, tvb, offset, 96, ENC_ASCII);
                offset += 96;
                /* nonce (8 bytes) */
                proto_tree_add_item(tree, hf_zmtp_curvezmq_nonce, tvb, offset, 8, ENC_ASCII);
                offset += 8;
                /* box (remainder) */
                proto_tree_add_item(tree, hf_zmtp_curvezmq_box, tvb, offset, -1, ENC_ASCII);
                break;
            default:
                break;
        }
    }
    else if (strcmp(command_name, "ERROR") == 0) {
        /* 1 byte length, followed by reason */
        uint8_t len = tvb_get_uint8(tvb, offset);
        offset++;
        const unsigned char *reason;
        proto_tree_add_item_ret_string(tree, hf_zmtp_error_reason, tvb, offset, len, ENC_ASCII, pinfo->pool, &reason);
        col_append_fstr(pinfo->cinfo, COL_INFO, " reason=%s", reason);
        offset += len;
    }
    else if (strcmp(command_name, "PING") == 0) {
        /* TTL (2 bytes) */
        proto_tree_add_item(tree, hf_zmtp_ping_ttl, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        /* Context (optional, remainder) */
        if (tvb_captured_length_remaining(tvb, offset)) {
            proto_tree_add_item(tree, hf_zmtp_ping_context, tvb, offset, -1, ENC_ASCII);
        }
    }
    else if (strcmp(command_name, "PONG") == 0) {
        proto_tree_add_item(tree, hf_zmtp_ping_context, tvb, offset, -1, ENC_ASCII);
    }

    /* Extra separator in case data follows in same segment */
    col_append_str(pinfo->cinfo, COL_INFO, "  ");

    return offset;
}

static int
dissect_zmtp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *zmtp_tree;
    proto_item *root_ti;
    int offset = 0;

    /* Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "zmtp");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_zmtp, tvb, offset, -1, ENC_NA);
    zmtp_tree = proto_item_add_subtree(root_ti, ett_zmtp);

    /* Look up, or create, conversation */
    zmtp_conversation_t *p_conv_data;
    conversation_t *p_conv;

    p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                               conversation_pt_to_conversation_type(pinfo->ptype),
                               pinfo->destport, pinfo->srcport,
                               0 /* options */);

    /* Look up data from conversation */
    p_conv_data = (zmtp_conversation_t *)conversation_get_proto_data(p_conv, proto_zmtp);

    /* Create new data for conversation data if not found */
    if (!p_conv_data && !PINFO_FD_VISITED(pinfo)) {
        p_conv_data = wmem_new(wmem_file_scope(), zmtp_conversation_t);

        /* Set initial values */
        p_conv_data->mechanism = MECH_NULL;
        p_conv_data->mechanism_frame = 0;

        /* Store in conversation */
        conversation_add_proto_data(p_conv, proto_zmtp, p_conv_data);
    }

    /* Flags */
    uint8_t flags = tvb_get_uint8(tvb, offset);
    if (flags == 0xff) {
        /* Greeting value not broken down */
        proto_tree_add_item(zmtp_tree, hf_zmtp_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    else {
        /* Break it down */
        static int* const flags_fields[] = { &hf_zmtp_flags_reserved,
                                             &hf_zmtp_flags_command,
                                             &hf_zmtp_flags_long,
                                             &hf_zmtp_flags_more,
                                             NULL
                                           };
        proto_tree_add_bitmask(zmtp_tree, tvb, offset, hf_zmtp_flags,
                               ett_zmtp_flags, flags_fields, ENC_BIG_ENDIAN);
    }
	offset += 1;
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
                    val_to_str(flags, flags_vals, "Unknown(%u)"));
    proto_item_append_text(root_ti, " (%s)", val_to_str(flags, flags_vals, "Unknown(%u)"));

    uint64_t length;

    switch (flags) {
        case 0xff:        /* Greeting */
        {
            /* signature = %xFF padding %x7F */
            proto_tree_add_item(zmtp_tree, hf_zmtp_signature, tvb, offset-1, 10, ENC_NA);
            offset += 9;

            /* version = version-major version-minor */
            uint32_t major, minor;
            /* subtree */
            proto_item *version_ti = proto_tree_add_string_format(zmtp_tree, hf_zmtp_version, tvb, offset, 2, "", "Version");
            proto_tree *version_tree = proto_item_add_subtree(version_ti, ett_zmtp_version);
            /* major */
            proto_tree_add_item_ret_uint(version_tree, hf_zmtp_version_major, tvb, offset, 1, ENC_NA, &major);
            offset++;
            /* minor */
            proto_tree_add_item_ret_uint(version_tree, hf_zmtp_version_minor, tvb, offset, 1, ENC_NA, &minor);
            offset++;
            col_append_fstr(pinfo->cinfo, COL_INFO, "(version=%u.%u", major, minor);
            proto_item_append_text(version_ti, " (%u.%u)", major, minor);

            /* mechanism (20 bytes). N.B. *must* must match setting from peer */
            const unsigned char *mechanism;
            unsigned mechanism_len;
            proto_tree_add_item_ret_string_and_length(zmtp_tree, hf_zmtp_mechanism, tvb, offset, 20, ENC_ASCII,
                                                      pinfo->pool, &mechanism, &mechanism_len);
            offset += mechanism_len;
            col_append_fstr(pinfo->cinfo, COL_INFO, " mechanism=%s", mechanism);
            /* Store in conversation data whether NULL, PLAIN or CURVE */
            /* This affects what we expect to find in commands, and also whether can call dissectors to data payloads */
            if (!PINFO_FD_VISITED(pinfo)) {
                if (strcmp(mechanism, "NULL") == 0) {
                    p_conv_data->mechanism = MECH_NULL;
                }
                else if (strcmp(mechanism, "PLAIN") == 0) {
                    p_conv_data->mechanism = MECH_PLAIN;
                }
                else if (strcmp(mechanism, "CURVE") == 0) {
                    p_conv_data->mechanism = MECH_CURVE;
                }

                p_conv_data->mechanism_frame = pinfo->num;
            }

            /* as-server */
            bool as_server;
            proto_tree_add_item_ret_boolean(zmtp_tree, hf_zmtp_as_server, tvb, offset, 1, ENC_NA, &as_server);
            offset++;
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s)", tfs_get_string(as_server, &tfs_server_client));

            /* filler (31 octets) */
            proto_tree_add_item(zmtp_tree, hf_zmtp_filler, tvb, offset, -1, ENC_NA);
            break;
        }

        case 0x04:           /* Command (short) */
            /* Length */
            proto_tree_add_item_ret_uint64(zmtp_tree, hf_zmtp_length, tvb, offset, 1, ENC_BIG_ENDIAN, &length);
            offset++;
            if (p_conv_data) {
                dissect_zmtp_command(tvb, offset, pinfo, zmtp_tree, p_conv_data->mechanism);
            }
            break;
        case 0x06:           /* Command (long) */
            proto_tree_add_item_ret_uint64(zmtp_tree, hf_zmtp_length, tvb, offset, 8, ENC_BIG_ENDIAN, &length);
            offset += 8;
            if (p_conv_data) {
                dissect_zmtp_command(tvb, offset, pinfo, zmtp_tree, p_conv_data->mechanism);
            }
            break;

        case 0x0:           /* Data short (more) */
        case 0x1:           /* Data short (last) */
            proto_tree_add_item_ret_uint64(zmtp_tree, hf_zmtp_length, tvb, offset, 1, ENC_BIG_ENDIAN, &length);
            offset++;
            dissect_zmtp_data(tvb, offset, pinfo, zmtp_tree, length, p_conv_data);
            break;

        case 0x2:           /* Data long (last) */
        case 0x3:           /* Data long (more) */
            proto_tree_add_item_ret_uint64(zmtp_tree, hf_zmtp_length, tvb, offset, 8, ENC_BIG_ENDIAN, &length);
            offset += 8;
            dissect_zmtp_data(tvb, offset, pinfo, zmtp_tree, length, p_conv_data);
            break;

        default:
            /* TODO: expert info? */
            break;
    }

    col_set_fence(pinfo->cinfo, COL_INFO);

    /* Claim whole frame regardless */
    return tvb_reported_length(tvb);
}

/******************************/
/* Main dissection function.  */
static int
dissect_zmtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* Frame starts off with no PDUs seen */
    static bool false_value = false;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_zmtp, 0, &false_value);

    /* Find whole PDUs and send them to dissect_zmtp_message() */
    tcp_dissect_pdus(tvb, pinfo, tree, true, /* desegment */
                     2,                      /* need flags bytes + long-size */
                     get_zmtp_message_len,
                     dissect_zmtp_message, data);
    return tvb_reported_length(tvb);
}


void
proto_register_zmtp(void)
{
  static hf_register_info hf[] = {
      { &hf_zmtp_flags,
        { "Flags", "zmtp.flags", FT_UINT8, BASE_HEX,
          VALS(flags_vals), 0x0, NULL, HFILL }},
      { &hf_zmtp_flags_reserved,
        { "Reserved", "zmtp.flags.reserved", FT_UINT8, BASE_HEX,
          NULL, 0xf8, NULL, HFILL }},
      { &hf_zmtp_flags_command,
        { "Command", "zmtp.flags.command", FT_UINT8, BASE_HEX,
          NULL, 0x04, NULL, HFILL }},
      { &hf_zmtp_flags_long,
        { "Long", "zmtp.flags.long", FT_UINT8, BASE_HEX,
          NULL, 0x02, NULL, HFILL }},
      { &hf_zmtp_flags_more,
        { "More", "zmtp.flags.more", FT_UINT8, BASE_HEX,
          NULL, 0x01, NULL, HFILL }},
      { &hf_zmtp_length,
        { "Length", "zmtp.length", FT_UINT64, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_data,
        { "Data", "zmtp.data", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_data_text,
        { "Text", "zmtp.data.text", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_signature,
        { "Signature", "zmtp.signature", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_padding,
        { "Padding", "zmtp.padding", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_version,
        { "Version", "zmtp.version", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_version_major,
        { "Major version", "zmtp.version.major", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_version_minor,
        { "Minor version", "zmtp.version.minor", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_mechanism,
        { "Mechanism", "zmtp.mechanism", FT_STRINGZ, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_as_server,
        { "As-Server", "zmtp.as-server", FT_BOOLEAN, BASE_NONE,
          TFS(&tfs_server_client), 0x0, NULL, HFILL }},
      { &hf_zmtp_filler,
        { "Filler", "zmtp.filler", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_metadata_key,
        { "Metadata key", "zmtp.metadata.key", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_metadata_value,
        { "Metadata value", "zmtp.metadata.value", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_command_name_length,
        { "command-name length", "zmtp.command-name.length", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_command_name,
        { "command-name", "zmtp.command-name", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_curvezmq_nonce,
        { "CurveZMQ nonce", "zmtp.curvezmq.nonce", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_curvezmq_box,
        { "CurveZMQ box", "zmtp.curvezmq.box", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_curvezmq_version,
        { "Version", "zmtp.curvezmq.version", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_curvezmq_version_major,
        { "Major version", "zmtp.curvezmq.version.major", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_curvezmq_version_minor,
        { "Minor version", "zmtp.curvezmq.version.minor", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_curvezmq_publickey,
        { "PublicKey", "zmtp.curvezmq.publickey", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_curvezmq_signature,
        { "Signature", "zmtp.curvezmq.signature", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_curvezmq_cookie,
        { "Cookie", "zmtp.curvezmq.cookie", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_username,
        { "Username", "zmtp.username", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_password,
        { "Password", "zmtp.password", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_error_reason,
        { "Reason", "zmtp.reason", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_ping_ttl,
        { "TTL", "zmtp.ping.ttl", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_zmtp_ping_context,
        { "Context", "zmtp.ping.context", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }}
    };

    static int *ett[] = {
        &ett_zmtp,
        &ett_zmtp_flags,
        &ett_zmtp_version,
        &ett_zmtp_curvezmq_version
    };

    module_t *zmtp_module;

    static uat_field_t zmtp_tcp_protocols_table_columns[] = {
        UAT_FLD_RANGE(zmtp_tcp_protocols, tcp_port_range, "TCP Ports", 0xFFFF, "TCP ports on which ZMTP data payloads will be dissected as protocol"),
        UAT_FLD_CSTRING(zmtp_tcp_protocols, protocol, "Protocol", "Protocol for data on these TCP ports"),
        UAT_END_FIELDS
    };
    uat_t* zmtp_tcp_protocols_uat;

    proto_zmtp = proto_register_protocol("ZeroMQ Message Transport Protocol", "ZMTP", "zmtp");
    proto_register_field_array(proto_zmtp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    zmtp_handle = register_dissector("zmtp", dissect_zmtp, proto_zmtp);

    zmtp_module = prefs_register_protocol(proto_zmtp, proto_reg_handoff_zmtp);

    zmtp_tcp_protocols_uat = uat_new("ZMTP TCP Protocols",
        sizeof(zmtp_tcp_protocol_t),
        "zmtp_tcp_protocols",
        true,
        &zmtp_tcp_protocols,
        &num_zmtp_tcp_protocols,
        UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
        NULL, /* "ChZMTPTCPProtocols", */
        zmtp_tcp_protocols_copy_cb,
        zmtp_tcp_protocols_update_cb,
        zmtp_tcp_protocols_free_cb,
        NULL,                 /* post_update_cb */
        NULL,                 /* reset_cb */
        zmtp_tcp_protocols_table_columns
    );
    prefs_register_uat_preference(zmtp_module, "tcp_protocols", "ZMTP TCP protocols",
        "Specify the protocol of data on certain TCP ports.",
        zmtp_tcp_protocols_uat);

    zmtp_port_dissector_table = register_dissector_table("zmtp.protocol",
                                    "ZMTP Data Type", proto_zmtp, FT_UINT16, BASE_DEC);

    credentials_tap = register_tap("credentials");
}

static void
apply_zmtp_prefs(void)
{
    global_zmtp_port_range = prefs_get_range_value("zmtp", "tcp.port");
}

void
proto_reg_handoff_zmtp(void)
{
    dissector_add_uint_range_with_preference("tcp.port", "", zmtp_handle);
    apply_zmtp_prefs();
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
