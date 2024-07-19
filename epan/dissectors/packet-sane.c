/* packet-sane.c
 * Routines for SANE dissection
 * Copyright 2024, James Ring <sjr@jdns.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * A dissector for the SANE protocol (https://sane-project.gitlab.io/standard/net.html).
 *
 * This dissector works only for the control protocol (typically between a
 * client on some ephemeral port and a server on port 6566). The data transfer
 * of scanned images is done on a separate connection. Future versions of this
 * dissector might provide dissected image information.
 *
 * SANE is a protocol layered on top of TCP. The main dissect_sane function
 * relies on tcp_dissect_pdus to reassemble large messages. The protocol has no
 * meta-information (e.g. length of packet, type of message), the only way you
 * can know the format of a response is to see the corresponding request. The
 * only way you can know the length of a PDU is to read and understand various
 * fields in the request/response.
 *
 * For these reasons, the get_sane_pdu_len function has to pretty much do all
 * the work of the dissector itself. There is probably a more elegant way to do
 * this without the duplication that exists between get_sane_pdu_len and
 * dissect_sane_pdu.
 */

/* TODO
 * - Setup proper request / response tracking, with
 *   - references to related packets,
 *   - response time indications.
 */

#include "config.h"

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/prefs.h>

#include "packet-tcp.h"

#define SANE_WORD_LENGTH 4
#define SANE_MODULE_NAME "sane"
#define SANE_PORT "6566"

static range_t *sane_server_ports;

static dissector_handle_t sane_handle;

static int hf_sane_opcode;
static int hf_sane_version;
static int hf_sane_version_major;
static int hf_sane_version_minor;
static int hf_sane_version_build;
static int hf_sane_username;
static int hf_sane_password;
static int hf_sane_string;
static int hf_sane_string_length;
static int hf_sane_array_length;
static int hf_sane_device_descriptor;
static int hf_sane_device_name;
static int hf_sane_device_vendor;
static int hf_sane_device_model;
static int hf_sane_device_type;
static int hf_sane_resource_name;
static int hf_sane_device_handle;
static int hf_sane_option_descriptor;
static int hf_sane_option_index;
static int hf_sane_option_control_action;
static int hf_sane_option_value_type;
static int hf_sane_option_length;
static int hf_sane_option_count;
static int hf_sane_option_name;
static int hf_sane_option_value;
static int hf_sane_option_string_value;
static int hf_sane_option_numeric_value;
static int hf_sane_option_boolean_value;
static int hf_sane_option_title;
static int hf_sane_option_description;
static int hf_sane_option_unit;
static int hf_sane_option_size;
static int hf_sane_option_capabilities;
static int hf_sane_option_constraints;
static int hf_sane_option_constraint_type;
static int hf_sane_option_possible_string_value;
static int hf_sane_option_possible_word_value;
static int hf_sane_option_range_min;
static int hf_sane_option_range_max;
static int hf_sane_option_range_quant;
static int hf_sane_status;
static int hf_sane_data_port;
static int hf_sane_byte_order;
static int hf_sane_pointer_value;
static int hf_sane_frame_format;
static int hf_sane_scan_line_count;
static int hf_sane_scan_pixel_depth;
static int hf_sane_scan_pixels_per_line;
static int hf_sane_scan_bytes_per_line;
static int hf_sane_scan_is_last_frame;
static int hf_sane_dummy_value;

#define SANE_CAP_NONE 0x00000000
#define SANE_CAP_SOFT_SELECT 0x00000001
#define SANE_CAP_HARD_SELECT 0x00000002
#define SANE_CAP_SOFT_DETECT 0x00000004
#define SANE_CAP_EMULATED 0x00000008
#define SANE_CAP_AUTOMATIC 0x00000010
#define SANE_CAP_INACTIVE 0x00000020
#define SANE_CAP_ADVANCED 0x00000040

static int hf_sane_option_capability_soft_select;
static int hf_sane_option_capability_hard_select;
static int hf_sane_option_capability_soft_detect;
static int hf_sane_option_capability_emulated;
static int hf_sane_option_capability_automatic;
static int hf_sane_option_capability_inactive;
static int hf_sane_option_capability_advanced;

#define SANE_INFO_INEXACT 0x00000001
#define SANE_INFO_RELOAD_OPTIONS 0x00000002
#define SANE_INFO_RELOAD_PARAMS 0x00000004

static int hf_sane_control_option_info;
static int hf_sane_control_option_inexact;
static int hf_sane_control_option_reload_options;
static int hf_sane_control_option_reload_params;

static int* const sane_cap_bits[] = {
    &hf_sane_option_capability_soft_select,
    &hf_sane_option_capability_hard_select,
    &hf_sane_option_capability_soft_detect,
    &hf_sane_option_capability_emulated,
    &hf_sane_option_capability_automatic,
    &hf_sane_option_capability_inactive,
    &hf_sane_option_capability_advanced,
    NULL,
};

static int* const sane_control_option_info_bits[] = {
    &hf_sane_control_option_inexact,
    &hf_sane_control_option_reload_options,
    &hf_sane_control_option_reload_params,
    NULL,
};

static int proto_sane;
static int ett_sane;
static int ett_sane_version;
static int ett_sane_string;
static int ett_sane_option;
static int ett_sane_option_value;
static int ett_sane_option_capabilities;
static int ett_sane_option_constraints;
static int ett_sane_control_option_info;
static int ett_sane_device_descriptor;

typedef enum {
    SANE_NET_UNKNOWN = -1,
    SANE_NET_INIT = 0,
    SANE_NET_GET_DEVICES = 1,
    SANE_NET_OPEN = 2,
    SANE_NET_CLOSE = 3,
    SANE_NET_GET_OPTION_DESCRIPTORS = 4,
    SANE_NET_CONTROL_OPTION = 5,
    SANE_NET_GET_PARAMETERS = 6,
    SANE_NET_START = 7,
    SANE_NET_CANCEL = 8,
    SANE_NET_AUTHORIZE = 9,
    SANE_NET_EXIT = 10,
} sane_rpc_code;

static const value_string opcode_vals[] = {
    {SANE_NET_INIT,                   "SANE_NET_INIT"},
    {SANE_NET_GET_DEVICES,            "SANE_NET_GET_DEVICES"},
    {SANE_NET_OPEN,                   "SANE_NET_OPEN"},
    {SANE_NET_CLOSE,                  "SANE_NET_CLOSE"},
    {SANE_NET_GET_OPTION_DESCRIPTORS, "SANE_NET_GET_OPTION_DESCRIPTORS"},
    {SANE_NET_CONTROL_OPTION,         "SANE_NET_CONTROL_OPTION"},
    {SANE_NET_GET_PARAMETERS,         "SANE_NET_GET_PARAMETERS"},
    {SANE_NET_START,                  "SANE_NET_START"},
    {SANE_NET_CANCEL,                 "SANE_NET_CANCEL"},
    {SANE_NET_AUTHORIZE,              "SANE_NET_AUTHORIZE"},
    {SANE_NET_EXIT,                   "SANE_NET_EXIT"},
    {0, NULL},
};

typedef enum {
    SANE_NO_CONSTRAINT = 0,
    SANE_CONSTRAINT_RANGE = 1,
    SANE_CONSTRAINT_WORD_LIST = 2,
    SANE_CONSTRAINT_STRING_LIST = 3,
} sane_constraint_type;

static const value_string sane_constraint_type_names[] = {
    {SANE_NO_CONSTRAINT,          "SANE_NO_CONSTRAINT"},
    {SANE_CONSTRAINT_RANGE,       "SANE_CONSTRAINT_RANGE"},
    {SANE_CONSTRAINT_WORD_LIST,   "SANE_CONSTRAINT_WORD_LIST"},
    {SANE_CONSTRAINT_STRING_LIST, "SANE_CONSTRAINT_STRING_LIST"},
    {0, NULL},
};

typedef enum {
    SANE_TYPE_BOOL = 0,
    SANE_TYPE_INT = 1,
    SANE_TYPE_FIXED = 2,
    SANE_TYPE_STRING = 3,
    SANE_TYPE_BUTTON = 4,
    SANE_TYPE_GROUP = 5,
} sane_value_type;

static const value_string sane_value_types[] = {
    {SANE_TYPE_BOOL,   "SANE_TYPE_BOOL"},
    {SANE_TYPE_INT,    "SANE_TYPE_INT"},
    {SANE_TYPE_FIXED,  "SANE_TYPE_FIXED"},
    {SANE_TYPE_STRING, "SANE_TYPE_STRING"},
    {SANE_TYPE_BUTTON, "SANE_TYPE_BUTTON"},
    {SANE_TYPE_GROUP,  "SANE_TYPE_GROUP"},
    {0, NULL},
};

static const value_string control_types[] = {
    {0, "SANE_ACTION_GET_VALUE"},
    {1, "SANE_ACTION_SET_VALUE"},
    {2, "SANE_ACTION_SET_AUTO"},
    {0, NULL},
};

typedef enum {
    SANE_UNIT_NONE = 0,
    SANE_UNIT_PIXEL = 1,
    SANE_UNIT_BIT = 2,
    SANE_UNIT_MM = 3,
    SANE_UNIT_DPI = 4,
    SANE_UNIT_PERCENT = 5,
    SANE_UNIT_MICROSECOND = 6,
} sane_option_unit;

static const value_string sane_option_units[] = {
    {SANE_UNIT_NONE,        "SANE_UNIT_NONE"},
    {SANE_UNIT_PIXEL,       "SANE_UNIT_PIXEL"},
    {SANE_UNIT_BIT,         "SANE_UNIT_BIT"},
    {SANE_UNIT_MM,          "SANE_UNIT_MM"},
    {SANE_UNIT_DPI,         "SANE_UNIT_DPI"},
    {SANE_UNIT_PERCENT,     "SANE_UNIT_PERCENT"},
    {SANE_UNIT_MICROSECOND, "SANE_UNIT_MICROSECOND"},
    {0, NULL},
};

static const value_string sane_option_unit_suffixes[] = {
    {1, "px"},
    {2, "bits"},
    {3, "mm"},
    {4, "dpi"},
    {5, "%"},
    {6, "ms"},
    {0, NULL},
};

typedef enum {
    SANE_STATUS_UNKNOWN = -1,
    SANE_STATUS_OK = 0,
} sane_status;

static const value_string status_values[] = {
    {0,  "SANE_STATUS_GOOD"},
    {1,  "SANE_STATUS_UNSUPPORTED"},
    {2,  "SANE_STATUS_CANCELLED"},
    {3,  "SANE_STATUS_DEVICE_BUSY"},
    {4,  "SANE_STATUS_INVAL"},
    {5,  "SANE_STATUS_EOF"},
    {6,  "SANE_STATUS_JAMMED"},
    {7,  "SANE_STATUS_NO_DOCS"},
    {8,  "SANE_STATUS_COVER_OPEN"},
    {9,  "SANE_STATUS_IO_ERROR"},
    {10, "SANE_STATUS_NO_MEM"},
    {11, "SANE_STATUS_ACCESS_DENIED"},
    {0, NULL},
};

static const value_string sane_frame_format_names[] = {
    {0, "SANE_FRAME_GRAY"},
    {1, "SANE_FRAME_RGB"},
    {2, "SANE_FRAME_RED"},
    {3, "SANE_FRAME_GREEN"},
    {4, "SANE_FRAME_BLUE"},
    {0, NULL},
};

typedef struct {
    bool is_request;
    sane_rpc_code opcode;
    uint32_t packet_num;
} sane_pdu;

/* Keep track of current request status during first pass.
   N.B. opcode is stored in per-frame data and read during subsequent passes.
   Could if necessary be expanded to include frame numbers and timestamps for
   more complete request/response tracking.
*/
typedef struct {
    bool     seen_request;
    sane_pdu last_request;
    bool     auth;
} sane_session;


typedef struct {
    tvbuff_t *tvb;
    int offset;
    int bytes_read;
} tvb_sane_reader;


static int
tvb_read_sane_word(tvb_sane_reader *r, uint32_t *dest) {
    if (tvb_captured_length_remaining(r->tvb, r->offset) < SANE_WORD_LENGTH) {
        return 0;
    }

    if (dest) {
        *dest = tvb_get_ntohl(r->tvb, r->offset);
    }
    r->offset += SANE_WORD_LENGTH;
    r->bytes_read += SANE_WORD_LENGTH;
    return SANE_WORD_LENGTH;
}

#define WORD_OR_RETURN(r, var) \
    do { if (tvb_read_sane_word((r), (var)) == 0) { return 0; } } while(0)


static int
tvb_read_sane_string(tvb_sane_reader *r, wmem_allocator_t *alloc, char **dest) {
    int str_len;
    WORD_OR_RETURN(r, &str_len);

    if (tvb_captured_length_remaining(r->tvb, r->offset) < str_len) {
        return 0;
    }

    if (dest) {
        *dest = tvb_get_string_enc(alloc, r->tvb, r->offset, str_len, ENC_ASCII | ENC_NA);
    }

    r->offset += str_len;
    r->bytes_read += str_len;
    return SANE_WORD_LENGTH + str_len;
}

#define STRING_OR_RETURN(r) \
    do { if (tvb_read_sane_string((r), NULL, NULL) == 0) { return 0; } } while(0)

static int
tvb_skip_bytes(tvb_sane_reader *r, int len) {
    if (tvb_captured_length_remaining(r->tvb, r->offset) < len) {
        return 0;
    }

    r->offset += len;
    r->bytes_read += len;
    return len;
}

/**
 * Returns the expected response type for the (presumed) response in `pinfo`.
 * This usually returns the opcode of the last request seen in the conversation,
 * except for special handling of the authorization flow, for example:
 *
 * Client: SANE_NET_OPEN request (1)
 * Server: SANE_NET_OPEN response, authentication resource set (2)
 * Client: SANE_NET_AUTHORIZE request, username+password sent (3)
 * Server: SANE_NET_AUTHORIZE response sent, success (4)
 * Server: SANE_NET_OPEN response immediately sent (5)
 *
 * In this case, if the expected response type of PDU 5 is SANE_NET_OPEN,
 * because the server is responding to the request sent in PDU 2.
 */
static sane_rpc_code
get_sane_expected_response_type(sane_session *sess, packet_info *pinfo) {

    /* Look up any previous result. N.B. as called for length *and* dissecting,
       there may already be a value stored on first pass! */
    if (PINFO_FD_VISITED(pinfo) || p_get_proto_data(wmem_file_scope(), pinfo, proto_sane, 0)) {
        return (sane_rpc_code)GPOINTER_TO_UINT(p_get_proto_data(wmem_file_scope(), pinfo, proto_sane, 0));
    }

    /* First pass. Will be response to last_request if set, or AUTH request if flag set. */
    sane_rpc_code code = SANE_NET_UNKNOWN;
    if (sess->seen_request) {
        if (sess->auth) {
            code = SANE_NET_AUTHORIZE;
            sess->auth = false;
        }
        else {
            code = sess->last_request.opcode;
        }
    }

    /* Remember this code for later queries. */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_sane, 0, GUINT_TO_POINTER(code));

    return code;
}

static proto_item *
dissect_sane_word(tvb_sane_reader *r, proto_tree *tree, int hfindex, int *word) {
    proto_item *item = proto_tree_add_item(tree, hfindex, r->tvb, r->offset, SANE_WORD_LENGTH,
                        ENC_BIG_ENDIAN);
    // safe to ignore the return value here, we're guaranteed to have enough bytes to
    // read a word.
    tvb_read_sane_word(r, word);
    return item;
}

/**
 * Dissects and returns a SANE-encoded string from `r`.
 *
 * Also creates a proto_item representing the string. The `format` string should
 * contain a string format specifier (i.e. "%s"), which will be replaced with the
 * consumed string in the proto_item's text.
 */
static char *
dissect_sane_string(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree, int hfindex, const char *format) {
    int offset = r->offset;
    char *str = "";
    int len = tvb_read_sane_string(r, pinfo->pool, &str);

    proto_item *str_item = proto_tree_add_item(tree, hf_sane_string, r->tvb, offset, len, ENC_NA);
    proto_tree *str_tree = proto_item_add_subtree(str_item, ett_sane_string);

    proto_item_set_text(str_item, format, str);
    proto_tree_add_item(str_tree, hf_sane_string_length, r->tvb, offset, SANE_WORD_LENGTH, ENC_BIG_ENDIAN);
    proto_tree_add_item(str_tree, hfindex, r->tvb, offset + SANE_WORD_LENGTH, len - SANE_WORD_LENGTH, ENC_NA);
    return str;
}

static void
dissect_sane_net_init_request(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    int version = 0;
    int offset = r->offset;
    proto_item *version_item = dissect_sane_word(r, tree, hf_sane_version, &version);
    proto_item *version_tree = proto_item_add_subtree(version_item, ett_sane_version);

    proto_item_append_text(version_item, " (major: %d, minor: %d, build: %d)", version >> 24,
                           (version >> 16) & 0xff, version & 0xffff);

    proto_tree_add_item(version_tree, hf_sane_version_major, r->tvb, offset, 1, ENC_NA);
    proto_tree_add_item(version_tree, hf_sane_version_minor, r->tvb, offset + 1, 1, ENC_NA);
    proto_tree_add_item(version_tree, hf_sane_version_build, r->tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    dissect_sane_string(r, pinfo, tree, hf_sane_username, "Username: %s");
}

static void
dissect_sane_net_open_request(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    dissect_sane_string(r, pinfo, tree, hf_sane_device_name, "Device name: %s");
}

static void
dissect_control_option_value(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    int value_type = 0;
    dissect_sane_word(r, tree, hf_sane_option_value_type, &value_type);

    proto_item *value_item = proto_tree_add_item(tree, hf_sane_option_value, r->tvb, r->offset, -1, ENC_NA);
    proto_tree *value_tree = proto_item_add_subtree(value_item, ett_sane_option_value);

    int array_length = 0;
    proto_item *length_item = dissect_sane_word(r, value_tree, hf_sane_option_length, &array_length);

    if (value_type == SANE_TYPE_STRING) {
        dissect_sane_string(r, pinfo, value_tree, hf_sane_option_string_value, "Option value: '%s'");
    } else {
        proto_item_append_text(length_item, " (vector of length %d)", array_length / SANE_WORD_LENGTH);
        dissect_sane_word(r, value_tree, hf_sane_array_length, &array_length);

        for (int i = 0; i < array_length; i++) {
            if (value_type == SANE_TYPE_FIXED) {
                int value = 0;
                proto_item *numeric_value = dissect_sane_word(r, value_tree, hf_sane_option_numeric_value, &value);
                proto_item_append_text(numeric_value, " (%f)", ((double) value) / (1 << 16));
            } else if (value_type == SANE_TYPE_INT) {
                int value = 0;
                proto_item *numeric_value = dissect_sane_word(r, value_tree, hf_sane_option_numeric_value, &value);
                proto_item_append_text(numeric_value, " (%d)", value);
            } else if (value_type == SANE_TYPE_BOOL) {
                dissect_sane_word(r, value_tree, hf_sane_option_boolean_value, NULL);
            }
        }
    }
}

static void
dissect_sane_net_control_option_request(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    dissect_sane_word(r, tree, hf_sane_device_handle, NULL);
    dissect_sane_word(r, tree, hf_sane_option_index, NULL);
    dissect_sane_word(r, tree, hf_sane_option_control_action, NULL);
    dissect_control_option_value(r, pinfo, tree);
}

static void
dissect_sane_net_authorize_request(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    dissect_sane_string(r, pinfo, tree, hf_sane_resource_name, "Authentication resource: %s");
    dissect_sane_string(r, pinfo, tree, hf_sane_username, "Username: %s");
    dissect_sane_string(r, pinfo, tree, hf_sane_password, "Password: %s");
}

/** Dissects a message whose only payload is a device handle. */
static void
dissect_sane_device_handle_request(tvb_sane_reader *r, proto_tree *tree) {
    dissect_sane_word(r, tree, hf_sane_device_handle, NULL);
}

static int
dissect_sane_request(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    unsigned opcode = SANE_NET_UNKNOWN;
    dissect_sane_word(r, tree, hf_sane_opcode, &opcode);
    proto_item_append_text(tree, ": %s request", val_to_str(opcode, opcode_vals, "Unknown opcode (%u)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s request", val_to_str(opcode, opcode_vals, "Unknown opcode (%u)"));

    switch (opcode) {
        case SANE_NET_INIT:
            dissect_sane_net_init_request(r, pinfo, tree);
            break;
        case SANE_NET_GET_DEVICES:
            // no additional payload here
            break;
        case SANE_NET_OPEN:
            dissect_sane_net_open_request(r, pinfo, tree);
            break;
        case SANE_NET_CONTROL_OPTION:
            dissect_sane_net_control_option_request(r, pinfo, tree);
            break;
        case SANE_NET_CLOSE:
        case SANE_NET_START:
        case SANE_NET_CANCEL:
        case SANE_NET_GET_PARAMETERS:
        case SANE_NET_GET_OPTION_DESCRIPTORS:
            dissect_sane_device_handle_request(r, tree);
            break;
        case SANE_NET_AUTHORIZE:
            dissect_sane_net_authorize_request(r, pinfo, tree);
            break;
    }

    return r->bytes_read;
}

static proto_item *
dissect_sane_status(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree, unsigned *status_ptr) {
    int offset = r->offset;
    unsigned status = SANE_STATUS_UNKNOWN;

    // Safe to ignore the return value here, we're guaranteed to have enough bytes to
    // read a word.
    tvb_read_sane_word(r, &status);

    proto_item_append_text(tree, " (%s)", val_to_str(status, status_values, "Unknown status (%u)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(status, status_values, "Unknown (%u)"));

    proto_item *status_item = proto_tree_add_item(tree, hf_sane_status, r->tvb, offset, SANE_WORD_LENGTH, ENC_BIG_ENDIAN);
    proto_item_append_text(status_item, " (%s)", val_to_str(status, status_values, "Unknown (%u)"));

    if (status_ptr) {
        *status_ptr = status;
    }

    return status_item;
}

static void
dissect_sane_net_init_response(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    unsigned status;
    dissect_sane_status(r, pinfo, tree, &status);

    int version = 0;
    proto_item *version_item = dissect_sane_word(r, tree, hf_sane_version, &version);
    proto_item *version_tree = proto_item_add_subtree(version_item, ett_sane_version);

    proto_item_append_text(version_item, " (major: %d, minor: %d, build: %d)", version >> 24,
                           (version >> 16) & 0xff, version & 0xffff);

    proto_tree_add_item(version_tree, hf_sane_version_major, r->tvb, SANE_WORD_LENGTH, 1, ENC_NA);
    proto_tree_add_item(version_tree, hf_sane_version_minor, r->tvb, SANE_WORD_LENGTH + 1, 1, ENC_NA);
    proto_tree_add_item(version_tree, hf_sane_version_build, r->tvb, SANE_WORD_LENGTH + 2, 2, ENC_BIG_ENDIAN);
}

static void
dissect_sane_net_open_response(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    unsigned status = SANE_STATUS_UNKNOWN;
    dissect_sane_status(r, pinfo, tree, &status);
    dissect_sane_word(r, tree, hf_sane_device_handle, NULL);
    dissect_sane_string(r, pinfo, tree, hf_sane_resource_name, "Authentication resource: '%s'");
}

static void
append_option_value(proto_item *item, int value, unsigned units, unsigned type) {
    switch (type) {
        case SANE_TYPE_INT:
            if (units) {
                proto_item_append_text(item, " (%d %s)", value,
                                    val_to_str_const(units, sane_option_unit_suffixes, "(unknown unit)"));
            } else {
                proto_item_append_text(item, " (%d)", value);
            }
            break;
        case SANE_TYPE_FIXED: {
            double fixed_val = ((double) value) / (1 << 16);
            if (units) {
                proto_item_append_text(item, " (%f %s)", fixed_val,
                                    val_to_str_const(units, sane_option_unit_suffixes, "(unknown unit)"));
            } else {
                proto_item_append_text(item, " (%f)", fixed_val);
            }
            break;
        }
        case SANE_TYPE_BOOL:
            proto_item_append_text(item, " (%s)", (value == 1) ? "True" : ((value == 0) ? "False" : "Invalid"));
            break;
        default:
            break;
    }
}

static void
dissect_sane_net_get_option_descriptors_response(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    int option_count = 0;
    dissect_sane_word(r, tree, hf_sane_option_count, &option_count);

    for (int i = 0; i < option_count; i++) {
        int unit = 0;
        int type = 0;
        int start_offset = r->offset;
        proto_item *option_item = proto_tree_add_item(tree, hf_sane_option_descriptor, r->tvb, start_offset, 0, ENC_NA);
        proto_tree *option_tree = proto_item_add_subtree(option_item, ett_sane_option);
        proto_item_set_text(option_item, "Option descriptor %d", i);

        dissect_sane_word(r, option_tree, hf_sane_pointer_value, NULL);
        char *option_name = dissect_sane_string(r, pinfo, option_tree, hf_sane_option_name, "Option name: %s");
        if (option_name && *option_name) {
            proto_item_append_text(option_item, " (%s)", option_name);
        }
        char *option_title = dissect_sane_string(r, pinfo, option_tree, hf_sane_option_title, "Option title: %s");
        if (!(option_name && *option_name) && (option_title && *option_title)) {
            proto_item_append_text(option_item, " (%s)", option_title);
        }
        dissect_sane_string(r, pinfo, option_tree, hf_sane_option_description, "Option description: %s");
        dissect_sane_word(r, option_tree, hf_sane_option_value_type, &type);
        dissect_sane_word(r, option_tree, hf_sane_option_unit, &unit);
        dissect_sane_word(r, option_tree, hf_sane_option_size, NULL);

        proto_tree_add_bitmask(option_tree, r->tvb, r->offset, hf_sane_option_capabilities,
                               ett_sane_option_capabilities,
                               sane_cap_bits, ENC_BIG_ENDIAN);
        /* XXX - Add consistency checks (expert items):
         * SANE_CAP_SOFT_SELECT set and SANE_CAP_HARD_SELECT set
         * SANE_CAP_SOFT_SELECT set and SANE_CAP_SOFT_DETECT not set
         */
        tvb_skip_bytes(r, SANE_WORD_LENGTH);

        int constraint_start = r->offset;
        proto_item *constraint_item = proto_tree_add_item(option_tree, hf_sane_option_constraints, r->tvb, constraint_start, 0, ENC_NA);
        proto_tree *constraint_tree = proto_item_add_subtree(constraint_item, ett_sane_option_constraints);

        int constraint_type = SANE_NO_CONSTRAINT;
        dissect_sane_word(r, constraint_tree, hf_sane_option_constraint_type, &constraint_type);
        proto_item_set_text(constraint_item, "Constraint type: %s",
                            val_to_str(constraint_type, sane_constraint_type_names, "Unknown (%u)"));

        int array_length = 0;
        int min = 0;
        int max = 0;
        int quant = 0;
        switch (constraint_type) {
            case SANE_CONSTRAINT_STRING_LIST:
                dissect_sane_word(r, constraint_tree, hf_sane_array_length, &array_length);

                for (int j = 0; j < array_length; j++) {
                    dissect_sane_string(r, pinfo, constraint_tree, hf_sane_option_possible_string_value, "Possible value: %s");
                }
                break;
            case SANE_CONSTRAINT_WORD_LIST:
                dissect_sane_word(r, constraint_tree, hf_sane_array_length, &array_length);

                for (int j = 0; j < array_length; j++) {
                    int value = 0;
                    proto_item *value_item = dissect_sane_word(r, constraint_tree, hf_sane_option_possible_word_value,
                                                               &value);
                    append_option_value(value_item, value, unit, type);
                }
                break;
            case SANE_CONSTRAINT_RANGE:
                dissect_sane_word(r, constraint_tree, hf_sane_pointer_value, NULL);

                proto_item *min_item = dissect_sane_word(r, constraint_tree, hf_sane_option_range_min, &min);
                append_option_value(min_item, min, unit, type);
                proto_item *max_item = dissect_sane_word(r, constraint_tree, hf_sane_option_range_max, &max);
                append_option_value(max_item, max, unit, type);
                proto_item *quant_item = dissect_sane_word(r, constraint_tree, hf_sane_option_range_quant, &quant);
                append_option_value(quant_item, quant, unit, type);
                break;
        }

        proto_item_set_len(constraint_item, r->offset - constraint_start);
        proto_item_set_len(option_item, r->offset - start_offset);
    }
}

static void
dissect_sane_net_start_response(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    dissect_sane_status(r, pinfo, tree, NULL);
    dissect_sane_word(r, tree, hf_sane_data_port, NULL);
    dissect_sane_word(r, tree, hf_sane_byte_order, NULL);
    dissect_sane_string(r, pinfo, tree, hf_sane_resource_name, "Authentication resource: %s");
}

static void
dissect_sane_net_get_parameters_response(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    dissect_sane_status(r, pinfo, tree, NULL);
    dissect_sane_word(r, tree, hf_sane_frame_format, NULL);
    dissect_sane_word(r, tree, hf_sane_scan_is_last_frame, NULL);
    dissect_sane_word(r, tree, hf_sane_scan_bytes_per_line, NULL);
    dissect_sane_word(r, tree, hf_sane_scan_pixels_per_line, NULL);
    dissect_sane_word(r, tree, hf_sane_scan_line_count, NULL);
    dissect_sane_word(r, tree, hf_sane_scan_pixel_depth, NULL);
}

static void
dissect_sane_net_control_option_response(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    dissect_sane_status(r, pinfo, tree, NULL);
    proto_tree_add_bitmask(tree, r->tvb, r->offset, hf_sane_control_option_info,
                           ett_sane_control_option_info,
                           sane_control_option_info_bits, ENC_BIG_ENDIAN);
    tvb_skip_bytes(r, SANE_WORD_LENGTH);
    dissect_control_option_value(r, pinfo, tree);
    dissect_sane_string(r, pinfo, tree, hf_sane_resource_name, "Authentication resource: %s");
}

static void
dissect_sane_dummy_response(tvb_sane_reader *r, proto_tree *tree) {
    dissect_sane_word(r, tree, hf_sane_dummy_value, NULL);
}

static void
dissect_sane_net_get_devices_response(tvb_sane_reader *r, packet_info *pinfo, proto_tree *tree) {
    dissect_sane_status(r, pinfo, tree, NULL);

    int array_len = 0;
    dissect_sane_word(r, tree, hf_sane_array_length, &array_len);
    for (int i = 0; i < array_len - 1; i++) {
        int offset = r->offset;
        proto_item *device_item = proto_tree_add_item(tree, hf_sane_device_descriptor, r->tvb, r->offset, -1, ENC_NA);
        proto_tree *device_tree = proto_item_add_subtree(device_item, ett_sane_device_descriptor);
        proto_item_set_text(device_item, "Device[%d] descriptor", i);

        dissect_sane_word(r, device_tree, hf_sane_pointer_value, NULL);
        dissect_sane_string(r, pinfo, device_tree, hf_sane_device_name, "Device name: %s");
        dissect_sane_string(r, pinfo, device_tree, hf_sane_device_vendor, "Device vendor: %s");
        dissect_sane_string(r, pinfo, device_tree, hf_sane_device_model, "Device model: %s");
        dissect_sane_string(r, pinfo, device_tree, hf_sane_device_type, "Device type: %s");
        proto_item_set_len(device_item, r->offset - offset);
    }

    dissect_sane_word(r, tree, hf_sane_pointer_value, NULL);
}

static void
dissect_sane_response(tvb_sane_reader *r, sane_session *sess, packet_info *pinfo, proto_tree *tree) {
    sane_rpc_code opcode = get_sane_expected_response_type(sess, pinfo);

    proto_item_append_text(tree, ": %s response", val_to_str(opcode, opcode_vals, "Unknown opcode (%u)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s response", val_to_str(opcode, opcode_vals, "Unknown opcode (%u)"));

    switch (opcode) {
        case SANE_NET_INIT:
            dissect_sane_net_init_response(r, pinfo, tree);
            break;
        case SANE_NET_OPEN:
            dissect_sane_net_open_response(r, pinfo, tree);
            break;
        case SANE_NET_GET_OPTION_DESCRIPTORS:
            dissect_sane_net_get_option_descriptors_response(r, pinfo, tree);
            break;
        case SANE_NET_START:
            dissect_sane_net_start_response(r, pinfo, tree);
            break;
        case SANE_NET_GET_PARAMETERS:
            dissect_sane_net_get_parameters_response(r, pinfo, tree);
            break;
        case SANE_NET_CONTROL_OPTION:
            dissect_sane_net_control_option_response(r, pinfo, tree);
            break;
        case SANE_NET_GET_DEVICES:
            dissect_sane_net_get_devices_response(r, pinfo, tree);
            break;
        case SANE_NET_CLOSE:
        case SANE_NET_CANCEL:
        case SANE_NET_AUTHORIZE:
            dissect_sane_dummy_response(r, tree);
            break;
        default:
            break;
    }
}

static int
dissect_sane_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tvb_sane_reader r = {.tvb = tvb, .bytes_read = 0, .offset = 0};

    conversation_t *conv = find_or_create_conversation(pinfo);
    if (!conv) {
        return 0;
    }

    sane_session *sess = conversation_get_proto_data(conv, proto_sane);
    DISSECTOR_ASSERT_HINT(sess, "no session found");

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SANE");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *sane_item = proto_tree_add_item(tree, proto_sane, r.tvb, 0, -1, ENC_NA);
    proto_tree *sane_tree = proto_item_add_subtree(sane_item, ett_sane);

    if (value_is_in_range(sane_server_ports, pinfo->destport)) {
        dissect_sane_request(&r, pinfo, sane_tree);
    } else {
        dissect_sane_response(&r, sess, pinfo, sane_tree);
    }

    proto_item_set_len(sane_item, r.bytes_read);
    return r.bytes_read;
}

/**
 * Returns the length, in bytes, of the SANE PDU beginning at the given offset
 * within the buffer. If the PDU appears to be a response from a client and its
 * type cannot be determined (e.g. because Wireshark never saw the request),
 * or if the PDU appears to be truncated and its length cannot be determined,
 * this function returns 0.
 */
static unsigned
get_sane_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_) {
    tvb_sane_reader r = {.tvb = tvb, .offset = offset, .bytes_read = 0};

    conversation_t *conv = find_or_create_conversation(pinfo);
    if (!conv) {
        return 0;
    }

    sane_session *sess = conversation_get_proto_data(conv, proto_sane);

    if (!sess) {
        sess = wmem_new0(wmem_file_scope(), sane_session);
        conversation_add_proto_data(conv, proto_sane, sess);
    }

    if (value_is_in_range(sane_server_ports, pinfo->destport)) {
        /* REQUEST */
        unsigned opcode;
        WORD_OR_RETURN(&r, &opcode);

        sane_pdu pdu = {
            .is_request = true,
            .opcode = opcode,
            .packet_num = pinfo->num
        };

        if (!PINFO_FD_VISITED(pinfo)) {
            sess->seen_request = true;
            if (opcode == SANE_NET_AUTHORIZE) {
                /* Just set this flag, so can remember op being authorised */
                sess->auth = true;
            }
            else {
                /* Remember normal request */
                sess->last_request = pdu;
                sess->auth = false;
            }
        }

        switch (opcode) {
            case SANE_NET_INIT:
                WORD_OR_RETURN(&r, NULL);
                STRING_OR_RETURN(&r);
                break;
            case SANE_NET_GET_DEVICES:
            case SANE_NET_EXIT:
                break;
            case SANE_NET_OPEN:
                STRING_OR_RETURN(&r);
                break;
            case SANE_NET_CLOSE:
            case SANE_NET_GET_OPTION_DESCRIPTORS:
            case SANE_NET_GET_PARAMETERS:
            case SANE_NET_START:
            case SANE_NET_CANCEL:
                WORD_OR_RETURN(&r, NULL);
                break;
            case SANE_NET_CONTROL_OPTION:
                for (int i = 0; i < 4; i++) {
                    WORD_OR_RETURN(&r, NULL);
                }
                unsigned value_size;
                WORD_OR_RETURN(&r, &value_size);

                // Pointer to void, contains an extra word for whether the pointer is NULL
                if (tvb_skip_bytes(&r, SANE_WORD_LENGTH + value_size) == 0) {
                    return 0;
                }

                break;
            case SANE_NET_AUTHORIZE:
                STRING_OR_RETURN(&r);
                STRING_OR_RETURN(&r);
                STRING_OR_RETURN(&r);
                break;
        }
    } else {
        /* RESPONSE */
        sane_rpc_code opcode = get_sane_expected_response_type(sess, pinfo);
        unsigned array_len;

        switch (opcode) {
            case SANE_NET_INIT:
                for (int i = 0; i < 2; i++) {
                    WORD_OR_RETURN(&r, NULL);
                }
                break;
            case SANE_NET_OPEN:
                // Status word
                WORD_OR_RETURN(&r, NULL);
                // Device handle
                WORD_OR_RETURN(&r, NULL);
                // Authentication resource name
                STRING_OR_RETURN(&r);
                break;

            case SANE_NET_GET_OPTION_DESCRIPTORS:
                WORD_OR_RETURN(&r, &array_len);

                for (unsigned i = 0; i < array_len; i++) {
                    WORD_OR_RETURN(&r, NULL);

                    // read name, title and description
                    for (int j = 0; j < 3; j++) {
                        STRING_OR_RETURN(&r);
                    }

                    for (int j = 0; j < 4; j++) {
                        WORD_OR_RETURN(&r, NULL);
                    }

                    // constraint type
                    unsigned constraint_type;
                    WORD_OR_RETURN(&r, &constraint_type);

                    unsigned string_count;
                    unsigned value_list_length;
                    switch (constraint_type) {
                        case SANE_CONSTRAINT_STRING_LIST:
                            WORD_OR_RETURN(&r, &string_count);

                            for (unsigned j = 0; j < string_count; j++) {
                                STRING_OR_RETURN(&r);
                            }
                            break;
                        case SANE_CONSTRAINT_WORD_LIST:
                            WORD_OR_RETURN(&r, &value_list_length);

                            for (unsigned j = 0; j < value_list_length; j++) {
                                WORD_OR_RETURN(&r, NULL);
                            }
                            break;
                        case SANE_CONSTRAINT_RANGE:
                            // Pointer to range, then min, max, quantization
                            for (unsigned j = 0; j < 4; j++) {
                                WORD_OR_RETURN(&r, NULL);
                            }
                            break;
                    }
                }
                break;
            case SANE_NET_CONTROL_OPTION:
                // Expected record format:
                // SANE_Status status
                // SANE_Word info
                // SANE_Word value_type
                // SANE_Word value_size
                // void *value
                // SANE_String *resource
                // See http://sane-project.org/html/doc017.html#s5.2.6.
                for (int i = 0; i < 3; i++) {
                    WORD_OR_RETURN(&r, NULL);
                }

                unsigned value_len;
                WORD_OR_RETURN(&r, &value_len);

                if (tvb_skip_bytes(&r, value_len + SANE_WORD_LENGTH) == 0) {
                    return 0;
                }

                STRING_OR_RETURN(&r);
                break;
            case SANE_NET_GET_DEVICES:
                WORD_OR_RETURN(&r, NULL);

                unsigned device_count;
                WORD_OR_RETURN(&r, &device_count);
                for (unsigned i = 0; i < device_count - 1; i++) {
                    WORD_OR_RETURN(&r, NULL);
                    STRING_OR_RETURN(&r);
                    STRING_OR_RETURN(&r);
                    STRING_OR_RETURN(&r);
                    STRING_OR_RETURN(&r);
                }
                WORD_OR_RETURN(&r, NULL);
                break;
            case SANE_NET_CLOSE:
                WORD_OR_RETURN(&r, NULL);
                break;
            case SANE_NET_START:
                for (int i = 0; i < 3; i++) {
                    WORD_OR_RETURN(&r, NULL);
                }
                STRING_OR_RETURN(&r);
                break;
            case SANE_NET_GET_PARAMETERS:
                for (int i = 0; i < 7; i++) {
                    WORD_OR_RETURN(&r, NULL);
                }
                break;
            case SANE_NET_CANCEL:
            case SANE_NET_AUTHORIZE:
                WORD_OR_RETURN(&r, NULL);
                break;
            default:
                break;
        }
    }

    return r.bytes_read;
}

static int
dissect_sane(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    tcp_dissect_pdus(tvb, pinfo, tree, true, SANE_WORD_LENGTH, get_sane_pdu_len, dissect_sane_pdu, data);
    return (int) tvb_reported_length(tvb);
}

static void
apply_sane_prefs(void) {
    sane_server_ports = prefs_get_range_value(SANE_MODULE_NAME, "tcp.port");
}

void proto_register_sane(void) {
    static hf_register_info hf[] = {
            {&hf_sane_opcode,
                    {
                            "Opcode",
                            "sane.opcode",
                            FT_UINT32,
                            BASE_DEC,
                            VALS(opcode_vals),
                            0,
                            "RPC request type",
                            HFILL,
                    }},
            {&hf_sane_version,
                    {
                            "Version",
                            "sane.version",
                            FT_UINT32,
                            BASE_HEX,
                            NULL,
                            0,
                            "Protocol version",
                            HFILL,
                    }},
            {&hf_sane_version_major,
                    {
                            "Version Major Number",
                            "sane.version.major",
                            FT_UINT8,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_version_minor,
                    {
                            "Version Minor Number",
                            "sane.version.minor",
                            FT_UINT8,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_version_build,
                    {
                            "Version Build Number",
                            "sane.version.build",
                            FT_UINT16,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_username,
                    {
                            "Username",
                            "sane.username",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_password,
                    {
                            "Password",
                            "sane.password",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_string,
                    {
                            "String",
                            "sane.string",
                            FT_NONE,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_string_length,
                    {
                            "String length",
                            "sane.string.length",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_array_length,
                    {
                            "Array length",
                            "sane.array.length",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_device_descriptor,
                    {
                            "Device descriptor",
                            "sane.device.descriptor",
                            FT_NONE,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_device_name,
                    {
                            "Device name",
                            "sane.device.name",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_device_vendor,
                    {
                            "Device vendor",
                            "sane.device.vendor",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_device_model,
                    {
                            "Device model",
                            "sane.device.model",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_device_type,
                    {
                            "Device type",
                            "sane.device.type",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_resource_name,
                    {
                            "Resource name",
                            "sane.resource.name",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_device_handle,
                    {
                            "Device handle",
                            "sane.device.handle",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_index,
                    {
                            "Option index",
                            "sane.option",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_control_action,
                    {
                            "Option control action",
                            "sane.option.action",
                            FT_UINT32,
                            BASE_DEC,
                            VALS(control_types),
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_length,
                    {
                            "Option value length",
                            "sane.option.length",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,

                    }},
            {&hf_sane_option_value_type,
                    {
                            "Option value type",
                            "sane.option.type",
                            FT_UINT32,
                            BASE_DEC,
                            VALS(sane_value_types),
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_status,
                    {
                            "Status",
                            "sane.status",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_count,
                    {
                            "Option count",
                            "sane.option_count",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_pointer_value,
                    {
                            "Pointer value",
                            "sane.pointer_value",
                            FT_UINT32,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_name,
                    {
                            "Option name",
                            "sane.option.name",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_title,
                    {
                            "Option title",
                            "sane.option.title",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_description,
                    {
                            "Option description",
                            "sane.option.description",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_descriptor,
                    {
                            "Option descriptor",
                            "sane.option.descriptor",
                            FT_BYTES,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_unit,
                    {
                            "Option unit",
                            "sane.option.unit",
                            FT_UINT32,
                            BASE_DEC,
                            VALS(sane_option_units),
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_size,
                    {
                            "Option size",
                            "sane.option.size",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_capabilities,
                    {
                            "Option capabilities",
                            "sane.option.capabilities",
                            FT_UINT32,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,

                    }},
            {&hf_sane_option_capability_soft_select,
                    {
                            "Can be changed in software",
                            "sane.option.soft_select",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            SANE_CAP_SOFT_SELECT,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_capability_hard_select,
                    {
                            "Requires user intervention to change",
                            "sane.option.hard_select",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            SANE_CAP_HARD_SELECT,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_capability_soft_detect,
                    {
                            "Can be detected by software",
                            "sane.option.soft_detect",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            SANE_CAP_SOFT_DETECT,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_capability_emulated,
                    {
                            "Emulated in software",
                            "sane.option.emulated",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            SANE_CAP_EMULATED,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_capability_automatic,
                    {
                            "Can be set automatically",
                            "sane.option.automatic",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            SANE_CAP_AUTOMATIC,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_capability_inactive,
                    {
                            "Inactive",
                            "sane.option.inactive",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            SANE_CAP_INACTIVE,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_capability_advanced,
                    {
                            "Advanced option",
                            "sane.option.advanced",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            SANE_CAP_ADVANCED,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_value,
                    {
                            "Option value",
                            "sane.option.value",
                            FT_NONE,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_string_value,
                    {
                            "Option string value",
                            "sane.option.value.string",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_numeric_value,
                    {
                            "Option numeric value",
                            "sane.option.value.numeric",
                            FT_UINT32,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_boolean_value,
                    {
                            "Option boolean value",
                            "sane.option.value.boolean",
                            FT_BOOLEAN,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_constraints,
                    {
                            "Option constraints",
                            "sane.option.constraints",
                            FT_BYTES,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_constraint_type,
                    {
                            "Option constraint type",
                            "sane.option.constraint_type",
                            FT_UINT32,
                            BASE_DEC,
                            VALS(sane_constraint_type_names),
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_possible_string_value,
                    {
                            "Possible option string value",
                            "sane.option.possible_string_value",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_possible_word_value,
                    {
                            "Possible option word value",
                            "sane.option.possible_word_value",
                            FT_UINT32,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_range_min,
                    {
                            "Option minimum value",
                            "sane.option.min_value",
                            FT_UINT32,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_range_max,
                    {
                            "Option maximum value",
                            "sane.option.max_value",
                            FT_UINT32,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_option_range_quant,
                    {
                            "Option value quantization",
                            "sane.option.quant",
                            FT_UINT32,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_data_port,
                    {
                            "Image data port number",
                            "sane.data_port",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_byte_order,
                    {
                            "Image data byte order",
                            "sane.byte_order",
                            FT_UINT32,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_frame_format,
                    {
                            "Image data frame format",
                            "sane.scan.frame_format",
                            FT_UINT32,
                            BASE_DEC,
                            VALS(sane_frame_format_names),
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_scan_line_count,
                    {
                            "Image data line count",
                            "sane.scan.line_count",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_scan_pixel_depth,
                    {
                            "Image data pixel depth",
                            "sane.scan.pixel_depth",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_scan_pixels_per_line,
                    {
                            "Image data pixels per line",
                            "sane.scan.pixels_per_line",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_scan_bytes_per_line,
                    {
                            "Image data bytes per line",
                            "sane.scan.bytes_per_line",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_scan_is_last_frame,
                    {
                            "Is last image data frame",
                            "sane.scan.last_frame",
                            FT_BOOLEAN,
                            BASE_NONE,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_dummy_value,
                    {
                            "Dummy value",
                            "sane.dummy_value",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_control_option_info,
                    {
                            "Control option info",
                            "sane.control_option.info",
                            FT_UINT32,
                            BASE_HEX,
                            NULL,
                            0,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_control_option_inexact,
                    {
                            "Inexact value selected",
                            "sane.control_option.info.inexact",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            SANE_INFO_INEXACT,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_control_option_reload_options,
                    {
                            "Client should reload options",
                            "sane.control_option.info.reload_options",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            SANE_INFO_RELOAD_OPTIONS,
                            NULL,
                            HFILL,
                    }},
            {&hf_sane_control_option_reload_params,
                    {
                            "Client should reload scan parameters",
                            "sane.control_option.info.reload_params",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            SANE_INFO_RELOAD_PARAMS,
                            NULL,
                            HFILL,
                    }},
    };


    static int *ett[] = {
        &ett_sane,
        &ett_sane_version,
        &ett_sane_string,
        &ett_sane_option,
        &ett_sane_option_value,
        &ett_sane_option_capabilities,
        &ett_sane_option_constraints,
        &ett_sane_control_option_info,
        &ett_sane_device_descriptor,
    };

    module_t *sane_module;

    proto_sane = proto_register_protocol("Scanner Access Now Easy", "SANE", "sane");
    proto_register_field_array(proto_sane, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector(SANE_MODULE_NAME, dissect_sane, proto_sane);

    /*
     * XXX - Required to be notified of server port changes,
     * while no other preferences are registered.
     */
    sane_module = prefs_register_protocol(proto_sane, apply_sane_prefs);
    (void)sane_module;
}

void
proto_reg_handoff_sane(void) {
    sane_handle = create_dissector_handle(dissect_sane, proto_sane);
    dissector_add_uint_range_with_preference("tcp.port", SANE_PORT, sane_handle);
    apply_sane_prefs();
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
