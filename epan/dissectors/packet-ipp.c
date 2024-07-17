/* packet-ipp.c
 * Routines for IPP packet disassembly
 *
 * Guy Harris <guy@alum.mit.edu>
 *     (original implementation)
 * Michael R Sweet <michael.r.sweet@gmail.com>
 *     (general improvements and support beyond RFC 2910/2911)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>
#include "packet-http.h"
#include "packet-media-type.h"
#include "packet-tls.h"

void proto_register_ipp(void);
void proto_reg_handoff_ipp(void);

static dissector_handle_t ipp_handle;

static int proto_ipp;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_ipp_version;
static int hf_ipp_operation_id;
static int hf_ipp_status_code;
static int hf_ipp_request_id;
static int hf_ipp_name;
static int hf_ipp_memberattrname;
static int hf_ipp_outofband_value;
static int hf_ipp_charstring_value;
static int hf_ipp_boolean_value;
static int hf_ipp_enum_value;
static int hf_ipp_enum_value_printer_state;
static int hf_ipp_enum_value_job_state;
static int hf_ipp_enum_value_document_state;
static int hf_ipp_enum_value_operations_supported;
static int hf_ipp_enum_value_finishings;
static int hf_ipp_enum_value_orientation;
static int hf_ipp_enum_value_print_quality;
static int hf_ipp_enum_value_transmission_status;
static int hf_ipp_integer_value;
static int hf_ipp_octetstring_value;
static int hf_ipp_datetime_value;
static int hf_ipp_resolution_value;
static int hf_ipp_rangeofinteger_value;
static int hf_ipp_textwithlanguage_value;
static int hf_ipp_namewithlanguage_value;
static int hf_ipp_unknown_value;

static int hf_ipp_response_in;
static int hf_ipp_response_to;
static int hf_ipp_response_time;

typedef struct _ipp_transaction_t {
        uint32_t req_frame;
        uint32_t rep_frame;
        nstime_t req_time;
} ipp_transaction_t;

typedef struct _ipp_conv_info_t {
        wmem_map_t *pdus;
} ipp_conv_info_t;

static int ett_ipp;
static int ett_ipp_as;
static int ett_ipp_attr;
static int ett_ipp_member;

#define PRINT_JOB              0x0002
#define PRINT_URI              0x0003
#define VALIDATE_JOB           0x0004
#define CREATE_JOB             0x0005
#define SEND_DOCUMENT          0x0006
#define SEND_URI               0x0007
#define CANCEL_JOB             0x0008
#define GET_JOB_ATTRIBUTES     0x0009
#define GET_JOBS               0x000A
#define GET_PRINTER_ATTRIBUTES 0x000B

static const value_string operation_vals[] = {
    { PRINT_JOB,              "Print-Job" },
    { PRINT_URI,              "Print-URI" },
    { VALIDATE_JOB,           "Validate-Job" },
    { CREATE_JOB,             "Create-Job" },
    { SEND_DOCUMENT,          "Send-Document" },
    { SEND_URI,               "Send-URI" },
    { CANCEL_JOB,             "Cancel-Job" },
    { GET_JOB_ATTRIBUTES,     "Get-Job-Attributes" },
    { GET_JOBS,               "Get-Jobs" },
    { GET_PRINTER_ATTRIBUTES, "Get-Printer-Attributes" },
    { 0x000C,                 "Hold-Job" },
    { 0x000D,                 "Release-Job" },
    { 0x000E,                 "Restart-Job" },
    { 0x0010,                 "Pause-Printer" },
    { 0x0011,                 "Resume-Printer" },
    { 0x0012,                 "Purge-Jobs" },
    { 0x0013,                 "Set-Printer-Attributes" },
    { 0x0014,                 "Set-Job-Attributes" },
    { 0x0015,                 "Get-Printer-Supported-Values" },
    { 0x0016,                 "Create-Printer-Subscriptions" },
    { 0x0017,                 "Create-Job-Subscriptions" },
    { 0x0018,                 "Get-Subscription-Attributes" },
    { 0x0019,                 "Get-Subscriptions" },
    { 0x001A,                 "Renew-Subscription" },
    { 0x001B,                 "Cancel-Subscription" },
    { 0x001C,                 "Get-Notifications" },
    { 0x001D,                 "Reserved (ipp-indp-method)" },
    { 0x001E,                 "Reserved (ipp-get-resources)" },
    { 0x001F,                 "Reserved (ipp-get-resources)" },
    { 0x0020,                 "Reserved (ipp-get-resources)" },
    { 0x0021,                 "Reserved (ipp-install)" },
    { 0x0022,                 "Enable-Printer" },
    { 0x0023,                 "Disable-Printer" },
    { 0x0024,                 "Pause-Printer-After-Current-Job" },
    { 0x0025,                 "Hold-New-Jobs" },
    { 0x0026,                 "Release-Held-New-Jobs" },
    { 0x0027,                 "Deactivate-Printer" },
    { 0x0028,                 "Activate-Printer" },
    { 0x0029,                 "Restart-Printer" },
    { 0x002A,                 "Shutdown-Printer" },
    { 0x002B,                 "Startup-Printer" },
    { 0x002C,                 "Reprocess-Job" },
    { 0x002D,                 "Cancel-Current-Job" },
    { 0x002E,                 "Suspend-Current-Job" },
    { 0x002F,                 "Resume-Job" },
    { 0x0030,                 "Promote-Job" },
    { 0x0031,                 "Schedule-Job-After" },
    { 0x0033,                 "Cancel-Document" },
    { 0x0034,                 "Get-Document-Attributes" },
    { 0x0035,                 "Get-Documents" },
    { 0x0036,                 "Delete-Document" },
    { 0x0037,                 "Set-Document-Attributes" },
    { 0x0038,                 "Cancel-Jobs" },
    { 0x0039,                 "Cancel-My-Jobs" },
    { 0x003A,                 "Resubmit-Job" },
    { 0x003B,                 "Close-Job" },
    { 0x003C,                 "Identify-Printer" },
    { 0x003D,                 "Validate-Document" },
    { 0x003E,                 "Add-Document-Images" },
    { 0x003F,                 "Acknowledge-Document" },
    { 0x0040,                 "Acknowledge-Identify-Printer" },
    { 0x0041,                 "Acknowledge-Job" },
    { 0x0042,                 "Fetch-Document" },
    { 0x0043,                 "Fetch-Job" },
    { 0x0044,                 "Get-Output-Device-Attributes" },
    { 0x0045,                 "Update-Active-Jobs" },
    { 0x0046,                 "Deregister-Output-Device" },
    { 0x0047,                 "Update-Document-Status" },
    { 0x0048,                 "Update-Job-Status" },
    { 0x0049,                 "Update-Output-Device-Attributes" },
    { 0x004A,                 "Get-Next-Document-Data" },
    { 0x4001,                 "CUPS-Get-Default" },
    { 0x4002,                 "CUPS-Get-Printers" },
    { 0x4003,                 "CUPS-Add-Modify-Printer" },
    { 0x4004,                 "CUPS-Delete-Printer" },
    { 0x4005,                 "CUPS-Get-Classes" },
    { 0x4006,                 "CUPS-Add-Modify-Class" },
    { 0x4007,                 "CUPS-Delete-Class" },
    { 0x4008,                 "CUPS-Accept-Jobs" },
    { 0x4009,                 "CUPS-Reject-Jobs" },
    { 0x400A,                 "CUPS-Set-Default" },
    { 0x400B,                 "CUPS-Get-Devices" },
    { 0x400C,                 "CUPS-Get-PPDs" },
    { 0x400D,                 "CUPS-Move-Job" },
    { 0x400E,                 "CUPS-Authenticate-Job" },
    { 0x400F,                 "CUPS-Get-PPD" },
    { 0x4027,                 "CUPS-Get-Document" },
    { 0x4028,                 "CUPS-Create-Local-Printer" },
    { 0,                      NULL }
};

/* Printer States */
#define PRINTER_STATE_IDLE      0x3
#define PRINTER_STATE_PROCESSING    0x4
#define PRINTER_STATE_STOPPED       0x5
static const value_string printer_state_vals[] = {
    { PRINTER_STATE_IDLE,       "idle" },
    { PRINTER_STATE_PROCESSING, "processing" },
    { PRINTER_STATE_STOPPED,    "stopped" },
    { 0, NULL }
};

/* Job States */
static const value_string job_state_vals[] = {
    { 3, "pending" },
    { 4, "pending-held" },
    { 5, "processing" },
    { 6, "processing-stopped" },
    { 7, "canceled" },
    { 8, "aborted" },
    { 9, "completed" },
    { 0, NULL }
};

/* Document States */
static const value_string document_state_vals[] = {
    { 3, "pending" },
    { 5, "processing" },
    { 6, "processing-stopped" },
    { 7, "canceled" },
    { 8, "aborted" },
    { 9, "completed" },
    { 0, NULL }
};

/* Finishings Values */
static const value_string finishings_vals[] = {
    { 3, "none" },
    { 4, "staple" },
    { 5, "punch" },
    { 6, "cover" },
    { 7, "bind" },
    { 8, "saddle-stitch" },
    { 9, "edge-stitch" },
    { 10, "fold" },
    { 11, "trim" },
    { 12, "bale" },
    { 13, "booklet-maker" },
    { 14, "jog-offset" },
    { 15, "coat" },
    { 16, "laminate" },
    { 20, "staple-top-left" },
    { 21, "staple-bottom-left" },
    { 22, "staple-top-right" },
    { 23, "staple-bottom-right" },
    { 24, "edge-stitch-left" },
    { 25, "edge-stitch-top" },
    { 26, "edge-stitch-right" },
    { 27, "edge-stitch-bottom" },
    { 28, "staple-dual-left" },
    { 29, "staple-dual-top" },
    { 30, "staple-dual-right" },
    { 31, "staple-dual-bottom" },
    { 32, "staple-triple-left" },
    { 33, "staple-triple-top" },
    { 34, "staple-triple-right" },
    { 35, "staple-triple-bottom" },
    { 50, "bind-left" },
    { 51, "bind-top" },
    { 52, "bind-right" },
    { 53, "bind-bottom" },
    { 60, "trim-after-pages" },
    { 61, "trim-after-documents" },
    { 62, "trim-after-copies" },
    { 63, "trim-after-job" },
    { 70, "punch-top-left" },
    { 71, "punch-bottom-left" },
    { 72, "punch-top-right" },
    { 73, "punch-bottom-right" },
    { 74, "punch-dual-left" },
    { 75, "punch-dual-top" },
    { 76, "punch-dual-right" },
    { 77, "punch-dual-bottom" },
    { 78, "punch-triple-left" },
    { 79, "punch-triple-top" },
    { 80, "punch-triple-right" },
    { 81, "punch-triple-bottom" },
    { 82, "punch-quad-left" },
    { 83, "punch-quad-top" },
    { 84, "punch-quad-right" },
    { 85, "punch-quad-bottom" },
    { 86, "punch-multiple-left" },
    { 87, "punch-multiple-top" },
    { 88, "punch-multiple-right" },
    { 89, "punch-multiple-bottom" },
    { 90, "fold-accordion" },
    { 91, "fold-double-gate" },
    { 92, "fold-gate" },
    { 93, "fold-half" },
    { 94, "fold-half-z" },
    { 95, "fold-left-gate" },
    { 96, "fold-letter" },
    { 97, "fold-parallel" },
    { 98, "fold-poster" },
    { 99, "fold-right-gate" },
    { 100, "fold-z" },
    { 0, NULL }
};

static const value_string orientation_vals[] = {
    { 3, "portrait" },
    { 4, "landscape" },
    { 5, "reverse-landscape" },
    { 6, "reverse-portrait" },
    { 7, "none" },
    { 0, NULL }
};

static const value_string quality_vals[] = {
    { 3, "draft" },
    { 4, "normal" },
    { 5, "high" },
    { 0, NULL }
};

static const value_string transmission_status_vals[] = {
    { 3, "pending" },
    { 4, "pending-retry" },
    { 5, "processing" },
    { 7, "canceled" },
    { 8, "aborted" },
    { 9, "completed" },
    { 0, NULL }
};


#define STATUS_SUCCESSFUL    0x0000
#define STATUS_INFORMATIONAL 0x0100
#define STATUS_REDIRECTION   0x0200
#define STATUS_CLIENT_ERROR  0x0400
#define STATUS_SERVER_ERROR  0x0500

#define STATUS_TYPE_MASK     0xFF00

static const value_string status_vals[] = {
    { 0x0000, "successful-ok" },
    { 0x0001, "successful-ok-ignored-or-substituted-attributes" },
    { 0x0002, "successful-ok-conflicting-attributes" },
    { 0x0003, "successful-ok-ignored-subscriptions" },
    { 0x0005, "successful-ok-too-many-events" },
    { 0x0007, "successful-ok-events-complete" },
    { 0x0400, "client-error-bad-request" },
    { 0x0401, "client-error-forbidden" },
    { 0x0402, "client-error-not-authenticated" },
    { 0x0403, "client-error-not-authorized" },
    { 0x0404, "client-error-not-possible" },
    { 0x0405, "client-error-timeout" },
    { 0x0406, "client-error-not-found" },
    { 0x0407, "client-error-gone" },
    { 0x0408, "client-error-request-entity-too-large" },
    { 0x0409, "client-error-request-value-too-long" },
    { 0x040A, "client-error-document-format-not-supported" },
    { 0x040B, "client-error-attributes-or-values-not-supported" },
    { 0x040C, "client-error-uri-scheme-not-supported" },
    { 0x040D, "client-error-charset-not-supported" },
    { 0x040E, "client-error-conflicting-attributes" },
    { 0x040F, "client-error-compression-not-supported" },
    { 0x0410, "client-error-compression-error" },
    { 0x0411, "client-error-document-format-error" },
    { 0x0412, "client-error-document-access-error" },
    { 0x0413, "client-error-attributes-not-settable" },
    { 0x0414, "client-error-ignored-all-subscriptions" },
    { 0x0415, "client-error-too-many-subscriptions" },
    { 0x0418, "client-error-document-password-error" },
    { 0x0419, "client-error-document-permission-error" },
    { 0x041A, "client-error-document-security-error" },
    { 0x041B, "client-error-document-unprintable-error" },
    { 0x041C, "client-error-account-info-needed" },
    { 0x041D, "client-error-account-closed" },
    { 0x041E, "client-error-account-limit-reached" },
    { 0x041F, "client-error-account-authorization-failed" },
    { 0x0420, "client-error-not-fetchable" },
    { 0x0500, "server-error-internal-error" },
    { 0x0501, "server-error-operation-not-supported" },
    { 0x0502, "server-error-service-unavailable" },
    { 0x0503, "server-error-version-not-supported" },
    { 0x0504, "server-error-device-error" },
    { 0x0505, "server-error-temporary-error" },
    { 0x0506, "server-error-not-accepting-jobs" },
    { 0x0507, "server-error-busy" },
    { 0x0508, "server-error-job-canceled" },
    { 0x0509, "server-error-multiple-document-jobs-not-supported" },
    { 0x050A, "server-error-printer-is-deactivated" },
    { 0x050B, "server-error-too-many-jobs" },
    { 0x050C, "server-error-too-many-documents" },
    { 0, NULL }
};

static int parse_attributes(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static proto_tree *add_integer_tree(proto_tree *tree, tvbuff_t *tvb,
                                        int offset, int name_length, const char *name, int value_length, uint8_t tag);
static void add_integer_value(const char *tag_desc, proto_tree *tree,
                                        tvbuff_t *tvb, int offset, int name_length, const char *name, int value_length, uint8_t tag);
static proto_tree *add_octetstring_tree(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
                                        int offset, int name_length, const char *name, int value_length, uint8_t tag);
static proto_tree *add_octetstring_value(const char *tag_desc, proto_tree *tree,
                                        tvbuff_t *tvb, packet_info *pinfo, int offset, int name_length, const char *name, int value_length, uint8_t tag);
static proto_tree *add_charstring_tree(proto_tree *tree, tvbuff_t *tvb,
                                        int offset, uint8_t tag, int name_length, const char *name, int value_length);
static void add_charstring_value(const char *tag_desc, proto_tree *tree,
                                        tvbuff_t *tvb, int offset, int name_length, const char *name, int value_length, uint8_t tag);
static int ipp_fmt_collection(tvbuff_t *tvb, packet_info *pinfo, int offset, char *buffer, int bufsize);

static int
dissect_ipp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree  *ipp_tree;
    proto_item  *ti;
    int         offset     = 0;
    media_content_info_t *content_info = (media_content_info_t *)data;
    bool        is_request;
    uint16_t    operation_status;
    const char *status_type;
    uint32_t	request_id;
    conversation_t *conversation;
    ipp_conv_info_t *ipp_info;
    ipp_transaction_t *ipp_trans;

    if (content_info != NULL) {
        switch (content_info->type) {

        case MEDIA_CONTAINER_HTTP_REQUEST:
            is_request = true;
            break;

        case MEDIA_CONTAINER_HTTP_RESPONSE:
            is_request = false;
            break;

        default:
            /* This isn't strictly correct, but we should never come here anyways */
            is_request = (pinfo->destport == pinfo->match_uint);
            break;
        }
    } else {
        /* This isn't strictly correct, but we should never come here anyways */
        is_request = (pinfo->destport == pinfo->match_uint);
    }

    operation_status = tvb_get_ntohs(tvb, 2);
    request_id       = tvb_get_ntohl(tvb, 4);

    if (proto_is_frame_protocol(pinfo->layers, "ippusb")) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPPUSB");
        if (is_request)
            col_add_fstr(pinfo->cinfo, COL_INFO, "IPPUSB Request (%s)", val_to_str(operation_status, operation_vals, "0x%04x"));
        else
            col_add_fstr(pinfo->cinfo, COL_INFO, "IPPUSB Response (%s)", val_to_str(operation_status, status_vals, "0x%04x"));
    } else {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPP");
        if (is_request)
            col_add_fstr(pinfo->cinfo, COL_INFO, "IPP Request (%s)", val_to_str(operation_status, operation_vals, "0x%04x"));
        else
            col_add_fstr(pinfo->cinfo, COL_INFO, "IPP Response (%s)", val_to_str(operation_status, status_vals, "0x%04x"));
    }

    ti = proto_tree_add_item(tree, proto_ipp, tvb, offset, -1, ENC_NA);
    ipp_tree = proto_item_add_subtree(ti, ett_ipp);

    conversation = find_or_create_conversation(pinfo);
    ipp_info = (ipp_conv_info_t *)conversation_get_proto_data(conversation, proto_ipp);
    if (!ipp_info) {
        ipp_info = wmem_new(wmem_file_scope(), ipp_conv_info_t);
        ipp_info->pdus=wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

        conversation_add_proto_data(conversation, proto_ipp, ipp_info);
    }
    if (!PINFO_FD_VISITED(pinfo)) {
        if (is_request) {
            /* This is a request */
            ipp_trans=wmem_new(wmem_file_scope(), ipp_transaction_t);
            ipp_trans->req_frame = pinfo->num;
            ipp_trans->rep_frame = 0;
            ipp_trans->req_time = pinfo->abs_ts;
            wmem_map_insert(ipp_info->pdus, GUINT_TO_POINTER(request_id), (void *)ipp_trans);
        } else {
            ipp_trans=(ipp_transaction_t *)wmem_map_lookup(ipp_info->pdus, GUINT_TO_POINTER(request_id));
            if (ipp_trans) {
                ipp_trans->rep_frame = pinfo->num;
            }
        }
    } else {
        ipp_trans=(ipp_transaction_t *)wmem_map_lookup(ipp_info->pdus, GUINT_TO_POINTER(request_id));
    }
    if (!ipp_trans) {
        /* create a "fake" ipp_trans structure */
        ipp_trans=wmem_new(pinfo->pool, ipp_transaction_t);
        ipp_trans->req_frame = 0;
        ipp_trans->rep_frame = 0;
        ipp_trans->req_time = pinfo->abs_ts;
    }

    /* print state tracking in the tree */
    if (is_request) {
        /* This is a request */
        if (ipp_trans->rep_frame) {
            proto_item *it;

            it = proto_tree_add_uint(ipp_tree, hf_ipp_response_in,
                            tvb, 0, 0, ipp_trans->rep_frame);
            proto_item_set_generated(it);
        }
    } else {
        /* This is a response */
        if (ipp_trans->req_frame) {
            proto_item *it;
            nstime_t ns;

            it = proto_tree_add_uint(ipp_tree, hf_ipp_response_to,
                            tvb, 0, 0, ipp_trans->req_frame);
            proto_item_set_generated(it);

            nstime_delta(&ns, &pinfo->abs_ts, &ipp_trans->req_time);
            it = proto_tree_add_time(ipp_tree, hf_ipp_response_time, tvb, 0, 0, &ns);
            proto_item_set_generated(it);
        }
    }

    proto_tree_add_item(ipp_tree, hf_ipp_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (is_request) {
        proto_tree_add_item(ipp_tree, hf_ipp_operation_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    } else {
        switch (operation_status & STATUS_TYPE_MASK) {

        case STATUS_SUCCESSFUL:
            status_type = "Successful";
            break;

        case STATUS_INFORMATIONAL:
            status_type = "Informational";
            break;

        case STATUS_REDIRECTION:
            status_type = "Redirection";
            break;

        case STATUS_CLIENT_ERROR:
            status_type = "Client Error";
            break;

        case STATUS_SERVER_ERROR:
            status_type = "Server Error";
            break;

        default:
            status_type = "Unknown";
            break;
        }
        proto_tree_add_uint_format_value(ipp_tree, hf_ipp_status_code, tvb, offset, 2, operation_status, "%s (%s)", status_type, val_to_str(operation_status, status_vals, "0x%04x"));
    }
    offset += 2;

    proto_tree_add_item(ipp_tree, hf_ipp_request_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = parse_attributes(tvb, pinfo, offset, ipp_tree);

    if (tvb_offset_exists(tvb, offset)) {
        call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, ipp_tree);
    }
    return tvb_captured_length(tvb);
}

#define TAG_TYPE(x)       ((x) & 0xF0)

#define TAG_TYPE_DELIMITER      0x00
#define TAG_TYPE_OUTOFBAND      0x10
#define TAG_TYPE_INTEGER        0x20
#define TAG_TYPE_OCTETSTRING    0x30
#define TAG_TYPE_CHARSTRING     0x40

#define TAG_END_OF_ATTRIBUTES   0x03

#define TAG_INTEGER             0x21
#define TAG_BOOLEAN             0x22
#define TAG_ENUM                0x23

#define TAG_OCTETSTRING         0x30
#define TAG_DATETIME            0x31
#define TAG_RESOLUTION          0x32
#define TAG_RANGEOFINTEGER      0x33
#define TAG_BEGCOLLECTION       0x34
#define TAG_TEXTWITHLANGUAGE    0x35
#define TAG_NAMEWITHLANGUAGE    0x36
#define TAG_ENDCOLLECTION       0x37

#define TAG_TEXTWITHOUTLANGUAGE 0x41
#define TAG_NAMEWITHOUTLANGUAGE 0x42
#define TAG_KEYWORD             0x44
#define TAG_URI                 0x45
#define TAG_URISCHEME           0x46
#define TAG_CHARSET             0x47
#define TAG_NATURALLANGUAGE     0x48
#define TAG_MIMEMEDIATYPE       0x49
#define TAG_MEMBERATTRNAME      0x4a

static const value_string tag_vals[] = {
    /* Delimiter tags */
    { 0x01,                    "operation-attributes-tag" },
    { 0x02,                    "job-attributes-tag" },
    { TAG_END_OF_ATTRIBUTES,   "end-of-attributes-tag" },
    { 0x04,                    "printer-attributes-tag" },
    { 0x05,                    "unsupported-attributes-tag" },
    { 0x06,                    "subscription-attributes-tag" },
    { 0x07,                    "event-notification-attributes-tag" },
    { 0x08,                    "resource-attributes-tag" },
    { 0x09,                    "document-attributes-tag" },

    /* Value tags */
    { 0x10,                    "unsupported" },
    { 0x12,                    "unknown" },
    { 0x13,                    "no-value" },
    { 0x15,                    "not-settable" },
    { 0x16,                    "delete-attribute" },
    { 0x17,                    "admin-define" },
    { TAG_INTEGER,             "integer" },
    { TAG_BOOLEAN,             "boolean" },
    { TAG_ENUM,                "enum" },
    { TAG_OCTETSTRING,         "octetString" },
    { TAG_DATETIME,            "dateTime" },
    { TAG_RESOLUTION,          "resolution" },
    { TAG_RANGEOFINTEGER,      "rangeOfInteger" },
    { TAG_BEGCOLLECTION,       "collection" }, /* Technically "begCollection" for encoding but "collection" for attribute syntax */
    { TAG_TEXTWITHLANGUAGE,    "textWithLanguage" },
    { TAG_NAMEWITHLANGUAGE,    "nameWithLanguage" },
    { TAG_ENDCOLLECTION,       "endCollection" },
    { TAG_TEXTWITHOUTLANGUAGE, "textWithoutLanguage" },
    { TAG_NAMEWITHOUTLANGUAGE, "nameWithoutLanguage" },
    { TAG_KEYWORD,             "keyword" },
    { TAG_URI,                 "uri" },
    { TAG_URISCHEME,           "uriScheme" },
    { TAG_CHARSET,             "charset" },
    { TAG_NATURALLANGUAGE,     "naturalLanguage" },
    { TAG_MIMEMEDIATYPE,       "mimeMediaType" },
    { TAG_MEMBERATTRNAME,      "memberAttrName" },
    { 0,                       NULL }
};

static int
parse_attributes(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree)
{
    uint8_t      tag;
    const char *tag_desc;
    char        *name = "";
    int          name_length, value_length;
    proto_tree  *as_tree      = tree;
    proto_item  *tas          = NULL;
    int          start_offset = offset;
    proto_tree  *attr_tree    = tree;
    proto_tree  *subtree      = NULL;

    while (tvb_offset_exists(tvb, offset)) {
        tag = tvb_get_uint8(tvb, offset);
        tag_desc = val_to_str(tag, tag_vals, "unknown-%02x");
        if (TAG_TYPE(tag) == TAG_TYPE_DELIMITER) {
            /*
             * If we had an attribute sequence we were
             * working on, we're done with it; set its
             * length to the length of all the stuff
             * we've done so far.
             */
            name = "";

            if (tas != NULL)
                proto_item_set_len(tas, offset - start_offset);

            /*
             * This tag starts a new attribute sequence;
             * create a new tree under this tag when we see
             * a non-delimiter tag, under which to put
             * those attributes.
             */
            as_tree   = NULL;
            attr_tree = tree;

            /*
             * Remember the offset at which this attribute
             * sequence started, so we can use it to compute
             * its length when it's finished.
             */
            start_offset = offset;

            /*
             * Now create a new item for this tag.
             */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_ipp_as, &tas, tag_desc);
            offset += 1;
            if (tag == TAG_END_OF_ATTRIBUTES) {
                /*
                 * No more attributes.
                 */
                break;
            }
        } else {
            /*
             * Value tag - get the name length.
             */
            name_length = tvb_get_ntohs(tvb, offset + 1);
            if (name_length != 0)
              name = tvb_format_text(wmem_packet_scope(), tvb, offset + 1 + 2, name_length);

            /*
             * OK, get the value length.
             */
            value_length = tvb_get_ntohs(tvb, offset + 1 + 2 + name_length);
            if (tag == TAG_MEMBERATTRNAME && value_length != 0)
              name = tvb_format_text(wmem_packet_scope(), tvb, offset + 1 + 2 + name_length + 2, value_length);

            /*
             * OK, does the value run past the end of the
             * frame?
             */
            if (as_tree == NULL) {
                /*
                 * OK, there's an attribute to hang
                 * under a delimiter tag, but we don't
                 * have a tree for that tag yet; create
                 * a tree.
                 */
                as_tree = subtree;
                attr_tree = as_tree;
            }

            switch (TAG_TYPE(tag)) {
                case TAG_TYPE_OUTOFBAND :
                    if (name_length != 0) {
                        /*
                         * This is an attribute, not
                         * an additional value, so
                         * start a tree for it.
                         */
                        attr_tree = proto_tree_add_subtree_format(as_tree, tvb, offset, 1 + 2 + name_length + 2 + value_length, ett_ipp_attr, NULL, "%s (%s)", name, tag_desc);
                    }
                    proto_tree_add_item(attr_tree, hf_ipp_outofband_value, tvb, offset, 1, ENC_NA);
                    break;

                case TAG_TYPE_INTEGER :
                    if (name_length != 0) {
                        /*
                         * This is an attribute, not
                         * an additional value, so
                         * start a tree for it.
                         */
                        attr_tree = add_integer_tree(as_tree, tvb, offset, name_length, name, value_length, tag);
                    }
                    add_integer_value(tag_desc, attr_tree, tvb, offset, name_length, name, value_length, tag);
                    break;

                case TAG_TYPE_OCTETSTRING :
                    if (name_length != 0) {
                        /*
                         * This is an attribute, not
                         * an additional value, so
                         * start a tree for it.
                         */
                        attr_tree = add_octetstring_tree(as_tree, tvb, pinfo, offset, name_length, name, value_length, tag);
                    }
                    if (tag == TAG_ENDCOLLECTION)
                        attr_tree = proto_tree_get_parent_tree(attr_tree);
                    else
                        attr_tree = add_octetstring_value(tag_desc, attr_tree, tvb, pinfo, offset, name_length, name, value_length, tag);
                    break;

                case TAG_TYPE_CHARSTRING :
                    if (name_length != 0) {
                        /*
                         * This is an attribute, not
                         * an additional value, so
                         * start a tree for it.
                         */
                        attr_tree = add_charstring_tree(as_tree, tvb, offset, tag, name_length, name, value_length);
                    }
                    add_charstring_value(tag_desc, attr_tree, tvb, offset, name_length, name, value_length, tag);
                    break;

                default :
                    if (name_length != 0) {
                        /*
                         * This is an attribute, not
                         * an additional value, so
                         * start a tree for it.
                         */
                        attr_tree = proto_tree_add_subtree_format(as_tree, tvb, offset, 1 + 2 + name_length + 2 + value_length, ett_ipp_attr, NULL, "%s (%s)", name, tag_desc);
                    }
                    proto_tree_add_item(attr_tree, hf_ipp_unknown_value, tvb, offset + 1 + 2 + name_length + 2, value_length, ENC_NA);
                    break;
            }
            offset += 1 + 2 + name_length + 2 + value_length;
        }
    }

    return offset;
}

static proto_tree *
add_integer_tree(proto_tree *tree, tvbuff_t *tvb, int offset,
                 int name_length, const char *name, int value_length, uint8_t tag)
{
    int count = 0;
    const char *type = val_to_str(tag, tag_vals, "unknown-%02x");
    char *value = NULL;
    int valoffset = offset;

    switch (tag) {
        case TAG_BOOLEAN:
            if (value_length == 1) {
                value = wmem_strdup(wmem_packet_scope(), tvb_get_uint8(tvb, offset + 1 + 2 + name_length + 2) ? "true" : "false");
            }
            else {
                value = wmem_strdup(wmem_packet_scope(), "???");
            }
            valoffset += 1 + 2 + name_length + 2 + value_length;
            break;

        case TAG_INTEGER :
            do
            {
               /*
                * Add the range/integer...
                */

                char* temp;

                count ++;

                valoffset += 1 + 2 + name_length + 2;

                if (!tvb_offset_exists(tvb, valoffset + value_length))
                    break;

                if (value_length == 8) {
                    uint32_t lower = tvb_get_ntohl(tvb, valoffset + 0);
                    uint32_t upper = tvb_get_ntohl(tvb, valoffset + 4);

                    temp = wmem_strdup_printf(wmem_packet_scope(), "%d-%d", lower, upper);
                }
                else if (value_length == 4) {
                    temp = wmem_strdup_printf(wmem_packet_scope(), "%d", tvb_get_ntohl(tvb, valoffset + 0));
                }
                else {
                    temp = "???";
                }

                if (value)
                    value = wmem_strconcat(wmem_packet_scope(), value, ",", temp, NULL);
                else
                    value = wmem_strdup(wmem_packet_scope(), temp);

                valoffset += value_length;

               /*
                * Move to the next value...
                */

                if (!tvb_offset_exists(tvb, valoffset + 3))
                    break;

                tag         = tvb_get_uint8(tvb, valoffset);
                name_length = tvb_get_ntohs(tvb, valoffset + 1);
                if (!tvb_offset_exists(tvb, valoffset + 1 + 2 + name_length + 2))
                    break;

                value_length = tvb_get_ntohs(tvb, valoffset + 1 + 2 + name_length);
            }
            while (name_length == 0 && (tag == TAG_INTEGER || tag == TAG_RANGEOFINTEGER));
            break;

        case TAG_ENUM :
            do
            {
               /*
                * Add the range/integer...
                */
                const char* temp;

                count ++;

                valoffset += 1 + 2 + name_length + 2;

                if (!tvb_offset_exists(tvb, valoffset + value_length))
                    break;

                if (value_length != 4) {
                    temp = "???";
                } else {
                    if (!strncmp(name, "printer-state", 13)) {
                        temp = val_to_str(tvb_get_ntohl(tvb, valoffset), printer_state_vals, "unknown-%d");
                    }
                    else if (!strncmp(name, "job-state", 9)) {
                        temp = val_to_str(tvb_get_ntohl(tvb, valoffset), job_state_vals, "unknown-%d");
                    }
                    else if (!strncmp(name, "document-state", 14)) {
                        temp = val_to_str(tvb_get_ntohl(tvb, valoffset), document_state_vals, "unknown-%d");
                    }
                    else if (!strncmp(name, "operations-supported", 20)) {
                        temp = val_to_str(tvb_get_ntohl(tvb, valoffset), operation_vals, "unknown-%04x");
                    }
                    else if (!strncmp(name, "finishings", 10)) {
                        temp = val_to_str(tvb_get_ntohl(tvb, valoffset), finishings_vals, "unknown-%d");
                    }
                    else if (!strncmp(name, "orientation-requested", 21) || !strncmp(name, "media-feed-orientation", 22)) {
                        temp = val_to_str(tvb_get_ntohl(tvb, valoffset), orientation_vals, "unknown-%d");
                    }
                    else if (!strncmp(name, "print-quality", 13)) {
                        temp = val_to_str(tvb_get_ntohl(tvb, valoffset), quality_vals, "unknown-%d");
                    }
                    else if (!strncmp(name, "transmission-status", 19)) {
                        temp = val_to_str(tvb_get_ntohl(tvb, valoffset), transmission_status_vals, "unknown-%d");
                    }
                    else {
                        temp = wmem_strdup_printf(wmem_packet_scope(), "%d", tvb_get_ntohl(tvb, offset + 1 + 2 + name_length + 2));
                    }
                }

                if (value)
                    value = wmem_strconcat(wmem_packet_scope(), value, ",", temp, NULL);
                else
                    value = wmem_strdup(wmem_packet_scope(), temp);

                valoffset += value_length;

               /*
                * Move to the next value...
                */

                if (!tvb_offset_exists(tvb, valoffset + 3))
                    break;

                tag         = tvb_get_uint8(tvb, valoffset);
                name_length = tvb_get_ntohs(tvb, valoffset + 1);
                if (!tvb_offset_exists(tvb, valoffset + 1 + 2 + name_length + 2))
                    break;

                value_length = tvb_get_ntohs(tvb, valoffset + 1 + 2 + name_length);
            }
            while (name_length == 0 && tag == TAG_ENUM);
            break;

        default:
            value = wmem_strdup(wmem_packet_scope(), "???");
            break;
    }

    return proto_tree_add_subtree_format(tree, tvb, offset, valoffset - offset, ett_ipp_attr, NULL, "%s (%s%s): %s", name, count > 1 ? "1setOf " : "", type, value);
}

static void
add_integer_value(const char *tag_desc, proto_tree *tree, tvbuff_t *tvb,
                  int offset, int name_length, const char *name, int value_length, uint8_t tag)
{
    int valoffset = offset + 1 + 2 + name_length + 2;

    if (name_length > 0)
        proto_tree_add_item(tree, hf_ipp_name, tvb, offset + 1 + 2, name_length, ENC_ASCII);

    switch (tag) {
        case TAG_BOOLEAN:
            if (value_length == 1) {
                proto_tree_add_item(tree, hf_ipp_boolean_value, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
            }
            else {
                proto_tree_add_boolean_format(tree, hf_ipp_boolean_value, tvb, valoffset, value_length, 0, "boolean value: ??? %d bytes ???", value_length);
            }
            break;

        case TAG_INTEGER:
            if (value_length == 4) {
                proto_tree_add_item(tree, hf_ipp_integer_value, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
            }
            else {
                proto_tree_add_int_format(tree, hf_ipp_integer_value, tvb, valoffset, value_length, 0, "integer value: ??? %d bytes ???", value_length);
            }
            break;

        case TAG_ENUM:
            if (value_length == 4) {
                if (!strncmp(name, "printer-state", 13)) {
                    proto_tree_add_item(tree, hf_ipp_enum_value_printer_state, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
                }
                else if (!strncmp(name, "job-state", 9)) {
                    proto_tree_add_item(tree, hf_ipp_enum_value_job_state, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
                }
                else if (!strncmp(name, "document-state", 14)) {
                    proto_tree_add_item(tree, hf_ipp_enum_value_document_state, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
                }
                else if (!strncmp(name, "operations-supported", 20)) {
                    proto_tree_add_item(tree, hf_ipp_enum_value_operations_supported, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
                }
                else if (!strncmp(name, "finishings", 10)) {
                    proto_tree_add_item(tree, hf_ipp_enum_value_finishings, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
                }
                else if (!strncmp(name, "orientation-requested", 21) || !strncmp(name, "media-feed-orientation", 22)) {
                    proto_tree_add_item(tree, hf_ipp_enum_value_orientation, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
                }
                else if (!strncmp(name, "print-quality", 13)) {
                    proto_tree_add_item(tree, hf_ipp_enum_value_print_quality, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
                }
                else if (!strncmp(name, "transmission-status", 19)) {
                    proto_tree_add_item(tree, hf_ipp_enum_value_transmission_status, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
                }
                else {
                    proto_tree_add_item(tree, hf_ipp_enum_value, tvb, valoffset, value_length, ENC_BIG_ENDIAN);
                }
            }
            else {
                proto_tree_add_int_format_value(tree, hf_ipp_enum_value, tvb, valoffset, value_length, 0, "??? %d bytes ???", value_length);
            }
            break;

        default :
            proto_tree_add_int_format(tree, hf_ipp_integer_value, tvb, valoffset, value_length, 0, "%s value: ??? %d bytes ???", tag_desc, value_length);
            break;
    }
}

static proto_tree *
add_octetstring_tree(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int name_length, const char *name, int value_length, uint8_t tag)
{
    int count = 0;
    const char *type = val_to_str(tag, tag_vals, "unknown-%02x");
    char *value = NULL;
    int valoffset = offset;

    switch (tag) {
        case TAG_OCTETSTRING :
            do {
               /*
                * Add the string...
                */

                count ++;
                if (value)
                    value = wmem_strconcat(wmem_packet_scope(), value, ",'", tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2, value_length), "'", NULL);
                else
                    value = wmem_strconcat(wmem_packet_scope(), "'", tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2, value_length), "'", NULL);

               /*
                * Move to the next value...
                */

                valoffset += 1 + 2 + name_length + 2 + value_length;

                if (!tvb_offset_exists(tvb, valoffset + 3))
                    break;

                tag         = tvb_get_uint8(tvb, valoffset);
                name_length = tvb_get_ntohs(tvb, valoffset + 1);
                if (!tvb_offset_exists(tvb, valoffset + 1 + 2 + name_length + 2))
                    break;

                value_length = tvb_get_ntohs(tvb, valoffset + 1 + 2 + name_length);
            }
            while (name_length == 0 && tag == TAG_OCTETSTRING);
            break;

        case TAG_DATETIME :
            valoffset += 1 + 2 + name_length + 2;

            if (value_length == 11) {
                uint16_t year = tvb_get_ntohs(tvb, valoffset + 0);
                uint8_t month = tvb_get_uint8(tvb, valoffset + 2);
                uint8_t day = tvb_get_uint8(tvb, valoffset + 3);
                uint8_t hours = tvb_get_uint8(tvb, valoffset + 4);
                uint8_t minutes = tvb_get_uint8(tvb, valoffset + 5);
                uint8_t seconds = tvb_get_uint8(tvb, valoffset + 6);
                uint8_t decisecs = tvb_get_uint8(tvb, valoffset + 7);
                uint8_t utcsign = tvb_get_uint8(tvb, valoffset + 8);
                if (utcsign != '+' && utcsign != '-') {
                    // XXX Add expert info
                    utcsign = '?';
                }
                uint8_t utchours = tvb_get_uint8(tvb, valoffset + 9);
                uint8_t utcminutes = tvb_get_uint8(tvb, valoffset + 10);

                value = wmem_strdup_printf(wmem_packet_scope(), "%04d-%02d-%02dT%02d:%02d:%02d.%d%c%02d%02d", year, month, day, hours, minutes, seconds, decisecs, utcsign, utchours, utcminutes);
            } else {
                value = wmem_strdup(wmem_packet_scope(), "???");
            }

            valoffset += value_length;
            break;

        case TAG_RESOLUTION :
            do {
               /*
                * Add the resolution...
                */

                char* temp;

                count ++;

                valoffset += 1 + 2 + name_length + 2;

                if (value_length == 9 && tvb_offset_exists(tvb, valoffset + value_length)) {
                    int xres = tvb_get_ntohl(tvb, valoffset + 0);
                    int yres = tvb_get_ntohl(tvb, valoffset + 4);
                    uint8_t units = tvb_get_uint8(tvb, valoffset + 8);

                    temp = wmem_strdup_printf(wmem_packet_scope(), "%dx%d%s", xres, yres, units == 3 ? "dpi" : units == 4 ? "dpcm" : "unknown");
                }
                else {
                    temp = "???";
                }

                if (value)
                    value = wmem_strconcat(wmem_packet_scope(), value, ",", temp, NULL);
                else
                    value = wmem_strdup(wmem_packet_scope(), temp);

                valoffset += value_length;

               /*
                * Move to the next value...
                */

                if (!tvb_offset_exists(tvb, valoffset + 3))
                    break;

                tag         = tvb_get_uint8(tvb, valoffset);
                name_length = tvb_get_ntohs(tvb, valoffset + 1);
                if (!tvb_offset_exists(tvb, valoffset + 1 + 2 + name_length + 2))
                    break;

                value_length = tvb_get_ntohs(tvb, valoffset + 1 + 2 + name_length);
            }
            while (name_length == 0 && tag == TAG_RESOLUTION);
            break;

        case TAG_RANGEOFINTEGER :
            do {
               /*
                * Add the range/integer...
                */

                char* temp;

                count ++;

                valoffset += 1 + 2 + name_length + 2;

                if (!tvb_offset_exists(tvb, valoffset + value_length))
                    break;

                if (value_length == 8) {
                    uint32_t lower = tvb_get_ntohl(tvb, valoffset + 0);
                    uint32_t upper = tvb_get_ntohl(tvb, valoffset + 4);

                    temp = wmem_strdup_printf(wmem_packet_scope(), "%d-%d", lower, upper);
                }
                else if (value_length == 4) {
                    temp = wmem_strdup_printf(wmem_packet_scope(), "%d", tvb_get_ntohl(tvb, valoffset + 0));
                }
                else {
                    temp = "???";
                }

                if (value)
                    value = wmem_strconcat(wmem_packet_scope(), value, ",", temp, NULL);
                else
                    value = wmem_strdup(wmem_packet_scope(), temp);

                valoffset += value_length;

               /*
                * Move to the next value...
                */

                if (!tvb_offset_exists(tvb, valoffset + 3))
                    break;

                tag         = tvb_get_uint8(tvb, valoffset);
                name_length = tvb_get_ntohs(tvb, valoffset + 1);
                if (!tvb_offset_exists(tvb, valoffset + 1 + 2 + name_length + 2))
                    break;

                value_length = tvb_get_ntohs(tvb, valoffset + 1 + 2 + name_length);
            }
            while (name_length == 0 && (tag == TAG_RANGEOFINTEGER || tag == TAG_INTEGER));
            break;

        case TAG_TEXTWITHLANGUAGE :
        case TAG_NAMEWITHLANGUAGE :
            do {
               /*
                * Add the string...
                */

                char *temp = NULL;

                count ++;

                if ((tag == TAG_NAMEWITHLANGUAGE || tag == TAG_TEXTWITHLANGUAGE) && value_length > 4) {
                    int language_length = tvb_get_ntohs(tvb, valoffset + 0);
                    int string_length;

                    if (tvb_offset_exists(tvb, valoffset + 2 + language_length)) {
                        string_length = tvb_get_ntohs(tvb, valoffset + 2 + language_length);
                        if (tvb_offset_exists(tvb, valoffset + 2 + language_length + 2 + string_length)) {
                            temp = wmem_strdup_printf(wmem_packet_scope(), "'%s'(%s)", tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2 + 2 + language_length + 2, string_length), tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2 + 2, language_length));
                        }
                    }
                }
                else {
                    temp = wmem_strdup_printf(wmem_packet_scope(), "'%s'", tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2, value_length));
                }

                if (value)
                    value = wmem_strconcat(wmem_packet_scope(), value, ",", temp, NULL);
                else
                    value = wmem_strdup(wmem_packet_scope(), temp);

               /*
                * Move to the next value...
                */

                valoffset += 1 + 2 + name_length + 2 + value_length;

                if (!tvb_offset_exists(tvb, valoffset + 3))
                    break;

                tag         = tvb_get_uint8(tvb, valoffset);
                name_length = tvb_get_ntohs(tvb, valoffset + 1);
                if (!tvb_offset_exists(tvb, valoffset + 1 + 2 + name_length + 2))
                    break;

                value_length = tvb_get_ntohs(tvb, valoffset + 1 + 2 + name_length);
            }
            while (name_length == 0 && (TAG_TYPE(tag) == TAG_TYPE_CHARSTRING || tag == TAG_NAMEWITHLANGUAGE || tag == TAG_TEXTWITHLANGUAGE));
            break;

        case TAG_BEGCOLLECTION :
            do {
               /*
                * Add the member attribute...
                */

                char temp[1024];

                count ++;

                valoffset = ipp_fmt_collection(tvb, pinfo, valoffset + 1 + 2 + name_length + 2 + value_length, temp, sizeof(temp));

                if (value)
                    value = wmem_strconcat(wmem_packet_scope(), value, ",", temp, NULL);
                else
                    value = wmem_strdup(wmem_packet_scope(), temp);

               /*
                * Move to the next value...
                */

                if (!tvb_offset_exists(tvb, valoffset + 3))
                    break;

                tag         = tvb_get_uint8(tvb, valoffset);
                name_length = tvb_get_ntohs(tvb, valoffset + 1);
                if (!tvb_offset_exists(tvb, valoffset + 1 + 2 + name_length + 2))
                    break;

                value_length = tvb_get_ntohs(tvb, valoffset + 1 + 2 + name_length);
            }
            while (name_length == 0 && tag == TAG_BEGCOLLECTION);
            break;

        default :
            if (value_length > 0 ) {
                value = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset + 1 + 2 + name_length + 2, value_length);
            }
            valoffset += 1 + 2 + name_length + 2 + value_length;
            break;
    }

    return proto_tree_add_subtree_format(tree, tvb, offset, valoffset - offset, ett_ipp_attr, NULL, "%s (%s%s): %s", name, count > 1 ? "1setOf " : "", type, value);
}

static proto_tree *
add_octetstring_value(const char *tag_desc, proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
                      int offset, int name_length, const char *name _U_, int value_length, uint8_t tag)
{
    proto_tree *subtree = tree;
    char value[176];
    int valoffset = offset + 1 + 2 + name_length + 2;
    int endoffset;

    if (name_length > 0)
        proto_tree_add_item(tree, hf_ipp_name, tvb, offset + 1 + 2, name_length, ENC_ASCII);

    switch (tag) {
        case TAG_OCTETSTRING :
            proto_tree_add_item(tree, hf_ipp_octetstring_value, tvb, valoffset, value_length, ENC_ASCII);
            break;

        case TAG_DATETIME :
            if (value_length == 11) {
                uint16_t year = tvb_get_ntohs(tvb, valoffset + 0);
                uint8_t month = tvb_get_uint8(tvb, valoffset + 2);
                uint8_t day = tvb_get_uint8(tvb, valoffset + 3);
                uint8_t hours = tvb_get_uint8(tvb, valoffset + 4);
                uint8_t minutes = tvb_get_uint8(tvb, valoffset + 5);
                uint8_t seconds = tvb_get_uint8(tvb, valoffset + 6);
                uint8_t decisecs = tvb_get_uint8(tvb, valoffset + 7);
                uint8_t utcsign = tvb_get_uint8(tvb, valoffset + 8);
                if (utcsign != '+' && utcsign != '-') {
                    // XXX Add expert info
                    utcsign = '?';
                }
                uint8_t utchours = tvb_get_uint8(tvb, valoffset + 9);
                uint8_t utcminutes = tvb_get_uint8(tvb, valoffset + 10);

                proto_tree_add_bytes_format(tree, hf_ipp_datetime_value, tvb, valoffset, value_length, NULL, "dateTime value: %04d-%02d-%02dT%02d:%02d:%02d.%d%c%02d%02d", year, month, day, hours, minutes, seconds, decisecs, utcsign, utchours, utcminutes);
            }
            else {
                proto_tree_add_item(tree, hf_ipp_datetime_value, tvb, valoffset, value_length, ENC_NA);
            }
            break;

        case TAG_RESOLUTION :
            if (value_length == 9) {
                int xres = tvb_get_ntohl(tvb, valoffset + 0);
                int yres = tvb_get_ntohl(tvb, valoffset + 4);
                uint8_t units = tvb_get_uint8(tvb, valoffset + 8);

                proto_tree_add_bytes_format(tree, hf_ipp_resolution_value, tvb, valoffset, value_length, NULL, "resolution value: %dx%d%s", xres, yres, units == 3 ? "dpi" : units == 4 ? "dpcm" : "unknown");
            }
            else {
                proto_tree_add_item(tree, hf_ipp_resolution_value, tvb, valoffset, value_length, ENC_NA);
            }
            break;

        case TAG_RANGEOFINTEGER :
            if (value_length == 8) {
                int lower = tvb_get_ntohl(tvb, valoffset + 0);
                int upper = tvb_get_ntohl(tvb, valoffset + 4);

                proto_tree_add_bytes_format(tree, hf_ipp_rangeofinteger_value, tvb, valoffset, value_length, NULL, "rangeOfInteger value: %d-%d", lower, upper);
            }
            else {
                proto_tree_add_item(tree, hf_ipp_rangeofinteger_value, tvb, valoffset, value_length, ENC_NA);
            }
            break;

        case TAG_TEXTWITHLANGUAGE :
        case TAG_NAMEWITHLANGUAGE :
            if (value_length > 4) {
                int language_length = tvb_get_ntohs(tvb, valoffset + 0);

                if (tvb_offset_exists(tvb, valoffset + 2 + language_length)) {
                    int string_length = tvb_get_ntohs(tvb, valoffset + 2 + language_length);
                    if (tvb_offset_exists(tvb, valoffset + 2 + language_length + 2 + string_length)) {
                        proto_tree_add_bytes_format(tree, tag == TAG_NAMEWITHLANGUAGE ? hf_ipp_namewithlanguage_value : hf_ipp_textwithlanguage_value, tvb, valoffset, value_length, NULL, "%s value: '%s'(%s)", tag_desc, tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2 + 2 + language_length + 2, string_length), tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2 + 2, language_length));
                        break;
                    }
                }

            }

            if (tag == TAG_NAMEWITHLANGUAGE) {
                proto_tree_add_item(tree, hf_ipp_namewithlanguage_value, tvb, valoffset, value_length, ENC_NA);
            }
            else {
                proto_tree_add_item(tree, hf_ipp_textwithlanguage_value, tvb, valoffset, value_length, ENC_NA);
            }
            break;

        case TAG_BEGCOLLECTION :
            endoffset = ipp_fmt_collection(tvb, pinfo, valoffset + value_length, value, sizeof(value));
            subtree = proto_tree_add_subtree_format(tree, tvb, valoffset, endoffset - valoffset, ett_ipp_member, NULL, "collection %s", value);
            break;

        default :
            proto_tree_add_string_format(tree, hf_ipp_octetstring_value, tvb, valoffset, value_length, NULL, "%s value: ??? %d bytes ???", tag_desc, value_length);
            break;
    }

    return subtree;
}

static proto_tree *
add_charstring_tree(proto_tree *tree, tvbuff_t *tvb, int offset,
                    uint8_t tag, int name_length, const char *name, int value_length)
{
    int count = 0, valoffset = offset;
    const char *type = val_to_str(tag, tag_vals, "unknown-%02x");
    char *value = NULL;

    do {
       /*
        * Add the string...
        */

        char *temp = NULL;

        count ++;

        if ((tag == TAG_NAMEWITHLANGUAGE || tag == TAG_TEXTWITHLANGUAGE) && value_length > 4) {
            int language_length = tvb_get_ntohs(tvb, valoffset + 0);
            int string_length;

            if (tvb_offset_exists(tvb, valoffset + 2 + language_length)) {
                string_length = tvb_get_ntohs(tvb, valoffset + 2 + language_length);
                if (tvb_offset_exists(tvb, valoffset + 2 + language_length + 2 + string_length)) {
                    temp = wmem_strdup_printf(wmem_packet_scope(), "'%s'(%s)", tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2 + 2 + language_length + 2, string_length), tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2 + 2, language_length));
                }
            }
        }
        else {
            temp = wmem_strdup_printf(wmem_packet_scope(), "'%s'", tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2, value_length));
        }

        if (value)
            value = wmem_strconcat(wmem_packet_scope(), value, ",", temp, NULL);
        else
            value = wmem_strdup(wmem_packet_scope(), temp);

       /*
        * Move to the next value...
        */

        valoffset += 1 + 2 + name_length + 2 + value_length;

        if (!tvb_offset_exists(tvb, valoffset + 3))
            break;

        tag         = tvb_get_uint8(tvb, valoffset);
        name_length = tvb_get_ntohs(tvb, valoffset + 1);
        if (!tvb_offset_exists(tvb, valoffset + 1 + 2 + name_length + 2))
            break;

        value_length = tvb_get_ntohs(tvb, valoffset + 1 + 2 + name_length);
    }
    while (name_length == 0 && (TAG_TYPE(tag) == TAG_TYPE_CHARSTRING || tag == TAG_NAMEWITHLANGUAGE || tag == TAG_TEXTWITHLANGUAGE));

    return proto_tree_add_subtree_format(tree, tvb, offset, valoffset - offset, ett_ipp_attr, NULL, "%s (%s%s): %s", name, count > 1 ? "1setOf " : "", type, value);
}

static void
add_charstring_value(const char *tag_desc, proto_tree *tree, tvbuff_t *tvb,
                     int offset, int name_length, const char *name _U_, int value_length, uint8_t tag)
{
    proto_item *ti;
    int valoffset = offset + 1 + 2 + name_length + 2;

    if (name_length > 0)
        proto_tree_add_item(tree, hf_ipp_name, tvb, offset + 1 + 2, name_length, ENC_ASCII);

    if (tag == TAG_MEMBERATTRNAME)
        proto_tree_add_item(tree, hf_ipp_memberattrname, tvb, valoffset, value_length, ENC_ASCII);
    else {
        ti = proto_tree_add_item(tree, hf_ipp_charstring_value, tvb, valoffset, value_length, ENC_ASCII);
        if (strcmp(tag_desc, "") == 0) {
            proto_item_prepend_text(ti, "string ");
        } else {
            proto_item_prepend_text(ti, "%s ", tag_desc);
        }
    }
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
ipp_fmt_collection(tvbuff_t *tvb, packet_info *pinfo, int valoffset, char *buffer, int bufsize)
{
    char *bufptr = buffer, *bufend = buffer + bufsize - 1;
    uint8_t tag;
    int name_length, value_length;
    int overflow = 0;

    /* Should be larger to be meaningful, but at least prevent illegal
     * memory accesses.
     */
    DISSECTOR_ASSERT_CMPINT(bufsize, >=, 2);

    *bufptr++ = '{';
    buffer ++;

    do {
        if (!tvb_offset_exists(tvb, valoffset + 3))
            break;

        tag         = tvb_get_uint8(tvb, valoffset);
        name_length = tvb_get_ntohs(tvb, valoffset + 1);
        if (!tvb_offset_exists(tvb, valoffset + 1 + 2 + name_length + 2))
            break;

        value_length = tvb_get_ntohs(tvb, valoffset + 1 + 2 + name_length);

        if (!tvb_offset_exists(tvb, valoffset + 1 + 2 + name_length + 2 + value_length))
            break;

        if (tag == TAG_MEMBERATTRNAME && !overflow) {
            if (bufptr > buffer && bufptr < bufend)
                *bufptr++ = ',';

            if ((bufend - bufptr) < value_length) {
                (void) g_strlcpy(bufptr, "...", bufend - bufptr + 1);
                overflow = 1;
            }
            else {
                (void) g_strlcpy(bufptr, tvb_format_text(wmem_packet_scope(), tvb, valoffset + 1 + 2 + name_length + 2, value_length), bufend - bufptr + 1);
            }

            bufptr += strlen(bufptr);
        }

        valoffset += 1 + 2 + name_length + 2 + value_length;

    if (tag == TAG_BEGCOLLECTION) {
            char temp[176];

            increment_dissection_depth(pinfo);
            valoffset = ipp_fmt_collection(tvb, pinfo, valoffset, temp, sizeof(temp));
            decrement_dissection_depth(pinfo);
            if (!overflow) {
                if ((bufend - bufptr) < (int)strlen(temp)) {
                    (void) g_strlcpy(bufptr, "...", bufend - bufptr + 1);
                    overflow = 1;
                }
                else {
                    (void) g_strlcpy(bufptr, temp, bufend - bufptr + 1);
                }
                bufptr += strlen(bufptr);
            }
        }
    } while (tag != TAG_ENDCOLLECTION);

    if (bufptr < bufend)
      *bufptr++ = '}';

    *bufptr = '\0';
    if (bufptr == bufend) {
        /* buffer was already advanced past the initial '{' */
        ws_utf8_truncate(buffer, bufsize - 2);
    }

    return (valoffset);
}


static void
ipp_fmt_version( char *result, uint32_t revision )
{
   snprintf( result, ITEM_LABEL_LENGTH, "%u.%u", (uint8_t)(( revision & 0xFF00 ) >> 8), (uint8_t)(revision & 0xFF) );
}

void
proto_register_ipp(void)
{
    static hf_register_info hf[] = {
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_ipp_version, { "version", "ipp.version", FT_UINT16, BASE_CUSTOM, CF_FUNC(ipp_fmt_version), 0x0, NULL, HFILL }},
      { &hf_ipp_operation_id, { "operation-id", "ipp.operation_id", FT_UINT16, BASE_HEX, VALS(operation_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_status_code, { "status-code", "ipp.status_code", FT_UINT16, BASE_HEX, VALS(status_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_request_id, { "request-id", "ipp.request_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_name, { "name", "ipp.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_memberattrname, { "memberAttrName", "ipp.memberattrname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_boolean_value, { "boolean value", "ipp.boolean_value", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_integer_value, { "integer value", "ipp.integer_value", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_enum_value, { "enum value", "ipp.enum_value", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_enum_value_printer_state, { "printer-state", "ipp.enum_value", FT_INT32, BASE_DEC, VALS(printer_state_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_enum_value_job_state, { "job-state", "ipp.enum_value", FT_INT32, BASE_DEC, VALS(job_state_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_enum_value_document_state, { "document-state", "ipp.enum_value", FT_INT32, BASE_DEC, VALS(document_state_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_enum_value_operations_supported, { "operations-supported", "ipp.enum_value", FT_INT32, BASE_DEC, VALS(operation_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_enum_value_finishings, { "finishings", "ipp.enum_value", FT_INT32, BASE_DEC, VALS(finishings_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_enum_value_orientation, { "orientation", "ipp.enum_value", FT_INT32, BASE_DEC, VALS(orientation_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_enum_value_print_quality, { "print-quality", "ipp.enum_value", FT_INT32, BASE_DEC, VALS(quality_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_enum_value_transmission_status, { "transmission-status", "ipp.enum_value", FT_INT32, BASE_DEC, VALS(transmission_status_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_outofband_value, { "out-of-band value", "ipp.outofband_value", FT_UINT8, BASE_HEX, VALS(tag_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_charstring_value, { "value", "ipp.charstring_value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_octetstring_value, { "octetString value", "ipp.octetstring_value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_datetime_value, { "dateTime value", "ipp.datetime_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_resolution_value, { "resolution value", "ipp.resolution_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_rangeofinteger_value, { "rangeOfInteger value", "ipp.rangeofinteger_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_textwithlanguage_value, { "textWithLanguage value", "ipp.textwithlanguage_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_namewithlanguage_value, { "nameWithLanguage value", "ipp.namewithlanguage_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_unknown_value, { "unknown value", "ipp.unknown_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_response_in, { "Response In", "ipp.response_in", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0, "The response to this IPP request is in this frame", HFILL }},
      { &hf_ipp_response_to, { "Request In", "ipp.response_to", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0, "This is a response to the IPP request in this frame", HFILL }},
      { &hf_ipp_response_time, { "Response Time", "ipp.response_time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, "The time between the Request and the Response", HFILL }}
    };
    static int *ett[] = {
        &ett_ipp,
        &ett_ipp_as,
        &ett_ipp_attr,
        &ett_ipp_member
    };

    proto_ipp = proto_register_protocol("Internet Printing Protocol", "IPP", "ipp");

    proto_register_field_array(proto_ipp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ipp_handle = register_dissector("ipp", dissect_ipp, proto_ipp);
}

void
proto_reg_handoff_ipp(void)
{
    /*
     * IPP uses the same well-known TCP port, 631, for both running atop HTTP
     * and atop HTTP over TLS (IPPS, RFC 7472). The latter includes both
     * connections that start out as HTTP and upgrade to using TLS (RFC 2817)
     * as well as connections that begin as TLS. Despite RFC 8010:
     *   the "Content-Type" of the message body in each request and response
     *   MUST be "application/ipp"
     * a number of implementations fail to include the Content-Type in their
     * chunked responses. (#18825, #5718, #6765).
     *
     * For that reason, we register IPP in the HTTP port-based dissector so
     * that packets without a Content-Type on port 631 will use this dissector.
     * (RFC 8010 also notes that HTTP/2 is an OPTIONAL transport layer; we
     * don't have a port-based dissector dissector for HTTP/2, but hopefully
     * any implementations that use HTTP/2 always send the Content-Type.)
     * Note we check for port-based dissectors after the Content-Type; this
     * is good because many IPP servers will respond to non-IPP HTTP requests
     * on port 631 just as they would on ports 80 or 443.
     *
     * We can only have a single dissector in the TCP dissector table for
     * port 631. If we don't register a fake helper protocol that tries
     * each of TLS, HTTP/2, and HTTP in order (cf. #16541, #18016), we're
     * currently better off having TLS be the registered dissector and HTTP
     * be detected heuristically, because the non-heuristic HTTP dissector
     * never rejects packets, even when it doesn't add anything to the tree.
     */
    dissector_handle_t http_tls_handle = find_dissector_add_dependency("http-over-tls", proto_ipp);
    http_tcp_dissector_add(631, ipp_handle);
    ssl_dissector_add(631, http_tls_handle);
    dissector_add_string("media_type", "application/ipp", ipp_handle);
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
