/* packet-ipp.c
 * Routines for IPP packet disassembly
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include "packet-http.h"

void proto_register_ipp(void);
void proto_reg_handoff_ipp(void);

static int proto_ipp = -1;
static int hf_ipp_timestamp = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_ipp_request_id = -1;
static int hf_ipp_name = -1;
static int hf_ipp_tag = -1;
static int hf_ipp_value_length = -1;
static int hf_ipp_charstring_value = -1;
static int hf_ipp_status_code = -1;
static int hf_ipp_version = -1;
static int hf_ipp_bool_value = -1;
static int hf_ipp_name_length = -1;
static int hf_ipp_job_state = -1;
static int hf_ipp_bytes_value = -1;
static int hf_ipp_operation_id = -1;
static int hf_ipp_printer_state = -1;
static int hf_ipp_uint32_value = -1;

static gint ett_ipp = -1;
static gint ett_ipp_as = -1;
static gint ett_ipp_attr = -1;

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
    { 0,                      NULL }
};

/* Printer States */
#define PRINTER_STATE_IDLE      0x3
#define PRINTER_STATE_PROCESSING    0x4
#define PRINTER_STATE_STOPPED       0x5
static const value_string printer_state_vals[] = {
    { PRINTER_STATE_IDLE,       "Idle" },
    { PRINTER_STATE_PROCESSING, "Processing" },
    { PRINTER_STATE_STOPPED,    "Stopped" },
    { 0, NULL }
};

/* Job States */
static const value_string job_state_vals[] = {
    { 3, "Pending" },
    { 4, "Pending - Job Held" },
    { 5, "Processing" },
    { 6, "Processing - Job Stopped" },
    { 7, "Canceled" },
    { 8, "Aborted" },
    { 9, "Completed" },
    { 0, NULL }
};

#define STATUS_SUCCESSFUL    0x0000
#define STATUS_INFORMATIONAL 0x0100
#define STATUS_REDIRECTION   0x0200
#define STATUS_CLIENT_ERROR  0x0400
#define STATUS_SERVER_ERROR  0x0500

#define STATUS_TYPE_MASK     0xFF00

#define SUCCESSFUL_OK                     0x0000
#define SUCCESSFUL_OK_IGN_OR_SUB_ATTR     0x0001
#define SUCCESSFUL_OK_CONFLICTING_ATTR    0x0002

#define CLIENT_ERROR_BAD_REQUEST          0x0400
#define CLIENT_ERROR_FORBIDDEN            0x0401
#define CLIENT_ERROR_NOT_AUTHENTICATED    0x0402
#define CLIENT_ERROR_NOT_AUTHORIZED       0x0403
#define CLIENT_ERROR_NOT_POSSIBLE         0x0404
#define CLIENT_ERROR_TIMEOUT              0x0405
#define CLIENT_ERROR_NOT_FOUND            0x0406
#define CLIENT_ERROR_GONE                 0x0407
#define CLIENT_ERROR_REQ_ENTITY_TOO_LRG   0x0408
#define CLIENT_ERROR_REQ_VALUE_TOO_LONG   0x0409
#define CLIENT_ERROR_DOC_FMT_NOT_SUPP     0x040A
#define CLIENT_ERROR_ATTR_OR_VAL_NOT_SUPP 0x040B
#define CLIENT_ERROR_URI_SCHEME_NOT_SUPP  0x040C
#define CLIENT_ERROR_CHARSET_NOT_SUPP     0x040D
#define CLIENT_ERROR_CONFLICTING_ATTRS    0x040E

#define SERVER_ERROR_INTERNAL_ERROR       0x0500
#define SERVER_ERROR_OPERATION_NOT_SUPP   0x0501
#define SERVER_ERROR_SERVICE_UNAVAIL      0x0502
#define SERVER_ERROR_VERSION_NOT_SUPP     0x0503
#define SERVER_ERROR_DEVICE_ERROR         0x0504
#define SERVER_ERROR_TEMPORARY_ERROR      0x0505
#define SERVER_ERROR_NOT_ACCEPTING_JOBS   0x0506
#define SERVER_ERROR_BUSY                 0x0507
#define SERVER_ERROR_JOB_CANCELED         0x0508

static const value_string status_vals[] = {
    { SUCCESSFUL_OK,                     "Successful-OK" },
    { SUCCESSFUL_OK_IGN_OR_SUB_ATTR,     "Successful-OK-Ignored-Or-Substituted-Attributes" },
    { SUCCESSFUL_OK_CONFLICTING_ATTR,    "Successful-OK-Conflicting-Attributes" },
    { CLIENT_ERROR_BAD_REQUEST,          "Client-Error-Bad-Request" },
    { CLIENT_ERROR_FORBIDDEN,            "Client-Error-Forbidden" },
    { CLIENT_ERROR_NOT_AUTHENTICATED,    "Client-Error-Not-Authenticated" },
    { CLIENT_ERROR_NOT_AUTHORIZED,       "Client-Error-Not-Authorized" },
    { CLIENT_ERROR_NOT_POSSIBLE,         "Client-Error-Not-Possible" },
    { CLIENT_ERROR_TIMEOUT,              "Client-Error-Timeout" },
    { CLIENT_ERROR_NOT_FOUND,            "Client-Error-Not-Found" },
    { CLIENT_ERROR_GONE,                 "Client-Error-Gone" },
    { CLIENT_ERROR_REQ_ENTITY_TOO_LRG,   "Client-Error-Request-Entity-Too-Large" },
    { CLIENT_ERROR_REQ_VALUE_TOO_LONG,   "Client-Error-Request-Value-Too-Long" },
    { CLIENT_ERROR_DOC_FMT_NOT_SUPP,     "Client-Error-Document-Format-Not-Supported" },
    { CLIENT_ERROR_ATTR_OR_VAL_NOT_SUPP, "Client-Error-Attributes-Or-Values-Not-Supported" },
    { CLIENT_ERROR_URI_SCHEME_NOT_SUPP,  "Client-Error-URI-Scheme-Not-Supported" },
    { CLIENT_ERROR_CHARSET_NOT_SUPP,     "Client-Error-Charset-Not-Supported" },
    { CLIENT_ERROR_CONFLICTING_ATTRS,    "Client-Error-Conflicting-Attributes" },
    { SERVER_ERROR_INTERNAL_ERROR,       "Server-Error-Internal-Error" },
    { SERVER_ERROR_OPERATION_NOT_SUPP,   "Server-Error-Operation-Not-Supported" },
    { SERVER_ERROR_SERVICE_UNAVAIL,      "Server-Error-Service-Unavailable" },
    { SERVER_ERROR_VERSION_NOT_SUPP,     "Server-Error-Version-Not-Supported" },
    { SERVER_ERROR_DEVICE_ERROR,         "Server-Error-Device-Error" },
    { SERVER_ERROR_TEMPORARY_ERROR,      "Server-Error-Temporary-Error" },
    { SERVER_ERROR_NOT_ACCEPTING_JOBS,   "Server-Error-Not-Accepting-Jobs" },
    { SERVER_ERROR_BUSY,                 "Server-Error-Busy" },
    { SERVER_ERROR_JOB_CANCELED,         "Server-Error-Job-Canceled" },
    { 0,                                 NULL }
};

static int parse_attributes(tvbuff_t *tvb, int offset, proto_tree *tree);
static proto_tree *add_integer_tree(proto_tree *tree, tvbuff_t *tvb,
                                        int offset, int name_length, int value_length, guint8 tag);
static void add_integer_value(const gchar *tag_desc, proto_tree *tree,
                                        tvbuff_t *tvb, int offset, int name_length, int value_length, guint8 tag);
static proto_tree *add_octetstring_tree(proto_tree *tree, tvbuff_t *tvb,
                                        int offset, int name_length, int value_length);
static void add_octetstring_value(const gchar *tag_desc, proto_tree *tree,
                                        tvbuff_t *tvb, int offset, int name_length, int value_length);
static proto_tree *add_charstring_tree(proto_tree *tree, tvbuff_t *tvb,
                                        int offset, int name_length, int value_length);
static void add_charstring_value(const gchar *tag_desc, proto_tree *tree,
                                        tvbuff_t *tvb, int offset, int name_length, int value_length);
static int add_value_head(const gchar *tag_desc, proto_tree *tree,
                                        tvbuff_t *tvb, int offset, int name_length, int value_length, char **name_val);

static int
dissect_ipp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree  *ipp_tree;
    proto_item  *ti;
    int          offset     = 0;
    http_message_info_t *message_info = (http_message_info_t *)data;
    gboolean     is_request;
    guint16      status_code;
    const gchar *status_type;

    if (message_info != NULL) {
        switch (message_info->type) {

        case HTTP_REQUEST:
            is_request = TRUE;
            break;

        case HTTP_RESPONSE:
            is_request = FALSE;
            break;

        default:
            is_request = (pinfo->destport == pinfo->match_uint);
            break;
        }
    } else
        is_request = (pinfo->destport == pinfo->match_uint);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPP");
    if (is_request)
        col_set_str(pinfo->cinfo, COL_INFO, "IPP request");
    else
        col_set_str(pinfo->cinfo, COL_INFO, "IPP response");

    ti = proto_tree_add_item(tree, proto_ipp, tvb, offset, -1, ENC_NA);
    ipp_tree = proto_item_add_subtree(ti, ett_ipp);

    proto_tree_add_item(ipp_tree, hf_ipp_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (is_request) {
        proto_tree_add_item(ipp_tree, hf_ipp_operation_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    } else {
        status_code = tvb_get_ntohs(tvb, offset);
        switch (status_code & STATUS_TYPE_MASK) {

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
            status_type = "Client error";
            break;

        case STATUS_SERVER_ERROR:
            status_type = "Server error";
            break;

        default:
            status_type = "Unknown";
            break;
        }
        proto_tree_add_uint_format_value(ipp_tree, hf_ipp_status_code, tvb, offset, 2, status_code,
                            "%s (%s)", status_type, val_to_str(status_code, status_vals, "0x804x"));
    }
    offset += 2;

    proto_tree_add_item(ipp_tree, hf_ipp_request_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = parse_attributes(tvb, offset, ipp_tree);

    if (tvb_offset_exists(tvb, offset)) {
        call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo,
                        ipp_tree);
    }
    return tvb_captured_length(tvb);
}

#define TAG_TYPE(x)       ((x) & 0xF0)

#define TAG_TYPE_DELIMITER      0x00
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
#define TAG_TEXTWITHLANGUAGE    0x35
#define TAG_NAMEWITHLANGUAGE    0x36

#define TAG_TEXTWITHOUTLANGUAGE 0x41
#define TAG_NAMEWITHOUTLANGUAGE 0x42
#define TAG_KEYWORD             0x44
#define TAG_URI                 0x45
#define TAG_URISCHEME           0x46
#define TAG_CHARSET             0x47
#define TAG_NATURALLANGUAGE     0x48
#define TAG_MIMEMEDIATYPE       0x49

static const value_string tag_vals[] = {
    /* Delimiter tags */
    { 0x01,                    "Operation attributes" },
    { 0x02,                    "Job attributes" },
    { TAG_END_OF_ATTRIBUTES,   "End of attributes" },
    { 0x04,                    "Printer attributes" },
    { 0x05,                    "Unsupported attributes" },

    /* Value tags */
    { 0x10,                    "Unsupported" },
    { 0x12,                    "Unknown" },
    { 0x13,                    "No value" },
    { TAG_INTEGER,             "Integer" },
    { TAG_BOOLEAN,             "Boolean" },
    { TAG_ENUM,                "Enum" },
    { TAG_OCTETSTRING,         "Octet string" },
    { TAG_DATETIME,            "Date/Time" },
    { TAG_RESOLUTION,          "Resolution" },
    { TAG_RANGEOFINTEGER,      "Range of integer" },
    { TAG_TEXTWITHLANGUAGE,    "Text with language" },
    { TAG_NAMEWITHLANGUAGE,    "Name with language" },
    { TAG_TEXTWITHOUTLANGUAGE, "Text without language" },
    { TAG_NAMEWITHOUTLANGUAGE, "Name without language" },
    { TAG_KEYWORD,             "Keyword" },
    { TAG_URI,                 "URI" },
    { TAG_URISCHEME,           "URI scheme" },
    { TAG_CHARSET,             "Character set" },
    { TAG_NATURALLANGUAGE,     "Natural language" },
    { TAG_MIMEMEDIATYPE,       "MIME media type" },
    { 0,                       NULL }
};

static int
parse_attributes(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    guint8       tag;
    const gchar *tag_desc;
    int          name_length, value_length;
    proto_tree  *as_tree      = tree;
    proto_item  *tas          = NULL;
    int          start_offset = offset;
    proto_tree  *attr_tree    = tree;
    proto_tree  *subtree      = NULL;

    while (tvb_offset_exists(tvb, offset)) {
        tag = tvb_get_guint8(tvb, offset);
        tag_desc = val_to_str(tag, tag_vals, "Reserved (0x%02x)");
        if (TAG_TYPE(tag) == TAG_TYPE_DELIMITER) {
            /*
             * If we had an attribute sequence we were
             * working on, we're done with it; set its
             * length to the length of all the stuff
             * we've done so far.
             */
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

            /*
             * OK, get the value length.
             */
            value_length = tvb_get_ntohs(tvb, offset + 1 + 2 + name_length);

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

            case TAG_TYPE_INTEGER:
                if (name_length != 0) {
                    /*
                     * This is an attribute, not
                     * an additional value, so
                     * start a tree for it.
                     */
                    attr_tree = add_integer_tree(as_tree,
                                                 tvb, offset, name_length,
                                                 value_length, tag);
                }
                add_integer_value(tag_desc, attr_tree, tvb,
                                  offset, name_length, value_length, tag);
                break;

            case TAG_TYPE_OCTETSTRING:
                if (name_length != 0) {
                    /*
                     * This is an attribute, not
                     * an additional value, so
                     * start a tree for it.
                     */
                    attr_tree = add_octetstring_tree(as_tree,
                                                     tvb, offset, name_length,
                                                     value_length);
                }
                add_octetstring_value(tag_desc, attr_tree, tvb,
                                      offset, name_length, value_length);
                break;

            case TAG_TYPE_CHARSTRING:
                if (name_length != 0) {
                    /*
                     * This is an attribute, not
                     * an additional value, so
                     * start a tree for it.
                     */
                    attr_tree = add_charstring_tree(as_tree,
                                                    tvb, offset, name_length,
                                                    value_length);
                }
                add_charstring_value(tag_desc, attr_tree, tvb,
                                     offset, name_length, value_length);
                break;
            }
            offset += 1 + 2 + name_length + 2 + value_length;
        }
    }

    return offset;
}

static const value_string bool_vals[] = {
    { 0x00, "false" },
    { 0x01, "true" },
    { 0,    NULL }
};

static proto_tree *
add_integer_tree(proto_tree *tree, tvbuff_t *tvb, int offset,
                 int name_length, int value_length, guint8 tag)
{
    proto_tree *subtree;
    guint8      bool_val;

    switch (tag) {

    case TAG_BOOLEAN:
        if (value_length != 1) {
            subtree = proto_tree_add_subtree_format(tree, tvb, offset,
                                     1 + 2 + name_length + 2 + value_length,
                                     ett_ipp_attr, NULL, "%s: Invalid boolean (length is %u, should be 1)",
                                     tvb_format_text(tvb, offset + 1 + 2, name_length),
                                     value_length);
        } else {
            bool_val = tvb_get_guint8(tvb,
                                      offset + 1 + 2 + name_length + 2);
            subtree = proto_tree_add_subtree_format(tree, tvb, offset,
                                     1 + 2 + name_length + 2 + value_length,
                                     ett_ipp_attr, NULL, "%s: %s",
                                     tvb_format_text(tvb, offset + 1 + 2, name_length),
                                     val_to_str(bool_val, bool_vals, "Unknown (0x%02x)"));
        }
        break;

    case TAG_INTEGER:
    case TAG_ENUM:
        if (value_length != 4) {
            subtree = proto_tree_add_subtree_format(tree, tvb, offset,
                                     1 + 2 + name_length + 2 + value_length,
                                     ett_ipp_attr, NULL, "%s: Invalid integer (length is %u, should be 4)",
                                     tvb_format_text(tvb, offset + 1 + 2, name_length),
                                     value_length);
        } else {
            const char *name_val;
            /* Some fields in IPP are really unix timestamps but IPP
             * transports these as 4 byte integers.
             * A simple heuristic to make the display of these fields
             * more human readable is to assume that if the field name
             * ends in '-time' then assume they are timestamps instead
             * of integers.
             */
            name_val=tvb_get_ptr(tvb, offset + 1 + 2, name_length);
            if ((name_length > 5) && name_val && !tvb_memeql(tvb, offset + 1 + 2 + name_length - 5, "-time", 5)) {
                subtree = proto_tree_add_subtree_format(tree, tvb, offset,
                                         1 + 2 + name_length + 2 + value_length,
                                         ett_ipp_attr, NULL, "%s: %s",
                                         format_text(name_val, name_length),
                                         abs_time_secs_to_str(wmem_packet_scope(), tvb_get_ntohl(tvb, offset + 1 + 2 + name_length + 2),
                                                              ABSOLUTE_TIME_LOCAL,
                                                              TRUE));

            }
            else if ((name_length > 5) && name_val && !tvb_memeql(tvb, offset + 1 + 2, "printer-state", 13)) {
                subtree = proto_tree_add_subtree_format(tree, tvb, offset,
                                         1 + 2 + name_length + 2 + value_length,
                                         ett_ipp_attr, NULL, "%s: %s",
                                         format_text(name_val, name_length),
                                         val_to_str_const(tvb_get_ntohl(tvb, offset + 1 + 2 + name_length + 2),
                                                          printer_state_vals,
                                                          "Unknown Printer State"));
            }
            else if ((name_length > 5) && name_val && !tvb_memeql(tvb, offset + 1 + 2, "job-state", 9)) {
                subtree = proto_tree_add_subtree_format(tree, tvb, offset,
                                         1 + 2 + name_length + 2 + value_length,
                                         ett_ipp_attr, NULL, "%s: %s",
                                         format_text(name_val, name_length),
                                         val_to_str_const(tvb_get_ntohl(tvb, offset + 1 + 2 + name_length + 2),
                                                          job_state_vals,
                                                          "Unknown Job State"));
            }
            else {
                subtree = proto_tree_add_subtree_format(tree, tvb, offset,
                                         1 + 2 + name_length + 2 + value_length,
                                         ett_ipp_attr, NULL, "%s: %u",
                                         format_text(name_val, name_length),
                                         tvb_get_ntohl(tvb, offset + 1 + 2 + name_length + 2));
            }
        }
        break;

    default:
        subtree = proto_tree_add_subtree_format(tree, tvb, offset,
                                 1 + 2 + name_length + 2 + value_length,
                                 ett_ipp_attr, NULL, "%s: Unknown integer type 0x%02x",
                                 tvb_format_text(tvb, offset + 1 + 2, name_length),
                                 tag);
        break;
    }
    return subtree;
}

static void
add_integer_value(const gchar *tag_desc, proto_tree *tree, tvbuff_t *tvb,
                  int offset, int name_length, int value_length, guint8 tag)
{
    char *name_val = NULL;

    offset = add_value_head(tag_desc, tree, tvb, offset, name_length,
                            value_length, &name_val);

    switch (tag) {

    case TAG_BOOLEAN:
        if (value_length == 1) {
            proto_tree_add_item(tree, hf_ipp_bool_value, tvb, offset, value_length, ENC_BIG_ENDIAN);
        }
        break;

    case TAG_INTEGER:
    case TAG_ENUM:
        /* Some fields in IPP are really unix timestamps but IPP
         * transports these as 4 byte integers.
         * A simple heuristic to make the display of these fields
         * more human readable is to assume that if the field name
         * ends in '-time' then assume they are timestamps instead
         * of integers.
         */
        if (value_length == 4) {
            if ((name_length > 5) && name_val && !strcmp(name_val+name_length-5, "-time")) {
                nstime_t ns;

                ns.secs=tvb_get_ntohl(tvb, offset);
                ns.nsecs=0;
                proto_tree_add_time(tree, hf_ipp_timestamp, tvb, offset, 4, &ns);
            }
            else if ((name_length > 5) && name_val && !strcmp(name_val, "printer-state")) {
                proto_tree_add_item(tree, hf_ipp_printer_state, tvb, offset, value_length, ENC_BIG_ENDIAN);
            }
            else if ((name_length > 5) && name_val && !strcmp(name_val, "job-state")) {
                proto_tree_add_item(tree, hf_ipp_job_state, tvb, offset, value_length, ENC_BIG_ENDIAN);
            }
            else{
                proto_tree_add_item(tree, hf_ipp_uint32_value, tvb, offset, value_length, ENC_BIG_ENDIAN);
            }
        }
        break;
    }
}

static proto_tree *
add_octetstring_tree(proto_tree *tree, tvbuff_t *tvb, int offset,
                     int name_length, int value_length)
{
    return proto_tree_add_subtree_format(tree, tvb, offset,
                             1 + 2 + name_length + 2 + value_length,
                             ett_ipp_attr, NULL, "%s: %s",
                             tvb_format_text(tvb, offset + 1 + 2, name_length),
                             tvb_bytes_to_str(wmem_packet_scope(), tvb, offset + 1 + 2 + name_length + 2, value_length));
}

static void
add_octetstring_value(const gchar *tag_desc, proto_tree *tree, tvbuff_t *tvb,
                      int offset, int name_length, int value_length)
{
    offset = add_value_head(tag_desc, tree, tvb, offset, name_length,
                            value_length, NULL);
    proto_tree_add_item(tree, hf_ipp_bytes_value, tvb, offset, value_length, ENC_NA);
}

static proto_tree *
add_charstring_tree(proto_tree *tree, tvbuff_t *tvb, int offset,
                    int name_length, int value_length)
{
    return proto_tree_add_subtree_format(tree, tvb, offset,
                             1 + 2 + name_length + 2 + value_length,
                             ett_ipp_attr, NULL, "%s: %s",
                             tvb_format_text(tvb, offset + 1 + 2, name_length),
                             tvb_format_text(tvb, offset + 1 + 2 + name_length + 2, value_length));
}

static void
add_charstring_value(const gchar *tag_desc, proto_tree *tree, tvbuff_t *tvb,
                     int offset, int name_length, int value_length)
{
    offset = add_value_head(tag_desc, tree, tvb, offset, name_length,
                            value_length, NULL);
    proto_tree_add_item(tree, hf_ipp_charstring_value, tvb, offset, value_length, ENC_NA|ENC_ASCII);
}

/* If name_val is !NULL then return the pointer to an emem allocated string in
 * this variable.
 */
static int
add_value_head(const gchar *tag_desc, proto_tree *tree, tvbuff_t *tvb,
               int offset, int name_length, int value_length, char **name_val)
{
    proto_tree_add_string(tree, hf_ipp_tag, tvb, offset, 1, tag_desc);
    offset += 1;
    proto_tree_add_uint(tree, hf_ipp_name_length, tvb, offset, 2, name_length);
    offset += 2;
    if (name_length != 0) {
        guint8 *nv;
        nv = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, name_length, ENC_ASCII);
        proto_tree_add_string(tree, hf_ipp_name, tvb, offset, name_length, format_text(nv, name_length));
        if (name_val) {
            *name_val=nv;
        }
    }
    offset += name_length;
    proto_tree_add_uint(tree, hf_ipp_value_length, tvb, offset, 2, value_length);
    offset += 2;
    return offset;
}

static void
ipp_fmt_version( gchar *result, guint32 revision )
{
   g_snprintf( result, ITEM_LABEL_LENGTH, "%u.%u", (guint8)(( revision & 0xFF00 ) >> 8), (guint8)(revision & 0xFF) );
}

void
proto_register_ipp(void)
{
    static hf_register_info hf[] = {
        { &hf_ipp_timestamp,
          { "Time", "ipp.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_ipp_version, { "Version", "ipp.version", FT_UINT16, BASE_CUSTOM, CF_FUNC(ipp_fmt_version), 0x0, NULL, HFILL }},
      { &hf_ipp_operation_id, { "Operation-id", "ipp.operation_id", FT_UINT16, BASE_HEX, VALS(operation_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_status_code, { "Status-code", "ipp.status_code", FT_UINT16, BASE_HEX, VALS(status_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_request_id, { "Request ID", "ipp.request_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_bool_value, { "Value", "ipp.bool_value", FT_UINT8, BASE_HEX, VALS(bool_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_printer_state, { "Printer State", "ipp.printer_state", FT_UINT32, BASE_DEC, VALS(printer_state_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_job_state, { "Job State", "ipp.job_state", FT_UINT32, BASE_DEC, VALS(job_state_vals), 0x0, NULL, HFILL }},
      { &hf_ipp_uint32_value, { "Value", "ipp.uint_value", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_bytes_value, { "Value", "ipp.bytes_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_charstring_value, { "Value", "ipp.charstring_value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_tag, { "Tag", "ipp.tag", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_name_length, { "Name length", "ipp.name_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_name, { "Name", "ipp.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ipp_value_length, { "Value length", "ipp.value_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };
    static gint *ett[] = {
        &ett_ipp,
        &ett_ipp_as,
        &ett_ipp_attr,
    };

    proto_ipp = proto_register_protocol("Internet Printing Protocol", "IPP", "ipp");

    proto_register_field_array(proto_ipp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipp(void)
{
    dissector_handle_t ipp_handle;

    /*
     * Register ourselves as running atop HTTP and using port 631.
     */
    ipp_handle = create_dissector_handle(dissect_ipp, proto_ipp);
    http_tcp_dissector_add(631, ipp_handle);
    dissector_add_string("media_type", "application/ipp", ipp_handle);
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
