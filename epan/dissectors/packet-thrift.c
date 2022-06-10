/* packet-thrift.c
 * Routines for thrift protocol dissection.
 * Based on work by John Song <jsong@facebook.com> and
 * Bill Fumerola <bill@facebook.com>
 *
 * https://github.com/andrewcox/wireshark-with-thrift-plugin/blob/wireshark-1.8.6-with-thrift-plugin/plugins/thrift/packet-thrift.cpp
 *
 * Copyright 2015, Anders Broman <anders.broman[at]ericsson.com>
 * Copyright 2021, Richard van der Hoff <richard[at]matrix.org>
 * Copyright 2019-2021, Triton Circonflexe <triton[at]kumal.info>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/* Ref https://thrift.apache.org/developers
 *     https://thrift.apache.org/docs/idl.html
 *     https://diwakergupta.github.io/thrift-missing-guide/
 *     https://erikvanoosten.github.io/thrift-missing-specification/
 *     https://github.com/apache/thrift/blob/master/doc/specs/thrift-compact-protocol.md
 */

#include "config.h"

#include <stdint.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include "packet-tcp.h"
#include "packet-tls.h"
#include "packet-thrift.h"

/* Line  30: Constants and early declarations. */
/* Line 180: Protocol data structure and helper functions. */
/* Line 300: Helper functions to use within custom sub-dissectors. */
/* Line 630: Generic functions to dissect TBinaryProtocol message content. */
/* Line 900: Generic functions to dissect Thrift message header. */

void proto_register_thrift(void);
void proto_reg_handoff_thrift(void);

#define THRIFT_BINARY_VERSION_VALUE_MASK   0x7fff
#define THRIFT_BINARY_VERSION_MASK     0xffff00f8
#define THRIFT_BINARY_MESSAGE_MASK     0x00000007
#define THRIFT_BINARY_VERSION_1        0x80010000

#define THRIFT_COMPACT_VERSION_VALUE_MASK   0x001f
#define THRIFT_COMPACT_VERSION_MASK         0xff1f
#define THRIFT_COMPACT_MESSAGE_MASK         0x00e0
#define THRIFT_COMPACT_VERSION_1            0x8201
#define THRIFT_COMPACT_MESSAGE_SHIFT             5

#define NOT_A_VALID_PDU (0)

#define ABORT_SUBDISSECTION_ON_ISSUE(offset) do { if (offset < 0) return offset; } while (0)

#define ABORT_ON_INCOMPLETE_PDU(len) do {\
    if (tvb_reported_length_remaining(tvb, *offset) < (len)) {\
        /* Do not indicate the incomplete data if we know the above dissector is able to reassemble. */\
        if (pinfo->can_desegment <= 0) \
            expert_add_info(pinfo, NULL, &ei_thrift_not_enough_data);\
        /* Do not consume more than available for the reassembly to work. */\
        thrift_opt->reassembly_offset = *offset;\
        thrift_opt->reassembly_length = len;\
        *offset = THRIFT_REQUEST_REASSEMBLY;\
        return THRIFT_REQUEST_REASSEMBLY;\
    } } while (0)

static dissector_handle_t thrift_handle;
static gboolean framed_desegment = TRUE;
static guint thrift_tls_port = 0;

static gboolean show_internal_thrift_fields = FALSE;
static gboolean try_generic_if_sub_dissector_fails = FALSE;
static guint nested_type_depth = 25;

static dissector_table_t thrift_method_name_dissector_table;

/* TBinaryProtocol elements length. */
static const int TBP_THRIFT_TYPE_LEN = 1;
static const int TBP_THRIFT_FID_LEN = 2;
static const int TBP_THRIFT_BOOL_LEN = 1;
static const int TBP_THRIFT_I8_LEN = 1;
static const int TBP_THRIFT_DOUBLE_LEN = 8;
static const int TBP_THRIFT_I16_LEN = 2;
static const int TBP_THRIFT_I32_LEN = 4;
static const int TBP_THRIFT_I64_LEN = 8;
static const int TBP_THRIFT_UUID_LEN = 16;
static const int TBP_THRIFT_MTYPE_OFFSET = 3;
static const int TBP_THRIFT_MTYPE_LEN = 1;
static const int TBP_THRIFT_VERSION_LEN = 4; /* (Version + method type) is explicitly passed as an int32 in libthrift */
static const int TBP_THRIFT_LENGTH_LEN = 4;
static const int TBP_THRIFT_SEQ_ID_LEN = 4;
static const int TBP_THRIFT_STRICT_HEADER_LEN = 8; /* (Protocol id + Version + Method type) + Name length = (4) + 4. */
                                    /* Old encoding: Name length [ + Name] + Message type      + Sequence Identifier   + T_STOP */
static const int TBP_THRIFT_MIN_MESSAGE_LEN = 10; /* TBP_THRIFT_LENGTH_LEN + TBP_THRIFT_I8_LEN + TBP_THRIFT_SEQ_ID_LEN + TBP_THRIFT_TYPE_LEN; */
static const int TBP_THRIFT_STRICT_MIN_MESSAGE_LEN = 13; /* TBP_THRIFT_STRICT_HEADER_LEN       + TBP_THRIFT_SEQ_ID_LEN + TBP_THRIFT_TYPE_LEN; */
static const int TBP_THRIFT_BINARY_LEN = 4; /* Length (even with empty content). */
static const int TBP_THRIFT_STRUCT_LEN = 1; /* Empty struct still contains T_STOP. */
static const int TBP_THRIFT_LINEAR_LEN = 5; /* Elements type + number of elements for list & set. */

/* TCompactProtocol elements length when different from TBinaryProtocol.
 * Are identical:
 * - Field Type (although Compact squeezes in the high nibble the field id delta or list/set length).
 * - T_BOOL (in linear containers, not structs)
 * - T_I8
 * - T_DOUBLE (endianness is inverted, though)
 */
static const int TCP_THRIFT_DELTA_NOT_SET = 0;
static const int TCP_THRIFT_LENGTH_LARGER = 0xf;
static const int TCP_THRIFT_MAP_TYPES_LEN = 1;      /* High nibble = key type, low nibble = value type. */
static const int TCP_THRIFT_NIBBLE_SHIFT = 4;
static const int TCP_THRIFT_VERSION_LEN = 2;     /* Protocol id + (Method type + Version) */
static const int TCP_THRIFT_MIN_VARINT_LEN = 1;
/* Those cannot be define as static const int since they are used within a switch. */
/* Maximum length in bytes for 16, 32, and 64 bits integers encoded as varint. */
#define TCP_THRIFT_MAX_I16_LEN (3)
#define TCP_THRIFT_MAX_I32_LEN (5)
#define TCP_THRIFT_MAX_I64_LEN (10)
static const int TCP_THRIFT_STRUCT_LEN = 1; /* Empty struct still contains T_STOP. */
static const int TCP_THRIFT_MIN_MESSAGE_LEN = 5; /* Protocol id + (Method type + Version) + Name length [+ Name] + Sequence Identifier + T_STOP */

static const guint32 TCP_THRIFT_NIBBLE_MASK = 0xf;

static const int OCTETS_TO_BITS_SHIFT = 3;   /* 8 bits per octets = 3 shifts left. */
static const int DISABLE_SUBTREE = -1;

static int proto_thrift = -1;
static int hf_thrift_frame_length = -1;
static int hf_thrift_protocol_id = -1;
static int hf_thrift_version = -1;
static int hf_thrift_mtype = -1;
static int hf_thrift_str_len = -1;
static int hf_thrift_method = -1;
static int hf_thrift_seq_id = -1;
static int hf_thrift_type = -1;
static int hf_thrift_key_type = -1;
static int hf_thrift_value_type = -1;
static int hf_thrift_compact_struct_type = -1;
static int hf_thrift_fid = -1;
static int hf_thrift_fid_delta = -1;
static int hf_thrift_bool = -1;
static int hf_thrift_i8 = -1;
static int hf_thrift_i16 = -1;
static int hf_thrift_i32 = -1;
static int hf_thrift_i64 = -1;
static int hf_thrift_uuid = -1;
static int hf_thrift_binary = -1;
static int hf_thrift_string = -1;
static int hf_thrift_struct = -1;
static int hf_thrift_list = -1;
static int hf_thrift_set = -1;
static int hf_thrift_map = -1;
static int hf_thrift_num_list_item = -1;
static int hf_thrift_num_list_pos = -1;
static int hf_thrift_num_set_item = -1;
static int hf_thrift_num_set_pos = -1;
static int hf_thrift_num_map_item = -1;
static int hf_thrift_large_container = -1;
static int hf_thrift_double = -1;
static int hf_thrift_exception = -1;
static int hf_thrift_exception_message = -1;
static int hf_thrift_exception_type = -1;

static int ett_thrift = -1;
static int ett_thrift_header = -1;
static int ett_thrift_params = -1;
static int ett_thrift_field = -1;
static int ett_thrift_struct = -1;
static int ett_thrift_list = -1;
static int ett_thrift_set = -1;
static int ett_thrift_map = -1;
static int ett_thrift_error = -1; /* Error while reading the header. */
static int ett_thrift_exception = -1; /* ME_THRIFT_T_EXCEPTION */

static expert_field ei_thrift_wrong_type = EI_INIT;
static expert_field ei_thrift_wrong_field_id = EI_INIT;
static expert_field ei_thrift_negative_length = EI_INIT;
static expert_field ei_thrift_wrong_proto_version = EI_INIT;
static expert_field ei_thrift_struct_fid_not_in_seq = EI_INIT;
static expert_field ei_thrift_frame_too_short = EI_INIT;
static expert_field ei_thrift_not_enough_data = EI_INIT;
static expert_field ei_thrift_frame_too_long = EI_INIT;
static expert_field ei_thrift_varint_too_large = EI_INIT;
static expert_field ei_thrift_undefined_field_id = EI_INIT;
static expert_field ei_thrift_negative_field_id = EI_INIT;
static expert_field ei_thrift_unordered_field_id = EI_INIT;
static expert_field ei_thrift_application_exception = EI_INIT;
static expert_field ei_thrift_protocol_exception = EI_INIT;
static expert_field ei_thrift_too_many_subtypes = EI_INIT;

static const thrift_member_t thrift_exception[] = {
    { &hf_thrift_exception_message, 1, TRUE, DE_THRIFT_T_BINARY, NULL, { .encoding = ENC_UTF_8|ENC_NA } },
    { &hf_thrift_exception_type, 2, FALSE, DE_THRIFT_T_I32, TMFILL },
    { NULL, 0, FALSE, DE_THRIFT_T_STOP, TMFILL }
};

typedef enum {
    DE_THRIFT_C_STOP = DE_THRIFT_T_STOP,
    DE_THRIFT_C_BOOL_TRUE,
    DE_THRIFT_C_BOOL_FALSE,
    DE_THRIFT_C_I8,
    DE_THRIFT_C_I16,
    DE_THRIFT_C_I32,
    DE_THRIFT_C_I64,
    DE_THRIFT_C_DOUBLE,
    DE_THRIFT_C_BINARY,
    DE_THRIFT_C_LIST,
    DE_THRIFT_C_SET,
    DE_THRIFT_C_MAP,
    DE_THRIFT_C_STRUCT,
    DE_THRIFT_C_UUID,
} thrift_compact_type_enum_t;

typedef struct _thrift_field_header_t {
    union {
        thrift_type_enum_t binary;
        thrift_compact_type_enum_t compact;
    } type;
    int type_offset;
    gint64 field_id;
    int fid_offset;
    int fid_length;
    proto_item *type_pi;
    proto_item *fid_pi;
    proto_tree *fh_tree;
} thrift_field_header_t;

static const value_string thrift_type_vals[] = {
    { DE_THRIFT_T_STOP, "T_STOP" },
    { DE_THRIFT_T_VOID, "T_VOID" },
    { DE_THRIFT_T_BOOL, "T_BOOL" },
    { DE_THRIFT_T_I8, "T_I8" },
    { DE_THRIFT_T_DOUBLE, "T_DOUBLE" },
    { DE_THRIFT_T_I16, "T_I16" },
    { DE_THRIFT_T_I32, "T_I32" },
    { DE_THRIFT_T_I64, "T_I64" },
    { DE_THRIFT_T_BINARY, "T_BINARY" },
    { DE_THRIFT_T_STRUCT, "T_STRUCT" },
    { DE_THRIFT_T_MAP, "T_MAP" },
    { DE_THRIFT_T_SET, "T_SET" },
    { DE_THRIFT_T_LIST, "T_LIST" },
    { DE_THRIFT_T_UUID, "T_UUID" },
    { 0, NULL }
};

/* type values used within structs in the compact protocol */
static const value_string thrift_compact_type_vals[] = {
    { DE_THRIFT_C_BOOL_TRUE, "BOOLEAN_TRUE" },
    { DE_THRIFT_C_BOOL_FALSE, "BOOLEAN_FALSE" },
    { DE_THRIFT_C_I8, "T_I8" },
    { DE_THRIFT_C_I16, "T_I16" },
    { DE_THRIFT_C_I32, "T_I32" },
    { DE_THRIFT_C_I64, "T_I64" },
    { DE_THRIFT_C_DOUBLE, "T_DOUBLE" },
    { DE_THRIFT_C_BINARY, "T_BINARY" },
    { DE_THRIFT_C_LIST, "T_LIST" },
    { DE_THRIFT_C_SET, "T_SET" },
    { DE_THRIFT_C_MAP, "T_MAP" },
    { DE_THRIFT_C_STRUCT, "T_STRUCT" },
    { DE_THRIFT_C_UUID, "T_UUID" },
    { 0, NULL }
};

static const value_string thrift_exception_type_vals[] = {
    {  0, "Unknown (type of peer)" },
    {  1, "Unknown Method" },
    {  2, "Invalid Message Type" },
    {  3, "Wrong Method Name" },
    {  4, "Bad Sequence Id" },
    {  5, "Missing Result" },
    {  6, "Internal Error" },
    {  7, "Protocol Error (something went wrong during decoding)" },
    {  8, "Invalid Transform" },
    {  9, "Invalid Protocol" },
    { 10, "Unsupported Client Type" },
    { 0, NULL }
};

static const value_string thrift_proto_vals[] = {
    { 0x80, "Strict Binary Protocol" },
    { 0x82, "Compact Protocol" },
    { 0, NULL }
};

static const value_string thrift_mtype_vals[] = {
    { ME_THRIFT_T_CALL,      "CALL" },
    { ME_THRIFT_T_REPLY,     "REPLY" },
    { ME_THRIFT_T_EXCEPTION, "EXCEPTION" },
    { ME_THRIFT_T_ONEWAY,    "ONEWAY" },
    { 0, NULL }
};

/* Options */
#define DECODE_BINARY_AS_AUTO_UTF8      0
#define DECODE_BINARY_AS_BINARY         1
#define DECODE_BINARY_AS_ASCII          2
#define DECODE_BINARY_AS_UTF8           3
#define DECODE_BINARY_AS_UTF16BE        4
#define DECODE_BINARY_AS_UTF16LE        5
#define DECODE_BINARY_AS_UTF32BE        6
#define DECODE_BINARY_AS_UTF32LE        7

static gint32   binary_decode = DECODE_BINARY_AS_AUTO_UTF8;

static const enum_val_t binary_display_options[] = {
    { "auto", "UTF-8 if printable", DECODE_BINARY_AS_AUTO_UTF8 },
    { "hexadecimal", "Binary (hexadecimal string)", DECODE_BINARY_AS_BINARY },
    { "ascii", "ASCII String", DECODE_BINARY_AS_ASCII },
    { "utf8", "UTF-8 String", DECODE_BINARY_AS_UTF8 },
    { "utf16be", "UTF-16 Big Endian", DECODE_BINARY_AS_UTF16BE },
    { "utf16le", "UTF-16 Little Endian", DECODE_BINARY_AS_UTF16LE },
    { "utf32be", "UTF-32 Big Endian", DECODE_BINARY_AS_UTF32BE },
    { "utf32le", "UTF-32 Little Endian", DECODE_BINARY_AS_UTF32LE },
    { NULL, NULL, -1 }
};

static int dissect_thrift_binary_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, proto_tree *header_tree, int type, proto_item *type_pi);
static int dissect_thrift_compact_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, proto_tree *header_tree, int type, proto_item *type_pi);


/*=====BEGIN GENERIC HELPERS=====*/
/* Check that the 4-byte value match a Thrift Strict TBinaryProtocol version
 * - 0x8001 The version itself
 * - 0x??   An undetermined byte (not used)
 * - 0x0m   The method type between 1 and 4.
 *          Values above 4 will be accepted if ignore_msg_type is TRUE.
 */
static gboolean
is_thrift_strict_version(guint32 header, gboolean ignore_msg_type)
{
    int msg_type;
    if ((header & THRIFT_BINARY_VERSION_MASK) == THRIFT_BINARY_VERSION_1) {
        if (ignore_msg_type) {
            return TRUE;
        }
        msg_type = (header & THRIFT_BINARY_MESSAGE_MASK);
        if ((ME_THRIFT_T_CALL <= msg_type) && (msg_type <= ME_THRIFT_T_ONEWAY)) {
            return TRUE;
        }
    }
    return FALSE;
}

/* Check that the 2-byte value match a Thrift TCompactProtocol version
 * - 0x82 The protocol id.
 * - 0bmmmvvvvv The method on the 3 MSbits and version on the 5 LSbits.
 */
static gboolean
is_thrift_compact_version(guint16 header, gboolean ignore_msg_type)
{
    int msg_type;
    if ((header & THRIFT_COMPACT_VERSION_MASK) == THRIFT_COMPACT_VERSION_1) {
        if (ignore_msg_type) {
            return TRUE;
        }
        msg_type = (header & THRIFT_COMPACT_MESSAGE_MASK) >> THRIFT_COMPACT_MESSAGE_SHIFT;
        if ((ME_THRIFT_T_CALL <= msg_type) && (msg_type <= ME_THRIFT_T_ONEWAY)) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Check that the string at the designed position is valid UTF-8.
 * This allows us to fail early if the length of the string seems very long.
 * This /can/ indicate that this packet does not contain a Thrift PDU.
 *
 * This method does /NOT/ check if the data is available, the caller must check that if needed.
 * - Heuristic for method name must check for captured length.
 * - Check UTF-8 vs. binary before adding to tree must check for reported length.
 */
static int
thrift_binary_utf8_isprint(tvbuff_t *tvb, int offset, int max_len, gboolean accept_crlf)
{
    int check_len = tvb_reported_length_remaining(tvb, offset);
    int pos, remaining = 0; /* position in tvb, remaining bytes for multi-byte characters. */
    guint8 min_next = 0x80, max_next = 0xBF;
    gboolean ended = FALSE;
    int printable_len = 0; /* In case the string ends with several NUL bytes. */
    if (max_len < check_len) {
        check_len = max_len;
    }
    for (pos = offset; pos < offset + check_len; pos++) {
        guint8 current = tvb_get_guint8(tvb, pos);
        if (ended) {
            if (current != 0) {
                return -1;
            }
        } else if (remaining == 0) {
            /* We are at the beginning of a character. */
            if (current == 0) {
                ended = TRUE;
                continue; /* Avoid counting this NUL byte as printable. */
            } else if ((current & 0x80) == 0) {
                if (!g_ascii_isprint(current)) {
                    if (!accept_crlf) {
                        /* New line and chariot return or not valid in the method name */
                        return -1;
                    }
                    if (current != '\r' && current != '\n') {
                        /* But would have been acceptable for data content */
                        return -1;
                    }
                }
            } else if ((current & 0xE0) == 0xC0) {
                /* 2 bytes code 8 to 11 bits */
                if (current >= 0xC2) {
                    remaining = 1;
                    min_next = 0x80;
                } else {
                    /* Overlong encoding of ASCII for C0 and C1. */
                    return -1;
                }
            } else if ((current & 0xF0) == 0xE0) {
                /* 3 bytes code 12 to 16 bits */
                remaining = 2;
                if (current == 0xE0) {
                    min_next = 0xA0; /* 0b101x xxxx to code at least 12 bits. */
                } else {
                    if (current == 0xED) {
                        /* Reject reserved UTF-16 surrogates as specified for UTF-8. */
                        max_next = 0x9F;
                    }
                    min_next = 0x80;
                }
            } else if ((current & 0xF8) == 0xF0) {
                /* 4 bytes code 17 to 21 bits */
                remaining = 3;
                if (current == 0xF0) {
                    min_next = 0x90; /* 0b1001 xxxx to code at least 17 bits. */
                } else if (current > 0xF4) {
                    /* Invalid leading byte (above U+10FFFF). */
                    return -1;
                } else {
                    min_next = 0x80;
                }
            } else {
                /* Not the beginning of an UTF-8 character. */
                return -1;
            }
            ++printable_len;
        } else {
            if ((current < min_next) || (max_next < current)) {
                /* Not a canonical UTF-8 character continuation. */
                return -1;
            }
            min_next = 0x80;
            max_next = 0xBF;
            --remaining;
            ++printable_len;
        }
    }
    return printable_len;
}

/** Simple wrapper around tvb_get_varint to handle reassembly.
 *
 * @param[in] tvb        Pointer to the tvbuff_t holding the captured data.
 * @param[in] pinfo      Pointer to the packet_info holding information about the currently dissected packet.
 * @param[in] tree       Pointer to the proto_tree used to hold the display tree in Wireshark's interface.
 * @param[in] offset     Offset from the beginning of the tvbuff_t where the Thrift field is. Function will dissect type, id, & data.
 * @param[in] max_length The expected maximum encoding length of the integer.
 * @param[in] value      If parsing succeeds, parsed varint will be stored here.
 * @param[in] encoding   The ENC_* that defines the format (e.g., ENC_VARINT_PROTOBUF or ENC_VARINT_ZIGZAG).
 *
 * @return THRIFT_REQUEST_REASSEMBLY(-1) if reassembly is necessary,
 *                                    0  in case of error,
 *         a positive value indicating the length of the varint otherwise.
 */
static int
thrift_get_varint_enc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int max_length, guint64 *value, const guint encoding)
{
    guint length;
    int readable = tvb_reported_length_remaining(tvb, offset);
    if (readable <= 0) {
        return THRIFT_REQUEST_REASSEMBLY;
    }
    if (readable > TCP_THRIFT_MAX_I64_LEN) {
        readable = TCP_THRIFT_MAX_I64_LEN;
    }
    length = tvb_get_varint(tvb, offset, readable, value, encoding);
    if (length == 0) {
        if (readable < max_length) {
            /* There was not enough data to ensure the varint is complete for the expected size of integer. */
            return THRIFT_REQUEST_REASSEMBLY;
        } else {
            /* Either an error on the wire or a sub-optimal encoding, we always consider it as an error. */
            proto_tree_add_expert(tree, pinfo, &ei_thrift_varint_too_large, tvb, offset, max_length);
        }
    }
    return length;
}

/* Function that reads the field header and return all associated data.
 *
 * @param[in] tvb:          Pointer to the tvbuff_t holding the captured data.
 * @param[in] pinfo:        Pointer to the packet_info holding information about the currently dissected packet.
 * @param[in] tree:         Pointer to the proto_tree used to hold the display tree in Wireshark's interface.
 *                          The caller may set it to NULL to prevent the creation of the field header sub-tree.
 *                          This possibility is used by sub-dissector when show_internal_thrift_fields is FALSE,
 *                          and by dissect_thrift_common to differentiate between successful and exception T_REPLY.
 * @param[in] offset:       Offset from the beginning of the tvbuff_t where the Thrift field is. Function will dissect type, id, & data.
 * @param[in] thrift_opt:   Options from the Thrift dissector that will be necessary for sub-dissection (binary vs. compact, ...)
 *
 */
static int
dissect_thrift_field_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, thrift_field_header_t *header)
{
    /*
     *  Binary protocol field header (3 bytes):
     *      +--------+--------+--------+
     *      |0000tttt| field id        |
     *      +--------+--------+--------+
     *
     *  Compact protocol field header (1 byte, short form):
     *      +--------+
     *      |ddddtttt|
     *      +--------+
     *
     *  Compact protocol field header (2 to 4 bytes, long form):
     *      +--------+--------+...+--------+
     *      |0000tttt| field id            |
     *      +--------+--------+...+--------+
     *
     *  Binary & Compact protocol stop field (1 byte):
     *      +--------+
     *      |00000000|
     *      +--------+
     *
     *  Where:
     *      'dddd'      is the field id delta, a strictly positive unsigned 4 bits integer.
     *      'tttt'      is the type of the field value, an unsigned 4 bits strictly positive integer.
     *      field id    is the numerical value of the field in the structure.
     */

    DISSECTOR_ASSERT(header != NULL);

    ABORT_SUBDISSECTION_ON_ISSUE(*offset); /* In case of sub-dissection functions. */
    ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_TYPE_LEN); /* In all dissection cases. */

    guint8 dfid_type = tvb_get_guint8(tvb, *offset);
    gint32 delta = TCP_THRIFT_DELTA_NOT_SET;
    gint64 fid = 0;

    memset(header, 0, sizeof(thrift_field_header_t));

    /* Read type (and delta for Compact) */
    header->type_offset = *offset;
    *offset += TBP_THRIFT_TYPE_LEN;

    if (dfid_type == DE_THRIFT_T_STOP) {
        header->type.binary = (thrift_type_enum_t)dfid_type;
        /* No need for sub-tree in this case. */
        header->type_pi = proto_tree_add_item(tree, hf_thrift_type, tvb, header->type_offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
        return *offset;
    }

    /* Read the field id */
    if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
        header->type.compact = (thrift_compact_type_enum_t)(dfid_type & TCP_THRIFT_NIBBLE_MASK);
        delta = (dfid_type >> TCP_THRIFT_NIBBLE_SHIFT) & TCP_THRIFT_NIBBLE_MASK;
        if (delta == TCP_THRIFT_DELTA_NOT_SET) {
            header->fid_offset = *offset;
            header->fid_length = thrift_get_varint_enc(tvb, pinfo, NULL, *offset, TCP_THRIFT_MAX_I16_LEN, &fid, ENC_VARINT_ZIGZAG);
            switch (header->fid_length) {
            case THRIFT_REQUEST_REASSEMBLY:
                /* Will always return after setting the expert parts. */
                ABORT_ON_INCOMPLETE_PDU(TCP_THRIFT_MAX_I16_LEN);
                return THRIFT_REQUEST_REASSEMBLY; // Just to avoid a false positive warning.
            case 0: /* In case of error, the offset stay at the error position. */
            default:
                header->field_id = fid;
                *offset += header->fid_length;
                break;
            }
        } else {
            /* The field id data in the tvb is represented by the delta with the type. */
            header->field_id = thrift_opt->previous_field_id + delta;
            header->fid_offset = header->type_offset;
            header->fid_length = TBP_THRIFT_TYPE_LEN;
        }
    } else {
        /* Fixed size field id for Binary protocol. */
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_FID_LEN);
        header->type.binary = (thrift_type_enum_t)dfid_type;
        header->field_id = tvb_get_ntohis(tvb, *offset);
        header->fid_offset = *offset;
        header->fid_length = TBP_THRIFT_FID_LEN;
        *offset += TBP_THRIFT_FID_LEN;
    }

    /* Create the field header sub-tree if requested only. */
    if (tree != NULL) {
        header->fh_tree = proto_tree_add_subtree_format(tree, tvb, header->type_offset, *offset - header->type_offset, ett_thrift_field, NULL,
                "Field Header #%" PRId64, header->field_id);
        if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
            header->type_pi = proto_tree_add_bits_item(header->fh_tree, hf_thrift_compact_struct_type, tvb, (header->type_offset << OCTETS_TO_BITS_SHIFT) + TCP_THRIFT_NIBBLE_SHIFT, TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
            header->fid_pi = proto_tree_add_bits_item(header->fh_tree, hf_thrift_fid_delta, tvb, header->type_offset << OCTETS_TO_BITS_SHIFT, TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
            if (delta == TCP_THRIFT_DELTA_NOT_SET) {
                proto_item_append_text(header->fid_pi, " (Not Set)");
            }
        } else {
            header->type_pi = proto_tree_add_item(header->fh_tree, hf_thrift_type, tvb, header->type_offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
        }
        if (delta == TCP_THRIFT_DELTA_NOT_SET) {
            if (header->fid_length > 0) {
                header->fid_pi = proto_tree_add_item(header->fh_tree, hf_thrift_fid, tvb, header->fid_offset, header->fid_length, ENC_BIG_ENDIAN);
            } else {
                /* Varint for field id was too long to decode, handle the error in the sub-tree. */
                proto_tree_add_expert(header->fh_tree, pinfo, &ei_thrift_varint_too_large, tvb, header->fid_offset, TCP_THRIFT_MAX_I16_LEN);
                return THRIFT_REQUEST_REASSEMBLY;
            }
        } else {
            if ((gint64)INT16_MIN > header->field_id || header->field_id > (gint64)INT16_MAX) {
                header->fid_pi = proto_tree_add_int64(header->fh_tree, hf_thrift_i64, tvb, header->fid_offset, header->fid_length, header->field_id);
                expert_add_info(pinfo, header->fid_pi, &ei_thrift_varint_too_large);
                /* We continue anyway as the field id was displayed successfully. */
            } else {
                header->fid_pi = proto_tree_add_int(header->fh_tree, hf_thrift_fid, tvb, header->fid_offset, header->fid_length, (gint16)header->field_id);
            }
            proto_item_set_generated(header->fid_pi);
        }
        /* When reading a successful T_REPLY, we always have
         * - previous_field_id == 0 because we are at the beginning of a structure, and
         * - header->field_id == 0 because it is the return value
         * so we need to ignore this case. */
        if (header->field_id < thrift_opt->previous_field_id || (header->field_id == thrift_opt->previous_field_id && thrift_opt->previous_field_id != 0)) {
            if (thrift_opt->previous_field_id == 0) {
                // Maybe an old application from when negative values were authorized.
                expert_add_info(pinfo, header->fid_pi, &ei_thrift_negative_field_id);
            } else {
                // Although not mandated by Thrift protocol, applications should send fields in numerical order.
                expert_add_info(pinfo, header->fid_pi, &ei_thrift_unordered_field_id);
            }
        }
    } else if (header->fid_length <= 0) {
        /* Varint for field id was too long to decode, handle the error without the sub-tree. */
        proto_tree_add_expert(tree, pinfo, &ei_thrift_varint_too_large, tvb, header->fid_offset, TCP_THRIFT_MAX_I16_LEN);
        return THRIFT_REQUEST_REASSEMBLY;
    }

    return *offset;
}

/* Dissect a varint and add it to the display tree with the requested hf_id.
 * This function is used by both generic compact dissector and sub-dissector.
 *
 * @param[in] tvb:          Pointer to the tvbuff_t holding the captured data.
 * @param[in] pinfo:        Pointer to the packet_info holding information about the currently dissected packet.
 * @param[in] tree:         Pointer to the proto_tree used to hold the display tree in Wireshark's interface.
 * @param[in,out] offset:   Pointer to the offset from the beginning of the tvbuff_t where the Thrift field is. Function will dissect only the data.
 *                          The offset is modified according to table in "GENERIC DISSECTION PARAMETERS DOCUMENTATION" section.
 * @param[in] thrift_opt:   Options from the Thrift dissector that will be necessary for sub-dissection (binary vs. compact, ...)
 *
 * @param[in] max_length:   Expected maximum length of the data that encodes the integer.
 *                          This is only used to check if reassembly is necessary as with enough data and sub-optimal encoding,
 *                          this function will happily dissect the value anyway.
 * @param[in] hf_id:        The hf_id that needs to be used for the display.
 *                          If the found integer is larger that the expected integer size (driven by max_length parameter),
 *                          the integer will always be displayed as a generic T_I64 and an expert info will be added.
 *
 * @return                  See "GENERIC DISSECTION PARAMETERS DOCUMENTATION".
 */
static int
dissect_thrift_varint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, int max_length, int hf_id)
{
    gint64 varint;
    proto_item *pi;
    int length = thrift_get_varint_enc(tvb, pinfo, tree, *offset, max_length, &varint, ENC_VARINT_ZIGZAG);
    switch (length) {
    case THRIFT_REQUEST_REASSEMBLY:
        /* Will always return after setting the expert parts. */
        ABORT_ON_INCOMPLETE_PDU(max_length);
        return THRIFT_REQUEST_REASSEMBLY; // Just to avoid a false positive warning.
    case 0:
        /* In case of error, the offset stay at the error position. */
        return THRIFT_REQUEST_REASSEMBLY;
    default:
        switch (max_length) {
        case TCP_THRIFT_MAX_I16_LEN:
            if ((gint64)INT16_MIN > varint || varint > (gint64)INT16_MAX) {
                pi = proto_tree_add_int64(tree, hf_thrift_i64, tvb, *offset, length, varint);
                expert_add_info(pinfo, pi, &ei_thrift_varint_too_large);
                /* We continue anyway as the varint was indeed decoded. */
            } else {
                proto_tree_add_int(tree, hf_id, tvb, *offset, length, (gint16)varint);
            }
            break;
        case TCP_THRIFT_MAX_I32_LEN:
            if ((gint64)INT32_MIN > varint || varint > (gint64)INT32_MAX) {
                pi = proto_tree_add_int64(tree, hf_thrift_i64, tvb, *offset, length, varint);
                expert_add_info(pinfo, pi, &ei_thrift_varint_too_large);
                /* We continue anyway as the varint was indeed decoded. */
            } else {
                proto_tree_add_int(tree, hf_id, tvb, *offset, length, (gint32)varint);
            }
            break;
        case TCP_THRIFT_MAX_I64_LEN:
        default:
            proto_tree_add_int64(tree, hf_id, tvb, *offset, length, varint);
            break;
        }
        *offset += length;
        break;
    }
    return *offset;
}

/* Common function used by both Binary and Compact generic dissectors to dissect T_BINARY fields
 * as requested in the dissector preferences.
 * This function only dissects the data, not the field header nor the length.
 */
static int
dissect_thrift_string_as_preferred(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, int str_len)
{
    ABORT_ON_INCOMPLETE_PDU(str_len); /* Thrift assumes there will never be binary/string >= 2GiB */

    if (tree) {
        switch (binary_decode) {
            case DECODE_BINARY_AS_UTF32LE:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UCS_4 | ENC_LITTLE_ENDIAN);
                break;
            case DECODE_BINARY_AS_UTF32BE:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UCS_4 | ENC_BIG_ENDIAN);
                break;
            case DECODE_BINARY_AS_UTF16LE:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                break;
            case DECODE_BINARY_AS_UTF16BE:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UTF_16 | ENC_BIG_ENDIAN);
                break;
            case DECODE_BINARY_AS_UTF8:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UTF_8);
                break;
            case DECODE_BINARY_AS_ASCII:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_ASCII);
                break;
            case DECODE_BINARY_AS_AUTO_UTF8:
                /* When there is no data at all, consider it a string
                 * but a buffer containing only NUL bytes is a binary.
                 * If not entirely captured, consider it as a binary. */
                if (tvb_captured_length_remaining(tvb, *offset) >= str_len &&
                    (str_len == 0 || thrift_binary_utf8_isprint(tvb, *offset, str_len, TRUE) > 0)) {
                    proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UTF_8);
                    break;
                }
                /* otherwise, continue with type BINARY */
                /* FALL THROUGH */
            case DECODE_BINARY_AS_BINARY:
            default:
                proto_tree_add_item(tree, hf_thrift_binary, tvb, *offset, str_len, ENC_NA);
                break;
        }
    }
    *offset += str_len;

    return *offset;
}

// Converts the type value in TCompactProtocol to the equivalent standard
// value from TBinaryProtocol.
static thrift_type_enum_t
compact_struct_type_to_generic_type(thrift_compact_type_enum_t compact)
{
    switch (compact) {
    case DE_THRIFT_C_STOP:
        return DE_THRIFT_T_STOP;
    case DE_THRIFT_C_BOOL_TRUE:
    case DE_THRIFT_C_BOOL_FALSE:
        return DE_THRIFT_T_BOOL;
    case DE_THRIFT_C_I8:
        return DE_THRIFT_T_I8;
    case DE_THRIFT_C_I16:
        return DE_THRIFT_T_I16;
    case DE_THRIFT_C_I32:
        return DE_THRIFT_T_I32;
    case DE_THRIFT_C_I64:
        return DE_THRIFT_T_I64;
    case DE_THRIFT_C_DOUBLE:
        return DE_THRIFT_T_DOUBLE;
    case DE_THRIFT_C_BINARY:
        return DE_THRIFT_T_BINARY;
    case DE_THRIFT_C_LIST:
        return DE_THRIFT_T_LIST;
    case DE_THRIFT_C_SET:
        return DE_THRIFT_T_SET;
    case DE_THRIFT_C_MAP:
        return DE_THRIFT_T_MAP;
    case DE_THRIFT_C_STRUCT:
        return DE_THRIFT_T_STRUCT;
    case DE_THRIFT_C_UUID:
        return DE_THRIFT_T_UUID;
    default:
        return DE_THRIFT_T_VOID;
    }
}
/*=====END GENERIC HELPERS=====*/

/*=====BEGIN SUB-DISSECTION=====*/
/*
 * Helper functions to use within custom sub-dissectors.
 *
 * Behavior:
 * 1. If is_field is TRUE, dissect the field header (field type + field id).
 * 1.a. Check the type in the PDU against the expected one according to the call.
 * 2. If requested, add the type and field id to the tree (internal thrift fields).
 * 3. Dissect the value of the field.
 *
 * Return the offset marking the end of the dissected value or a negative error code.
 * See packet-thrift.h for details.
 */

/*
 * See packet-thrift.h for parameters documentation of dissect_thrift_t_<type> functions.
 */
int
dissect_thrift_t_stop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    if (tvb_get_guint8(tvb, offset) != DE_THRIFT_T_STOP) {
        proto_tree_add_expert(tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN);
        return THRIFT_SUBDISSECTOR_ERROR;
    }
    if (show_internal_thrift_fields) {
        proto_tree_add_item(tree, hf_thrift_type, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
    }
    offset += TBP_THRIFT_TYPE_LEN;

    return offset;
}

/* Common function used by all sub-dissection functions to handle the field header dissection as well as the display.
 *
 * @param[in] tvb:          Pointer to the tvbuff_t holding the captured data.
 * @param[in] pinfo:        Pointer to the packet_info holding information about the currently dissected packet.
 * @param[in] tree:         Pointer to the proto_tree used to hold the display tree in Wireshark's interface.
 * @param[in] offset:       Offset from the beginning of the tvbuff_t where the Thrift field is. Function will dissect type, id, & data.
 * @param[in] thrift_opt:   Options from the Thrift dissector that will be necessary for sub-dissection (binary vs. compact, ...)
 *
 * @param[in] expected:     The type expected by the caller sub-dissector.
 *                          Note: the generic type is used even in case of compact dissection.
 *
 * @param[in] field_id:     Thrift field identifier, to check that the right field is being dissected (in case of optional fields).
 *
 * @param[out] header_tree: Optional pointer to a proto_tree pointer.
 *                          If not NULL, the field header sub-tree will be set in this variable.
 *                          Used by binary/string sub-dissector to put the length in this field header as well.
 *
 * @return                  Offset of the first non-dissected byte in case of success,
 *                          THRIFT_REQUEST_REASSEMBLY (-1) in case reassembly is required, or
 *                          THRIFT_SUBDISSECTOR_ERROR (-2) in case of error.
 */
static int
dissect_thrift_t_field_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, thrift_type_enum_t expected, int field_id, proto_tree **header_tree)
{
    thrift_field_header_t field_header;
    proto_tree *internal_tree = NULL;
    thrift_type_enum_t generic_type;

    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    if (show_internal_thrift_fields) {
        internal_tree = tree;
    }
    /* Read the entire field header using the dedicated function. */
    if (dissect_thrift_field_header(tvb, pinfo, internal_tree, &offset, thrift_opt, &field_header) == THRIFT_REQUEST_REASSEMBLY) {
        if (offset == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        } else {
            return THRIFT_SUBDISSECTOR_ERROR;
        }
    }

    /* Check the type first. */
    if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
        generic_type = compact_struct_type_to_generic_type(field_header.type.compact);
    } else {
        generic_type = field_header.type.binary;
    }
    if (generic_type != expected) {
        proto_tree_add_expert_format(tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN,
                "Sub-dissector expects type = %s, found %s.",
                val_to_str(expected, thrift_type_vals, "%02x"),
                val_to_str(generic_type, thrift_type_vals, "%02x"));
        return THRIFT_SUBDISSECTOR_ERROR;
    }

    /* Once we know it's the expected type (which is /not/ T_STOP), we can read the field id. */
    if (field_header.field_id != (gint64)field_id) {
        expert_add_info_format(pinfo, field_header.fid_pi, &ei_thrift_wrong_field_id,
                "Sub-dissector expects field id = %d, found %" PRId64 " instead.", field_id, field_header.field_id);
    }

    /* Expose the field header sub-tree if requested. */
    if (header_tree != NULL) {
        *header_tree = field_header.fh_tree;
    }

    return offset;
}

int
dissect_thrift_t_bool(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id)
{
    int dt_offset = offset;
    gboolean bool_val = FALSE;
    proto_item *pi;
    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (is_field) {
        /* In case of Compact protocol struct field (or command parameter / return value),
         * the boolean type also indicates the boolean value. */
        if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
            /* Read value in type nibble. */
            if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
                return THRIFT_REQUEST_REASSEMBLY;
            }
            if (((tvb_get_guint8(tvb, offset) >> TCP_THRIFT_NIBBLE_SHIFT) & TCP_THRIFT_NIBBLE_MASK) == DE_THRIFT_C_BOOL_TRUE) {
                bool_val = TRUE;
            }
            /* If we have neither DE_THRIFT_C_BOOL_TRUE nor DE_THRIFT_C_BOOL_FALSE as the type,
             * dissect_thrift_t_field_header will catch the issue anyway. */
        }
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_BOOL, field_id, NULL);
        ABORT_SUBDISSECTION_ON_ISSUE(offset);
        if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
            /* The value must be in the top-level tree, /after/ the field header tree. */
            pi = proto_tree_add_boolean(tree, hf_id, tvb, dt_offset, TBP_THRIFT_TYPE_LEN, bool_val);
            proto_item_set_generated(pi);
            return offset;
        }
    }
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_BOOL_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    /* Either in a list/set/map or in a Binary protocol encoding. */
    proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_BOOL_LEN, ENC_BIG_ENDIAN);
    offset += TBP_THRIFT_BOOL_LEN;

    return offset;
}

int
dissect_thrift_t_i8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id)
{
    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_I8, field_id, NULL);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_I8_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    /* Compact protocol does not use varint for T_I8 as it would be counter-productive. */
    proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_I8_LEN, ENC_BIG_ENDIAN);
    offset += TBP_THRIFT_I8_LEN;

    return offset;
}

int
dissect_thrift_t_i16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id)
{
    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_I16, field_id, NULL);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
        int result = dissect_thrift_varint(tvb, pinfo, tree, &offset, thrift_opt, TCP_THRIFT_MAX_I16_LEN, hf_id);
        if (result == THRIFT_REQUEST_REASSEMBLY) {
            if (offset == THRIFT_REQUEST_REASSEMBLY) {
                return THRIFT_REQUEST_REASSEMBLY;
            } else {
                return THRIFT_SUBDISSECTOR_ERROR;
            }
        }
    } else if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_I16_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    } else {
        proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_I16_LEN, ENC_BIG_ENDIAN);
        offset += TBP_THRIFT_FID_LEN;
    }

    return offset;
}

int
dissect_thrift_t_i32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id)
{
    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_I32, field_id, NULL);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
        int result = dissect_thrift_varint(tvb, pinfo, tree, &offset, thrift_opt, TCP_THRIFT_MAX_I32_LEN, hf_id);
        if (result == THRIFT_REQUEST_REASSEMBLY) {
            if (offset == THRIFT_REQUEST_REASSEMBLY) {
                return THRIFT_REQUEST_REASSEMBLY;
            } else {
                return THRIFT_SUBDISSECTOR_ERROR;
            }
        }
    } else if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_I32_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    } else {
        proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_I32_LEN, ENC_BIG_ENDIAN);
        offset += TBP_THRIFT_I32_LEN;
    }

    return offset;
}

int
dissect_thrift_t_i64(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id)
{
    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_I64, field_id, NULL);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
        int result = dissect_thrift_varint(tvb, pinfo, tree, &offset, thrift_opt, TCP_THRIFT_MAX_I64_LEN, hf_id);
        if (result == THRIFT_REQUEST_REASSEMBLY) {
            if (offset == THRIFT_REQUEST_REASSEMBLY) {
                return THRIFT_REQUEST_REASSEMBLY;
            } else {
                return THRIFT_SUBDISSECTOR_ERROR;
            }
        }
    } else if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_I64_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    } else {
        proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_I64_LEN, ENC_BIG_ENDIAN);
        offset += TBP_THRIFT_I64_LEN;
    }

    return offset;
}

int
dissect_thrift_t_double(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id)
{
    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_DOUBLE, field_id, NULL);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_DOUBLE_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
        proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_DOUBLE_LEN, ENC_LITTLE_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_DOUBLE_LEN, ENC_BIG_ENDIAN);
    }
    offset += TBP_THRIFT_DOUBLE_LEN;

    return offset;
}

int
dissect_thrift_t_uuid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id)
{
    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    /* Dissect field header if necessary. */
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_UUID, field_id, NULL);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);

    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_UUID_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_UUID_LEN, ENC_BIG_ENDIAN);
    offset += TBP_THRIFT_UUID_LEN;

    return offset;
}

int
dissect_thrift_t_binary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id)
{
    return dissect_thrift_t_string_enc(tvb, pinfo, tree, offset, thrift_opt, is_field, field_id, hf_id, ENC_NA);
}

int
dissect_thrift_t_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id)
{
    return dissect_thrift_t_string_enc(tvb, pinfo, tree, offset, thrift_opt, is_field, field_id, hf_id, ENC_UTF_8|ENC_NA);
}

int
dissect_thrift_t_string_enc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, guint encoding)
{
    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    proto_tree *header_tree = NULL;
    proto_item *len_item = NULL;
    gint32 str_len, len_len;
    gint64 varint;

    /* Dissect field header if necessary. */
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_BINARY, field_id, &header_tree);
    } else {
        header_tree = tree;
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);

    /* Dissect length. */
    if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
        len_len = thrift_get_varint_enc(tvb, pinfo, header_tree, offset, TCP_THRIFT_MAX_I32_LEN, &varint, ENC_VARINT_PROTOBUF);
        switch (len_len) {
            case THRIFT_REQUEST_REASSEMBLY:
                return THRIFT_REQUEST_REASSEMBLY;
            case 0:
                return THRIFT_SUBDISSECTOR_ERROR;
            default:
                break;
        }
        if ((gint64)INT32_MIN > varint || varint > (gint64)INT32_MAX) {
            len_item = proto_tree_add_int64(header_tree, hf_thrift_i64, tvb, offset, len_len, varint);
            expert_add_info(pinfo, len_item, &ei_thrift_varint_too_large);
            return THRIFT_REQUEST_REASSEMBLY;
        }
        str_len = (gint32)varint;
        if (show_internal_thrift_fields) {
            len_item = proto_tree_add_int(header_tree, hf_thrift_str_len, tvb, offset, len_len, str_len);
        }
    } else {
        len_len = TBP_THRIFT_LENGTH_LEN;
        if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_LENGTH_LEN) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        if (show_internal_thrift_fields) {
            len_item = proto_tree_add_item_ret_int(header_tree, hf_thrift_str_len, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN, &str_len);
        } else {
            str_len = tvb_get_ntohil(tvb, offset);
        }
    }
    if (str_len < 0) {
        expert_add_info(pinfo, len_item, &ei_thrift_negative_length);
        return THRIFT_SUBDISSECTOR_ERROR;
    }
    offset += len_len;
    /* Since we put the length inside the field header, we need to extend it. */
    if (header_tree != tree) {
        proto_item_set_end(proto_tree_get_parent(header_tree), tvb, offset);
    }

    /* Dissect data */
    if (tvb_reported_length_remaining(tvb, offset) < str_len) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, str_len, encoding);
    offset = offset + str_len;

    return offset;
}

/* Simple dispatch function for lists, sets, maps, and structs internal elements to avoid code duplication. */
static int
dissect_thrift_t_member(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, const thrift_member_t *elt)
{
    switch (elt->type) {
    case DE_THRIFT_T_STOP:
        offset = dissect_thrift_t_stop(tvb, pinfo, tree, offset);
        break;
    case DE_THRIFT_T_BOOL:
        offset = dissect_thrift_t_bool(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_I8:
        offset = dissect_thrift_t_i8(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_I16:
        offset = dissect_thrift_t_i16(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_I32:
        offset = dissect_thrift_t_i32(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_I64:
        offset = dissect_thrift_t_i64(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_DOUBLE:
        offset = dissect_thrift_t_double(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_BINARY:
        offset = dissect_thrift_t_string(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_LIST:
        offset = dissect_thrift_t_list(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id, *elt->p_ett_id, elt->u.element);
        break;
    case DE_THRIFT_T_SET:
        offset = dissect_thrift_t_set(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id, *elt->p_ett_id, elt->u.element);
        break;
    case DE_THRIFT_T_MAP:
        offset = dissect_thrift_t_map(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id, *elt->p_ett_id, elt->u.m.key, elt->u.m.value);
        break;
    case DE_THRIFT_T_STRUCT:
        offset = dissect_thrift_t_struct(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id, *elt->p_ett_id, elt->u.members);
        break;
    case DE_THRIFT_T_UUID:
        offset = dissect_thrift_t_uuid(tvb, pinfo, tree, offset, thrift_opt, is_field, elt->fid, *elt->p_hf_id);
        break;
    default:
        REPORT_DISSECTOR_BUG("Unexpected Thrift type dissection requested.");
        break;
    }
    return offset;
}

/* Effective sub-dissection for lists, sets, and maps in Binary Protocol.
 * Since the only difference is in the hf_id used when showing internal Thrift fields,
 * this prevents code duplication.
 * Map is only adding a type in the header and one element in each loop
 * so it's easy to use the same code and handle the additional elements only when necessary.
 */
static int
dissect_thrift_b_linear(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *key, const thrift_member_t *val, thrift_type_enum_t expected)
{
    proto_item *container_pi = NULL;
    proto_item *len_pi = NULL;
    proto_tree *sub_tree;
    gint32 key_type, val_type;
    gint32 length;

    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);
    DISSECTOR_ASSERT((thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) == 0);

    /* Dissect field header if necessary. */
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, thrift_opt, expected, field_id, NULL);
    }

    /* Create the sub-tree. */
    container_pi = proto_tree_add_item(tree, hf_id, tvb, offset, -1, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(container_pi, ett_id);
    ABORT_SUBDISSECTION_ON_ISSUE(offset);

    /* Read and check the type of the key in case of map. */
    if (expected == DE_THRIFT_T_MAP) {
        if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        key_type = tvb_get_guint8(tvb, offset);
        if (show_internal_thrift_fields) {
            proto_tree_add_item(sub_tree, hf_thrift_type, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
        }
        if (key_type != key->type) {
            proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN);
            return THRIFT_SUBDISSECTOR_ERROR;
        }
        offset += TBP_THRIFT_TYPE_LEN;
    }

    /* Read and check the type of the elements (or type of the values in case of map). */
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }
    val_type = tvb_get_guint8(tvb, offset);
    if (show_internal_thrift_fields) {
        proto_tree_add_item(sub_tree, hf_thrift_type, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
    }
    if (val_type != val->type) {
        proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN);
        return THRIFT_SUBDISSECTOR_ERROR;
    }
    offset += TBP_THRIFT_TYPE_LEN;

    /* Read and check the number of entries of the container. */
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_LENGTH_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }
    length = tvb_get_ntohil(tvb, offset);
    if (show_internal_thrift_fields) {
        gint hf_num_item;
        switch (expected) {
            case DE_THRIFT_T_MAP:
                hf_num_item = hf_thrift_num_map_item;
                break;
            case DE_THRIFT_T_SET:
                hf_num_item = hf_thrift_num_set_item;
                break;
            case DE_THRIFT_T_LIST:
                hf_num_item = hf_thrift_num_list_item;
                break;
            default:
                return THRIFT_SUBDISSECTOR_ERROR;
        }
        len_pi = proto_tree_add_item_ret_int(sub_tree, hf_num_item, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN, &length);
    }
    offset += TBP_THRIFT_LENGTH_LEN;
    if (length < 0) {
        expert_add_info(pinfo, len_pi, &ei_thrift_negative_length);
        return THRIFT_SUBDISSECTOR_ERROR;
    }

    /* Read the content of the container. */
    for(int i = 0; i < length; ++i) {
        if (expected == DE_THRIFT_T_MAP) {
            offset = dissect_thrift_t_member(tvb, pinfo, sub_tree, offset, thrift_opt, FALSE, key);
        }
        offset = dissect_thrift_t_member(tvb, pinfo, sub_tree, offset, thrift_opt, FALSE, val);
        /* Avoid continuing the loop if anything went sideways. */
        ABORT_SUBDISSECTION_ON_ISSUE(offset);
    }
    if (container_pi && offset > 0) {
        proto_item_set_end(container_pi, tvb, offset);
    }
    return offset;
}

/* Effective sub-dissection for both lists and sets for Compact Protocol.
 * Since the only difference is in the hf_id used when showing internal Thrift fields,
 * this prevents code duplication.
 */
static int
dissect_thrift_c_list_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *elt, gboolean is_list)
{
    proto_item *container_pi;
    proto_item *type_pi = NULL;
    proto_item *len_pi = NULL;
    proto_tree *sub_tree = NULL;
    guint32 len_type;
    thrift_compact_type_enum_t elt_type;
    gint32 container_len, len_len, i;
    guint64 varint;
    int lt_offset;
    int hf_num_item = hf_thrift_num_set_item;
    int hf_pos_item = hf_thrift_num_set_pos;
    thrift_type_enum_t expected = DE_THRIFT_T_SET;

    if (is_list) {
        hf_num_item = hf_thrift_num_list_item;
        hf_pos_item = hf_thrift_num_list_pos;
        expected = DE_THRIFT_T_LIST;
    }

    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);
    DISSECTOR_ASSERT(thrift_opt->tprotocol & PROTO_THRIFT_COMPACT);

    /* Dissect field header if necessary. */
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, thrift_opt, expected, field_id, NULL);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    /* Create the sub-tree. */
    container_pi = proto_tree_add_item(tree, hf_id, tvb, offset, -1, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(container_pi, ett_id);

    /* Read the type of the elements (and length if lower than 15). */
    lt_offset = offset;
    len_type = tvb_get_guint8(tvb, lt_offset);
    offset += TBP_THRIFT_TYPE_LEN;
    elt_type = (thrift_compact_type_enum_t)(len_type & TCP_THRIFT_NIBBLE_MASK);
    if (show_internal_thrift_fields) {
        type_pi = proto_tree_add_bits_item(sub_tree, hf_thrift_type, tvb, (lt_offset << OCTETS_TO_BITS_SHIFT) + TCP_THRIFT_NIBBLE_SHIFT, TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
    }
    /* Check the type of the elements. */
    if (compact_struct_type_to_generic_type(elt_type) != elt->type) {
        if (show_internal_thrift_fields) {
            expert_add_info(pinfo, type_pi, &ei_thrift_wrong_type);
        }
        proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN);
        return THRIFT_SUBDISSECTOR_ERROR;
    }
    container_len = (len_type >> TCP_THRIFT_NIBBLE_SHIFT) & TCP_THRIFT_NIBBLE_MASK;

    /* Read and check the number of entries of the container. */
    if (container_len == TCP_THRIFT_LENGTH_LARGER) {
        if (show_internal_thrift_fields) {
            proto_tree_add_bits_item(sub_tree, hf_thrift_large_container, tvb, (lt_offset << OCTETS_TO_BITS_SHIFT), TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
        }
        /* Length is greater than 14, read effective length as a varint. */
        len_len = thrift_get_varint_enc(tvb, pinfo, sub_tree, offset, TCP_THRIFT_MAX_I32_LEN, &varint, ENC_VARINT_PROTOBUF);
        switch (len_len) {
        case THRIFT_REQUEST_REASSEMBLY:
            return THRIFT_REQUEST_REASSEMBLY;
        case 0:
            /* In case of error, the offset stay at the error position. */
            return THRIFT_SUBDISSECTOR_ERROR;
        default:
            if (varint > (guint64)INT32_MAX) {
                len_pi = proto_tree_add_int64(sub_tree, hf_thrift_i64, tvb, offset, len_len, varint);
                expert_add_info(pinfo, len_pi, &ei_thrift_varint_too_large);
                return THRIFT_SUBDISSECTOR_ERROR;
            }
            container_len = (guint32)varint;
            if (show_internal_thrift_fields) {
                proto_tree_add_int(sub_tree, hf_num_item, tvb, offset, len_len, container_len);
            }
            offset += len_len;
            break;
        }
    } else if (show_internal_thrift_fields) {
        proto_tree_add_bits_item(sub_tree, hf_pos_item, tvb, (lt_offset << OCTETS_TO_BITS_SHIFT), TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
    }

    /* Read the content of the container. */
    for (i = 0; i < container_len; ++i) {
        offset = dissect_thrift_t_member(tvb, pinfo, sub_tree, offset, thrift_opt, FALSE, elt);
        /* Avoid continuing the loop if anything went sideways. */
        ABORT_SUBDISSECTION_ON_ISSUE(offset);
    }
    if (container_pi && offset > 0) {
        proto_item_set_end(container_pi, tvb, offset);
    }
    return offset;
}

int
dissect_thrift_t_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *elt)
{
    if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
        return dissect_thrift_c_list_set(tvb, pinfo, tree, offset, thrift_opt, is_field, field_id, hf_id, ett_id, elt, TRUE);
    } else {
        return dissect_thrift_b_linear(tvb, pinfo, tree, offset, thrift_opt, is_field, field_id, hf_id, ett_id, NULL, elt, DE_THRIFT_T_LIST);
    }
}

int
dissect_thrift_t_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *elt)
{
    if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
        return dissect_thrift_c_list_set(tvb, pinfo, tree, offset, thrift_opt, is_field, field_id, hf_id, ett_id, elt, FALSE);
    } else {
        return dissect_thrift_b_linear(tvb, pinfo, tree, offset, thrift_opt, is_field, field_id, hf_id, ett_id, NULL, elt, DE_THRIFT_T_SET);
    }
}

int
dissect_thrift_t_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *key, const thrift_member_t *value)
{
    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    if ((thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) == 0) {
        return dissect_thrift_b_linear(tvb, pinfo, tree, offset, thrift_opt, is_field, field_id, hf_id, ett_id, key, value, DE_THRIFT_T_MAP);
    } else {
        proto_tree *sub_tree = NULL;
        proto_item *container_pi, *len_pi;
        proto_item *ktype_pi = NULL;
        proto_item *vtype_pi = NULL;
        gint32 container_len, len_len, i, types;
        gint32 len_offset = offset;
        thrift_compact_type_enum_t ktype, vtype;
        guint64 varint;

        /* Dissect field header if necessary. */
        if (is_field) {
            if (show_internal_thrift_fields) {
                sub_tree = tree;
            }
            offset = dissect_thrift_t_field_header(tvb, pinfo, sub_tree, offset, thrift_opt, DE_THRIFT_T_MAP, field_id, NULL);
        }

        /* Read and check number of key-value pair in the map. */
        if (tvb_reported_length_remaining(tvb, offset) < TCP_THRIFT_MIN_VARINT_LEN) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        len_len = thrift_get_varint_enc(tvb, pinfo, sub_tree, offset, TCP_THRIFT_MAX_I32_LEN, &varint, ENC_VARINT_PROTOBUF);
        switch (len_len) {
        case THRIFT_REQUEST_REASSEMBLY:
            return THRIFT_REQUEST_REASSEMBLY;
        case 0:
            /* In case of error, the offset stay at the error position. */
            return THRIFT_SUBDISSECTOR_ERROR;
        default:
            if (varint > (guint64)INT32_MAX) {
                len_pi = proto_tree_add_int64(sub_tree, hf_thrift_i64, tvb, offset, len_len, varint);
                expert_add_info(pinfo, len_pi, &ei_thrift_varint_too_large);
                return THRIFT_SUBDISSECTOR_ERROR;
            }
            container_len = (guint32)varint;
            offset += len_len;
            break;
        }

        /* Create the sub-tree. */
        container_pi = proto_tree_add_item(tree, hf_id, tvb, len_offset, -1, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(container_pi, ett_id);

        if (container_len == 0) {
            proto_item_set_end(container_pi, tvb, offset);
            proto_item_append_text(container_pi, " (Empty)");
            return offset;
        }

        /* If the map is not empty, read the types of keys and values. */
        if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        types = tvb_get_guint8(tvb, offset);
        ktype = (thrift_compact_type_enum_t)((types >> TCP_THRIFT_NIBBLE_SHIFT) & TCP_THRIFT_NIBBLE_MASK);
        vtype = (thrift_compact_type_enum_t)(types & TCP_THRIFT_NIBBLE_MASK);
        if (show_internal_thrift_fields) {
            proto_tree_add_int(sub_tree, hf_thrift_num_map_item, tvb, len_offset, len_len, container_len);
            ktype_pi = proto_tree_add_bits_item(sub_tree, hf_thrift_key_type, tvb, offset << OCTETS_TO_BITS_SHIFT, TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
            vtype_pi = proto_tree_add_bits_item(sub_tree, hf_thrift_value_type, tvb, (offset << OCTETS_TO_BITS_SHIFT) + TCP_THRIFT_NIBBLE_SHIFT, TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
        }

        /* Check that types match what is expected. */
        if (compact_struct_type_to_generic_type(ktype) != key->type) {
            if (show_internal_thrift_fields) {
                expert_add_info(pinfo, ktype_pi, &ei_thrift_wrong_type);
            } else {
                proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN);
            }
            return THRIFT_SUBDISSECTOR_ERROR;
        }
        if (compact_struct_type_to_generic_type(vtype) != value->type) {
            if (show_internal_thrift_fields) {
                expert_add_info(pinfo, vtype_pi, &ei_thrift_wrong_type);
            } else {
                proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN);
            }
            return THRIFT_SUBDISSECTOR_ERROR;
        }

        /* Read the content of the container. */
        for (i = 0; i < container_len; ++i) {
            offset = dissect_thrift_t_member(tvb, pinfo, sub_tree, offset, thrift_opt, FALSE, key);
            offset = dissect_thrift_t_member(tvb, pinfo, sub_tree, offset, thrift_opt, FALSE, value);
            /* Avoid continuing the loop if anything went sideways. */
            ABORT_SUBDISSECTION_ON_ISSUE(offset);
        }

        if (container_pi && offset > 0) {
            proto_item_set_end(container_pi, tvb, offset);
        }
        return offset;
    }
}

int
dissect_thrift_t_struct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *seq)
{
    thrift_field_header_t field_header;
    proto_tree *sub_tree = NULL;
    proto_item *type_pi = NULL;

    gboolean enable_subtree = (ett_id != DISABLE_SUBTREE) || (hf_id != DISABLE_SUBTREE);

    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    /* Dissect field header if necessary. */
    if (is_field) {
        if (show_internal_thrift_fields) {
            sub_tree = tree;
        }
        offset = dissect_thrift_t_field_header(tvb, pinfo, sub_tree, offset, thrift_opt, DE_THRIFT_T_STRUCT, field_id, NULL);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    /* Create the sub-tree, if not explicitly refused. */
    if (enable_subtree) {
        /* Add the struct to the tree. */
        type_pi = proto_tree_add_item(tree, hf_id, tvb, offset, -1, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(type_pi, ett_id);
    } else {
        /* Sub-dissector requested that we don't use a sub_tree.
         * This is useful for ME_THRIFT_T_REPLY or unions where we always have only 1 sub-element. */
        sub_tree = tree;
    }

    thrift_opt->previous_field_id = 0;
    /* Read and check available fields. */
    while (seq->type != DE_THRIFT_T_STOP) {
        int local_offset = offset;
        /* Read the type and check for the end of the structure.
         * Never create the field header sub-tree here as it will be handled by the field's own dissector.
         * We only want to get the type & field id information to compare them against what we expect.
         */
        if (dissect_thrift_field_header(tvb, pinfo, NULL, &local_offset, thrift_opt, &field_header) == THRIFT_REQUEST_REASSEMBLY) {
            if (local_offset == THRIFT_REQUEST_REASSEMBLY) {
                return THRIFT_REQUEST_REASSEMBLY;
            } else {
                return THRIFT_SUBDISSECTOR_ERROR;
            }
        }
        /* Right now, we only check for T_STOP type. The member sub-dissection will take care of checking the type. */
        if (field_header.type.binary == DE_THRIFT_T_STOP) {
            if (seq->optional) {
                seq++;
                continue;
            } else {
                proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_struct_fid_not_in_seq, tvb, offset, TBP_THRIFT_TYPE_LEN);
                return THRIFT_SUBDISSECTOR_ERROR;
            }
        }

        /* Read and check the field id which is the only way to make sure we are aligned. */
        if (field_header.field_id != seq->fid) {
            /* Wrong field in sequence or was it optional? */
            if (seq->optional) {
                /* Skip to next element*/
                seq++;
                continue;
            } else {
                proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_struct_fid_not_in_seq, tvb, offset, TBP_THRIFT_TYPE_LEN);
                return THRIFT_SUBDISSECTOR_ERROR;
            }
        }

        if (seq->type != DE_THRIFT_T_GENERIC) {
            /* Type is not T_STOP and field id matches one we know how to dissect. */
            offset = dissect_thrift_t_member(tvb, pinfo, sub_tree, offset, thrift_opt, TRUE, seq);
        } else {
            /* The field is not defined in the struct, switch back to generic dissection.
             * Re-read the header ensuring it is displayed (no need to check result,
             * we already dissected it but without the header tree creation. */
            dissect_thrift_field_header(tvb, pinfo, sub_tree, &offset, thrift_opt, &field_header);
            expert_add_info(pinfo, field_header.fid_pi, &ei_thrift_undefined_field_id);
            // Then dissect just this field.
            if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
                if (dissect_thrift_compact_type(tvb, pinfo, sub_tree, &offset, thrift_opt, field_header.fh_tree, field_header.type.compact, field_header.type_pi) == THRIFT_REQUEST_REASSEMBLY) {
                    return THRIFT_REQUEST_REASSEMBLY;
                }
            } else {
                if (dissect_thrift_binary_type(tvb, pinfo, sub_tree, &offset, thrift_opt, field_header.fh_tree, field_header.type.compact, field_header.type_pi) == THRIFT_REQUEST_REASSEMBLY) {
                    return THRIFT_REQUEST_REASSEMBLY;
                }
            }
        }
        ABORT_SUBDISSECTION_ON_ISSUE(offset);
        if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        seq++;

        /* Allow the proper handling of next delta field id in Compact protocol. */
        thrift_opt->previous_field_id = field_header.field_id;
    }

    /* The loop exits before dissecting the T_STOP. */
    offset = dissect_thrift_t_stop(tvb, pinfo, sub_tree, offset);

    if (enable_subtree && offset > 0) {
        proto_item_set_end(type_pi, tvb, offset);
    }

    return offset;
}
/*=====END SUB-DISSECTION=====*/

/* GENERIC DISSECTION PARAMETERS DOCUMENTATION
 *
 * Generic functions for when there is no custom sub-dissector.
 * Same conventions are used for binary and compact.
 *
 *  +--------------------+--------------------------+---------------------+
 *  | offset   \  return | REQUEST_REASSEMBLY = -1  | Length              |
 *  +--------------------+--------------------------+---------------------+
 *  | REQUEST_REASSEMBLY | Reassembly required      | SHALL NEVER HAPPEN! |
 *  +--------------------+--------------------------+---------------------+
 *  | Length             | Error occurred at offset | Data fully parsed.  |
 *  +--------------------+--------------------------+---------------------+
 *
 * @param[in] tvb:          Pointer to the tvbuff_t holding the captured data.
 * @param[in] pinfo:        Pointer to the packet_info holding information about the currently dissected packet.
 * @param[in] tree:         Pointer to the proto_tree used to hold the display tree in Wireshark's interface.
 * @param[in,out] offset:   Pointer to the offset from the beginning of the tvbuff_t where the Thrift field is. Function will dissect only the data.
 *                          The offset is modified according to table hereabove in sync with the return value.
 * @param[in] thrift_opt:   Options from the Thrift dissector that will be useful for dissection of deep data (to expose the position of failure).
 *
 * //   Specific to dissect_thrift_binary_linear.
 * @param[in] expected:     Expected container type (list, set, or map).
 *
 * //   Specific to dissect_thrift_compact_list_set.
 * @param[in] is_list:      `true` if the expected container type is list.
 *                          `false` if the expected container type is set.
 *
 * //   Specific to dissect_thrift_(binary|compact)_binary.
 * //   Present in dissect_thrift_(binary|compact)_type for forwarding purpose.
 * @param[in] header_tree:  The proto_tree in which the length must be inserted.
 *                          If it is NULL, tree will be used instead.
 *                          Used in structs to push the length in the field header.
 *
 * //   Specific to dissect_thrift_(binary|compact)_type.
 * @param[in] type:         The type for which data needs to be dissected.
 *                          Neither type nor field_id to dissect as there is no such "header" in list, set, and map.
 * @param[in] type_pi:      The proto_item of the type field to indicate position of failure.
 */

/*=====BEGIN BINARY GENERIC DISSECTION=====*/
static int
dissect_thrift_binary_binary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, proto_tree *header_tree)
{
    /*  Binary protocol binary/string data (4 bytes + data):
     *      +--------+--------+--------+--------+--------+ ... +--------+
     *      | Number of bytes                   | N bytes of data       |
     *      +--------+--------+--------+--------+--------+ ... +--------+
     *
     *  Where:
     *      Number of bytes is the number of encoded bytes of data.
     *                      In particular, it might be larger than the number
     *                      of characters in an UTF-8 string.
     */
    gint32 str_len;
    proto_item *pi;
    ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_BINARY_LEN);
    if (header_tree == NULL) {
        header_tree = tree;
    }
    pi = proto_tree_add_item_ret_int(header_tree, hf_thrift_str_len, tvb, *offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN, &str_len);
    *offset += TBP_THRIFT_LENGTH_LEN;
    if (header_tree != tree) {
        proto_item_set_end(proto_tree_get_parent(header_tree), tvb, *offset);
    }

    if (str_len < 0) {
        expert_add_info(pinfo, pi, &ei_thrift_negative_length);
        return THRIFT_REQUEST_REASSEMBLY;
    }

    return dissect_thrift_string_as_preferred(tvb, pinfo, tree, offset, thrift_opt, str_len);
}

static int
dissect_thrift_binary_linear(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, thrift_type_enum_t expected)
{
    /*  Binary protocol list and set (5 bytes + elements):
     *      +--------+--------+--------+--------+--------+---...---+ ... +---...---+
     *      |0000tttt| number of elements                |element 1|     |element N|
     *      +--------+--------+--------+--------+--------+---...---+ ... +---...---+
     *
     *  Binary protocol map (6 bytes + key-value pairs):
     *      +--------+--------+--------+--------+--------+--------+--...--+---...---+ ... +--...--+---...---+
     *      |0000kkkk|0000vvvv| number of key+value pairs         | key 1 | value 1 |     | key N | value N |
     *      +--------+--------+--------+--------+--------+--------+--...--+---...---+ ... +--...--+---...---+
     *
     *  Where:
     *      'tttt'      is the type of the list or set elements, an unsigned 4 bits strictly positive integer.
     *      'kkkk'      is the type of the map keys, an unsigned 4 bits strictly positive integer.
     *      'vvvv'      is the type of the map values, an unsigned 4 bits strictly positive integer.
     */
    proto_tree *sub_tree;
    proto_item *container_pi, *len_pi, *vtype_pi;
    proto_item *ktype_pi = NULL; // Avoid a false positive warning.
    gint32 ktype, vtype;
    gint32 container_len, i;
    int ett = -1;
    int hf_container = -1;
    int hf_num_item = -1;
    int hf_vtype = hf_thrift_type;
    int min_len = TBP_THRIFT_LINEAR_LEN;

    /* Set the different hf_id & ett depending on effective type. */
    switch (expected) {
        case DE_THRIFT_T_SET:
            ett = ett_thrift_set;
            hf_container = hf_thrift_set;
            hf_num_item = hf_thrift_num_set_item;
            break;
        case DE_THRIFT_T_LIST:
            ett = ett_thrift_list;
            hf_container = hf_thrift_list;
            hf_num_item = hf_thrift_num_list_item;
            break;
        case DE_THRIFT_T_MAP:
            ett = ett_thrift_map;
            hf_container = hf_thrift_map;
            hf_num_item = hf_thrift_num_map_item;
            hf_vtype = hf_thrift_value_type; /* Use specific hf_info as we have several types. */
            min_len += TBP_THRIFT_TYPE_LEN; /* Additional type key + value instead of element only. */
            break;
        default:
            REPORT_DISSECTOR_BUG("dissect_thrift_binary_linear called with something else than a container type.");
            break;
    }
    ABORT_ON_INCOMPLETE_PDU(min_len);

    /* Create the sub-tree. */
    container_pi = proto_tree_add_item(tree, hf_container, tvb, *offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(container_pi, ett);

    /* Read the type of the key in case of map. */
    if (expected == DE_THRIFT_T_MAP) {
        ktype_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_key_type, tvb, *offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN, &ktype);
        *offset += TBP_THRIFT_TYPE_LEN;
    }
    /* Read the type of the elements (or type of the values in case of map). */
    vtype_pi = proto_tree_add_item_ret_uint(sub_tree, hf_vtype, tvb, *offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN, &vtype);
    *offset += TBP_THRIFT_TYPE_LEN;
    /* Read and check the number of entries of the container. */
    len_pi = proto_tree_add_item_ret_int(sub_tree, hf_num_item, tvb, *offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN, &container_len);
    *offset += TBP_THRIFT_LENGTH_LEN;
    if (container_len < 0) {
        expert_add_info(pinfo, len_pi, &ei_thrift_negative_length);
        return THRIFT_REQUEST_REASSEMBLY;
    }

    /* Read the content of the container. */
    for (i = 0; i < container_len; ++i) {
        if (expected == DE_THRIFT_T_MAP) {
            if (dissect_thrift_binary_type(tvb, pinfo, sub_tree, offset, thrift_opt, NULL, ktype, ktype_pi) == THRIFT_REQUEST_REASSEMBLY)
                return THRIFT_REQUEST_REASSEMBLY;
        }
        if (dissect_thrift_binary_type(tvb, pinfo, sub_tree, offset, thrift_opt, NULL, vtype, vtype_pi) == THRIFT_REQUEST_REASSEMBLY)
            return THRIFT_REQUEST_REASSEMBLY;
    }
    proto_item_set_end(container_pi, tvb, *offset);

    return *offset;
}

static int
dissect_thrift_binary_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt)
{
    return dissect_thrift_binary_linear(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_LIST);
}

static int
dissect_thrift_binary_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt)
{
    return dissect_thrift_binary_linear(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_SET);
}

static int
dissect_thrift_binary_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt)
{
    return dissect_thrift_binary_linear(tvb, pinfo, tree, offset, thrift_opt, DE_THRIFT_T_MAP);
}

static int
dissect_thrift_binary_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt)
{
    /*
     *  Binary protocol field header (3 bytes) and field value:
     *      +--------+--------+--------+--------+...+--------+
     *      |0000tttt| field id        | field value         |
     *      +--------+--------+--------+--------+...+--------+
     *
     *  Binary & Compact protocol stop field (1 byte):
     *      +--------+
     *      |00000000|
     *      +--------+
     *
     *  Where:
     *      'dddd'      is the field id delta, a strictly positive unsigned 4 bits integer.
     *      'tttt'      is the type of the field value, an unsigned 4 bits strictly positive integer.
     *      field id    is the numerical value of the field in the structure.
     *      field value is the encoded value.
     */

    /* This function does not create the subtree, it's the responsibility of the caller:
     * - either dissect_thrift_common which creates the "Data" sub-tree,
     * - or dissect_thrift_binary_struct which creates the "Struct" sub-tree.
     */
    thrift_field_header_t field_header;

    thrift_opt->previous_field_id = 0;
    while (TRUE) {
        if (dissect_thrift_field_header(tvb, pinfo, tree, offset, thrift_opt, &field_header) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        if (field_header.type.binary == DE_THRIFT_T_STOP) {
            break;
        }
        if (dissect_thrift_binary_type(tvb, pinfo, tree, offset, thrift_opt, field_header.fh_tree, field_header.type.binary, field_header.type_pi) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
    }

    return *offset;
}

static int
dissect_thrift_binary_struct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt)
{
    /* This function only creates the "Struct" sub-tree
     * then it delegates the fields dissection to dissect_thrift_binary_fields.
     */
    proto_tree *sub_tree;
    proto_item *pi;

    ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_STRUCT_LEN);
    pi = proto_tree_add_item(tree, hf_thrift_struct, tvb, *offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(pi, ett_thrift_struct);

    if (dissect_thrift_binary_fields(tvb, pinfo, sub_tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
        return THRIFT_REQUEST_REASSEMBLY;
    } else {
        proto_item_set_end(pi, tvb, *offset);
    }
    return *offset;
}

static int
dissect_thrift_binary_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, proto_tree *header_tree, int type, proto_item *type_pi)
{
    guint nested_count = p_get_proto_depth(pinfo, proto_thrift);
    if (++nested_count > thrift_opt->nested_type_depth) {
        expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_thrift_too_many_subtypes);
        return THRIFT_REQUEST_REASSEMBLY;
    }
    p_set_proto_depth(pinfo, proto_thrift, nested_count);

    switch (type) {
    case DE_THRIFT_T_BOOL:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_BOOL_LEN);
        proto_tree_add_item(tree, hf_thrift_bool, tvb, *offset, TBP_THRIFT_BOOL_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_BOOL_LEN;
        break;
    case DE_THRIFT_T_I8:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_I8_LEN);
        proto_tree_add_item(tree, hf_thrift_i8, tvb, *offset, TBP_THRIFT_I8_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_I8_LEN;
        break;
    case DE_THRIFT_T_I16:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_I16_LEN);
        proto_tree_add_item(tree, hf_thrift_i16, tvb, *offset, TBP_THRIFT_I16_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_I16_LEN;
        break;
    case DE_THRIFT_T_I32:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_I32_LEN);
        proto_tree_add_item(tree, hf_thrift_i32, tvb, *offset, TBP_THRIFT_I32_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_I32_LEN;
        break;
    case DE_THRIFT_T_I64:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_I64_LEN);
        proto_tree_add_item(tree, hf_thrift_i64, tvb, *offset, TBP_THRIFT_I64_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_I64_LEN;
        break;
    case DE_THRIFT_T_DOUBLE:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_DOUBLE_LEN);
        proto_tree_add_item(tree, hf_thrift_double, tvb, *offset, TBP_THRIFT_DOUBLE_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_DOUBLE_LEN;
        break;
    case DE_THRIFT_T_UUID:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_UUID_LEN);
        proto_tree_add_item(tree, hf_thrift_uuid, tvb, *offset, TBP_THRIFT_UUID_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_UUID_LEN;
        break;
    case DE_THRIFT_T_BINARY:
        if (dissect_thrift_binary_binary(tvb, pinfo, tree, offset, thrift_opt, header_tree) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_T_LIST:
        if (dissect_thrift_binary_list(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_T_SET:
        if (dissect_thrift_binary_set(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_T_MAP:
        if (dissect_thrift_binary_map(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_T_STRUCT:
        if (dissect_thrift_binary_struct(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    default:
        /* Bail out */
        expert_add_info(pinfo, type_pi, &ei_thrift_wrong_type);
        return THRIFT_REQUEST_REASSEMBLY;
    }

    p_set_proto_depth(pinfo, proto_thrift, --nested_count);
    return *offset;
}
/*=====END BINARY GENERIC DISSECTION=====*/

/*=====BEGIN COMPACT GENERIC DISSECTION=====*/
/*
 * Generic functions for when there is no custom sub-dissector.
 *
 * Use the same conventions (parameters & return values) as TBinaryProtocol.
 *
 * See "GENERIC DISSECTION PARAMETERS DOCUMENTATION" comment.
 */

static int
dissect_thrift_compact_binary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, proto_tree *header_tree)
{
    /*  Compact protocol binary/string data (1 to 5 bytes + data):
     *      +--------+...+--------+--------+...+--------+
     *      | number of bytes     | N bytes of data     |
     *      +--------+...+--------+--------+...+--------+
     *
     *  Where:
     *      Number of bytes is the number of encoded bytes of data encoded as an unsigned varint.
     *                      In particular, it might be larger than the number
     *                      of characters in an UTF-8 string.
     */
    gint32 str_len;
    proto_item *pi;
    gint64 varint;

    if (header_tree == NULL) {
        header_tree = tree;
    }
    int len_len = thrift_get_varint_enc(tvb, pinfo, header_tree, *offset, TCP_THRIFT_MAX_I32_LEN, &varint, ENC_VARINT_PROTOBUF);

    switch (len_len) {
    case THRIFT_REQUEST_REASSEMBLY:
        /* Will always return after setting the expert parts. */
        ABORT_ON_INCOMPLETE_PDU(TCP_THRIFT_MAX_I32_LEN);
        return THRIFT_REQUEST_REASSEMBLY; // Just to avoid a false positive warning.
    case 0:
        /* In case of error, the offset stay at the error position. */
        return THRIFT_REQUEST_REASSEMBLY;
    default:
        *offset += len_len;
        break;
    }
    if (header_tree != tree) {
        proto_item_set_end(proto_tree_get_parent(header_tree), tvb, *offset);
    }
    if ((gint64)INT32_MIN > varint || varint > (gint64)INT32_MAX) {
        pi = proto_tree_add_int64(header_tree, hf_thrift_i64, tvb, *offset, len_len, varint);
        expert_add_info(pinfo, pi, &ei_thrift_varint_too_large);
        return THRIFT_REQUEST_REASSEMBLY;
    }
    str_len = (gint32)varint;
    pi = proto_tree_add_int(header_tree, hf_thrift_str_len, tvb, *offset, len_len, str_len);
    if (str_len < 0) {
        expert_add_info(pinfo, pi, &ei_thrift_negative_length);
        return THRIFT_REQUEST_REASSEMBLY;
    }

    return dissect_thrift_string_as_preferred(tvb, pinfo, tree, offset, thrift_opt, str_len);
}

static int
dissect_thrift_compact_list_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, gboolean is_list)
{
    /*  Compact protocol list/set (short form, 1 byte):
     *      +--------+--------+...+--------+
     *      |nnnntttt| nnnn elements       |
     *      +--------+--------+...+--------+
     *
     *  Compact protocol list/set (long form, 2+ bytes):
     *      +--------+--------+...+--------+--------+...+--------+
     *      |1111tttt| number of elements  | elements            |
     *      +--------+--------+...+--------+--------+...+--------+
     *
     *  Where:
     *      'nnnn'  is the number of elements if between 0 and 14 included encoded as a 4 bits unsigned integer.
     *      'tttt'  is the type of the elements (using the same convention as TBinaryProtocol, unlike compact structures.
     *      '1111'  indicates that the number of elements is encoded as an unsigned 32 bits varint (for number >= 15).
     */
    proto_tree *sub_tree;
    proto_item *container_pi, *type_pi, *len_pi;
    guint32 len_type, type;
    gint32 container_len, len_len, i;
    guint64 varint;
    int lt_offset = *offset;
    int ett = ett_thrift_set;
    int hf_container = hf_thrift_set;
    int hf_num_item = hf_thrift_num_set_item;
    int hf_pos_item = hf_thrift_num_set_pos;
    ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_TYPE_LEN);

    /* Set the different hf_id & ett depending on effective type. */
    if (is_list) {
        ett = ett_thrift_list;
        hf_container = hf_thrift_list;
        hf_num_item = hf_thrift_num_list_item;
        hf_pos_item = hf_thrift_num_list_pos;
    }

    /* Create the sub-tree. */
    container_pi = proto_tree_add_item(tree, hf_container, tvb, *offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(container_pi, ett);

    /* Read the type of the elements (and length if lower than 15). */
    len_type = tvb_get_guint8(tvb, lt_offset);
    *offset += TBP_THRIFT_TYPE_LEN;
    type = len_type & TCP_THRIFT_NIBBLE_MASK;
    type_pi = proto_tree_add_bits_item(sub_tree, hf_thrift_type, tvb, (lt_offset << OCTETS_TO_BITS_SHIFT) + TCP_THRIFT_NIBBLE_SHIFT, TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
    container_len = (len_type >> TCP_THRIFT_NIBBLE_SHIFT) & TCP_THRIFT_NIBBLE_MASK;

    /* Read and check the number of entries of the container. */
    if (container_len == TCP_THRIFT_LENGTH_LARGER) {
        proto_tree_add_bits_item(sub_tree, hf_thrift_large_container, tvb, (lt_offset << OCTETS_TO_BITS_SHIFT), TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
        /* Length is greater than 14, read effective length as a varint. */
        len_len = thrift_get_varint_enc(tvb, pinfo, sub_tree, *offset, TCP_THRIFT_MAX_I32_LEN, &varint, ENC_VARINT_PROTOBUF);
        switch (len_len) {
        case THRIFT_REQUEST_REASSEMBLY:
            /* Will always return after setting the expert parts. */
            ABORT_ON_INCOMPLETE_PDU(TCP_THRIFT_MAX_I32_LEN);
            return THRIFT_REQUEST_REASSEMBLY; // Just to avoid a false positive warning.
        case 0:
            /* In case of error, the offset stay at the error position. */
            return THRIFT_REQUEST_REASSEMBLY;
        default:
            if (varint > (guint64)INT32_MAX) {
                len_pi = proto_tree_add_int64(sub_tree, hf_thrift_i64, tvb, *offset, len_len, varint);
                expert_add_info(pinfo, len_pi, &ei_thrift_varint_too_large);
                return THRIFT_REQUEST_REASSEMBLY;
            }
            container_len = (guint32)varint;
            len_pi = proto_tree_add_int(sub_tree, hf_num_item, tvb, *offset, len_len, container_len);
            *offset += len_len;
            break;
        }
    } else {
        len_pi = proto_tree_add_bits_item(sub_tree, hf_pos_item, tvb, (lt_offset << OCTETS_TO_BITS_SHIFT), TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
    }
    if (container_len < 0) {
        expert_add_info(pinfo, len_pi, &ei_thrift_negative_length);
        return THRIFT_REQUEST_REASSEMBLY;
    }

    /* Read the content of the container. */
    for (i = 0; i < container_len; ++i) {
        if (dissect_thrift_compact_type(tvb, pinfo, sub_tree, offset, thrift_opt, NULL, type, type_pi) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
    }
    proto_item_set_end(container_pi, tvb, *offset);

    return *offset;
}

static int
dissect_thrift_compact_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt)
{
    return dissect_thrift_compact_list_set(tvb, pinfo, tree, offset, thrift_opt, TRUE);
}

static int
dissect_thrift_compact_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt)
{
    return dissect_thrift_compact_list_set(tvb, pinfo, tree, offset, thrift_opt, FALSE);
}

static int
dissect_thrift_compact_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt)
{
    /* Compact protocol map header (1 byte, empty map):
     *      +--------+
     *      |00000000|
     *      +--------+
     *
     *  Compact protocol map (4+ bytes, non empty map) and key-value pairs:
     *      +--------+...+--------+--------+--...--+---...---+ ... +--...--+---...---+
     *      | number of elements  |kkkkvvvv| key 1 | value 1 |     | key N | value N |
     *      +--------+...+--------+--------+--...--+---...---+ ... +--...--+---...---+
     *
     *  Where:
     *      nb of elts  is the number of key + value pairs, encoded as an unsigned 32 bits varint.
     *                  If this varint is null (map is empty), the types are not encoded at all.
     *      'kkkk'      is the type of the map keys, an unsigned 4 bits strictly positive integer.
     *      'vvvv'      is the type of the map values, an unsigned 4 bits strictly positive integer.
     */

    proto_tree *sub_tree;
    proto_item *container_pi, *len_pi, *ktype_pi, *vtype_pi;
    guint32 types, ktype, vtype;
    gint32 container_len, len_len, i;
    guint64 varint;

    ABORT_ON_INCOMPLETE_PDU(TCP_THRIFT_MIN_VARINT_LEN);
    /* Create the sub-tree. */
    container_pi = proto_tree_add_item(tree, hf_thrift_map, tvb, *offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(container_pi, ett_thrift_map);

    /* Read and check number of key-value pair in the map. */
    len_len = thrift_get_varint_enc(tvb, pinfo, sub_tree, *offset, TCP_THRIFT_MAX_I32_LEN, &varint, ENC_VARINT_PROTOBUF);
    switch (len_len) {
    case THRIFT_REQUEST_REASSEMBLY:
        /* Will always return after setting the expert parts. */
        ABORT_ON_INCOMPLETE_PDU(TCP_THRIFT_MAX_I32_LEN);
        return THRIFT_REQUEST_REASSEMBLY; // Just to avoid a false positive warning.
    case 0:
        /* In case of error, the offset stay at the error position. */
        return THRIFT_REQUEST_REASSEMBLY;
    default:
        if (varint > (guint64)INT32_MAX) {
            len_pi = proto_tree_add_int64(sub_tree, hf_thrift_i64, tvb, *offset, len_len, varint);
            expert_add_info(pinfo, len_pi, &ei_thrift_varint_too_large);
            return THRIFT_REQUEST_REASSEMBLY;
        }
        container_len = (guint32)varint;
        len_pi = proto_tree_add_int(sub_tree, hf_thrift_num_map_item, tvb, *offset, len_len, container_len);
        *offset += len_len;
        break;
    }
    if (container_len < 0) {
        expert_add_info(pinfo, len_pi, &ei_thrift_negative_length);
        return THRIFT_REQUEST_REASSEMBLY;
    }

    /* Do not try to read the key & value types of an empty map. */
    if (container_len > 0) {
        /* If the map is not empty, read the types of keys and values. */
        types = tvb_get_guint8(tvb, *offset);
        ktype = (types >> TCP_THRIFT_NIBBLE_SHIFT) & TCP_THRIFT_NIBBLE_MASK;
        ktype_pi = proto_tree_add_bits_item(sub_tree, hf_thrift_key_type, tvb, *offset << OCTETS_TO_BITS_SHIFT, TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
        vtype = types & TCP_THRIFT_NIBBLE_MASK;
        vtype_pi = proto_tree_add_bits_item(sub_tree, hf_thrift_value_type, tvb, (*offset << OCTETS_TO_BITS_SHIFT) + TCP_THRIFT_NIBBLE_SHIFT, TCP_THRIFT_NIBBLE_SHIFT, ENC_BIG_ENDIAN);
        *offset += TCP_THRIFT_MAP_TYPES_LEN;

        /* Read the content of the container. */
        for (i = 0; i < container_len; ++i) {
            if (dissect_thrift_compact_type(tvb, pinfo, sub_tree, offset, thrift_opt, NULL, ktype, ktype_pi) == THRIFT_REQUEST_REASSEMBLY) {
                return THRIFT_REQUEST_REASSEMBLY;
            }
            if (dissect_thrift_compact_type(tvb, pinfo, sub_tree, offset, thrift_opt, NULL, vtype, vtype_pi) == THRIFT_REQUEST_REASSEMBLY) {
                return THRIFT_REQUEST_REASSEMBLY;
            }
        }
    }
    proto_item_set_end(container_pi, tvb, *offset);

    return *offset;
}

static int
dissect_thrift_compact_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt)
{
    /*
     *  Compact protocol field header (1 byte, short form) and field value:
     *      +--------+--------+...+--------+
     *      |ddddtttt| field value         |
     *      +--------+--------+...+--------+
     *
     *  Compact protocol field header (2 to 4 bytes, long form) and field value:
     *      +--------+--------+...+--------+--------+...+--------+
     *      |0000tttt| field id            | field value         |
     *      +--------+--------+...+--------+--------+...+--------+
     *
     *  Compact protocol stop field (1 byte):
     *      +--------+
     *      |00000000|
     *      +--------+
     *
     * Where:
     *
     *      'dddd'      is the field id delta, a strictly positive unsigned 4 bits integer.
     *      'tttt'      is the type of the field value, a strictly positive unsigned 4 bits integer.
     *      field id    is the numerical value of the field in the structure.
     *      field value is the encoded value.
     */

    /* This function does not create the subtree, it's the responsibility of the caller:
     * - either dissect_thrift_common which creates the "Data" sub-tree,
     * - or dissect_thrift_compact_struct which creates the "Struct" sub-tree.
     */
    thrift_field_header_t field_header;

    thrift_opt->previous_field_id = 0;
    while (TRUE) {
        if (dissect_thrift_field_header(tvb, pinfo, tree, offset, thrift_opt, &field_header) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        if (field_header.type.compact == DE_THRIFT_C_STOP) {
            break; /* Need to break out of the loop, cannot do that in the switch. */
        }
        if (dissect_thrift_compact_type(tvb, pinfo, tree, offset, thrift_opt, field_header.fh_tree, field_header.type.compact, field_header.type_pi) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        thrift_opt->previous_field_id = field_header.field_id;
    }

    return *offset;
}

static int
dissect_thrift_compact_struct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt)
{
    /* This function only creates the "Struct" sub-tree
     * then it delegates the fields dissection to dissect_thrift_compact_fields.
     */
    proto_tree *sub_tree;
    proto_item *pi;

    ABORT_ON_INCOMPLETE_PDU(TCP_THRIFT_STRUCT_LEN);
    pi = proto_tree_add_item(tree, hf_thrift_struct, tvb, *offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(pi, ett_thrift_struct);

    if (dissect_thrift_compact_fields(tvb, pinfo, sub_tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
        return THRIFT_REQUEST_REASSEMBLY;
    } else {
        proto_item_set_end(pi, tvb, *offset);
    }
    return *offset;
}

/* Dissect a compact thrift field of a given type.
 *
 * This function is used only for linear containers (list, set, map).
 * It uses the same type identifiers as TBinaryProtocol.
 */
static int
dissect_thrift_compact_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, thrift_option_data_t *thrift_opt, proto_tree *header_tree, int type, proto_item *type_pi)
{
    guint nested_count = p_get_proto_depth(pinfo, proto_thrift);
    if (++nested_count > thrift_opt->nested_type_depth) {
        expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_thrift_too_many_subtypes);
        return THRIFT_REQUEST_REASSEMBLY;
    }
    p_set_proto_depth(pinfo, proto_thrift, nested_count);

    switch (type) {
    case DE_THRIFT_C_BOOL_TRUE:
    case DE_THRIFT_C_BOOL_FALSE:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_BOOL_LEN);
        proto_tree_add_item(tree, hf_thrift_bool, tvb, *offset, TBP_THRIFT_BOOL_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_BOOL_LEN;
        break;
    case DE_THRIFT_C_I8:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_I8_LEN);
        proto_tree_add_item(tree, hf_thrift_i8, tvb, *offset, TBP_THRIFT_I8_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_I8_LEN;
        break;
    case DE_THRIFT_C_I16:
        if (dissect_thrift_varint(tvb, pinfo, tree, offset, thrift_opt, TCP_THRIFT_MAX_I16_LEN, hf_thrift_i16) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_C_I32:
        if (dissect_thrift_varint(tvb, pinfo, tree, offset, thrift_opt, TCP_THRIFT_MAX_I32_LEN, hf_thrift_i32) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_C_I64:
        if (dissect_thrift_varint(tvb, pinfo, tree, offset, thrift_opt, TCP_THRIFT_MAX_I64_LEN, hf_thrift_i64) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_C_DOUBLE:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_DOUBLE_LEN);
        /* https://github.com/apache/thrift/blob/master/doc/specs/thrift-compact-protocol.md
         * In section double encoding:
         * "But while the binary protocol encodes the int64 in 8 bytes in big endian order,
         * the compact protocol encodes it in little endian order - this is due to an early
         * implementation bug that finally became the de-facto standard."
         */
        proto_tree_add_item(tree, hf_thrift_double, tvb, *offset, TBP_THRIFT_DOUBLE_LEN, ENC_LITTLE_ENDIAN);
        *offset += TBP_THRIFT_DOUBLE_LEN;
        break;
    case DE_THRIFT_C_UUID:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_UUID_LEN);
        proto_tree_add_item(tree, hf_thrift_uuid, tvb, *offset, TBP_THRIFT_UUID_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_UUID_LEN;
        break;
    case DE_THRIFT_C_BINARY:
        if (dissect_thrift_compact_binary(tvb, pinfo, tree, offset, thrift_opt, header_tree) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_C_LIST:
        if (dissect_thrift_compact_list(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_C_SET:
        if (dissect_thrift_compact_set(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_C_MAP:
        if (dissect_thrift_compact_map(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_C_STRUCT:
        if (dissect_thrift_compact_struct(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    default:
        /* Bail out */
        expert_add_info(pinfo, type_pi, &ei_thrift_wrong_type);
        return THRIFT_REQUEST_REASSEMBLY;
    }

    p_set_proto_depth(pinfo, proto_thrift, --nested_count);
    return *offset;
}
/*=====END COMPACT GENERIC DISSECTION=====*/

/*
 * End of generic functions
 */

/*
Binary protocol Message, strict encoding, 13+ bytes:
   +--------+--------+--------+--------++--------+--------+--------+--------++--------+...+--------++--------+--------+--------+--------++...++--------+
   |1vvvvvvv|vvvvvvvv|unused  |00000mmm|| name length                       || name                || seq id                            ||   || T_STOP |
   +--------+--------+--------+--------++--------+--------+--------+--------++--------+...+--------++--------+--------+--------+--------++...++--------+

   Where:

   * 'vvvvvvvvvvvvvvv' is the version, an unsigned 15 bit number fixed to '1' (in binary: '000 0000 0000 0001'). The leading bit is 1.
   * Although for consistency with Compact protocol, we will use |pppppppp|000vvvvv| instead in the display:
   *       'pppppppp' = 0x80 for the protocol id and
   *       '000' 3 zeroed bits as mandated by the specs.
   *       'vvvvv' 5 bits for the version (see below).
   * 'unused' is an ignored byte.
   * 'mmm' is the message type, an unsigned 3 bit integer.
   *       The 5 leading bits must be '0' as some clients take the whole byte.
   *       (checked for java in 0.9.1)
   * 'name length' is the byte length of the name field, a signed 32 bit integer encoded in network (big endian) order (must be >= 0).
   * 'name' is the method name, an UTF-8 encoded string.
   * 'seq id' is the sequence id, a signed 32 bit integer encoded in network (big endian) order.

Binary protocol Message, old encoding, 9+ bytes:
   +--------+--------+--------+--------++--------+...+--------++--------++--------+--------+--------+--------++...++--------+
   | name length                       || name                ||00000mmm|| seq id                            ||   || T_STOP |
   +--------+--------+--------+--------++--------+...+--------++--------++--------+--------+--------+--------++...++--------+

   Where name length, name, mmm, seq id are the same as above.

   Because name length must be positive (therefore the first bit is always 0),
   the first bit allows the receiver to see whether the strict format or the old format is used.

Note: Double separators indicate how the Thrift parts are sent on the wire depending on the network settings.
      There are clients and server in production that do not squeeze as much data as possible in a packet
      but push each Thrift write<Type>() call directly to the wire, making it harder to detect
      as we only have 4 bytes in the first packet.

Compact protocol Message (5+ bytes):
   +--------+--------+--------+...+--------+--------+...+--------+--------+...+--------+...+--------+
   |pppppppp|mmmvvvvv| seq id              | name length         | name                |   | T_STOP |
   +--------+--------+--------+...+--------+--------+...+--------+--------+...+--------+...+--------+

   Where:

   * 'pppppppp' is the protocol id, fixed to '1000 0010', 0x82.
   * 'mmm' is the message type, an unsigned 3 bit integer.
   * 'vvvvv' is the version, an unsigned 5 bit integer, fixed to '00001'.
   * 'seq id' is the sequence id, a signed 32 bit integer encoded as a varint.
   * 'name length' is the byte length of the name field, a signed 32 bit integer encoded as a varint (must be >= 0).
   * 'name' is the method name to invoke, an UTF-8 encoded string.

Note: The content of the message is everything after the header until and including the T_STOP last byte,
      In both protocols, the content is arranged exactly as the content of a struct.

Framed Transport can encapsulate any protocol version:
   +--------+--------+--------+--------+--------+...+--------+--------+
   | message length                    | Any protocol message, T_STOP |
   +--------+--------+--------+--------+--------+...+--------+--------+
                                       |<------ message length ------>|

   Message types are encoded with the following values:

   * _Call_: 1
   * _Reply_: 2
   * _Exception_: 3
   * _Oneway_: 4
 */

/*=====BEGIN HEADER GENERIC DISSECTION=====*/
/* Dissect a unique Thrift TBinaryProtocol PDU and return the effective length of this PDU.
 *
 * This method is called only if the preliminary verifications have been done so it will use as
 * much data as possible and will return THRIFT_REQUEST_REASSEMBLY and ask for reassembly if there is
 * not enough data.
 *
 * In case of TFramedTransport, tcp_dissect_pdus made sure that we had all necessary data so reassembly
 * will fail if the effective data is bigger than the frame which is a real error.
 *
 * Returns:
 * - THRIFT_REQUEST_REASSEMBLY = -1 if reassembly is required
 * -                              0 if an error occurred
 * -                     offset > 0 to indicate the end of the PDU in case of success
 *
 * This method MUST be called with non-null thrift_opt.
 */
static int
dissect_thrift_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, thrift_option_data_t *thrift_opt)
{
    proto_tree *thrift_tree, *sub_tree;
    proto_item *thrift_pi, *data_pi;
    proto_item *mtype_pi = NULL;
    proto_item *fid_pi = NULL;
    int start_offset = offset;
    int header_offset = 0, data_offset = 0;
    gint32 seqid_len = TCP_THRIFT_MAX_I32_LEN;
    gint32 str_len_len = TCP_THRIFT_MAX_I32_LEN;
    guint8 mtype;
    guint16 version;
    gint32 str_len, seq_id;
    gint64 varint;
    guint8 *method_str;
    int remaining;
    tvbuff_t *msg_tvb;
    int len, tframe_length = 0;
    gboolean is_framed, is_compact, request_reasm;

    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    is_framed = (thrift_opt->tprotocol & PROTO_THRIFT_FRAMED) != 0;
    is_compact = (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) != 0;
    /* Create the item now in case of malformed buffer to use with expert_add_info() */
    thrift_pi = proto_tree_add_item(tree, proto_thrift, tvb, offset, -1, ENC_NA);
    thrift_tree = proto_item_add_subtree(thrift_pi, ett_thrift);
    data_pi = thrift_pi; /* Used for expert_add_info in case of reassembly before the sub-tree is created. */

    if (is_framed) {
        /* Thrift documentation indicates a maximum of 16 MB frames by default.
         * Configurable since Thrift 0.14.0 so better stay on the safe side.
         * We are more tolerant with 2 GiB. */
        /* TODO: Add a dissector parameter using the same default as Thrift?
         *       If we do, check the length in test_thrift_strict as well. */
        tframe_length = tvb_get_ntohil(tvb, offset);
        if (tframe_length <= 0) {
            thrift_tree = proto_item_add_subtree(thrift_pi, ett_thrift_error);
            data_pi = proto_tree_add_item(thrift_tree, hf_thrift_frame_length, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN);
            expert_add_info(pinfo, data_pi, &ei_thrift_negative_length);
            return 0;
        }
        proto_item_set_len(thrift_pi, TBP_THRIFT_LENGTH_LEN + tframe_length);
        /* Keep the same start point to avoid awkward offset calculations */
        offset += TBP_THRIFT_LENGTH_LEN;
    }

    header_offset = offset;
    remaining = tvb_reported_length_remaining(tvb, offset);
    /* We should be called only when the entire frame is ready
     * so we don't need to verify if we have enough data.
     * If not framed, anything remaining is obviously greater than 0. */
    DISSECTOR_ASSERT(remaining >= tframe_length);

    /****************************************************************/
    /* Decode the header depending on compact, strict (new) or old. */
    /****************************************************************/
    if (is_compact) {
        if (remaining < TCP_THRIFT_MIN_MESSAGE_LEN) {
            goto add_expert_and_reassemble;
        }
        /* Compact: proto_id|mtype+version|seqid|length|name */
        version = tvb_get_ntohs(tvb, offset) & THRIFT_COMPACT_VERSION_VALUE_MASK;
        mtype = (tvb_get_ntohs(tvb, offset) & THRIFT_COMPACT_MESSAGE_MASK) >> THRIFT_COMPACT_MESSAGE_SHIFT;
        offset += TCP_THRIFT_VERSION_LEN;
        /* Pass sequence id */
        seqid_len = thrift_get_varint_enc(tvb, pinfo, tree, offset, TCP_THRIFT_MAX_I32_LEN, &varint, ENC_VARINT_ZIGZAG);
        /* We use the same reassembly/error convention. */
        if (seqid_len <= 0) {
            return seqid_len;
        }
        offset += seqid_len;
        if (varint > (gint64)INT32_MAX || varint < (gint64)INT32_MIN) {
            expert_add_info(pinfo, thrift_pi, &ei_thrift_varint_too_large);
            /* Sequence id is only informative, we may be just fine. */
        }
        seq_id = (gint32)varint;
        /* Read length of method name */
        str_len_len = thrift_get_varint_enc(tvb, pinfo, tree, offset, TCP_THRIFT_MAX_I32_LEN, &varint, ENC_VARINT_PROTOBUF);
        if (str_len_len <= 0) {
            return str_len_len;
        }
        if (varint > (gint64)INT32_MAX) {
            expert_add_info(pinfo, thrift_pi, &ei_thrift_varint_too_large);
            return 0;
        }
        str_len = (gint32)varint;
        if (str_len < 0) {
            expert_add_info(pinfo, thrift_pi, &ei_thrift_negative_length);
            return 0;
        }
        offset += str_len_len;
        /* Set method name */
        if (tvb_reported_length_remaining(tvb, offset) < str_len) {
            goto add_expert_and_reassemble;
        }
        method_str = tvb_get_string_enc(pinfo->pool, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
    } else if (thrift_opt->tprotocol & PROTO_THRIFT_STRICT) {
        if (remaining < TBP_THRIFT_STRICT_MIN_MESSAGE_LEN) {
            goto add_expert_and_reassemble;
        }
        version = tvb_get_ntohs(tvb, offset) & THRIFT_BINARY_VERSION_VALUE_MASK;
        mtype = tvb_get_guint8(tvb, offset + TBP_THRIFT_MTYPE_OFFSET) & THRIFT_BINARY_MESSAGE_MASK;
        str_len = tvb_get_ntohil(tvb, offset + TBP_THRIFT_VERSION_LEN);
        if (str_len < 0) {
            expert_add_info(pinfo, thrift_pi, &ei_thrift_negative_length);
            return 0;
        }
        if (remaining < TBP_THRIFT_STRICT_MIN_MESSAGE_LEN + str_len) {
            goto add_expert_and_reassemble;
        }
        offset += TBP_THRIFT_VERSION_LEN + TBP_THRIFT_LENGTH_LEN;
        method_str = tvb_get_string_enc(pinfo->pool, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;

        seq_id = tvb_get_ntohil(tvb, offset);
        offset += TBP_THRIFT_SEQ_ID_LEN;
    } else {
        if (remaining < TBP_THRIFT_MIN_MESSAGE_LEN) {
            goto add_expert_and_reassemble;
        }
        version = 0;
        str_len = tvb_get_ntohil(tvb, offset);
        if (str_len < 0) {
            expert_add_info(pinfo, thrift_pi, &ei_thrift_negative_length);
            return 0;
        }
        if (remaining < TBP_THRIFT_MIN_MESSAGE_LEN + str_len) {
            goto add_expert_and_reassemble;
        }
        offset += TBP_THRIFT_LENGTH_LEN;
        method_str = tvb_get_string_enc(pinfo->pool, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        mtype = tvb_get_guint8(tvb, offset + TBP_THRIFT_LENGTH_LEN + str_len) & THRIFT_BINARY_MESSAGE_MASK;
        offset += TBP_THRIFT_TYPE_LEN;

        seq_id = tvb_get_ntohil(tvb, offset);
        offset += TBP_THRIFT_SEQ_ID_LEN;
    }

    data_offset = offset;

    /* Can be used in case of error, in particular when TFramedTransport is in use. */
    thrift_opt->reassembly_tree = thrift_tree;
    thrift_opt->reassembly_offset = start_offset;
    thrift_opt->reassembly_length = -1;
    thrift_opt->mtype = (thrift_method_type_enum_t)mtype;

    /*****************************************************/
    /* Create the header tree with the extracted fields. */
    /*****************************************************/
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s %s", val_to_str(mtype, thrift_mtype_vals, "%d"), method_str);

    if (thrift_tree) {
        offset = start_offset; /* Reset parsing position. */
        if (is_framed) {
            proto_tree_add_item(thrift_tree, hf_thrift_frame_length, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_LENGTH_LEN;
        }
        sub_tree = proto_tree_add_subtree_format(thrift_tree, tvb, header_offset, data_offset - header_offset, ett_thrift_header, &data_pi,
                "%s [version: %d, seqid: %d, method: %s]",
                val_to_str(mtype, thrift_mtype_vals, "%d"),
                version, seq_id, method_str);
        /* Decode the header depending on compact, strict (new) or old. */
        if (is_compact) {
            /* Compact: proto_id|mtype+version|seqid|length|name */
            proto_tree_add_item(sub_tree, hf_thrift_protocol_id, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
            proto_tree_add_bits_item(sub_tree, hf_thrift_version, tvb, (offset << OCTETS_TO_BITS_SHIFT) + 11, 5, ENC_BIG_ENDIAN);
            mtype_pi = proto_tree_add_bits_item(sub_tree, hf_thrift_mtype, tvb, (offset << OCTETS_TO_BITS_SHIFT) + 8, 3, ENC_BIG_ENDIAN);
            offset += TCP_THRIFT_VERSION_LEN;
            proto_tree_add_int(sub_tree, hf_thrift_seq_id, tvb, offset, seqid_len, seq_id);
            offset += seqid_len;
            proto_tree_add_int(sub_tree, hf_thrift_str_len, tvb, offset, str_len_len, str_len);
            offset += str_len_len;
            proto_tree_add_item(sub_tree, hf_thrift_method, tvb, offset, str_len, ENC_UTF_8);
            offset = offset + str_len;
        } else if (thrift_opt->tprotocol & PROTO_THRIFT_STRICT) {
            /* Strict: proto_id|version|mtype|length|name|seqid */
            proto_tree_add_item(sub_tree, hf_thrift_protocol_id, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
            proto_tree_add_bits_item(sub_tree, hf_thrift_version, tvb, (offset << OCTETS_TO_BITS_SHIFT) + 11, 5, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_MTYPE_OFFSET;
            mtype_pi = proto_tree_add_bits_item(sub_tree, hf_thrift_mtype, tvb, (offset << OCTETS_TO_BITS_SHIFT) + 5, 3, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_MTYPE_LEN;
            proto_tree_add_item(sub_tree, hf_thrift_str_len, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_LENGTH_LEN;
            proto_tree_add_item(sub_tree, hf_thrift_method, tvb, offset, str_len, ENC_UTF_8);
            offset = offset + str_len;
            proto_tree_add_item(sub_tree, hf_thrift_seq_id, tvb, offset, TBP_THRIFT_SEQ_ID_LEN, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_SEQ_ID_LEN;
        } else {
            /* Old: length|name|mtype|seqid */
            proto_tree_add_item(sub_tree, hf_thrift_str_len, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_LENGTH_LEN;
            proto_tree_add_item(sub_tree, hf_thrift_method, tvb, offset, str_len, ENC_UTF_8);
            offset = offset + str_len;
            mtype_pi = proto_tree_add_bits_item(sub_tree, hf_thrift_mtype, tvb, (offset << OCTETS_TO_BITS_SHIFT) + 5, 3, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_MTYPE_LEN;
            proto_tree_add_item(sub_tree, hf_thrift_seq_id, tvb, offset, TBP_THRIFT_SEQ_ID_LEN, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_SEQ_ID_LEN;
        }
        DISSECTOR_ASSERT(offset == data_offset);
    }

    /* TODO: Save CALL seq_id to link with matching REPLY|EXCEPTION for conversation_t. */
    /* TODO: Track the command name as well? Act differently for null & non-null seq_id? */
    if (tvb_reported_length_remaining(tvb, data_offset) < TBP_THRIFT_TYPE_LEN) {
        goto add_expert_and_reassemble;
    }

    /***********************************************************/
    /* Call method dissector here using dissector_try_string() */
    /* except in case of EXCEPTION for detailed dissection.    */
    /***********************************************************/
    thrift_opt->previous_field_id = 0;
    msg_tvb = tvb_new_subset_remaining(tvb, data_offset);
    if (thrift_opt->mtype == ME_THRIFT_T_REPLY) {
        thrift_field_header_t header;
        /* For REPLY, in order to separate successful answers from errors (exceptions),
         * Thrift generates a struct with as much fields (all optional) as there are exceptions possible + 1.
         * At most 1 field will be filled for any reply
         * - Field id = 0: The effective type of the return value of the method (not set if void).
         * - Field id > 0: The number of the exception that was raised by the method.
         *   Note: This is different from the ME_THRIFT_T_EXCEPTION method type that is used in case the method is unknown
         *         or the PDU invalid/impossible to decode for the other endpoint.
         * We read this before checking for sub-dissectors as the information might be useful to them.
         */
        int result = data_offset;
        result = dissect_thrift_field_header(tvb, pinfo, NULL, &result, thrift_opt, &header);
        switch (result) {
        case THRIFT_REQUEST_REASSEMBLY:
            goto add_expert_and_reassemble;
        case THRIFT_SUBDISSECTOR_ERROR:
            return 0;
        default:
            break;
        }
        thrift_opt->reply_field_id = header.field_id;
        fid_pi = header.fid_pi;
    }
    if (thrift_opt->mtype != ME_THRIFT_T_EXCEPTION) {
        if (pinfo->can_desegment > 0) pinfo->can_desegment++;
        len = dissector_try_string(thrift_method_name_dissector_table, method_str, msg_tvb, pinfo, tree, thrift_opt);
        if (pinfo->can_desegment > 0) pinfo->can_desegment--;
    } else {
        expert_add_info(pinfo, mtype_pi, &ei_thrift_protocol_exception);
        /* Leverage the sub-dissector capabilities to dissect Thrift exceptions. */
        len = dissect_thrift_t_struct(msg_tvb, pinfo, thrift_tree, 0, thrift_opt, FALSE, 0, hf_thrift_exception, ett_thrift_exception, thrift_exception);
    }
    if (len > 0) {
        /* The sub dissector dissected the tvb*/
        if (!is_framed) {
            proto_item_set_end(thrift_pi, msg_tvb, len);
        }
        return data_offset + len;
    } else if (len == THRIFT_REQUEST_REASSEMBLY) {
        /* The sub-dissector requested more bytes (len = -1) */
        goto reassemble_pdu;
    } else if (len <= THRIFT_SUBDISSECTOR_ERROR) {
        /* All other negative values are treated as error codes (only -2 is recommended). */
        if (!try_generic_if_sub_dissector_fails) {
            return 0;
        }
        /* else { Fallback to dissect using the generic dissector. } */
    } /* else len = 0, no specific sub-dissector. */

    /***********************/
    /* Generic dissection. */
    /***********************/
    sub_tree = proto_tree_add_subtree(thrift_tree, tvb, data_offset, -1, ett_thrift_params, &data_pi, "Data");
    thrift_opt->reassembly_length = TBP_THRIFT_TYPE_LEN;
    if (thrift_opt->reply_field_id != 0) {
        expert_add_info(pinfo, fid_pi, &ei_thrift_application_exception);
        proto_item_set_text(data_pi, "Exception: %" PRId64, thrift_opt->reply_field_id);
    }

    if (is_compact) {
        request_reasm = dissect_thrift_compact_fields(tvb, pinfo, sub_tree, &offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY;
    } else { /* Binary (strict/old distinction only applies to the header) */
        request_reasm = dissect_thrift_binary_fields(tvb, pinfo, sub_tree, &offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY;
    }
    /* Check the result of the Data part dissection. */
    if (request_reasm) {
        if (offset > 0) {
            /* An error occurred at the given offset, consume everything. */
            return tvb_reported_length(tvb);
        } /* else It's really a reassembly request. */
        goto reassemble_pdu;
    } else {
        /* We found the end of the data. */
        proto_item_set_end(data_pi, tvb, offset);
    }
    /* Set the end of the global Thrift tree (except if framed because it's already set),
     * as well as the end of the Data sub-tree. */
    if (!is_framed) {
        /* In case the frame is larger than the data, we need to know the difference. */
        proto_item_set_end(thrift_pi, tvb, offset);
    }
    proto_item_set_end(data_pi, tvb, offset);
    return offset;
add_expert_and_reassemble: /* When detected in this function. */
    expert_add_info(pinfo, data_pi, &ei_thrift_not_enough_data);
reassemble_pdu: /* When detected by any called function (that already added the expert info). */
    /* We did not encounter final T_STOP. */
    pinfo->desegment_offset = start_offset;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return THRIFT_REQUEST_REASSEMBLY;
}

/* For tcp_dissect_pdus. */
static guint
get_framed_thrift_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (guint)TBP_THRIFT_LENGTH_LEN + tvb_get_ntohl(tvb, offset);
}

/* Effective dissection once the exact encoding has been determined.
 * - Calls dissect_thrift_common in a loop until end of a packet matches end of Thrift PDU.
 *
 * This method MUST be called with non-null thrift_opt.
 */
static int
dissect_thrift_loop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, thrift_option_data_t *thrift_opt)
{
    gint32 offset = 0;
    gint32 hdr_offset = 0;
    gint32 last_pdu_start_offset = 0;
    gint32 remaining = tvb_reported_length_remaining(tvb, offset);

    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    /* Loop until the end of the packet coincides with the end of a PDU. */
    while (remaining > 0) {
        last_pdu_start_offset = offset;
        if (remaining < TBP_THRIFT_LENGTH_LEN) {
            goto reassemble_pdu;
        }
        if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
            offset = dissect_thrift_common(tvb, pinfo, tree, offset, thrift_opt);
        } else {
            /* According to Thrift documentation, old and new (strict) binary protocols
             * could coexist on a single server so we cannot assume it's still the same.
             * In particular, client could send a first request in old format to get
             * the server version and switch to strict if the server is up-to-date
             * or if it rejected explicitly the old format (there's an example for that). */
            if (tvb_get_gint8(tvb, offset + hdr_offset) < 0) {
                /* Strict header (If only the message type is incorrect, assume this is a new one. */
                if (!is_thrift_strict_version(tvb_get_ntohl(tvb, offset + hdr_offset), TRUE)) {
                    expert_add_info(pinfo, NULL, &ei_thrift_wrong_proto_version);
                    return tvb_reported_length_remaining(tvb, 0);
                }
                thrift_opt->tprotocol = (thrift_protocol_enum_t)(thrift_opt->tprotocol | PROTO_THRIFT_STRICT);
            } else {
                /* Old header. */
                thrift_opt->tprotocol = (thrift_protocol_enum_t)(thrift_opt->tprotocol & ~PROTO_THRIFT_STRICT);
            }
            offset = dissect_thrift_common(tvb, pinfo, tree, offset, thrift_opt);
        }

        if (offset == THRIFT_REQUEST_REASSEMBLY) {
            goto reassemble_pdu;
        } else if (offset == 0) {
            /* An error occurred, we just stop, consuming everything. */
            return tvb_reported_length_remaining(tvb, 0);
        }
        remaining = tvb_reported_length_remaining(tvb, offset);
    }
    return offset;
reassemble_pdu:
    /* We did not encounter a final T_STOP exactly at the last byte. */
    pinfo->desegment_offset = last_pdu_start_offset;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return tvb_reported_length(tvb);
}

/* Dissect a unique Thrift PDU within a TFramedTransport and return the effective length of this PDU.
 *
 * This method is called only if the preliminary verifications have been done including length.
 * This method will throw if there is not enough data or too much data.
 *
 * This method MUST be called with non-null thrift_opt/data using thrift_option_data_t effective type.
 */
static int
dissect_thrift_framed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint32 offset = 0;
    gint32 frame_len = 0;
    gint32 reported = tvb_reported_length_remaining(tvb, offset);
    thrift_option_data_t *thrift_opt = (thrift_option_data_t *)data;

    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);
    DISSECTOR_ASSERT(thrift_opt->tprotocol & PROTO_THRIFT_FRAMED);
    frame_len = tvb_get_ntohil(tvb, offset);
    DISSECTOR_ASSERT((frame_len + TBP_THRIFT_LENGTH_LEN) == reported);

    offset = dissect_thrift_common(tvb, pinfo, tree, offset, thrift_opt);
    if (offset == THRIFT_REQUEST_REASSEMBLY) {
        /* No reassembly possible in this case */
        proto_tree_add_expert(thrift_opt->reassembly_tree, pinfo, &ei_thrift_frame_too_short,
                tvb, thrift_opt->reassembly_offset, thrift_opt->reassembly_length);
        pinfo->desegment_offset = reported;
        pinfo->desegment_len = 0;
    } else if (offset > 0 && tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(thrift_opt->reassembly_tree, pinfo, &ei_thrift_frame_too_long,
                tvb, offset, tvb_reported_length_remaining(tvb, offset));
    }
    return reported;
}

/* Thrift dissection when forced by Decode As… or port selection */
static int
dissect_thrift_transport(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint32 str_len, length = tvb_reported_length(tvb);
    thrift_option_data_t thrift_opt;
    memset(&thrift_opt, 0, sizeof(thrift_option_data_t));
    thrift_opt.nested_type_depth = nested_type_depth;

    /* Starting without even the version / frame length / name length probably means a Keep-Alive at the beginning of the capture. */
    if (length < TBP_THRIFT_VERSION_LEN) {
        if (tvb_get_guint8(tvb, 0) != (THRIFT_COMPACT_VERSION_1 >> 8)) {
            proto_tree_add_expert(tree, pinfo, &ei_thrift_not_enough_data, tvb, 0, length);
            /* Not a Thrift packet, maybe a keep-alive at the beginning of the capture. */
            return NOT_A_VALID_PDU;
        } /* else this might be a compact capture without Nagle activated. */
    }
    /* Need at least the old encoding header (Name Length + Method + Sequence Id) + ending T_STOP */
    if (length < TBP_THRIFT_MIN_MESSAGE_LEN) {
        /* Note: if Nagle algorithm is not active, some systems can spit out Thrift individual elements one by one.
         * For instance on strict protocol:
         * Frame x+0: 4 bytes = version + method type (sent using writeI32)
         * Frame x+1: 4 bytes = method length
         * Frame x+2: n bytes = method name
         * Frame x+3: 4 bytes = sequence id
         * Frame x+4: 1 byte  = field type… */
        goto reassemble_pdu;
    }

    /* MSb of first byte is 1 for compact and binary strict protocols
     * and 0 for framed transport and old binary protocol. */
    if (tvb_get_gint8(tvb, 0) >= 0) {
        /* Option 1 = old binary
         * Option 2 = framed strict binary
         * Option 3 = framed old binary
         * Option 4 = framed compact or anything  not handled. */
        int remaining = tvb_reported_length_remaining(tvb, TBP_THRIFT_LENGTH_LEN); /* Remaining after initial 4 bytes of "length" */
        /* Old header. */
        str_len = tvb_get_ntohil(tvb, 0);

        if (remaining == 0) {
            /* The endpoint probably does not have Nagle activated, wait for next packet. */
            goto reassemble_pdu;
        }
        /* Checking for old binary option. */
        if (remaining < str_len) {
            /* Not enough data to check name validity.
             * Even without Nagle activated, this is /not/ plain old binary Thrift data (or method name is awfully long).
             * Non-framed old binary is not possible, consider framed data only. */
            // TODO: Display available data & error in case we can't reassemble?
            pinfo->desegment_len = str_len - remaining;
            /* Maybe we should return NOT_A_VALID_PDU instead and drop this packet but port preferences tells us this /is/ Thrift data. */
            return THRIFT_REQUEST_REASSEMBLY;
        }

        if (thrift_binary_utf8_isprint(tvb, TBP_THRIFT_LENGTH_LEN, str_len, FALSE) == str_len) {
            /* UTF-8 valid data means first byte is greater than 0x20 and not between 0x80 and 0xbf (neither 0x80 nor 0x82 in particular).
             * This would indicate a method name longer than 512 MiB in Framed old binary protocol which is insane.
             * Therefore, most sane option is old binary without any framing. */
            thrift_opt.canary = THRIFT_OPTION_DATA_CANARY;
            thrift_opt.tprotocol = PROTO_THRIFT_BINARY;
            /* Name length + name + method + seq_id + T_STOP */
            if (length < TBP_THRIFT_MIN_MESSAGE_LEN + str_len) {
                goto reassemble_pdu;
            }
        } else {
            /* This cannot be non-framed old binary so it must be framed (and we have all of it). */
            if (str_len < TBP_THRIFT_MIN_MESSAGE_LEN) {
                /* This is /not/ valid Framed data. */
                return NOT_A_VALID_PDU;
            }
            if (tvb_get_gint8(tvb, TBP_THRIFT_LENGTH_LEN) >= 0) {
                /* Framed old binary format is the only matching option remaining. */
                thrift_opt.canary = THRIFT_OPTION_DATA_CANARY;
                thrift_opt.tprotocol = PROTO_THRIFT_FRAMED;
            } else {
                if (is_thrift_strict_version(tvb_get_ntohl(tvb, TBP_THRIFT_LENGTH_LEN), TRUE)) {
                    /* Framed strict binary protocol. */
                    thrift_opt.canary = THRIFT_OPTION_DATA_CANARY;
                    thrift_opt.tprotocol = (thrift_protocol_enum_t)(PROTO_THRIFT_FRAMED | PROTO_THRIFT_STRICT);
                } else {
                    /* Framed compact protocol or something else entirely, bail out. */
                    return NOT_A_VALID_PDU;
                }
            }
        }
    } else if (is_thrift_strict_version(tvb_get_ntohl(tvb, 0), TRUE)) {
        /* We don't need all the checks from the heuristic because the user prefs told us it /is/ Thrift data.
         * If it fails, it will probably pass through otherwise hard-to-reach code-paths so that's good for tests. */
        thrift_opt.canary = THRIFT_OPTION_DATA_CANARY;
        thrift_opt.tprotocol = PROTO_THRIFT_STRICT;
    } else if (tvb_get_guint8(tvb, 0) == 0x82) {
        /* Same thing here so 0x82 gives us the TCompactProtocol answer. */
        thrift_opt.canary = THRIFT_OPTION_DATA_CANARY;
        thrift_opt.tprotocol = PROTO_THRIFT_COMPACT;
    } else {
        /* else { Not a Thrift packet. } */
        return NOT_A_VALID_PDU;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "THRIFT");
    col_clear(pinfo->cinfo, COL_INFO);

    if (thrift_opt.tprotocol & PROTO_THRIFT_FRAMED) {
        tcp_dissect_pdus(tvb, pinfo, tree, framed_desegment, TBP_THRIFT_LENGTH_LEN,
                get_framed_thrift_pdu_len, dissect_thrift_framed, &thrift_opt);
        return tvb_reported_length(tvb);
    } else {
        return dissect_thrift_loop(tvb, pinfo, tree, &thrift_opt);
    }

reassemble_pdu:
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return THRIFT_REQUEST_REASSEMBLY;
}

/* Test if the captured packet matches a Thrift strict binary packet header.
 * We check for captured and not reported length because:
 * - We need to check the content to verify validity;
 * - We must not have exception in heuristic dissector.
 * Due to that, we might have false negative if the capture is too much shorten
 * but it would have been useless anyway.
 */
static gboolean
test_thrift_strict(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, thrift_option_data_t *thrift_opt)
{
    gint tframe_length = 0;
    int offset = 0;
    guint length = tvb_captured_length(tvb);
    gint32 str_len;

    /* This heuristic only detects strict binary protocol, possibly framed.
     * Detection of old binary protocol is tricky due to the lack of fixed data.
     * TODO: Maybe by assuming a maximum size for the method name like 1kB… or less.
     *
     * In order to avoid false positive, the first packet is expected to contain:
     * 1. Possibly Frame size (4 bytes, if MSb of first byte is 0),
     * 2. Thrift "version" (4 bytes = 0x8001..0m, containing protocol id, version, and method type),
     * 3. Method length (4 bytes),
     * 4. Method name (method length bytes, verified as acceptable UTF-8),
     * 5. Sequence ID (4 bytes, content not verified),
     * 6. First field type (1 byte, content not verified). */

    /* Enough data for elements 2 to 6? */
    if (length < (guint)TBP_THRIFT_STRICT_HEADER_LEN) {
        return FALSE;
    }

    /* 1. Check if it is framed (and if the frame length is large enough for a complete message). */
    if (tvb_get_gint8(tvb, offset) >= 0) {
        /* It is framed. */
        tframe_length = tvb_get_ntohil(tvb, offset);

        if (tframe_length < TBP_THRIFT_STRICT_MIN_MESSAGE_LEN) {
            return FALSE;
        }
        offset = TBP_THRIFT_LENGTH_LEN; /* Strict header starts after frame length. */
        if (length < (guint)(offset + TBP_THRIFT_STRICT_HEADER_LEN)) {
            return FALSE;
        }
    }
    if (thrift_opt) {
        thrift_opt->canary = THRIFT_OPTION_DATA_CANARY;
        /* Set the protocol used since we now have enough information. */
        thrift_opt->tprotocol = PROTO_THRIFT_STRICT;
        if (tframe_length > 0) {
            thrift_opt->tprotocol = (thrift_protocol_enum_t)(thrift_opt->tprotocol | PROTO_THRIFT_FRAMED);
        }
    } else REPORT_DISSECTOR_BUG("%s called without data structure.", G_STRFUNC);

    /* 2. Thrift version & method type (heuristic does /not/ ignore the message type). */
    if (!is_thrift_strict_version(tvb_get_ntohl(tvb, offset), FALSE)) {
        return FALSE;
    }
    offset += TBP_THRIFT_VERSION_LEN;

    /* 3. Get method name length and check against what we have. */
    str_len = tvb_get_ntohil(tvb, offset);
    if ((tframe_length > 0) && (tframe_length < TBP_THRIFT_STRICT_MIN_MESSAGE_LEN + str_len)) {
        /* The frame cannot even contain an empty Thrift message (no data, only T_STOP after the sequence id). */
        return FALSE;
    }
    offset += TBP_THRIFT_LENGTH_LEN;

    /* 4. Check method name itself. */
    if (tvb_captured_length_remaining(tvb, offset) < str_len) {
        /* Method name is no entirely captured, we cannot check it. */
        return FALSE;
    }
    if (thrift_binary_utf8_isprint(tvb, offset, str_len, FALSE) < str_len) {
        return FALSE;
    }
    offset += str_len;

    /* 5 & 6. Check that there is enough data remaining for a sequence ID and a field type (but no need for it to be captured). */
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_LENGTH_LEN + TBP_THRIFT_TYPE_LEN) {
        return FALSE;
    }

    thrift_opt->canary = THRIFT_OPTION_DATA_CANARY;
    return TRUE;
}

/* Test if the captured packet matches a Thrift compact packet header.
 * Same comments as for test_thrift_strict.
 */
static gboolean
test_thrift_compact(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, thrift_option_data_t *thrift_opt)
{
    gint tframe_length = 0;
    int offset = 0;
    guint length = tvb_captured_length(tvb);
    int len_len;
    gint32 str_len = 0;
    guint64 seq_id;

    /* This heuristic detects compact protocol, possibly framed.
     * Note: It assumes a maximum size of 127 bytes for the method name.
     *       Increasing the limit would be easy but this is the heuristic.
     *
     * In order to avoid false positive, the first packet is expected to contain:
     * 1. Possibly Frame size (4 bytes, if MSb of first byte is 0),
     * 2. Thrift "version" (2 bytes = 0x82mv, containing protocol id, method type, and version),
     * 3. Sequence ID (1 to 5 bytes, content not verified),
     * 4. Method length (theoretically 1 to 5 bytes, in practice only 1 byte is accepted),
     * 5. Method name (method length bytes, verified as acceptable UTF-8),
     * 6. First field type (1 byte, content not verified). */

    /* Enough data for elements 2 to 6? */
    if (length < (guint)TCP_THRIFT_MIN_MESSAGE_LEN) {
        return FALSE;
    }

    /* 1. Check if it is framed (and if the frame length is large enough for a complete message). */
    if (tvb_get_gint8(tvb, offset) >= 0) {
        /* It is framed. */
        tframe_length = tvb_get_ntohil(tvb, offset);

        if (tframe_length < TCP_THRIFT_MIN_MESSAGE_LEN) {
            return FALSE;
        }
        offset = TBP_THRIFT_LENGTH_LEN; /* Compact header starts after frame length. */
        if (length < (guint)(offset + TCP_THRIFT_MIN_MESSAGE_LEN)) {
            return FALSE;
        }
    }
    if (thrift_opt) {
        thrift_opt->canary = THRIFT_OPTION_DATA_CANARY;
        /* Set the protocol used since we now have enough information. */
        if (tframe_length > 0) {
            thrift_opt->tprotocol = (thrift_protocol_enum_t)(PROTO_THRIFT_COMPACT | PROTO_THRIFT_FRAMED);
        } else {
            thrift_opt->tprotocol = PROTO_THRIFT_COMPACT;
        }
    } else REPORT_DISSECTOR_BUG("%s called without data structure.", G_STRFUNC);

    /* 2. Thrift version & method type (heuristic does /not/ ignore the message type). */
    if (!is_thrift_compact_version(tvb_get_ntohs(tvb, offset), FALSE)) {
        return FALSE;
    }
    offset += TCP_THRIFT_VERSION_LEN;

    /* 3. Sequence id in varint encoding. We need to make sure we don't try to read not captured data. */
    len_len = tvb_captured_length_remaining(tvb, offset);
    if (len_len > TCP_THRIFT_MAX_I32_LEN) {
        len_len = TCP_THRIFT_MAX_I32_LEN;
    }
    len_len = tvb_get_varint(tvb, offset, len_len, &seq_id, ENC_VARINT_ZIGZAG);
    if (len_len == 0) return FALSE;
    offset += len_len;

    /* 4. Get method name length and check against what we have. */
    if ((guint)offset >= length) return FALSE;
    str_len = tvb_get_gint8(tvb, offset);
    ++offset;
    if ((tframe_length > 0) && (TBP_THRIFT_LENGTH_LEN + tframe_length < offset + str_len)) {
        /* The frame cannot even contain an empty Thrift message (no data, only T_STOP after the sequence id). */
        return FALSE;
    }

    /* 5. Check method name itself. */
    if (tvb_captured_length_remaining(tvb, offset) < str_len) {
        /* Method name is no entirely captured, we cannot check it. */
        return FALSE;
    }
    if (thrift_binary_utf8_isprint(tvb, offset, str_len, FALSE) < str_len) {
        return FALSE;
    }
    offset += str_len;

    /* 6. Check that there is enough data remaining for a field type (but no need for it to be captured). */
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
        return FALSE;
    }

    thrift_opt->canary = THRIFT_OPTION_DATA_CANARY;
    return TRUE;
}

/* Thrift heuristic dissection when the packet is not grabbed by another protocol dissector. */
static gboolean
dissect_thrift_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    thrift_option_data_t thrift_opt;
    memset(&thrift_opt, 0, sizeof(thrift_option_data_t));
    thrift_opt.nested_type_depth = nested_type_depth;

    if (!test_thrift_strict(tvb, pinfo, tree, &thrift_opt) && !test_thrift_compact(tvb, pinfo, tree, &thrift_opt)) {
        return FALSE;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "THRIFT");
    col_clear(pinfo->cinfo, COL_INFO);

    if (thrift_opt.tprotocol & PROTO_THRIFT_FRAMED) {
        tcp_dissect_pdus(tvb, pinfo, tree, framed_desegment, TBP_THRIFT_LENGTH_LEN,
                get_framed_thrift_pdu_len, dissect_thrift_framed, &thrift_opt);
    } else {
        dissect_thrift_loop(tvb, pinfo, tree, &thrift_opt);
    }

    return TRUE;
}
/*=====END HEADER GENERIC DISSECTION=====*/

void
proto_register_thrift(void)
{
    static hf_register_info hf[] = {
        { &hf_thrift_frame_length,
            { "Frame length", "thrift.frame_len",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_exception,
            { "Exception", "thrift.exception",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_exception_message,
            { "Exception Message", "thrift.exception.message",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_exception_type,
            { "Exception Type", "thrift.exception.type",
                FT_INT32, BASE_DEC, VALS(thrift_exception_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_protocol_id,
            { "Protocol id", "thrift.protocol_id",
                FT_UINT8, BASE_HEX, VALS(thrift_proto_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_version,
            { "Version", "thrift.version",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_mtype,
            { "Message type", "thrift.mtype",
                FT_UINT8, BASE_HEX, VALS(thrift_mtype_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_str_len,
            { "Length", "thrift.str_len",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_method,
            { "Method", "thrift.method",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_seq_id,
            { "Sequence Id", "thrift.seq_id",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_type,
            { "Type", "thrift.type",
                FT_UINT8, BASE_HEX, VALS(thrift_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_key_type,
            { "Key Type", "thrift.type",
                FT_UINT8, BASE_HEX, VALS(thrift_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_value_type,
            { "Value Type", "thrift.type",
                FT_UINT8, BASE_HEX, VALS(thrift_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_compact_struct_type,
            { "Type", "thrift.type",
                FT_UINT8, BASE_HEX, VALS(thrift_compact_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_fid,
            { "Field Id", "thrift.fid",
                FT_INT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_fid_delta,
            { "Field Id Delta", "thrift.fid_delta",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_bool,
            { "Boolean", "thrift.bool",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0, /* libthrift (C++) also considers boolean value = (byte != 0x00) */
                NULL, HFILL }
        },
        { &hf_thrift_i8,
            { "Integer8", "thrift.i8",
                FT_INT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_i16,
            { "Integer16", "thrift.i16",
                FT_INT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_i32,
            { "Integer32", "thrift.i32",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_i64,
            { "Integer64", "thrift.i64",
                FT_INT64, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_double,
            { "Double", "thrift.double",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_binary,
            { "Binary", "thrift.binary",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_string,
            { "String", "thrift.string",
                FT_STRING, BASE_NONE, NULL, 0x0,
                "Binary field interpreted as a string.", HFILL }
        },
        { &hf_thrift_struct,
            { "Struct", "thrift.struct",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_list,
            { "List", "thrift.list",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_set,
            { "Set", "thrift.set",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_map,
            { "Map", "thrift.map",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_num_set_item,
            { "Number of Set Items", "thrift.num_set_item",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_num_set_pos,
            { "Number of Set Items", "thrift.num_set_item",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_num_list_item,
            { "Number of List Items", "thrift.num_list_item",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_num_list_pos,
            { "Number of List Items", "thrift.num_list_item",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_num_map_item,
            { "Number of Map Items", "thrift.num_map_item",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_large_container,
            { "More than 14 items", "thrift.num_item",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_uuid,
            { "UUID", "thrift.uuid",
                FT_GUID, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
    };


    /* setup protocol subtree arrays */
    static gint *ett[] = {
        &ett_thrift,
        &ett_thrift_header,
        &ett_thrift_params,
        &ett_thrift_field,
        &ett_thrift_struct,
        &ett_thrift_list,
        &ett_thrift_set,
        &ett_thrift_map,
        &ett_thrift_error,
        &ett_thrift_exception,
    };

    static ei_register_info ei[] = {
        { &ei_thrift_wrong_type, { "thrift.wrong_type", PI_PROTOCOL, PI_ERROR, "Type value not expected.", EXPFILL } },
        { &ei_thrift_wrong_field_id, { "thrift.wrong_field_id", PI_PROTOCOL, PI_WARN, "Field id different from value provided by sub-dissector.", EXPFILL } },
        { &ei_thrift_negative_length, { "thrift.negative_length", PI_PROTOCOL, PI_ERROR, "Length greater than 2 GiB not supported.", EXPFILL } },
        { &ei_thrift_wrong_proto_version, { "thrift.wrong_proto_version", PI_MALFORMED, PI_ERROR, "Protocol version invalid or unsupported.", EXPFILL } },
        { &ei_thrift_struct_fid_not_in_seq, { "thrift.struct_fid_not_in_seq", PI_PROTOCOL, PI_ERROR, "Missing mandatory field id in struct.", EXPFILL } },
        { &ei_thrift_not_enough_data, { "thrift.not_enough_data", PI_PROTOCOL, PI_WARN, "Not enough data to decode.", EXPFILL } },
        { &ei_thrift_frame_too_short, { "thrift.frame_too_short", PI_MALFORMED, PI_ERROR, "Thrift frame shorter than data.", EXPFILL } },
        { &ei_thrift_frame_too_long, { "thrift.frame_too_long", PI_PROTOCOL, PI_WARN, "Thrift frame longer than data.", EXPFILL } },
        { &ei_thrift_varint_too_large, { "thrift.varint_too_large", PI_PROTOCOL, PI_ERROR, "Thrift varint value too large for target integer type.", EXPFILL } },
        { &ei_thrift_undefined_field_id, { "thrift.undefined_field_id", PI_PROTOCOL, PI_NOTE, "Field id not defined by sub-dissector, using generic Thrift dissector.", EXPFILL } },
        { &ei_thrift_negative_field_id, { "thrift.negative_field_id", PI_PROTOCOL, PI_NOTE, "Encountered unexpected negative field id, possibly an old application.", EXPFILL } },
        { &ei_thrift_unordered_field_id, { "thrift.unordered_field_id", PI_PROTOCOL, PI_WARN, "Field id not defined by sub-dissector, using generic Thrift dissector.", EXPFILL } },
        { &ei_thrift_application_exception, { "thrift.application_exception", PI_PROTOCOL, PI_NOTE, "The application recognized the method but rejected the content.", EXPFILL } },
        { &ei_thrift_protocol_exception, { "thrift.protocol_exception", PI_PROTOCOL, PI_WARN, "The application was not able to handle the request.", EXPFILL } },
        { &ei_thrift_too_many_subtypes, { "thrift.too_many_subtypes", PI_PROTOCOL, PI_ERROR, "Too many level of sub-types nesting.", EXPFILL } },
    };


    module_t *thrift_module;
    expert_module_t *expert_thrift;


    /* Register protocol name and description */
    proto_thrift = proto_register_protocol("Thrift Protocol", "Thrift", "thrift");

    expert_thrift = expert_register_protocol(proto_thrift);

    /* register field array */
    proto_register_field_array(proto_thrift, hf, array_length(hf));

    /* register subtree array */
    proto_register_subtree_array(ett, array_length(ett));

    expert_register_field_array(expert_thrift, ei, array_length(ei));

    /* register dissector */
    thrift_handle = register_dissector("thrift", dissect_thrift_transport, proto_thrift);

    thrift_module = prefs_register_protocol(proto_thrift, proto_reg_handoff_thrift);

    thrift_method_name_dissector_table = register_dissector_table("thrift.method_names", "Thrift Method names",
        proto_thrift, FT_STRING, FALSE); /* FALSE because Thrift is case-sensitive */

    prefs_register_enum_preference(thrift_module, "decode_binary",
                                   "Display binary as bytes or strings",
                                   "How the binary should be decoded",
                                   &binary_decode, binary_display_options, FALSE);

    prefs_register_uint_preference(thrift_module, "tls.port",
                                   "Thrift TLS port",
                                   "Thrift TLS port",
                                   10, &thrift_tls_port);

    prefs_register_bool_preference(thrift_module, "show_internal",
                                   "Show internal Thrift fields in the dissection tree",
                                   "Whether the Thrift dissector should display Thrift internal fields for sub-dissectors.",
                                   &show_internal_thrift_fields);

    prefs_register_bool_preference(thrift_module, "fallback_on_generic",
                                   "Fallback to generic Thrift dissector if sub-dissector fails.",
                                   "Whether the Thrift dissector should try to dissect the data if the sub-dissector failed."
                                   " This option can be useful if the data is well-formed but the sub-dissector is expecting different type/content.",
                                   &try_generic_if_sub_dissector_fails);

    prefs_register_uint_preference(thrift_module, "nested_type_depth",
                                   "Thrift nested types depth",
                                   "Maximum expected depth of nested types in the Thrift structures and containers."
                                   " A Thrift-based protocol using no parameter and void return types only uses a depth of 0."
                                   " A Thrift-based protocol using only simple types as parameters or return values uses a depth of 1.",
                                   10, &nested_type_depth);

    prefs_register_bool_preference(thrift_module, "desegment_framed",
                                   "Reassemble Framed Thrift messages spanning multiple TCP segments",
                                   "Whether the Thrift dissector should reassemble framed messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &framed_desegment);
}

void
proto_reg_handoff_thrift(void)
{
    static guint saved_thrift_tls_port;
    static dissector_handle_t thrift_http_handle;
    static gboolean thrift_initialized = FALSE;

    thrift_http_handle = create_dissector_handle(dissect_thrift_heur, proto_thrift);

    if (!thrift_initialized) {
        thrift_initialized = TRUE;
        heur_dissector_add("tcp", dissect_thrift_heur, "Thrift over TCP", "thrift_tcp", proto_thrift, HEURISTIC_ENABLE);
        heur_dissector_add("udp", dissect_thrift_heur, "Thrift over UDP", "thrift_udp", proto_thrift, HEURISTIC_ENABLE);
        heur_dissector_add("usb.bulk", dissect_thrift_heur, "Thrift over USB", "thrift_usb_bulk", proto_thrift, HEURISTIC_ENABLE);
        dissector_add_for_decode_as_with_preference("tcp.port", thrift_handle);
        dissector_add_for_decode_as_with_preference("udp.port", thrift_handle);
        dissector_add_string("media_type", "application/x-thrift", thrift_http_handle); /* Obsolete but still in use. */
        dissector_add_string("media_type", "application/vnd.apache.thrift.binary", thrift_http_handle); /* Officially registered. */
    } else {
        ssl_dissector_delete(saved_thrift_tls_port, thrift_handle);
    }
    ssl_dissector_add(thrift_tls_port, thrift_handle);
    saved_thrift_tls_port = thrift_tls_port;
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
