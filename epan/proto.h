/* proto.h
 * Definitions for protocol display
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/*! @file proto.h
    The protocol tree related functions.<BR>
    A protocol tree will hold all necessary data to display the whole dissected packet.
    Creating a protocol tree is done in a two stage process:
    A static part at program startup, and a dynamic part when the dissection with the real packet data is done.<BR>
    The "static" information is provided by creating a hf_register_info hf[] array, and register it using the
    proto_register_field_array() function. This is usually done at dissector registering.<BR>
    The "dynamic" information is added to the protocol tree by calling one of the proto_tree_add_...() functions,
    e.g. proto_tree_add_bytes().
*/

#ifndef __PROTO_H__
#define __PROTO_H__

#include <stdarg.h>

#include <glib.h>

#include <epan/wmem_scopes.h>

#include "ipv4.h"
#include "wsutil/nstime.h"
#include "tvbuff.h"
#include "value_string.h"
#include "tfs.h"
#include "packet_info.h"
#include "ftypes/ftypes.h"
#include "register.h"
#include "ws_symbol_export.h"
#include "ws_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup prototree The Protocol Tree
 *
 * Dissectors use proto_tree_add_* to add items to the protocol tree. In
 * most cases you'll want to use proto_tree_add_item().
 *
 * @{
 */

/** The header-field index for the special text pseudo-field. Exported by libwireshark.dll */
WS_DLL_PUBLIC int hf_text_only;

/** the maximum length of a protocol field string representation */
#define ITEM_LABEL_LENGTH       240

#define ITEM_LABEL_UNKNOWN_STR  "Unknown"

struct expert_field;

/* Type-check that 'x' is compatible with 'type', should give compiler warnings otherwise. */
#define cast_same(type, x) (0 ? (type)0 : (x))

/** Make a const value_string[] look like a _value_string pointer, used to set header_field_info.strings */
#define VALS(x)     (cast_same(const struct _value_string*, (x)))

/** Make a const val64_string[] look like a _val64_string pointer, used to set header_field_info.strings */
#define VALS64(x)   (cast_same(const struct _val64_string*, (x)))

/** Something to satisfy checkAPIs when you have a pointer to a value_string_ext (e.g., one built with value_string_ext_new()) */
#define VALS_EXT_PTR(x) (cast_same(value_string_ext*, (x)))

/** Make a const true_false_string[] look like a _true_false_string pointer, used to set header_field_info.strings */
#define TFS(x)      (cast_same(const struct true_false_string*, (x)))

typedef void (*custom_fmt_func_t)(gchar *, guint32);

typedef void (*custom_fmt_func_64_t)(gchar *, guint64);

/** Make a custom format function pointer look like a void pointer. Used to set header_field_info.strings.
 *
 * We cast to gsize first, which 1) is guaranteed to be wide enough to
 * hold a pointer and 2) lets us side-step warnings about casting function
 * pointers to 'void *'. This violates ISO C but should be fine on POSIX
 * and Windows.
 */
#define CF_FUNC(x) ((const void *) (gsize) (x))

/** Make a const range_string[] look like a _range_string pointer, used to set
 * header_field_info.strings */
#define RVALS(x) (cast_same(const struct _range_string*, (x)))

/** Cast a ft_framenum_type_t, used to set header_field_info.strings */
#define FRAMENUM_TYPE(x) GINT_TO_POINTER(x)

struct _protocol;

/** Structure for information about a protocol */
typedef struct _protocol protocol_t;

/** Function used for reporting errors in dissectors; it throws a
 * DissectorError exception, with a string generated from the format
 * and arguments to the format, as the message for the exception, so
 * that it can show up in the Info column and the protocol tree.
 *
 * If the WIRESHARK_ABORT_ON_DISSECTOR_BUG environment variable is set,
 * it will call abort(), instead, to make it easier to get a stack trace.
 *
 * @param format format string to use for the message
 */
WS_DLL_PUBLIC WS_NORETURN
void proto_report_dissector_bug(const char *format, ...)
    G_GNUC_PRINTF(1, 2);

#define REPORT_DISSECTOR_BUG(...)  \
    proto_report_dissector_bug(__VA_ARGS__)

/** Macro used to provide a hint to static analysis tools.
 * (Currently only Visual C++.)
 */
#ifdef _MSC_VER
/* XXX - Is there a way to say "quit checking at this point"? */
#define __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(expression) \
  ; __analysis_assume(expression);
#else
#define __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(expression)
#endif

/** Macro used for assertions in dissectors; it doesn't abort, it just
 * throws a DissectorError exception, with the assertion failure
 * message as a parameter, so that it can show up in the protocol tree.
 *
 * NOTE: this should only be used to detect bugs in the dissector (e.g., logic
 * conditions that shouldn't happen).  It should NOT be used for showing
 * that a packet is malformed.  For that, use expert_infos instead.
 *
 * @param s expression to test in the assertion
 */

#define __DISSECTOR_ASSERT_STRINGIFY(s) # s

#define __DISSECTOR_ASSERT(expression, file, lineno)  \
  (REPORT_DISSECTOR_BUG("%s:%u: failed assertion \"%s\"", \
        file, lineno, __DISSECTOR_ASSERT_STRINGIFY(expression)))

#define __DISSECTOR_ASSERT_HINT(expression, file, lineno, hint)  \
  (REPORT_DISSECTOR_BUG("%s:%u: failed assertion \"%s\" (%s)", \
        file, lineno, __DISSECTOR_ASSERT_STRINGIFY(expression), hint))

#define DISSECTOR_ASSERT(expression)  \
  ((void) ((expression) ? (void)0 : \
   __DISSECTOR_ASSERT (expression, __FILE__, __LINE__))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(expression)

/**
 * Same as DISSECTOR_ASSERT(), but takes an extra 'hint' parameter that
 * can be used to provide information as to why the assertion might fail.
 *
 * @param expression expression to test in the assertion
 * @param hint message providing extra information
 */
#define DISSECTOR_ASSERT_HINT(expression, hint)  \
  ((void) ((expression) ? (void)0 : \
   __DISSECTOR_ASSERT_HINT (expression, __FILE__, __LINE__, hint))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(expression)

#if 0
/* win32: using a debug breakpoint (int 3) can be very handy while debugging,
 * as the assert handling of GTK/GLib is currently not very helpful */
#define DISSECTOR_ASSERT(expression)  \
{ if(!(expression)) _asm { int 3}; }
#endif

/** Same as DISSECTOR_ASSERT(), but will throw DissectorError exception
 * unconditionally, much like GLIB's g_assert_not_reached works.
 *
 * NOTE: this should only be used to detect bugs in the dissector (e.g., logic
 * conditions that shouldn't happen).  It should NOT be used for showing
 * that a packet is malformed.  For that, use expert_infos instead.
 *
 */
#define DISSECTOR_ASSERT_NOT_REACHED()  \
  (REPORT_DISSECTOR_BUG("%s:%u: failed assertion \"DISSECTOR_ASSERT_NOT_REACHED\"", \
        __FILE__, __LINE__))

/** Compare two integers.
 *
 * This is functionally the same as `DISSECTOR_ASSERT(a op b)` except that it
 * will display the values of a and b upon failure.
 *
 *     DISSECTOR_ASSERT_CMPINT(a, ==, b);
 *     DISSECTOR_ASSERT_CMPINT(min, <=, max);
 *
 * This function can currently compare values that fit inside a gint64.
 *
 * WARNING: The number of times the arguments are evaluated is undefined.  Do
 * not use expressions with side effects as arguments.
 *
 * @param a  The first integer.
 * @param op Any binary operator.
 * @param b  The second integer.
 * @param type the type operator
 * @param fmt the fmt operator
 */
#define __DISSECTOR_ASSERT_CMPINT(a, op, b, type, fmt) \
  (REPORT_DISSECTOR_BUG("%s:%u: failed assertion " #a " " #op " " #b " (" fmt " " #op " " fmt ")", \
        __FILE__, __LINE__, (type)a, (type)b))

#define DISSECTOR_ASSERT_CMPINT(a, op, b)  \
  ((void) ((a op b) ? (void)0 : \
   __DISSECTOR_ASSERT_CMPINT (a, op, b, int64_t, "%" PRId64))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(a op b)

/** Like DISSECTOR_ASSERT_CMPINT() except the arguments are treated as
 * unsigned values.
 *
 * This function can currently compare values that fit inside a guint64.
 */
#define DISSECTOR_ASSERT_CMPUINT(a, op, b)  \
  ((void) ((a op b) ? (void)0 : \
   __DISSECTOR_ASSERT_CMPINT (a, op, b, uint64_t, "%" PRIu64))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(a op b)

/** Like DISSECTOR_ASSERT_CMPUINT() except the values are displayed in
 * hexadecimal upon assertion failure.
 */
#define DISSECTOR_ASSERT_CMPUINTHEX(a, op, b)  \
  ((void) ((a op b) ? (void)0 : \
   __DISSECTOR_ASSERT_CMPINT (a, op, b, uint64_t, "0x%" PRIX64))) \
  __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(a op b)

/*
 * This is similar to DISSECTOR_ASSERT(hfinfo->type == type) except that
 * it will report the name of the field with the wrong type as well as
 * the type.
 *
 * @param hfinfo  The hfinfo for the field being tested
 * @param type    The type it's expected to have
 */
#define __DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, t) \
  (REPORT_DISSECTOR_BUG("%s:%u: field %s is not of type "#t, \
        __FILE__, __LINE__, (hfinfo)->abbrev))

#define DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, t)  \
  ((void) (((hfinfo)->type == t) ? (void)0 : \
   __DISSECTOR_ASSERT_FIELD_TYPE ((hfinfo), t))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT((hfinfo)->type == t)

#define DISSECTOR_ASSERT_FIELD_TYPE_IS_INTEGRAL(hfinfo)  \
  ((void) ((IS_FT_INT((hfinfo)->type) || \
            IS_FT_UINT((hfinfo)->type)) ? (void)0 : \
   REPORT_DISSECTOR_BUG("%s:%u: field %s is not of type FT_CHAR or an FT_{U}INTn type", \
         __FILE__, __LINE__, (hfinfo)->abbrev))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(IS_FT_INT((hfinfo)->type) || \
                                           IS_FT_UINT((hfinfo)->type))

#define __DISSECTOR_ASSERT_FIELD_TYPE_IS_STRING(hfinfo) \
  (REPORT_DISSECTOR_BUG("%s:%u: field %s is not of type FT_STRING, FT_STRINGZ, FT_STRINGZPAD, or FT_STRINGZTRUNC", \
        __FILE__, __LINE__, (hfinfo)->abbrev))

#define DISSECTOR_ASSERT_FIELD_TYPE_IS_STRING(hfinfo)  \
  ((void) (IS_FT_STRING((hfinfo)->type) ? (void)0 : \
   __DISSECTOR_ASSERT_FIELD_TYPE_IS_STRING ((hfinfo)))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(IS_FT_STRING((hfinfo)->type))

#define __DISSECTOR_ASSERT_FIELD_TYPE_IS_TIME(hfinfo) \
  (REPORT_DISSECTOR_BUG("%s:%u: field %s is not of type FT_ABSOLUTE_TIME or FT_RELATIVE_TIME", \
        __FILE__, __LINE__, (hfinfo)->abbrev))

#define DISSECTOR_ASSERT_FIELD_TYPE_IS_TIME(hfinfo)  \
  ((void) (((hfinfo)->type == FT_ABSOLUTE_TIME || \
            (hfinfo)->type == FT_RELATIVE_TIME) ? (void)0 : \
   __DISSECTOR_ASSERT_FIELD_TYPE_IS_TIME ((hfinfo)))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT((hfinfo)->type == FT_ABSOLUTE_TIME || \
                                           (hfinfo)->type == FT_RELATIVE_TIME)

/*
 * Encoding flags that apply to multiple data types.
 */
/*
 * The encoding of a field of a particular type may involve more
 * than just whether it's big-endian or little-endian and its size.
 *
 * For integral values, that's it, as 99.9999999999999% of the machines
 * out there are 2's complement binary machines with 8-bit bytes,
 * so the protocols out there expect that and, for example, any Unisys
 * 2200 series machines out there just have to translate between 2's
 * complement and 1's complement (and nobody's put any IBM 709x's on
 * any networks lately :-)).
 *
 * However:
 *
 *  for floating-point numbers, in addition to IEEE decimal
 *  floating-point, there's also IBM System/3x0 and PDP-11/VAX
 *  floating-point - most protocols use IEEE binary, but DCE RPC
 *  can use other formats if that's what the sending host uses;
 *
 *  for character strings, there are various character encodings
 *  (various ISO 646 sets, ISO 8859/x, various other national
 *  standards, various DOS and Windows encodings, various Mac
 *  encodings, UTF-8, UTF-16, other extensions to ASCII, EBCDIC,
 *  etc.);
 *
 *  for absolute times, there's UNIX time_t, UNIX time_t followed
 *  by 32-bit microseconds, UNIX time_t followed by 32-bit
 *  nanoseconds, DOS date/time, Windows FILETIME, NTP time, etc..
 *
 * We might also, in the future, want to allow a field specifier to
 * indicate the encoding of the field, or at least its default
 * encoding, as most fields in most protocols always use the
 * same encoding (although that's not true of all fields, so we
 * still need to be able to specify that at run time).
 *
 * So, for now, we define ENC_BIG_ENDIAN and ENC_LITTLE_ENDIAN as
 * bit flags, to be combined, in the future, with other information
 * to specify the encoding in the last argument to
 * proto_tree_add_item(), and possibly to specify in a field
 * definition (e.g., ORed in with the type value).
 *
 * Currently, proto_tree_add_item() treats its last argument as a
 * Boolean - if it's zero, the field is big-endian, and if it's non-zero,
 * the field is little-endian - and other code in epan/proto.c does
 * the same.  We therefore define ENC_BIG_ENDIAN as 0x00000000 and
 * ENC_LITTLE_ENDIAN as 0x80000000 - we're using the high-order bit
 * so that we could put a field type and/or a value such as a character
 * encoding in the lower bits.
 */
#define ENC_BIG_ENDIAN      0x00000000
#define ENC_LITTLE_ENDIAN   0x80000000

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    #define ENC_HOST_ENDIAN      ENC_LITTLE_ENDIAN
    #define ENC_ANTI_HOST_ENDIAN ENC_BIG_ENDIAN
#else
    #define ENC_HOST_ENDIAN      ENC_BIG_ENDIAN
    #define ENC_ANTI_HOST_ENDIAN ENC_LITTLE_ENDIAN
#endif

/*
 * For protocols (FT_PROTOCOL), aggregate items with subtrees (FT_NONE),
 * opaque byte-array fields (FT_BYTES), and other fields where there
 * is no choice of encoding (either because it's "just a bucket
 * of bytes" or because the encoding is completely fixed), we
 * have ENC_NA (for "Not Applicable").
 */
#define ENC_NA          0x00000000

/*
 * Encoding for character strings - and for character-encoded values
 * for non-string types.
 *
 * Historically, the only place the representation mattered for strings
 * was with FT_UINT_STRINGs, where we had FALSE for the string length
 * being big-endian and TRUE for it being little-endian.
 *
 * We now have encoding values for the character encoding.  The encoding
 * values are encoded in all but the top bit (which is the byte-order
 * bit, required for FT_UINT_STRING and for UCS-2 and UTF-16 strings)
 * and the bottom bit (which we ignore for now so that programs that
 * pass TRUE for the encoding just do ASCII).  (The encodings are given
 * directly as even numbers in hex, so that make-init-lua.py can just
 * turn them into numbers for use in init.lua.)
 *
 * We don't yet process ASCII and UTF-8 differently.  Ultimately, for
 * ASCII, all bytes with the 8th bit set should be mapped to some "this
 * is not a valid character" code point, as ENC_ASCII should mean "this
 * is ASCII, not some extended variant thereof".  We should also map
 * 0x00 to that as well - null-terminated and null-padded strings
 * never have NULs in them, but counted strings might.  (Either that,
 * or the values for strings should be counted, not null-terminated.)
 * For UTF-8, invalid UTF-8 sequences should be mapped to the same
 * code point.
 *
 * For display, perhaps we should also map control characters to the
 * Unicode glyphs showing the name of the control character in small
 * caps, diagonally.  (Unfortunately, those only exist for C0, not C1.)
 *
 * *DO NOT* add anything to this set that is not a character encoding!
 */
#define ENC_CHARENCODING_MASK             0x0000FFFE  /* mask out byte-order bits and other bits used with string encodings */
#define ENC_ASCII                         0x00000000
#define ENC_ISO_646_IRV                   ENC_ASCII   /* ISO 646 International Reference Version = ASCII */
#define ENC_UTF_8                         0x00000002
#define ENC_UTF_16                        0x00000004
#define ENC_UCS_2                         0x00000006
#define ENC_UCS_4                         0x00000008
#define ENC_ISO_8859_1                    0x0000000A
#define ENC_ISO_8859_2                    0x0000000C
#define ENC_ISO_8859_3                    0x0000000E
#define ENC_ISO_8859_4                    0x00000010
#define ENC_ISO_8859_5                    0x00000012
#define ENC_ISO_8859_6                    0x00000014
#define ENC_ISO_8859_7                    0x00000016
#define ENC_ISO_8859_8                    0x00000018
#define ENC_ISO_8859_9                    0x0000001A
#define ENC_ISO_8859_10                   0x0000001C
#define ENC_ISO_8859_11                   0x0000001E
/* #define ENC_ISO_8859_12                  0x00000020 ISO 8859-12 was abandoned */
#define ENC_ISO_8859_13                   0x00000022
#define ENC_ISO_8859_14                   0x00000024
#define ENC_ISO_8859_15                   0x00000026
#define ENC_ISO_8859_16                   0x00000028
#define ENC_WINDOWS_1250                  0x0000002A
#define ENC_3GPP_TS_23_038_7BITS_PACKED   0x0000002C
#define ENC_3GPP_TS_23_038_7BITS          ENC_3GPP_TS_23_038_7BITS_PACKED
#define ENC_EBCDIC                        0x0000002E
#define ENC_MAC_ROMAN                     0x00000030
#define ENC_CP437                         0x00000032
#define ENC_ASCII_7BITS                   0x00000034
#define ENC_T61                           0x00000036
#define ENC_EBCDIC_CP037                  0x00000038
#define ENC_WINDOWS_1252                  0x0000003A
#define ENC_WINDOWS_1251                  0x0000003C
#define ENC_CP855                         0x0000003E
#define ENC_CP866                         0x00000040
#define ENC_ISO_646_BASIC                 0x00000042
#define ENC_BCD_DIGITS_0_9                0x00000044 /* Packed BCD, digits 0-9 */
#define ENC_KEYPAD_ABC_TBCD               0x00000046 /* Keypad-with-a/b/c "telephony BCD" = 0-9, *, #, a, b, c */
#define ENC_KEYPAD_BC_TBCD                0x00000048 /* Keypad-with-B/C "telephony BCD" = 0-9, B, C, *, # */
#define ENC_3GPP_TS_23_038_7BITS_UNPACKED 0x0000004C
#define ENC_ETSI_TS_102_221_ANNEX_A       0x0000004E /* ETSI TS 102 221 Annex A */
#define ENC_GB18030                       0x00000050
#define ENC_EUC_KR                        0x00000052
#define ENC_APN_STR                       0x00000054 /* The encoding the APN/DNN field follows 3GPP TS 23.003 [2] clause 9.1.*/
/*
 * TODO:
 *
 * packet-bacapp.c refers to two currently unsupported character sets (where
 * we just use ASCII currently):
 *
 *  "IBM MS DBCS" - At the very least could be any IBM/MS Double Byte
 *      Character Set for CJK (4 major ones), but also could just be any non
 *      Unicode and non ISO-8859-1 code page. This would be supported via the
 *      various code pages.
 *  JIS C 6226 / JIS X 0206 - Does this refer to ISO-2022-JP, SHIFT-JIS, or
 *      EUC-JP, which are all encoding schemes that support the JIS X 0206
 *      character set?
 *
 * As those are added, change code such as the code in packet-bacapp.c
 * to use them.
 *
 * There's also some other code (e.g., packet-smpp.c) that just ignores
 * strings if it determines that they are in an unsupported encoding, such
 * as various encodings of Japanese mentioned above, for example.
 *
 */

/*
 * This is a modifier for FT_UINT_STRING and FT_UINT_BYTES values;
 * it indicates that the length field should be interpreted as per
 * sections 2.5.2.11 Octet String through 2.5.2.14 Long Character
 * String of the ZigBee Cluster Library Specification, where if all
 * bits are set in the length field, the string has an invalid value,
 * and the number of octets in the value is 0.
 */
#define ENC_ZIGBEE               0x40000000

/*
 * For cases where either native type or string encodings could both be
 * valid arguments, we need something to distinguish which one is being
 * passed as the argument, because ENC_BIG_ENDIAN and ENC_ASCII are both
 * 0x00000000. So we use ENC_STR_NUM or ENC_STR_HEX bit-or'ed with
 * ENC_ASCII and its ilk.
 *
 * XXX - ENC_STR_NUM is not yet supported by any code in Wireshark,
 * and these are aonly used for byte arrays.  Presumably they could
 * also be used for integral values in the future.
 */
/* this is for strings as numbers "12345" */
#define ENC_STR_NUM     0x01000000
/* this is for strings as hex "1a2b3c" */
#define ENC_STR_HEX     0x02000000
/* a convenience macro for either of the above */
#define ENC_STRING      0x03000000
/* Kept around for compatibility for Lua scripts; code should use ENC_CHARENCODING_MASK */
#define ENC_STR_MASK    0x0000FFFE

/*
 * For cases where the number is allowed to have a leading '+'/'-'
 * this can't collide with ENC_SEP_* because they can be used simultaneously
 *
 * XXX - this is not used anywhere in Wireshark's code, dating back to
 * at least Wireshark 2.6 and continuing to the current version.
 * Perhaps the intent was to use it in the future, but 1) I'm not sure
 * why it would be combined with ENC_SEP_, as byte arrays have no sign
 * but integral values do, and 2) if we were to support string encodings
 * for integral types, presumably whether it's signed (FT_INTn) or
 * unsigned (FT_UINTn) would suffice to indicate whether the value
 * can be signed or not.
 */
#define ENC_NUM_PREF    0x00200000

/*
 * Encodings for byte arrays.
 *
 * For cases where the byte array is encoded as a string composed of
 * pairs of hex digits, possibly with a separator character between
 * the pairs.  That's specified by the encoding having ENC_STR_HEX,
 * plus one of these values, set.
 *
 * See hex_str_to_bytes_encoding() in epan/strutil.h for details.
 */
#define ENC_SEP_NONE    0x00010000
#define ENC_SEP_COLON   0x00020000
#define ENC_SEP_DASH    0x00040000
#define ENC_SEP_DOT     0x00080000
#define ENC_SEP_SPACE   0x00100000
/* a convenience macro for the above */
#define ENC_SEP_MASK    0x001F0000

/* Encodings for BCD strings
 * Depending if the BCD string has even or odd number of digits
 * we may need to strip of the last digit/High nibble
 */
#define ENC_BCD_ODD_NUM_DIG     0x00010000
#define ENC_BCD_SKIP_FIRST      0x00020000
 /*
 * Encodings for time values.
 *
 * Historically FT_TIMEs were only timespecs; the only question was whether
 * they were stored in big- or little-endian format.
 *
 * For backwards compatibility, we interpret an encoding of 1 as meaning
 * "little-endian timespec", so that passing TRUE is interpreted as that.
 *
 * We now support:
 *
 *  ENC_TIME_SECS_NSECS - 8, 12, or 16 bytes.  For 8 bytes, the first 4
 *  bytes are seconds and the next 4 bytes are nanoseconds; for 12 bytes,
 *  the first 8 bytes are seconds and the next 4 bytes are nanoseconds;
 *  for 16 bytes, the first 8 bytes are seconds and the next 8 bytes are
 *  nanoseconds.  If the time is absolute, the seconds are seconds since
 *  the UN*X epoch (1970-01-01 00:00:00 UTC).  (I.e., a UN*X struct
 *  timespec with a 4-byte or 8-byte time_t or a structure with an
 *  8-byte time_t and an 8-byte nanoseconds field.)
 *
 *  ENC_TIME_NTP - 8 bytes; the first 4 bytes are seconds since the NTP
 *  epoch (1900-01-01 00:00:00 GMT) and the next 4 bytes are 1/2^32's of
 *  a second since that second.  (I.e., a 64-bit count of 1/2^32's of a
 *  second since the NTP epoch, with the upper 32 bits first and the
 *  lower 32 bits second, even when little-endian.)
 *
 *  ENC_TIME_TOD - 8 bytes, as a count of microseconds since the System/3x0
 *  and z/Architecture epoch (1900-01-01 00:00:00 GMT).
 *
 *  ENC_TIME_RTPS - 8 bytes; the first 4 bytes are seconds since the UN*X
 *  epoch and the next 4 bytes are 1/2^32's of a second since that
 *  second.  (I.e., it's the offspring of a mating between UN*X time and
 *  NTP time).  It's used by the Object Management Group's Real-Time
 *  Publish-Subscribe Wire Protocol for the Data Distribution Service.
 *
 *  ENC_TIME_SECS_USECS - 8 bytes; the first 4 bytes are seconds and the
 *  next 4 bytes are microseconds.  If the time is absolute, the seconds
 *  are seconds since the UN*X epoch.  (I.e., a UN*X struct timeval with
 *  a 4-byte time_t.)
 *
 *  ENC_TIME_SECS - 4 to 8 bytes, representing a value in seconds.
 *  If the time is absolute, it's seconds since the UN*X epoch.
 *
 *  ENC_TIME_MSECS - 6 to 8 bytes, representing a value in milliseconds.
 *  If the time is absolute, it's milliseconds since the UN*X epoch.
 *
 *  ENC_TIME_USECS - 8 bytes, representing a value in microseconds.
 *  If the time is absolute, it's microseconds since the UN*X epoch.
 *
 *  ENC_TIME_NSECS - 8 bytes, representing a value in nanoseconds.
 *  If the time is absolute, it's nanoseconds since the UN*X epoch.
 *
 *  ENC_TIME_SECS_NTP - 4 bytes, representing a count of seconds since
 *  the NTP epoch.
 *
 *  ENC_TIME_RFC_3971 - 8 bytes, representing a count of 1/64ths of a
 *  second since the UN*X epoch; see section 5.3.1 "Timestamp Option"
 *  in RFC 3971.
 *
 *  ENC_TIME_MSEC_NTP - 4-8 bytes, representing a count of milliseconds since
 *  the NTP epoch.
 *
 *  ENC_TIME_MIP6 - 8 bytes; the first 48 bits are seconds since the UN*X epoch
 *  and the remaining 16 bits indicate the number of 1/65536's of a second
 *  since that second.
 *
 *  ENC_TIME_CLASSIC_MAC_OS_SECS - 4-8 bytes, representing a count of seconds
 *  since January 1, 1904, 00:00:00 UTC.
 *
 * The backwards-compatibility names are defined as hex numbers so that
 * the script to generate init.lua will add them as global variables,
 * along with the new names.
 */
#define ENC_TIME_SECS_NSECS          0x00000000
#define ENC_TIME_TIMESPEC            0x00000000 /* for backwards source compatibility */
#define ENC_TIME_NTP                 0x00000002
#define ENC_TIME_TOD                 0x00000004
#define ENC_TIME_RTPS                0x00000008
#define ENC_TIME_NTP_BASE_ZERO       0x00000008 /* for backwards source compatibility */
#define ENC_TIME_SECS_USECS          0x00000010
#define ENC_TIME_TIMEVAL             0x00000010 /* for backwards source compatibility */
#define ENC_TIME_SECS                0x00000012
#define ENC_TIME_MSECS               0x00000014
#define ENC_TIME_SECS_NTP            0x00000018
#define ENC_TIME_RFC_3971            0x00000020
#define ENC_TIME_MSEC_NTP            0x00000022
#define ENC_TIME_MIP6                0x00000024
#define ENC_TIME_CLASSIC_MAC_OS_SECS 0x00000026
#define ENC_TIME_NSECS               0x00000028
#define ENC_TIME_USECS               0x00000030

/*
 * For cases where a string encoding contains a timestamp, use one
 * of these (but only one). These values can collide with the ENC_SEP_
 * values used when a string encoding contains a byte array, because
 * you can't do both at the same time.  They must not, however,
 * overlap with the character encoding values.
 */
#define ENC_ISO_8601_DATE             0x00010000
#define ENC_ISO_8601_TIME             0x00020000
#define ENC_ISO_8601_DATE_TIME        0x00030000
#define ENC_RFC_822                   0x00040000
#define ENC_RFC_1123                  0x00080000
#define ENC_ISO_8601_DATE_TIME_BASIC  0x00100000
/* a convenience macro for the above - for internal use only */
#define ENC_STR_TIME_MASK             0x001F0000

/*
 * Encodings for variable-length integral types.
 */

/* Use varint format as described in Protobuf protocol
 * https://developers.google.cn/protocol-buffers/docs/encoding
 */
#define ENC_VARINT_PROTOBUF      0x00000002
/*
 * Decodes a variable-length integer used in QUIC protocol
 * See https://tools.ietf.org/html/draft-ietf-quic-transport-08#section-8.1
 */
#define ENC_VARINT_QUIC          0x00000004
 /*
 * Use "zig-zag" varint format as described in Protobuf protocol
 * See https://developers.google.com/protocol-buffers/docs/encoding?csw=1#types
 */
#define ENC_VARINT_ZIGZAG        0x00000008

#define ENC_VARINT_MASK          (ENC_VARINT_PROTOBUF|ENC_VARINT_QUIC|ENC_VARINT_ZIGZAG)

/* Values for header_field_info.display */

/* For integral types, the display format is a BASE_* field_display_e value
 * possibly ORed with BASE_*_STRING */

/** FIELD_DISPLAY_E_MASK selects the field_display_e value. */
#define FIELD_DISPLAY_E_MASK 0xFF

/*
 * Note that this enum values are parsed in make-init-lua.py so make sure
 * any changes here still makes valid entries in init.lua.
 * XXX The script requires the equals sign.
 */
typedef enum {
    BASE_NONE    = 0,   /**< none */

/* Integral types */
    BASE_DEC     = 1,   /**< decimal */
    BASE_HEX     = 2,   /**< hexadecimal */
    BASE_OCT     = 3,   /**< octal */
    BASE_DEC_HEX = 4,   /**< decimal (hexadecimal) */
    BASE_HEX_DEC = 5,   /**< hexadecimal (decimal) */
    BASE_CUSTOM  = 6,   /**< call custom routine (in ->strings) to format */

/* Float types */
    BASE_FLOAT   = BASE_NONE, /**< decimal-format float */

/* Byte separators */
    SEP_DOT      = 8,   /**< hexadecimal bytes with a period (.) between each byte */
    SEP_DASH     = 9,   /**< hexadecimal bytes with a dash (-) between each byte */
    SEP_COLON    = 10,  /**< hexadecimal bytes with a colon (:) between each byte */
    SEP_SPACE    = 11,  /**< hexadecimal bytes with a space between each byte */

/* Address types */
    BASE_NETMASK = 12,  /**< Used for IPv4 address that shouldn't be resolved (like for netmasks) */

/* Port types */
    BASE_PT_UDP  = 13,  /**< UDP port */
    BASE_PT_TCP  = 14,  /**< TCP port */
    BASE_PT_DCCP = 15,  /**< DCCP port */
    BASE_PT_SCTP = 16,  /**< SCTP port */

/* OUI types */
    BASE_OUI     = 17,  /**< OUI resolution */

/* Time types */
    ABSOLUTE_TIME_LOCAL   = 18,     /**< local time in our time zone, with month and day */
    ABSOLUTE_TIME_UTC     = 19,     /**< UTC, with month and day */
    ABSOLUTE_TIME_DOY_UTC = 20,     /**< UTC, with 1-origin day-of-year */
    ABSOLUTE_TIME_NTP_UTC = 21,     /**< UTC, with "NULL" when timestamp is all zeros */
} field_display_e;

#define FIELD_DISPLAY(d) ((d) & FIELD_DISPLAY_E_MASK)

#define FIELD_DISPLAY_IS_ABSOLUTE_TIME(d) \
        (FIELD_DISPLAY(d) >= ABSOLUTE_TIME_LOCAL && FIELD_DISPLAY(d) <= ABSOLUTE_TIME_NTP_UTC)

/* Following constants have to be ORed with a field_display_e when dissector
 * want to use specials value-string MACROs for a header_field_info */
#define BASE_RANGE_STRING         0x00000100  /**< Use the supplied range string to convert the field to text */
#define BASE_EXT_STRING           0x00000200
#define BASE_VAL64_STRING         0x00000400

#define BASE_ALLOW_ZERO           0x00000800  /**< Display `<none>` instead of `<MISSING>` for zero sized byte array */

#define BASE_UNIT_STRING          0x00001000  /**< Add unit text to the field value */

#define BASE_NO_DISPLAY_VALUE     0x00002000  /**< Just display the field name with no value.  Intended for
                                                   byte arrays or header fields above a subtree */

#define BASE_PROTOCOL_INFO        0x00004000  /**< protocol_t in [FIELDCONVERT].  Internal use only. */

#define BASE_SPECIAL_VALS         0x00008000  /**< field will not display "Unknown" if value_string match is not found */

#define BASE_SHOW_ASCII_PRINTABLE 0x00010000 /**< show byte array as ASCII if it's all printable characters */

#define BASE_SHOW_UTF_8_PRINTABLE 0x00020000 /**< show byte array as UTF-8 if it's all valid and printable UTF-8 characters */

/** BASE_ values that cause the field value to be displayed twice */
#define IS_BASE_DUAL(b) ((b)==BASE_DEC_HEX||(b)==BASE_HEX_DEC)

/** BASE_PT_ values display decimal and transport port service name */
#define IS_BASE_PORT(b) (((b)==BASE_PT_UDP||(b)==BASE_PT_TCP||(b)==BASE_PT_DCCP||(b)==BASE_PT_SCTP))

typedef enum {
    HF_REF_TYPE_NONE,       /**< Field is not referenced */
    HF_REF_TYPE_INDIRECT,   /**< Field is indirectly referenced (only applicable for FT_PROTOCOL) via. its child */
    HF_REF_TYPE_DIRECT      /**< Field is directly referenced */
} hf_ref_type;

/** information describing a header field */
typedef struct _header_field_info header_field_info;

/** information describing a header field */
struct _header_field_info {
    /* ---------- set by dissector --------- */
    const char        *name;              /**< [FIELDNAME] full name of this field */
    const char        *abbrev;            /**< [FIELDFILTERNAME] filter name of this field */
    enum ftenum        type;              /**< [FIELDTYPE] field type, one of FT_ (from ftypes.h) */
    int                display;           /**< [FIELDDISPLAY] one of BASE_, or field bit-width if FT_BOOLEAN and non-zero bitmask */
    const void        *strings;           /**< [FIELDCONVERT] value_string, val64_string, range_string or true_false_string,
                                               typically converted by VALS(), RVALS() or TFS().
                                               If this is an FT_PROTOCOL or BASE_PROTOCOL_INFO then it points to the
                                               associated protocol_t structure */
    guint64            bitmask;           /**< [BITMASK] bitmask of interesting bits */
    const char        *blurb;             /**< [FIELDDESCR] Brief description of field */

    /* ------- set by proto routines (prefilled by HFILL macro, see below) ------ */
    int                id;                /**< Field ID */
    int                parent;            /**< parent protocol tree */
    hf_ref_type        ref_type;          /**< is this field referenced by a filter */
    int                same_name_prev_id; /**< ID of previous hfinfo with same abbrev */
    header_field_info *same_name_next;    /**< Link to next hfinfo with same abbrev */
};

/**
 * HFILL initializes all the "set by proto routines" fields in a
 * _header_field_info. If new fields are added or removed, it should
 * be changed as necessary.
 */
#define HFILL -1, 0, HF_REF_TYPE_NONE, -1, NULL

#define HFILL_INIT(hf)   \
    (hf).hfinfo.id                = -1;   \
    (hf).hfinfo.parent            = 0;   \
    (hf).hfinfo.ref_type          = HF_REF_TYPE_NONE;   \
    (hf).hfinfo.same_name_prev_id = -1;   \
    (hf).hfinfo.same_name_next    = NULL;

/** Used when registering many fields at once, using proto_register_field_array() */
typedef struct hf_register_info {
    int               *p_id;   /**< written to by register() function */
    header_field_info  hfinfo; /**< the field info to be registered */
} hf_register_info;

/** string representation, if one of the proto_tree_add_..._format() functions used */
typedef struct _item_label_t {
    char representation[ITEM_LABEL_LENGTH];
} item_label_t;

/** Contains the field information for the proto_item. */
typedef struct field_info {
    header_field_info   *hfinfo;          /**< pointer to registered field information */
    gint                 start;           /**< current start of data in field_info.ds_tvb */
    gint                 length;          /**< current data length of item in field_info.ds_tvb */
    gint                 appendix_start;  /**< start of appendix data */
    gint                 appendix_length; /**< length of appendix data */
    gint                 tree_type;       /**< one of ETT_ or -1 */
    guint32              flags;           /**< bitfield like FI_GENERATED, ... */
    item_label_t        *rep;             /**< string for GUI tree */
    tvbuff_t            *ds_tvb;          /**< data source tvbuff */
    fvalue_t             value;
    int                 total_layer_num;        /**< Hierarchical layer number, for all protocols in the tree. */
    int                 proto_layer_num;        /**< Protocol layer number, so 1st, 2nd, 3rd, ... for protocol X. */
} field_info;


/*
 * This structure describes one segment of a split-bits item
 * crumb_bit_offset is the bit offset in the input tvb of the first (most significant) bit of this crumb
 * crumb_bit_length is the number of contiguous bits of this crumb.
 * The first element of an array of bits_specs describes the most significant crumb of the output value.
 * The second element of an array of bits_specs describes the next-most significant crumb of the output value, etc.
 * The array is terminated by a sentinel entry with crumb_bit_length of 0.
*/
typedef struct
{
    guint  crumb_bit_offset;
    guint8 crumb_bit_length;
} crumb_spec_t;

/*
 * Flag fields.  Do not assign values greater than 0x000FFFFF unless you
 * shuffle the expert information upward; see below.
 */

/** The protocol field should not be shown in the tree (it's used for filtering only),
 * used in field_info.flags. */
/** HIDING PROTOCOL FIELDS IS DEPRECATED, IT'S CONSIDERED TO BE BAD GUI DESIGN!
   A user cannot tell by looking at the packet detail that the field exists
   and that they can filter on its value. */
#define FI_HIDDEN               0x00000001
/** The protocol field should be displayed as "generated by Wireshark",
 * used in field_info.flags. */
#define FI_GENERATED            0x00000002
/** The protocol field is actually a URL */
#define FI_URL                  0x00000004

/** The protocol field value is in little endian */
#define FI_LITTLE_ENDIAN        0x00000008
/** The protocol field value is in big endian */
#define FI_BIG_ENDIAN           0x00000010
/** Field value start from nth bit (values from 0x20 - 0x100) */
#define FI_BITS_OFFSET(n)       (((n) & 7) << 5)
/** Field value takes n bits (values from 0x100 - 0x4000) */
/* if 0, it means that field takes fi->length * 8 */
#define FI_BITS_SIZE(n)         (((n) & 63) << 8)
/** The protocol field value is a varint */
#define FI_VARINT               0x00004000

/** convenience macro to get field_info.flags */
#define FI_GET_FLAG(fi, flag)   ((fi) ? ((fi)->flags & (flag)) : 0)
/** convenience macro to set field_info.flags */
#define FI_SET_FLAG(fi, flag) \
    do { \
      if (fi) \
        (fi)->flags = (fi)->flags | (flag); \
    } while(0)
/** convenience macro to reset field_info.flags */
#define FI_RESET_FLAG(fi, flag) \
    do { \
      if (fi) \
        (fi)->flags = (fi)->flags & ~(flag); \
    } while(0)

#define FI_GET_BITS_OFFSET(fi) (FI_GET_FLAG(fi, FI_BITS_OFFSET(7)) >> 5)
#define FI_GET_BITS_SIZE(fi)   (FI_GET_FLAG(fi, FI_BITS_SIZE(63)) >> 8)

/** One of these exists for the entire protocol tree. Each proto_node
 * in the protocol tree points to the same copy. */
typedef struct {
    GHashTable          *interesting_hfids;
    gboolean             visible;
    gboolean             fake_protocols;
    guint                count;
    struct _packet_info *pinfo;
} tree_data_t;

/** Each proto_tree, proto_item is one of these. */
typedef struct _proto_node {
    struct _proto_node *first_child;
    struct _proto_node *last_child;
    struct _proto_node *next;
    struct _proto_node *parent;
    field_info         *finfo;
    tree_data_t        *tree_data;
} proto_node;

/** A protocol tree element. */
typedef proto_node proto_tree;
/** A protocol item element. */
typedef proto_node proto_item;

/*
 * Expert information.
 * This is in the flags field; we allocate this from the top down,
 * so as not to collide with FI_ flags, which are allocated from
 * the bottom up.
 */

/* do not modify the PI_SEVERITY_MASK name - it's used by make-init-lua.py */
/* expert severities */
#define PI_SEVERITY_MASK        0x00F00000  /**< mask usually for internal use only! */
/** Packet comment */
#define PI_COMMENT              0x00100000
/** Usual workflow, e.g. TCP connection establishing */
#define PI_CHAT                 0x00200000
/** Notable messages, e.g. an application returned an "unusual" error code like HTTP 404 */
#define PI_NOTE                 0x00400000
/** Warning, e.g. application returned an "unusual" error code */
#define PI_WARN                 0x00600000
/** Serious problems, e.g. a malformed packet */
#define PI_ERROR                0x00800000

/* do not modify the PI_GROUP_MASK name - it's used by make-init-lua.py */
/* expert "event groups" */
#define PI_GROUP_MASK           0xFF000000  /**< mask usually for internal use only! */
/** The protocol field has a bad checksum, usually uses PI_WARN severity */
#define PI_CHECKSUM             0x01000000
/** The protocol field indicates a sequence problem (e.g. TCP window is zero) */
#define PI_SEQUENCE             0x02000000
/** The protocol field indicates a bad application response code (e.g. HTTP 404), usually PI_NOTE severity */
#define PI_RESPONSE_CODE        0x03000000
/** The protocol field indicates an application request (e.g. File Handle == xxxx), usually PI_CHAT severity */
#define PI_REQUEST_CODE         0x04000000
/** The data is undecoded, the protocol dissection is incomplete here, usually PI_WARN severity */
#define PI_UNDECODED            0x05000000
/** The protocol field indicates a reassemble (e.g. DCE/RPC defragmentation), usually PI_CHAT severity (or PI_ERROR) */
#define PI_REASSEMBLE           0x06000000
/** The packet data is malformed, the dissector has "given up", usually PI_ERROR severity */
#define PI_MALFORMED            0x07000000
/** A generic debugging message (shouldn't remain in production code!), usually PI_ERROR severity */
#define PI_DEBUG                0x08000000
/** The protocol field violates a protocol specification, usually PI_WARN severity */
#define PI_PROTOCOL             0x09000000
/** The protocol field indicates a security problem (e.g. insecure implementation) */
#define PI_SECURITY             0x0a000000
/** The protocol field indicates a packet comment */
#define PI_COMMENTS_GROUP       0x0b000000
/** The protocol field indicates a decryption problem */
#define PI_DECRYPTION           0x0c000000
/** The protocol field has incomplete data, decode based on assumed value */
#define PI_ASSUMPTION           0x0d000000
/** The protocol field has been deprecated, usually PI_NOTE severity */
#define PI_DEPRECATED           0x0e000000

/*
 * add more, see
 *    https://gitlab.com/wireshark/wireshark/-/wikis/Development/ExpertInfo
 */

/** Retrieve the field_info from a proto_node */
#define PNODE_FINFO(proto_node)  ((proto_node)->finfo)

/** Retrieve the field_info from a proto_item */
#define PITEM_FINFO(proto_item)  PNODE_FINFO(proto_item)

/** Retrieve the field_info from a proto_tree */
#define PTREE_FINFO(proto_tree)  PNODE_FINFO(proto_tree)

/** Retrieve the tree_data_t from a proto_tree */
#define PTREE_DATA(proto_tree)   ((proto_tree)->tree_data)

/** Retrieve the wmem_allocator_t from a proto_node */
#define PNODE_POOL(proto_node)   ((proto_node)->tree_data->pinfo->pool)

/** Is this protocol field hidden from the protocol tree display? Used for filtering only.
 * Use with caution, HIDING PROTOCOL FIELDS IS CONSIDERED TO BE BAD GUI DESIGN!
 * @param ti The item to check. May be NULL.
 * @return TRUE if the item is hidden, FALSE otherwise.
 */
static inline gboolean proto_item_is_hidden(proto_item *ti) {
    if (ti) {
        return FI_GET_FLAG(PITEM_FINFO(ti), FI_HIDDEN);
    }
    return FALSE;
}
#define PROTO_ITEM_IS_HIDDEN(ti) proto_item_is_hidden((ti))

/** Mark this protocol field to be hidden from the protocol tree display. Used for filtering only.
 * Use with caution, HIDING PROTOCOL FIELDS IS CONSIDERED TO BE BAD GUI DESIGN!
 * @param ti The item to hide. May be NULL.
 */
static inline void proto_item_set_hidden(proto_item *ti) {
    if (ti) {
        FI_SET_FLAG(PITEM_FINFO(ti), FI_HIDDEN);
    }
}
#define PROTO_ITEM_SET_HIDDEN(ti) proto_item_set_hidden((ti))

/** Mark this protocol field to be visible from the protocol tree display.
 * @param ti The item to hide. May be NULL.
 */
static inline void proto_item_set_visible(proto_item *ti) {
    if (ti) {
        FI_RESET_FLAG(PITEM_FINFO(ti), FI_HIDDEN);
    }
}
#define PROTO_ITEM_SET_VISIBLE(ti) proto_item_set_visible((ti))

/** Is this protocol field generated by Wireshark (and not read from the packet data)?
 * @param ti The item to check. May be NULL.
 * @return TRUE if the item is generated, FALSE otherwise.
 */
static inline gboolean proto_item_is_generated(proto_item *ti) {
    if (ti) {
        return FI_GET_FLAG(PITEM_FINFO(ti), FI_GENERATED);
    }
    return FALSE;
}
#define PROTO_ITEM_IS_GENERATED(ti) proto_item_is_generated((ti))

/** Mark this protocol field as generated by Wireshark (and not read from the packet data).
 * @param ti The item to mark as generated. May be NULL.
 */
static inline void proto_item_set_generated(proto_item *ti) {
    if (ti) {
        FI_SET_FLAG(PITEM_FINFO(ti), FI_GENERATED);
    }
}
#define PROTO_ITEM_SET_GENERATED(ti) proto_item_set_generated((ti))

/** Is this protocol field actually a URL?
 * @brief proto_item_is_url
 * @param ti The item to check. May be NULL.
 * @return TRUE if the item is a URL, FALSE otherwise.
 */
static inline gboolean proto_item_is_url(proto_item *ti) {
    if (ti) {
        return FI_GET_FLAG(PITEM_FINFO(ti), FI_URL);
    }
    return FALSE;
}
#define PROTO_ITEM_IS_URL(ti) proto_item_is_url((ti))

/** Mark this protocol field as a URL
 * @param ti The item to mark as a URL. May be NULL.
 */
static inline void proto_item_set_url(proto_item *ti) {
    if (ti) {
        FI_SET_FLAG(PITEM_FINFO(ti), FI_URL);
    }
}
#define PROTO_ITEM_SET_URL(ti) proto_item_set_url((ti))

typedef void (*proto_tree_foreach_func)(proto_node *, gpointer);
typedef gboolean (*proto_tree_traverse_func)(proto_node *, gpointer);

WS_DLL_PUBLIC void proto_tree_children_foreach(proto_tree *tree,
    proto_tree_foreach_func func, gpointer data);

typedef struct {
    void (*register_protoinfo)(void);   /* routine to call to register protocol information */
    void (*register_handoff)(void);     /* routine to call to register dissector handoff */
} proto_plugin;

/** Register dissector plugin with the plugin system. */
WS_DLL_PUBLIC void proto_register_plugin(const proto_plugin *plugin);

/** Sets up memory used by proto routines. Called at program startup */
void proto_init(GSList *register_all_plugin_protocols_list,
    GSList *register_all_plugin_handoffs_list, register_cb cb, void *client_data);

/** Frees memory used by proto routines. Called at program shutdown */
extern void proto_cleanup(void);

/** This function takes a tree and a protocol id as parameter and
    will return TRUE/FALSE for whether the protocol or any of the filterable
    fields in the protocol is referenced by any fitlers.
    If this function returns FALSE then it is safe to skip any
    proto_tree_add_...() calls and just treat the call as if the
    dissector was called with tree==NULL.
    If you reset the tree to NULL by this dissector returning FALSE,
    you will still need to call any subdissector with the original value of
    tree or filtering will break.

    The purpose of this is to optimize wireshark for speed and make it
    faster for when filters are being used.
*/
WS_DLL_PUBLIC gboolean proto_field_is_referenced(proto_tree *tree, int proto_id);

/** Create a subtree under an existing item.
 @param pi the parent item of the new subtree
 @param idx one of the ett_ array elements registered with proto_register_subtree_array()
 @return the new subtree */
WS_DLL_PUBLIC proto_tree* proto_item_add_subtree(proto_item *pi, const gint idx) G_GNUC_WARN_UNUSED_RESULT;

/** Get an existing subtree under an item.
 @param pi the parent item of the subtree
 @return the subtree or NULL */
WS_DLL_PUBLIC proto_tree* proto_item_get_subtree(proto_item *pi);

/** Get the parent of a subtree item.
 @param pi the child item in the subtree
 @return parent item or NULL */
WS_DLL_PUBLIC proto_item* proto_item_get_parent(const proto_item *pi);

/** Get Nth generation parent item.
 @param pi the child item in the subtree
 @param gen the generation to get (using 1 here is the same as using proto_item_get_parent())
 @return parent item */
WS_DLL_PUBLIC proto_item* proto_item_get_parent_nth(proto_item *pi, int gen);

/** Replace text of item after it already has been created.
 @param pi the item to set the text
 @param format printf like format string
 @param ... printf like parameters */
WS_DLL_PUBLIC void proto_item_set_text(proto_item *pi, const char *format, ...)
    G_GNUC_PRINTF(2,3);

/** Append to text of item after it has already been created.
 @param pi the item to append the text to
 @param format printf like format string
 @param ... printf like parameters */
WS_DLL_PUBLIC void proto_item_append_text(proto_item *pi, const char *format, ...)
    G_GNUC_PRINTF(2,3);

/** Prepend to text of item after it has already been created.
 @param pi the item to prepend the text to
 @param format printf like format string
 @param ... printf like parameters */
WS_DLL_PUBLIC void proto_item_prepend_text(proto_item *pi, const char *format, ...)
    G_GNUC_PRINTF(2,3);

/** Set proto_item's length inside tvb, after it has already been created.
 @param pi the item to set the length
 @param length the new length of the item */
WS_DLL_PUBLIC void proto_item_set_len(proto_item *pi, const gint length);

/**
 * Sets the length of the item based on its start and on the specified
 * offset, which is the offset past the end of the item; as the start
 * in the item is relative to the beginning of the data source tvbuff,
 * we need to pass in a tvbuff.
 *
 * Given an item created as:
 *      ti = proto_tree_add_item(*, *, tvb, offset, -1, *);
 * then
 *      proto_item_set_end(ti, tvb, end);
 * is equivalent to
 *      proto_item_set_len(ti, end - offset);
 *
 @param pi the item to set the length
 @param tvb end is relative to this tvbuff
 @param end this end offset is relative to the beginning of tvb
 @todo make usage clearer, I don't understand it!
 */
WS_DLL_PUBLIC void proto_item_set_end(proto_item *pi, tvbuff_t *tvb, gint end);

/** Get length of a proto_item. Useful after using proto_tree_add_item()
 * to add a variable-length field (e.g., FT_NSTRING_UINT8).
 @param pi the item to get the length from
 @return the current length */
WS_DLL_PUBLIC int proto_item_get_len(const proto_item *pi);

/** Set the bit offset and length for the specified proto_item.
 * @param ti The item to set.
 * @param bits_offset The number of bits from the beginning of the field.
 * @param bits_len The new length in bits.
 */
WS_DLL_PUBLIC void proto_item_set_bits_offset_len(proto_item *ti, int bits_offset, int bits_len);

/** Get the display representation of a proto_item.
 * Can be used, for example, to append that to the parent item of
 * that item.
 @param scope the wmem scope to use to allocate the string
 @param pi the item from which to get the display representation
 @return the display representation */
WS_DLL_PUBLIC char *proto_item_get_display_repr(wmem_allocator_t *scope, proto_item *pi);

/** Creates a new proto_tree root.
 @return the new tree root */
extern proto_tree* proto_tree_create_root(struct _packet_info *pinfo);

void proto_tree_reset(proto_tree *tree);

/** Clear memory for entry proto_tree. Clears proto_tree struct also.
 @param tree the tree to free */
WS_DLL_PUBLIC void proto_tree_free(proto_tree *tree);

/** Set the tree visible or invisible.
 Is the parsing being done for a visible proto_tree or an invisible one?
 By setting this correctly, the proto_tree creation is sped up by not
 having to call vsnprintf and copy strings around.
 @param tree the tree to be set
 @param visible ... or not
 @return the old value */
WS_DLL_PUBLIC gboolean
proto_tree_set_visible(proto_tree *tree, gboolean visible);

/** Indicate whether we should fake protocols during dissection (default = TRUE)
 @param tree the tree to be set
 @param fake_protocols TRUE if we should fake protocols */
extern void
proto_tree_set_fake_protocols(proto_tree *tree, gboolean fake_protocols);

/** Mark a field/protocol ID as "interesting".
 @param tree the tree to be set (currently ignored)
 @param hfid the interesting field id
 @todo what *does* interesting mean? */
extern void
proto_tree_prime_with_hfid(proto_tree *tree, const int hfid);

/** Get a parent item of a subtree.
 @param tree the tree to get the parent from
 @return parent item */
WS_DLL_PUBLIC proto_item* proto_tree_get_parent(proto_tree *tree);

/** Get the parent tree of a subtree.
 @param tree the tree to get the parent from
 @return parent tree */
WS_DLL_PUBLIC proto_tree *proto_tree_get_parent_tree(proto_tree *tree);

/** Get the root tree from any subtree.
 @param tree the tree to get the root from
 @return root tree */
WS_DLL_PUBLIC proto_tree* proto_tree_get_root(proto_tree *tree);

/** Move an existing item behind another existing item.
 @param tree the tree to which both items belong
 @param fixed_item the item which keeps its position
 @param item_to_move the item which will be moved */
WS_DLL_PUBLIC void proto_tree_move_item(proto_tree *tree, proto_item *fixed_item, proto_item *item_to_move);


/** Set start and length of an appendix for a proto_tree.
 @param tree the tree to set the appendix start and length
 @param tvb the tv buffer of the current data
 @param start the start offset of the appendix
 @param length the length of the appendix */
WS_DLL_PUBLIC void proto_tree_set_appendix(proto_tree *tree, tvbuff_t *tvb, gint start, const gint length);


/** Add an item to a proto_tree, using the text label registered to that item.
   The item is extracted from the tvbuff handed to it.
 @param tree the tree to append this item to
 @param hfinfo field
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param encoding data encoding
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_item_new(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding);

WS_DLL_PUBLIC proto_item *
proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding);

/** Add an item to a proto_tree, using the text label registered to that item.
   The item is extracted from the tvbuff handed to it.

   Return the length of the item through the pointer.
 @param tree the tree to append this item to
 @param hfinfo field
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param encoding data encoding
 @param[out] lenretval points to a gint that will be set to the item length
 @return the newly created item, and *lenretval is set to the item length */
WS_DLL_PUBLIC proto_item *
proto_tree_add_item_new_ret_length(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, gint *lenretval);

WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_length(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, gint *lenretval);

/** Add an integer data item to a proto_tree, using the text label registered to that item.
The item is extracted from the tvbuff handed to it, and the retrieved
value is also set to *retval so the caller gets it back for other uses.

This function retrieves the value even if the passed-in tree param is NULL,
so that it can be used by dissectors at all times to both get the value
and set the tree item to it.

Like other proto_tree_add functions, if there is a tree and the value cannot
be decoded from the tvbuff, then an expert info error is reported.

This function accepts ENC_LITTLE_ENDIAN and ENC_BIG_ENDIAN for native number
encoding in the tvbuff

The length argument must
be set to the appropriate size of the native type as in other proto_add routines.

Integers of 8, 16, 24 and 32 bits can be retrieved with the _ret_int and
ret_uint functions; integers of 40, 48, 56, and 64 bits can be retrieved
with the _ret_uint64 function; Boolean values of 8, 16, 24, 32, 40, 48,
56, and 64 bits can be retrieved with the _ret_boolean function.

@param tree the tree to append this item to
@param hfindex field
@param tvb the tv buffer of the current data
@param start start of data in tvb (cannot be negative)
@param length length of data in tvb (for strings can be -1 for remaining)
@param encoding data encoding (e.g, ENC_LITTLE_ENDIAN, ENC_BIG_ENDIAN, ENC_ASCII|ENC_STRING, etc.)
@param[out] retval points to a gint32 or guint32 which will be set to the value
@return the newly created item, and *retval is set to the decoded value masked/shifted according to bitmask
*/
WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_int(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, gint32 *retval);

WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, gint64 *retval);

WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, guint32 *retval);

WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, guint64 *retval);

WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_varint(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, guint64 *retval, gint *lenretval);

WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_boolean(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, gboolean *retval);

WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_ipv4(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, ws_in4_addr *retval);

/** Add an string item to a proto_tree, using the text label registered to
that item.

The item is extracted from the tvbuff handed to it, and the retrieved
value and its length are returned through pointers so the caller can use
them.  The value is allocated using the wmem scope passed in.

This function retrieves the value and length even if the passed-in tree
param is NULL, so that then can be used by dissectors at all times to
both get the value and set the tree item to it.

Like other proto_tree_add functions, if there is a tree and the value cannot
be decoded from the tvbuff, then an expert info error is reported.

This function accepts string encodings.

@param scope the wmem scope to use to allocate the string
@param tree the tree to append this item to
@param hfindex field
@param tvb the tv buffer of the current data
@param start start of data in tvb (cannot be negative)
@param length length of data in tvb (for strings can be -1 for remaining)
@param encoding data encoding (e.g, ENC_ASCII, ENC_UTF_8, etc.)
@param[out] retval points to a guint8 * that will be set to point to the
string value
@param[out] lenretval points to a gint that will be set to the item length
@return the newly created item, *retval is set to the decoded value,
and *lenretval is set to the item length
*/
WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_string_and_length(proto_tree *tree, int hfindex,
    tvbuff_t *tvb, const gint start, gint length, const guint encoding,
    wmem_allocator_t *scope, const guint8 **retval, gint *lenretval);

/** Add an string item to a proto_tree, using the text label registered to
that item.

The item is extracted from the tvbuff handed to it, and the retrieved
value is returned through a pointer so the caller can use it.  The value
is allocated using the wmem scope passed in.

This function retrieves the value even if the passed-in tree param is NULL,
so that it can be used by dissectors at all times to both get the value
and set the tree item to it.

Like other proto_tree_add functions, if there is a tree and the value cannot
be decoded from the tvbuff, then an expert info error is reported.

This function accepts string encodings.

@param scope the wmem scope to use to allocate the string
@param tree the tree to append this item to
@param hfindex field
@param tvb the tv buffer of the current data
@param start start of data in tvb (cannot be negative)
@param length length of data in tvb (for strings can be -1 for remaining)
@param encoding data encoding (e.g, ENC_ASCII, ENC_UTF_8, etc.)
@param[out] retval points to a guint8 * that will be set to point to the
string value
@return the newly created item, and *retval is set to the decoded value
*/
WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_string(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding,
    wmem_allocator_t *scope, const guint8 **retval);

/** Add an string or byte array item to a proto_tree, using the
text label registered to that item.

This provides a string that is a display representation of the value,
and the length of the item, similar to what
proto_tree_add_item_ret_string_and_length() does.

@param scope the wmem scope to use to allocate the string
@param tree the tree to append this item to
@param hfindex field
@param tvb the tv buffer of the current data
@param start start of data in tvb (cannot be negative)
@param length length of data in tvb (for strings can be -1 for remaining)
@param encoding data encoding (e.g, ENC_ASCII, ENC_UTF_8, etc.)
@param[out] retval points to a guint8 * that will be set to point to the
string value
@param[out] lenretval points to a gint that will be set to the item length
@return the newly created item, *retval is set to the display string,
and *lenretval is set to the item length
*/
WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_display_string_and_length(proto_tree *tree, int hfindex,
    tvbuff_t *tvb,
    const gint start, gint length, const guint encoding,
    wmem_allocator_t *scope, char **retval, gint *lenretval);

/** Add an string or byte array item to a proto_tree, using the
text label registered to that item.

This provides a string that is a display representation of the value,
similar to what proto_tree_add_item_ret_string() does.

@param tree the tree to append this item to
@param hfindex field
@param tvb the tv buffer of the current data
@param start start of data in tvb (cannot be negative)
@param length length of data in tvb (for strings can be -1 for remaining)
@param encoding data encoding (e.g, ENC_ASCII, ENC_UTF_8, etc.)
@param scope the wmem scope to use to allocate the string
@param[out] retval points to a guint8 * that will be set to point to the
string value
@return the newly created item, *retval is set to the display string
*/
WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_display_string(proto_tree *tree, int hfindex,
    tvbuff_t *tvb,
    const gint start, gint length, const guint encoding,
    wmem_allocator_t *scope, char **retval);

/** Add a time item to a proto_tree, using thetext label registered to that item.

This provides a string that is a display representation of the time value

@param tree the tree to append this item to
@param hfindex field
@param tvb the tv buffer of the current data
@param start start of data in tvb (cannot be negative)
@param length length of data in tvb (for strings can be -1 for remaining)
@param encoding data encoding (e.g, ENC_ASCII, ENC_UTF_8, etc.)
@param scope the wmem scope to use to allocate the string
@param[out] retval points to a guint8 * that will be set to point to the
string value
@return the newly created item, *retval is set to the display string
*/
WS_DLL_PUBLIC proto_item *
proto_tree_add_item_ret_time_string(proto_tree *tree, int hfindex,
	tvbuff_t *tvb,
	const gint start, gint length, const guint encoding,
	wmem_allocator_t *scope, char **retval);

/** (INTERNAL USE ONLY) Add a text-only node to a proto_tree.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
proto_item *
proto_tree_add_text_internal(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, const char *format,
    ...) G_GNUC_PRINTF(5,6);

/** (INTERNAL USE ONLY) Add a text-only node to a proto_tree using a variable argument list.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param format printf like format string
 @param ap variable argument list
 @return the newly created item */
proto_item *
proto_tree_add_text_valist_internal(proto_tree *tree, tvbuff_t *tvb, gint start,
    gint length, const char *format, va_list ap) G_GNUC_PRINTF(5, 0);

/** Add a text-only node that creates a subtree underneath.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param idx one of the ett_ array elements registered with proto_register_subtree_array()
 @param tree_item item returned with tree creation. Can be NULL if going to be unused
 @param text label for the tree
 @return the newly created tree */
WS_DLL_PUBLIC proto_tree *
proto_tree_add_subtree(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, gint idx,
    proto_item **tree_item, const char *text);

/** Add a text-only node that creates a subtree underneath.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param idx one of the ett_ array elements registered with proto_register_subtree_array()
 @param tree_item item returned with tree creation. Can be NULL if going to be unused
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created tree */
WS_DLL_PUBLIC proto_tree *
proto_tree_add_subtree_format(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, gint idx,
    proto_item **tree_item, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a text-only node to a proto_tree with tvb_format_text() string. */
proto_item *
proto_tree_add_format_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length);

/** Add a text-only node to a proto_tree with tvb_format_text_wsp() string. */
proto_item *
proto_tree_add_format_wsp_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length);

/** Add a FT_NONE field to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_none_format(proto_tree *tree, const int hfindex, tvbuff_t *tvb, const gint start,
    gint length, const char *format, ...) G_GNUC_PRINTF(6,7);

/** Add a FT_PROTOCOL to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const char *format, ...) G_GNUC_PRINTF(6,7);

/** Add a FT_BYTES to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param start_ptr pointer to the data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bytes(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const guint8* start_ptr);

/** Add a FT_BYTES to a proto_tree like proto_tree_add_bytes,
 but used when the tvb data length does not match the bytes length.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param start_ptr pointer to the data to display
 @param ptr_length length of data in start_ptr
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bytes_with_length(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const guint8 *start_ptr, gint ptr_length);

/** Get and add a byte-array-based FT_* to a proto_tree.

 Supported: FT_BYTES, FT_UINT_BYTES, FT_OID, FT_REL_OID, and FT_SYSTEM_ID.

 The item is extracted from the tvbuff handed to it, based on the ENC_* passed
 in for the encoding, and the retrieved byte array is also set to *retval so the
 caller gets it back for other uses.

 This function retrieves the value even if the passed-in tree param is NULL,
 so that it can be used by dissectors at all times to both get the value
 and set the tree item to it.

 Like other proto_tree_add functions, if there is a tree and the value cannot
 be decoded from the tvbuff, then an expert info error is reported. For string
 encoding, this means that a failure to decode the hex value from the string
 results in an expert info error being added to the tree.

 If encoding is string-based, it will convert using tvb_get_string_bytes(); see
 that function's comments for details.

 @note The GByteArray retval must be pre-constructed using g_byte_array_new().

 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param encoding data encoding (e.g, ENC_LITTLE_ENDIAN, or ENC_UTF_8|ENC_STR_HEX)
 @param[in,out] retval points to a GByteArray which will be set to the bytes from the Tvb.
 @param[in,out] endoff if not NULL, gets set to the character after those consumed.
 @param[in,out] err if not NULL, gets set to 0 if no failure, else the errno code (e.g., EDOM, ERANGE).
 @return the newly created item, and retval is set to the decoded value
 */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bytes_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding,
    GByteArray *retval, gint *endoff, gint *err);

/** Add a formatted FT_BYTES to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param start_ptr pointer to the data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bytes_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, const guint8* start_ptr, const char *format,
    ...) G_GNUC_PRINTF(7,8);

/** Add a formatted FT_BYTES to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param start_ptr pointer to the data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bytes_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const guint8* start_ptr, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_ABSOLUTE_TIME or FT_RELATIVE_TIME to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr pointer to the data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_time(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const nstime_t* value_ptr);

/** Get and add a FT_ABSOLUTE_TIME or FT_RELATIVE_TIME to a proto_tree.
 The item is extracted from the tvbuff handed to it, based on the ENC_* passed
 in for the encoding, and the retrieved value is also set to *retval so the
 caller gets it back for other uses.

 This function retrieves the value even if the passed-in tree param is NULL,
 so that it can be used by dissectors at all times to both get the value
 and set the tree item to it.

 Like other proto_tree_add functions, if there is a tree and the value cannot
 be decoded from the tvbuff, then an expert info error is reported. For string
 encoding, this means that a failure to decode the time value from the string
 results in an expert info error being added to the tree.

 If encoding is string-based, it will convert using tvb_get_string_time(); see
 that function's comments for details.

 @note The nstime_t *retval must be pre-allocated as a nstime_t.

 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param encoding data encoding (e.g, ENC_LITTLE_ENDIAN, ENC_UTF_8|ENC_ISO_8601_DATE_TIME, etc.)
 @param[in,out] retval points to a nstime_t which will be set to the value
 @param[in,out] endoff if not NULL, gets set to the character after those consumed.
 @param[in,out] err if not NULL, gets set to 0 if no failure, else the errno code (e.g., EDOM, ERANGE).
 @return the newly created item, and retval is set to the decoded value
 */
WS_DLL_PUBLIC proto_item *
proto_tree_add_time_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding,
    nstime_t *retval, gint *endoff, gint *err);


/** Add a formatted FT_ABSOLUTE_TIME or FT_RELATIVE_TIME to a proto_tree, with
    the format generating the string for the value and with the field name
    being included automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr pointer to the data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_time_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, nstime_t* value_ptr, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_ABSOLUTE_TIME or FT_RELATIVE_TIME to a proto_tree, with
    the format generating the entire string for the entry, including any field
    name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr pointer to the data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, nstime_t* value_ptr, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_IPXNET to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ipxnet(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, guint32 value);

/** Add a formatted FT_IPXNET to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ipxnet_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, guint32 value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_IPXNET to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, guint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_IPv4 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ipv4(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, ws_in4_addr value);

/** Add a formatted FT_IPv4 to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ipv4_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, ws_in4_addr value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_IPv4 to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, ws_in4_addr value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_IPv6 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ipv6(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const ws_in6_addr *value_ptr);

/** Add a formatted FT_IPv6 to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ipv6_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, const ws_in6_addr *value_ptr, const char *format,
    ...) G_GNUC_PRINTF(7,8);

/** Add a formatted FT_IPv6 to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const ws_in6_addr *value_ptr, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_ETHER to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ether(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const guint8* value);

/** Add a formatted FT_ETHER to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ether_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, const guint8* value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_ETHER to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const guint8* value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_GUID to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_guid(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const e_guid_t *value_ptr);

/** Add a formatted FT_GUID to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_guid_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, const e_guid_t *value_ptr, const char *format,
    ...) G_GNUC_PRINTF(7,8);

/** Add a formatted FT_GUID to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_guid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const e_guid_t *value_ptr, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_OID to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_oid(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const guint8* value_ptr);

/** Add a formatted FT_OID to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_oid_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, const guint8* value_ptr, const char *format,
    ...) G_GNUC_PRINTF(7,8);

/** Add a formatted FT_OID to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_oid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const guint8* value_ptr, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add an FT_STRING, FT_STRINGZ, FT_STRINGZPAD, or FT_STRINGZTRUNC to a
    proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const char* value);

/** Add a formatted FT_STRING, FT_STRINGZ, FT_STRINGZPAD, or FT_STRINGZTRUNC
    to a proto_tree, with the format generating the string for the value
    and with the field name being included automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_string_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, const char* value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_STRING, FT_STRINGZ, FT_STRINGZPAD, or FT_STRINGZTRUNC
    to a proto_tree, with the format generating the entire string for the
    entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const char* value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_BOOLEAN to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_boolean(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, guint32 value);

/** Add a formatted FT_BOOLEAN to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_boolean_format_value(proto_tree *tree, int hfindex,
    tvbuff_t *tvb, gint start, gint length, guint32 value,
    const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a formatted FT_BOOLEAN to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, guint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_FLOAT to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_float(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, float value);

/** Add a formatted FT_FLOAT to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_float_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, float value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_FLOAT to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_float_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, float value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_DOUBLE to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_double(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, double value);

/** Add a formatted FT_DOUBLE to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_double_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, double value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_DOUBLE to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_double_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, double value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add one of FT_UINT8, FT_UINT16, FT_UINT24 or FT_UINT32 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, guint32 value);

/** Add a formatted FT_UINT8, FT_UINT16, FT_UINT24 or FT_UINT32 to a proto_tree,
    with the format generating the string for the value and with the field
    name being included automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_uint_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, guint32 value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_UINT8, FT_UINT16, FT_UINT24 or FT_UINT32 to a proto_tree,
    with the format generating the entire string for the entry, including any
    field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, guint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add an FT_UINT64 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, guint64 value);

/** Add a formatted FT_UINT64 to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_uint64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, guint64 value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_UINT64 to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_uint64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, guint64 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add one of FT_INT8, FT_INT16, FT_INT24 or FT_INT32 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, gint32 value);

/** Add a formatted FT_INT8, FT_INT16, FT_INT24 or FT_INT32 to a proto_tree,
    with the format generating the string for the value and with the field
    name being included automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_int_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gint32 value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_INT8, FT_INT16, FT_INT24 or FT_INT32 to a proto_tree,
    with the format generating the entire string for the entry, including
    any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_int_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, gint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add an FT_INT64 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, gint64 value);

/** Add a formatted FT_INT64 to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_int64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gint64 value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_INT64 to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_int64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, gint64 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_EUI64 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_eui64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const guint64 value);

/** Add a formatted FT_EUI64 to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_eui64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, const guint64 value, const char *format, ...)
    G_GNUC_PRINTF(7,8);

/** Add a formatted FT_EUI64 to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_eui64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint length, const guint64 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Useful for quick debugging. Also sends string to STDOUT, so don't
    leave call to this function in production code.
 @param tree the tree to append the text to
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_debug_text(proto_tree *tree, const char *format,
    ...) G_GNUC_PRINTF(2,3);

/** Fill given label_str with a simple string representation of field.
 @param finfo the item to get the info from
 @param label_str the string to fill
 @todo think about changing the parameter profile */
WS_DLL_PUBLIC void
proto_item_fill_label(field_info *finfo, gchar *label_str);

/** Fill the given display_label_str with the string representation of a field
 * formatted according to its type and field display specifier.
 * Used to display custom columns and packet diagram values.
 @param fi The item to get the info from
 @param display_label_str The string to fill
 @return The length of the label excluding the terminating '\0'.
 */
WS_DLL_PUBLIC int
proto_item_fill_display_label(field_info *fi, gchar *display_label_str, const int label_str_size);

/** Register a new protocol.
 @param name the full name of the new protocol
 @param short_name abbreviated name of the new protocol
 @param filter_name protocol name used for a display filter string
 @return the new protocol handle */
WS_DLL_PUBLIC int
proto_register_protocol(const char *name, const char *short_name, const char *filter_name);

/** Register a "helper" protocol (pino - protocol in name only).
 This is for dissectors that need distinguishing names and don't need the other
 features (like enable/disable).  One use case is a protocol with multiple dissection
 functions in a single dissector table needing unique "dissector names" to remove
 confusion with Decode As dialog.  Another use case is for a dissector table set
 up to handle TLVs within a single protocol (and allow "external" TLVs being
 registered through the dissector table).
 @param name the full name of the new protocol
 @param short_name abbreviated name of the new protocol
 @param filter_name protocol name used for a display filter string
 @param parent_proto the "real" protocol for the helper.  The parent decides enable/disable
 @param field_type FT_PROTOCOL or FT_BYTES.  Allows removal of "protocol highlighting" (FT_BYTES)
 if pino is part of TLV.
 @return the new protocol handle */
WS_DLL_PUBLIC int
proto_register_protocol_in_name_only(const char *name, const char *short_name, const char *filter_name,
    int parent_proto, enum ftenum field_type);

/** Deregister a protocol.
 @param short_name abbreviated name of the protocol
 @return TRUE if protocol is removed */
gboolean
proto_deregister_protocol(const char *short_name);

/** Register a protocol alias.
 This is for dissectors whose original name has changed, e.g. BOOTP to DHCP.
 @param proto_id protocol id returned by proto_register_protocol (0-indexed)
 @param alias_name alias for the protocol's filter name */
WS_DLL_PUBLIC void
proto_register_alias(const int proto_id, const char *alias_name);

/** This type of function can be registered to get called whenever
    a given field was not found but a its prefix is matched;
    It can be used to procrastinate the hf array registration.
   @param match  what's being matched */
typedef void (*prefix_initializer_t)(const char* match);

/** Register a new prefix for delayed initialization of field arrays
    Note that the initializer function MAY NOT be called before the dissector
    is first called.  That is, dissectors using this function must be prepared
    to call the initializer before beginning dissection; they should do this by
    calling proto_registrar_get_byname() on one of the dissector's field names.
@param prefix the prefix for the new protocol
@param initializer function that will initialize the field array for the given prefix */
WS_DLL_PUBLIC void
proto_register_prefix(const char *prefix,  prefix_initializer_t initializer);

/** Initialize every remaining uninitialized prefix. */
WS_DLL_PUBLIC void proto_initialize_all_prefixes(void);

/** Register a header_field array.
 @param parent the protocol handle from proto_register_protocol()
 @param hf the hf_register_info array
 @param num_records the number of records in hf */
WS_DLL_PUBLIC void
proto_register_field_array(const int parent, hf_register_info *hf, const int num_records);

/** Deregister an already registered field.
 @param parent the protocol handle from proto_register_protocol()
 @param hf_id the field to deregister */
WS_DLL_PUBLIC void
proto_deregister_field (const int parent, gint hf_id);

/** Add data to be freed when deregistered fields are freed.
 @param data a pointer to data to free */
WS_DLL_PUBLIC void
proto_add_deregistered_data (void *data);

/** Add a memory slice to be freed when deregistered fields are freed.
 @param block_size the size of the block
 @param mem_block a pointer to the block to free */
void
proto_add_deregistered_slice (gsize block_size, gpointer mem_block);

/** Free strings in a field.
 @param field_type the field type (one of FT_ values)
 @param field_display field display value (one of BASE_ values)
 @param field_strings field strings */
WS_DLL_PUBLIC void
proto_free_field_strings (ftenum_t field_type, unsigned int field_display, const void *field_strings);

/** Free fields deregistered in proto_deregister_field(). */
WS_DLL_PUBLIC void
proto_free_deregistered_fields (void);

/** Register a protocol subtree (ett) array.
 @param indices array of ett indices
 @param num_indices the number of records in indices */
WS_DLL_PUBLIC void
proto_register_subtree_array(gint * const *indices, const int num_indices);

/** Get name of registered header_field number n.
 @param n item # n (0-indexed)
 @return the name of this registered item */
WS_DLL_PUBLIC const char* proto_registrar_get_name(const int n);

/** Get abbreviation of registered header_field number n.
 @param n item # n (0-indexed)
 @return the abbreviation of this registered item */
WS_DLL_PUBLIC const char* proto_registrar_get_abbrev(const int n);

/** Get the header_field information based upon a field or protocol id.
 @param hfindex item # n (0-indexed)
 @return the registered item */
WS_DLL_PUBLIC header_field_info* proto_registrar_get_nth(guint hfindex);

/** Get the header_field information based upon a field name.
 @param field_name the field name to search for
 @return the registered item */
WS_DLL_PUBLIC header_field_info* proto_registrar_get_byname(const char *field_name);

/** Get the header_field information based upon a field alias.
 @param alias_name the aliased field name to search for
 @return the registered item */
WS_DLL_PUBLIC header_field_info* proto_registrar_get_byalias(const char *alias_name);

/** Get the header_field id based upon a field name.
 @param field_name the field name to search for
 @return the field id for the registered item */
WS_DLL_PUBLIC int proto_registrar_get_id_byname(const char *field_name);

/** Get enum ftenum FT_ of registered header_field number n.
 @param n item # n (0-indexed)
 @return the registered item */
WS_DLL_PUBLIC enum ftenum proto_registrar_get_ftype(const int n);

/** Get parent protocol of registered header_field number n.
 @param n item # n (0-indexed)
 @return -1 if item _is_ a protocol */
WS_DLL_PUBLIC int proto_registrar_get_parent(const int n);

/** Is item # n a protocol?
 @param n item # n (0-indexed)
 @return TRUE if it's a protocol, FALSE if it's not */
WS_DLL_PUBLIC gboolean proto_registrar_is_protocol(const int n);

/** Get length of registered field according to field type.
 @param n item # n (0-indexed)
 @return 0 means undeterminable at registration time, -1 means unknown field */
extern gint proto_registrar_get_length(const int n);


/** Routines to use to iterate over the protocols and their fields;
 * they return the item number of the protocol in question or the
 * appropriate hfinfo pointer, and keep state in "*cookie". */
WS_DLL_PUBLIC int proto_get_first_protocol(void **cookie);
WS_DLL_PUBLIC int proto_get_data_protocol(void *cookie);
WS_DLL_PUBLIC int proto_get_next_protocol(void **cookie);
WS_DLL_PUBLIC header_field_info *proto_get_first_protocol_field(const int proto_id, void **cookie);
WS_DLL_PUBLIC header_field_info *proto_get_next_protocol_field(const int proto_id, void **cookie);

/** Check if a protocol name is already registered.
 @param name the name to search for
 @return proto_id */
WS_DLL_PUBLIC int proto_name_already_registered(const gchar *name);

/** Given a protocol's filter_name.
 @param filter_name the filter name to search for
 @return proto_id */
WS_DLL_PUBLIC int proto_get_id_by_filter_name(const gchar* filter_name);

/** Given a protocol's short name.
 @param short_name the protocol short name to search for
 @return proto_id */
WS_DLL_PUBLIC int proto_get_id_by_short_name(const gchar* short_name);

/** Can item # n decoding be disabled?
 @param proto_id protocol id (0-indexed)
 @return TRUE if it's a protocol, FALSE if it's not */
WS_DLL_PUBLIC gboolean proto_can_toggle_protocol(const int proto_id);

/** Get the "protocol_t" structure for the given protocol's item number.
 @param proto_id protocol id (0-indexed) */
WS_DLL_PUBLIC protocol_t *find_protocol_by_id(const int proto_id);

/** Get the protocol's name for the given protocol's item number.
 @param proto_id protocol id (0-indexed)
 @return its name */
WS_DLL_PUBLIC const char *proto_get_protocol_name(const int proto_id);

/** Get the protocol's item number, for the given protocol's "protocol_t".
 @return its proto_id */
WS_DLL_PUBLIC int proto_get_id(const protocol_t *protocol);

/** Get the protocol's short name, for the given protocol's "protocol_t".
 @return its short name. */
WS_DLL_PUBLIC const char *proto_get_protocol_short_name(const protocol_t *protocol);

/** Get the protocol's long name, for the given protocol's "protocol_t".
 @return its long name. */
WS_DLL_PUBLIC const char *proto_get_protocol_long_name(const protocol_t *protocol);

/** Is protocol's decoding enabled ?
 @return TRUE if decoding is enabled, FALSE if not */
WS_DLL_PUBLIC gboolean proto_is_protocol_enabled(const protocol_t *protocol);

/** Is protocol's enabled by default (most are)?
 @return TRUE if decoding is enabled by default, FALSE if not */
WS_DLL_PUBLIC gboolean proto_is_protocol_enabled_by_default(const protocol_t *protocol);

/** Is this a protocol in name only (i.e. not a real one)?
 @return TRUE if helper, FALSE if not */
WS_DLL_PUBLIC gboolean proto_is_pino(const protocol_t *protocol);

/** Get a protocol's filter name by its item number.
 @param proto_id protocol id (0-indexed)
 @return its filter name. */
WS_DLL_PUBLIC const char *proto_get_protocol_filter_name(const int proto_id);

/** Associate a heuristic dissector with a protocol
 * INTERNAL USE ONLY!!!
 * @param protocol to associate the heuristic with
 * @param short_name heuristic dissector's short name
 */
extern void proto_add_heuristic_dissector(protocol_t *protocol, const char *short_name);

/** Apply func to all heuristic dissectors of a protocol
 * @param protocol to iterate over heuristics
 * @param func function to execute on heuristics
 * @param user_data user-specific data for function
 */
WS_DLL_PUBLIC void proto_heuristic_dissector_foreach(const protocol_t *protocol, GFunc func,
    gpointer user_data);

/** Find commonly-used protocols in a layer list.
 * @param layers Protocol layer list
 * @param is_ip Set to TRUE if the layer list contains IPv4 or IPv6, otherwise
 * unchanged. May be NULL.
 * @param is_tcp Set to TRUE if the layer list contains TCP, otherwise
 * unchanged. May be NULL.
 * @param is_udp Set to TRUE if the layer list contains UDP, otherwise
 * unchanged. May be NULL.
 * @param is_sctp Set to TRUE if the layer list contains SCTP, otherwise
 * unchanged. May be NULL.
 * @param is_tls Set to TRUE if the layer list contains SSL/TLS, otherwise
 * unchanged. May be NULL.
 * @param is_rtp Set to TRUE if the layer list contains RTP, otherwise
 * unchanged. May be NULL.
 * @param is_lte_rlc Set to TRUE if the layer list contains LTE RLC, otherwise
 * unchanged. May be NULL.
 */
WS_DLL_PUBLIC void proto_get_frame_protocols(const wmem_list_t *layers,
      gboolean *is_ip, gboolean *is_tcp, gboolean *is_udp, gboolean *is_sctp,
      gboolean *is_tls, gboolean *is_rtp, gboolean *is_lte_rlc);

/** Check whether a protocol, specified by name, is in a layer list.
 * @param layers Protocol layer list
 * @param proto_name Name of protocol to find
 * @return TRUE if the protocol is found, FALSE if it isn't
 */
WS_DLL_PUBLIC gboolean proto_is_frame_protocol(const wmem_list_t *layers, const char* proto_name);

/** Mark protocol with the given item number as disabled by default.
 @param proto_id protocol id (0-indexed) */
WS_DLL_PUBLIC void proto_disable_by_default(const int proto_id);

/** Enable / Disable protocol of the given item number.
 @param proto_id protocol id (0-indexed)
 @param enabled enable / disable the protocol */
WS_DLL_PUBLIC void proto_set_decoding(const int proto_id, const gboolean enabled);

/** Re-enable all protocols that are not marked as disabled by default. */
WS_DLL_PUBLIC void proto_reenable_all(void);

/** Disable disabling/enabling of protocol of the given item number.
 @param proto_id protocol id (0-indexed) */
WS_DLL_PUBLIC void proto_set_cant_toggle(const int proto_id);

/** Checks for existence any protocol or field within a tree.
 @param tree "Protocols" are assumed to be a child of the [empty] root node.
 @param id hfindex of protocol or field
 @return TRUE = found, FALSE = not found
 @todo add explanation of id parameter */
extern gboolean proto_check_for_protocol_or_field(const proto_tree* tree, const int id);

/** Return GPtrArray* of field_info pointers for all hfindex that appear in
    tree. Only works with primed trees, and is fast.
 @param tree tree of interest
 @param hfindex primed hfindex
 @return GPtrArray pointer */
WS_DLL_PUBLIC GPtrArray* proto_get_finfo_ptr_array(const proto_tree *tree, const int hfindex);

/** Return whether we're tracking any interesting fields.
    Only works with primed trees, and is fast.
 @param tree tree of interest
 @return TRUE if we're tracking interesting fields */
WS_DLL_PUBLIC gboolean proto_tracking_interesting_fields(const proto_tree *tree);

/** Return GPtrArray* of field_info pointers for all hfindex that appear in
    tree. Works with any tree, primed or unprimed, and is slower than
    proto_get_finfo_ptr_array because it has to search through the tree.
 @param tree tree of interest
 @param hfindex index of field info of interest
 @return GPtrArry pointer */
WS_DLL_PUBLIC GPtrArray* proto_find_finfo(proto_tree *tree, const int hfindex);

/** Return GPtrArray* of field_info pointer for first hfindex that appear in
tree. Works with any tree, primed or unprimed, and is slower than
proto_get_finfo_ptr_array because it has to search through the tree.
@param tree tree of interest
@param hfindex index of field info of interest
@return GPtrArry pointer */
WS_DLL_PUBLIC GPtrArray* proto_find_first_finfo(proto_tree *tree, const int hfindex);

/** Return GPtrArray* of field_info pointers containg all hfindexes that appear
    in tree.
 @param tree tree of interest
 @return GPtrArry pointer */
WS_DLL_PUBLIC GPtrArray* proto_all_finfos(proto_tree *tree);

/** Dumps a glossary of the protocol registrations to STDOUT */
WS_DLL_PUBLIC void proto_registrar_dump_protocols(void);

/** Dumps a glossary of the field value strings or true/false strings to STDOUT */
WS_DLL_PUBLIC void proto_registrar_dump_values(void);

/** Dumps a mapping file for loading tshark output into ElasticSearch */
WS_DLL_PUBLIC void proto_registrar_dump_elastic(const gchar* filter);

/** Dumps the number of protocol and field registrations to STDOUT.
 @return FALSE if we pre-allocated enough fields, TRUE otherwise. */
WS_DLL_PUBLIC gboolean proto_registrar_dump_fieldcount(void);

/** Dumps a glossary of the protocol and field registrations to STDOUT. */
WS_DLL_PUBLIC void proto_registrar_dump_fields(void);

/** Dumps a glossary field types and descriptive names to STDOUT */
WS_DLL_PUBLIC void proto_registrar_dump_ftypes(void);

/** Get string representation of display field value
 @param field_display field display value (one of BASE_ values)
 @return string representation of display field value or "Unknown" if doesn't exist */
WS_DLL_PUBLIC const char* proto_field_display_to_string(int field_display);

/** Number of elements in the tree_is_expanded array. With MSVC and a
 * libwireshark.dll, we need a special declaration. */
WS_DLL_PUBLIC int num_tree_types;

/** Returns TRUE if subtrees of that type are to be expanded. */
WS_DLL_PUBLIC gboolean tree_expanded(int tree_type);

/** Sets if subtrees of that type are to be expanded. */
WS_DLL_PUBLIC void tree_expanded_set(int tree_type, gboolean value);

/** glib doesn't have g_ptr_array_len of all things!*/
#ifndef g_ptr_array_len
#define g_ptr_array_len(a)      ((a)?(a)->len:0)
#endif

WS_DLL_PUBLIC int
hfinfo_bitshift(const header_field_info *hfinfo);

struct epan_dissect;

/** Can we do a "match selected" on this field.
 @param finfo field_info
 @param edt epan dissecting
 @return TRUE if we can do a "match selected" on the field, FALSE otherwise. */
WS_DLL_PUBLIC gboolean
proto_can_match_selected(field_info *finfo, struct epan_dissect *edt);

/** Construct a "match selected" display filter string.
 @param finfo field_info
 @param edt epan dissecting
 @return the wmem NULL alloced display filter string.  Needs to be freed with wmem_free(NULL, ...) */
WS_DLL_PUBLIC char*
proto_construct_match_selected_string(field_info *finfo, struct epan_dissect *edt);

/** Find field from offset in tvb.
 @param tree tree of interest
 @param offset offset in the tvb
 @param tvb the tv buffer
 @return the corresponding field_info */
WS_DLL_PUBLIC field_info*
proto_find_field_from_offset(proto_tree *tree, guint offset, tvbuff_t *tvb);

/** Find undecoded bytes in a tree
 @param tree tree of interest
 @param length the length of the frame
 @return an array to be used as bitmap of decoded bytes */
WS_DLL_PUBLIC gchar*
proto_find_undecoded_data(proto_tree *tree, guint length);

/** This function will dissect a sequence of bytes that describe a bitmask.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param hf_hdr an 8/16/24/32/40/48/56/64 bit integer that describes the
        bitmask to be dissected.
        This field will form an expansion under which the individual fields
        of the bitmask are dissected and displayed.
        This field must be of the type FT_[U]INT{8|16|24|32|40|48|56|64}.
 @param ett subtree index
 @param fields an array of pointers to int that lists all the fields of the
        bitmask. These fields can be either of the type FT_BOOLEAN for flags
        or another integer of the same type/size as hf_hdr with a mask specified.
        This array is terminated by a NULL entry.
        FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
        FT_integer fields that have a value_string attached will have the
        matched string displayed on the expansion line.
 @param encoding big or little endian byte representation (ENC_BIG_ENDIAN/ENC_LITTLE_ENDIAN/ENC_HOST_ENDIAN)
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bitmask(proto_tree *tree, tvbuff_t *tvb, const guint offset,
        const int hf_hdr, const gint ett, int * const *fields, const guint encoding);

/** This function will dissect a sequence of bytes that describe a bitmask.
    The value of the integer containing the bitmask is returned through
    a pointer.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param hf_hdr an 8/16/24/32/40/48/56/64 bit integer that describes the
        bitmask to be dissected.
        This field will form an expansion under which the individual fields
        of the bitmask are dissected and displayed.
        This field must be of the type FT_[U]INT{8|16|24|32|40|48|56|64}.
 @param ett subtree index
 @param fields an array of pointers to int that lists all the fields of the
        bitmask. These fields can be either of the type FT_BOOLEAN for flags
        or another integer of the same type/size as hf_hdr with a mask specified.
        This array is terminated by a NULL entry.
        FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
        FT_integer fields that have a value_string attached will have the
        matched string displayed on the expansion line.
 @param encoding big or little endian byte representation (ENC_BIG_ENDIAN/ENC_LITTLE_ENDIAN/ENC_HOST_ENDIAN)
 @param[out] retval points to a guint64 which will be set
 @return the newly created item, and *retval is set to the decoded value masked/shifted according to bitmask */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bitmask_ret_uint64(proto_tree *tree, tvbuff_t *tvb, const guint offset,
        const int hf_hdr, const gint ett, int * const *fields,
        const guint encoding, guint64 *retval);

/** This function will dissect a sequence of bytes that describe a bitmask.
    This has "filterable" bitmask header functionality of proto_tree_add_bitmask
    with the ability to control what data is appended to the header like
    proto_tree_add_bitmask_text
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param hf_hdr an 8/16/24/32/40/48/56/64 bit integer that describes the
        bitmask to be dissected.
        This field will form an expansion under which the individual fields
        of the bitmask are dissected and displayed.
        This field must be of the type FT_[U]INT{8|16|24|32|40|48|56|64}.
 @param ett subtree index
 @param fields an array of pointers to int that lists all the fields of the
        bitmask. These fields can be either of the type FT_BOOLEAN for flags
        or another integer of the same type/size as hf_hdr with a mask specified.
        This array is terminated by a NULL entry.
        FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
        FT_integer fields that have a value_string attached will have the
        matched string displayed on the expansion line.
 @param encoding big or little endian byte representation (ENC_BIG_ENDIAN/ENC_LITTLE_ENDIAN/ENC_HOST_ENDIAN)
 @param flags bitmask field using BMT_NO_* flags to determine behavior
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bitmask_with_flags(proto_tree *tree, tvbuff_t *tvb, const guint offset,
        const int hf_hdr, const gint ett, int * const *fields, const guint encoding, const int flags);

/** This function will dissect a sequence of bytes that describe a bitmask.
    This has "filterable" bitmask header functionality of proto_tree_add_bitmask
    with the ability to control what data is appended to the header like
    proto_tree_add_bitmask_text
    The value of the integer containing the bitmask is returned through
    a pointer.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param hf_hdr an 8/16/24/32/40/48/56/64 bit integer that describes the
        bitmask to be dissected.
        This field will form an expansion under which the individual fields
        of the bitmask are dissected and displayed.
        This field must be of the type FT_[U]INT{8|16|24|32|40|48|56|64}.
 @param ett subtree index
 @param fields an array of pointers to int that lists all the fields of the
        bitmask. These fields can be either of the type FT_BOOLEAN for flags
        or another integer of the same type/size as hf_hdr with a mask specified.
        This array is terminated by a NULL entry.
        FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
        FT_integer fields that have a value_string attached will have the
        matched string displayed on the expansion line.
 @param encoding big or little endian byte representation (ENC_BIG_ENDIAN/ENC_LITTLE_ENDIAN/ENC_HOST_ENDIAN)
 @param flags bitmask field using BMT_NO_* flags to determine behavior
 @param[out] retval points to a guint64 which will be set
 @return the newly created item, and *retval is set to the decoded value masked/shifted according to bitmask */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bitmask_with_flags_ret_uint64(proto_tree *tree, tvbuff_t *tvb, const guint offset,
        const int hf_hdr, const gint ett, int * const *fields,
        const guint encoding, const int flags, guint64 *retval);

/** This function will dissect a value that describe a bitmask. Similar to proto_tree_add_bitmask(),
    but with a passed in value (presumably because it can't be retrieved directly from tvb)
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param hf_hdr an 8/16/24/32/64 bit integer that describes the bitmask to be dissected.
        This field will form an expansion under which the individual fields of the
        bitmask is dissected and displayed.
        This field must be of the type FT_[U]INT{8|16|24|32|64}.
 @param ett subtree index
 @param fields an array of pointers to int that lists all the fields of the
        bitmask. These fields can be either of the type FT_BOOLEAN for flags
        or another integer of the same type/size as hf_hdr with a mask specified.
        This array is terminated by a NULL entry.
        FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
        FT_integer fields that have a value_string attached will have the
        matched string displayed on the expansion line.
 @param value bitmask value
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bitmask_value(proto_tree *tree, tvbuff_t *tvb, const guint offset,
        const int hf_hdr, const gint ett, int * const *fields, const guint64 value);

/** This function will dissect a value that describe a bitmask. Similar to proto_tree_add_bitmask(),
    but with a passed in value (presumably because it can't be retrieved directly from tvb)
    This has "filterable" bitmask header functionality of proto_tree_add_bitmask_value
    with the ability to control what data is appended to the header like
    proto_tree_add_bitmask_text
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param hf_hdr an 8/16/24/32/64 bit integer that describes the bitmask to be dissected.
        This field will form an expansion under which the individual fields of the
        bitmask is dissected and displayed.
        This field must be of the type FT_[U]INT{8|16|24|32|64}.
 @param ett subtree index
 @param fields an array of pointers to int that lists all the fields of the
        bitmask. These fields can be either of the type FT_BOOLEAN for flags
        or another integer of the same type/size as hf_hdr with a mask specified.
        This array is terminated by a NULL entry.
        FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
        FT_integer fields that have a value_string attached will have the
        matched string displayed on the expansion line.
 @param value bitmask value
 @param flags bitmask field using BMT_NO_* flags to determine behavior
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bitmask_value_with_flags(proto_tree *tree, tvbuff_t *tvb, const guint offset,
        const int hf_hdr, const gint ett, int * const *fields, const guint64 value, const int flags);

/** This function will dissect a sequence of bytes that describe a bitmask. Similar
    to proto_tree_add_bitmask(), but with no "header" item to group all of the fields
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param len number of bytes of data
 @param fields an array of pointers to int that lists all the fields of the
        bitmask. These fields can be either of the type FT_BOOLEAN for flags
        or another integer of the same type/size as hf_hdr with a mask specified.
        This array is terminated by a NULL entry.
        FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
        FT_integer fields that have a value_string attached will have the
        matched string displayed on the expansion line.
 @param encoding big or little endian byte representation (ENC_BIG_ENDIAN/ENC_LITTLE_ENDIAN/ENC_HOST_ENDIAN) */
WS_DLL_PUBLIC void
proto_tree_add_bitmask_list(proto_tree *tree, tvbuff_t *tvb, const guint offset,
                                const int len, int * const *fields, const guint encoding);

/** This function will dissect a value that describe a bitmask. Similar to proto_tree_add_bitmask_list(),
    but with a passed in value (presumably because it can't be retrieved directly from tvb)
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param len number of bytes of data
 @param fields an array of pointers to int that lists all the fields of the
        bitmask. These fields can be either of the type FT_BOOLEAN for flags
        or another integer of the same type/size as hf_hdr with a mask specified.
        This array is terminated by a NULL entry.
        FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
        FT_integer fields that have a value_string attached will have the
        matched string displayed on the expansion line.
 @param value bitmask value */
WS_DLL_PUBLIC void
proto_tree_add_bitmask_list_value(proto_tree *tree, tvbuff_t *tvb, const guint offset,
                                const int len, int * const *fields, const guint64 value);


/** This function will dissect a sequence of bytes that describe a bitmask.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param len number of bytes of data
 @param hf_hdr an 8/16/24/32 bit integer that describes the bitmask to be dissected.
        This field will form an expansion under which the individual fields of the
        bitmask are dissected and displayed.
        This field must be of the type FT_[U]INT{8|16|24|32}.
 @param ett subtree index
 @param fields an array of pointers to int that lists all the fields of the
        bitmask. These fields can be either of the type FT_BOOLEAN for flags
        or another integer with a mask specified.
        This array is terminated by a NULL entry.
        FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
        FT_integer fields that have a value_string attached will have the
        matched string displayed on the expansion line.
 @param exp expert info field used when decodable_len < len.  This also means this function
        should be called even when tree == NULL
 @param encoding big or little endian byte representation (ENC_BIG_ENDIAN/ENC_LITTLE_ENDIAN/ENC_HOST_ENDIAN)
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bitmask_len(proto_tree *tree, tvbuff_t *tvb, const guint offset, const guint len,
        const int hf_hdr, const gint ett, int * const *fields, struct expert_field* exp, const guint encoding);

/** Add a text with a subtree of bitfields.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param len length of the field name
 @param name field name (NULL if bitfield contents should be used)
 @param fallback field name if none of bitfields were usable
 @param ett subtree index
 @param fields NULL-terminated array of bitfield indexes
 @param encoding big or little endian byte representation (ENC_BIG_ENDIAN/ENC_LITTLE_ENDIAN/ENC_HOST_ENDIAN)
 @param flags bitmask field
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bitmask_text(proto_tree *tree, tvbuff_t *tvb, const guint offset, const guint len,
        const char *name, const char *fallback,
        const gint ett, int * const *fields, const guint encoding, const int flags);

#define BMT_NO_FLAGS    0x00    /**< Don't use any flags */
#define BMT_NO_APPEND   0x01    /**< Don't change the title at all */
#define BMT_NO_INT      0x02    /**< Don't add integral (non-boolean) fields to title */
#define BMT_NO_FALSE    0x04    /**< Don't add booleans unless they're TRUE */
#define BMT_NO_TFS      0x08    /**< Don't use true_false_string while formatting booleans */

/** Add bits to a proto_tree, using the text label registered to that item.
   The item is extracted from the tvbuff handed to it.
 @param tree the tree to append this item to
 @param hf_index field index. Fields for use with this function should have bitmask==0.
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bits
 @param encoding data encoding
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bits_item(proto_tree *tree, const int hf_index, tvbuff_t *tvb, const guint bit_offset,
    const gint no_of_bits, const guint encoding);

/** Add bits to a proto_tree, using the text label registered to that item.
*  The item is extracted from the tvbuff handed to it as a set
*  of crumbs (segments) of contiguous bits, specified by an
*  array of crumb_spec elements.  The crumbs are assembled to
*  create the value.  There may be any number of crumbs
*  specifying up to a total of 64 bits which may occur anywhere
*  within the tvb. If the span of the crumbs within the tvb is 4
*  octets or less, a bitmap of the crumbs is produced.
 @param tree the tree to append this item to
 @param hf_index field index. Fields for use with this function should have bitmask==0.
 @param tvb the tv buffer of the current data
 @param bit_offset of the first crumb in tvb expressed in bits
 @param crumb_spec pointer to crumb_spec array
 @param return_value if a pointer is passed here the value is returned.
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_split_bits_item_ret_val(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
    const guint bit_offset, const crumb_spec_t *crumb_spec, guint64 *return_value);

/** Add bitmap text for a split-bits crumb to a proto_tree,
*  using the text label registered to an item. The bitmap is
*  extracted from the tvbuff handed to it as a crumb (segment)
*  of contiguous bits, specified by one of an array of
*  crumb_spec elements. This function is normally called once
*  per crumb, after the call to
   proto_tree_add_split_bits_item_ret_val
 @param tree the tree to append this item to
 @param hf_index field index. Fields for use with this function should have bitmask==0.
 @param tvb the tv buffer of the current data
 @param bit_offset of the first crumb in tvb expressed in bits
 @param crumb_spec pointer to crumb_spec array
 @param crumb_index into the crumb_spec array for this crumb */
void
proto_tree_add_split_bits_crumb(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
    const guint bit_offset, const crumb_spec_t *crumb_spec, guint16 crumb_index);

/** Add bits to a proto_tree, using the text label registered to that item.
   The item is extracted from the tvbuff handed to it.
 @param tree the tree to append this item to
 @param hf_index field index. Fields for use with this function should have bitmask==0.
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bits
 @param return_value if a pointer is passed here the value is returned.
 @param encoding data encoding
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bits_ret_val(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
    const guint bit_offset, const gint no_of_bits, guint64 *return_value, const guint encoding);

/** Add bits for a FT_UINT8, FT_UINT16, FT_UINT24 or FT_UINT32
    header field to a proto_tree, with the format generating the
    string for the value and with the field name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param encoding data encoding
 @param format printf like format string
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_uint_bits_format_value(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
    const guint bit_offset, const gint no_of_bits, guint32 value, const guint encoding,
    const char *format, ...)
    G_GNUC_PRINTF(8,9);

/** Add bits for a FT_UINT8, FT_UINT16, FT_UINT24 or FT_UINT32
    header field to a proto_tree, with the format generating the
    string for the value and with the field name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param encoding data encoding
 @param format printf like format string
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_uint64_bits_format_value(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
    const guint bit_offset, const gint no_of_bits, guint64 value, const guint encoding,
    const char *format, ...)
    G_GNUC_PRINTF(8,9);

/** Add bits for a FT_BOOLEAN header field to a proto_tree, with
    the format generating the string for the value and with the field
    name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param encoding data encoding
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
proto_item *
proto_tree_add_boolean_bits_format_value(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
    const guint bit_offset, const gint no_of_bits, guint32 value, const guint encoding,
    const char *format, ...)
    G_GNUC_PRINTF(8,9);

/** Add bits for a FT_BOOLEAN header field to a proto_tree, with
    the format generating the string for the value and with the field
    name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param encoding data encoding
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
proto_item *
proto_tree_add_boolean_bits_format_value64(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
    const guint bit_offset, const gint no_of_bits, guint64 value, const guint encoding,
    const char *format, ...)
    G_GNUC_PRINTF(8,9);

/** Add bits for a FT_INT8, FT_INT16, FT_INT24 or FT_INT32
    header field to a proto_tree, with the format generating the
    string for the value and with the field name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param encoding data encoding
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
proto_item *
proto_tree_add_int_bits_format_value(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
    const guint bit_offset, const gint no_of_bits, gint32 value, const guint encoding,
    const char *format, ...)
    G_GNUC_PRINTF(8,9);

/** Add bits for a FT_INT8, FT_INT16, FT_INT24 or FT_INT32
    header field to a proto_tree, with the format generating the
    string for the value and with the field name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param encoding data encoding
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
proto_item *
proto_tree_add_int64_bits_format_value(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
    const guint bit_offset, const gint no_of_bits, gint64 value, const guint encoding,
    const char *format, ...)
    G_GNUC_PRINTF(8,9);

/** Add bits for a FT_FLOAT header field to a proto_tree, with
    the format generating the string for the value and with the field
    name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param encoding data encoding
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
proto_item *
proto_tree_add_float_bits_format_value(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
    const guint bit_offset, const gint no_of_bits, float value, const guint encoding,
    const char *format, ...)
    G_GNUC_PRINTF(8,9);


/** Add a FT_STRING with ENC_3GPP_TS_23_038_7BITS_PACKED encoding to a
    proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_chars number of 7bits characters to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ts_23_038_7bits_packed_item(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
    const guint bit_offset, const gint no_of_chars);

/** Add a FT_STRING with ENC_ASCII_7BITS encoding to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_chars number of 7bits characters to display
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_ascii_7bits_item(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
    const guint bit_offset, const gint no_of_chars);

/** Add a checksum filed to a proto_tree.
 This standardizes the display of a checksum field as well as any
 status and expert info supporting it.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param hf_checksum checksum field index
 @param hf_checksum_status optional checksum status field index.  If none
 exists, just pass -1
 @param bad_checksum_expert optional expert info for a bad checksum.  If
 none exists, just pass NULL
 @param pinfo Packet info used for optional expert info.  If unused, NULL can
 be passed
 @param computed_checksum Checksum to verify against
 @param encoding data encoding of checksum from tvb
 @param flags bitmask field of PROTO_CHECKSUM_ options
 @return the newly created item */
WS_DLL_PUBLIC proto_item *
proto_tree_add_checksum(proto_tree *tree, tvbuff_t *tvb, const guint offset,
        const int hf_checksum, const int hf_checksum_status, struct expert_field* bad_checksum_expert,
        packet_info *pinfo, guint32 computed_checksum, const guint encoding, const guint flags);

typedef enum
{
    PROTO_CHECKSUM_E_BAD = 0,
    PROTO_CHECKSUM_E_GOOD,
    PROTO_CHECKSUM_E_UNVERIFIED,
    PROTO_CHECKSUM_E_NOT_PRESENT,
    PROTO_CHECKSUM_E_ILLEGAL
} proto_checksum_enum_e;

#define PROTO_CHECKSUM_NO_FLAGS     0x00    /**< Don't use any flags */
#define PROTO_CHECKSUM_VERIFY       0x01    /**< Compare against computed checksum */
#define PROTO_CHECKSUM_GENERATED    0x02    /**< Checksum is generated only */
#define PROTO_CHECKSUM_IN_CKSUM     0x04    /**< Internet checksum routine used for computation */
#define PROTO_CHECKSUM_ZERO         0x08    /**< Computed checksum must be zero (but correct checksum can't be calculated) */
#define PROTO_CHECKSUM_NOT_PRESENT  0x10    /**< Checksum field is not present (Just populates status field) */

WS_DLL_PUBLIC const value_string proto_checksum_vals[];

/** Check if given string is a valid field name
 @param field_name the field name to check
 @return 0 if valid, else first illegal character */
WS_DLL_PUBLIC guchar
proto_check_field_name(const gchar *field_name);

/** Check if given string is a valid field name. Accepts only lower case
 * characters.
 @param field_name the field name to check
 @return 0 if valid, else first illegal character */
WS_DLL_PUBLIC guchar
proto_check_field_name_lower(const gchar *field_name);


/** Check if given string is a valid field name
 @param tree the tree to append this item to
 @param field_id the field id used for custom column
 @param occurrence the occurrence of the field used for custom column
 @param result the buffer to fill with the field string
 @param expr the filter expression
 @param size the size of the string buffer */
const gchar *
proto_custom_set(proto_tree* tree, GSList *field_id,
                             gint occurrence,
                             gchar *result,
                             gchar *expr, const int size );

/** @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* proto.h */

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
