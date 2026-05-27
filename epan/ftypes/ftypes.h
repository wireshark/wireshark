/** @file
 * Definitions for field types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <wireshark.h>

#include <wsutil/regex.h>
#include <epan/wmem_scopes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define ASSERT_FTYPE_NOT_REACHED(ft) \
	ws_error("Invalid field type '%s'.", ftype_name(ft))

/**
 * @brief Fundamental field value types used throughout the Wireshark dissector framework.
 */
enum ftenum {
    FT_NONE,             /**< Text label with no associated value */
    FT_PROTOCOL,         /**< Protocol subtree node */
    FT_BOOLEAN,          /**< Boolean value; true/false from <glib.h> */
    FT_CHAR,             /**< Single-octet character, displayed as value 0–255 */
    FT_UINT8,            /**< Unsigned 8-bit integer */
    FT_UINT16,           /**< Unsigned 16-bit integer */
    FT_UINT24,           /**< Unsigned 24-bit integer; stored as UINT32, displayed as 6 hex digits with FD_HEX */
    FT_UINT32,           /**< Unsigned 32-bit integer */
    FT_UINT40,           /**< Unsigned 40-bit integer; stored as UINT64, displayed as 10 hex digits with FD_HEX */
    FT_UINT48,           /**< Unsigned 48-bit integer; stored as UINT64, displayed as 12 hex digits with FD_HEX */
    FT_UINT56,           /**< Unsigned 56-bit integer; stored as UINT64, displayed as 14 hex digits with FD_HEX */
    FT_UINT64,           /**< Unsigned 64-bit integer */
    FT_INT8,             /**< Signed 8-bit integer */
    FT_INT16,            /**< Signed 16-bit integer */
    FT_INT24,            /**< Signed 24-bit integer; stored as INT32 (see FT_UINT24) */
    FT_INT32,            /**< Signed 32-bit integer */
    FT_INT40,            /**< Signed 40-bit integer; stored as INT64 (see FT_UINT40) */
    FT_INT48,            /**< Signed 48-bit integer; stored as INT64 (see FT_UINT48) */
    FT_INT56,            /**< Signed 56-bit integer; stored as INT64 (see FT_UINT56) */
    FT_INT64,            /**< Signed 64-bit integer */
    FT_IEEE_11073_SFLOAT, /**< IEEE 11073 16-bit SFLOAT (medical device float) */
    FT_IEEE_11073_FLOAT,  /**< IEEE 11073 32-bit FLOAT (medical device float) */
    FT_FLOAT,            /**< IEEE 754 single-precision (32-bit) floating point */
    FT_DOUBLE,           /**< IEEE 754 double-precision (64-bit) floating point */
    FT_ABSOLUTE_TIME,    /**< Absolute date/time timestamp */
    FT_RELATIVE_TIME,    /**< Relative time delta */
    FT_STRING,           /**< Counted byte string with no null terminator */
    FT_STRINGZ,          /**< Null-terminated (C-style) string */
    FT_UINT_STRING,      /**< Length-prefixed string; leading bytes encode the count */
    FT_ETHER,            /**< IEEE 802 MAC address (6 bytes) */
    FT_BYTES,            /**< Arbitrary byte array */
    FT_UINT_BYTES,       /**< Length-prefixed byte array; leading bytes encode the count */
    FT_IPv4,             /**< IPv4 address (4 bytes) */
    FT_IPv6,             /**< IPv6 address (16 bytes) */
    FT_IPXNET,           /**< IPX network address (4 bytes) */
    FT_FRAMENUM,         /**< UINT32 frame number; clicking navigates to the referenced frame */
    FT_GUID,             /**< Globally Unique Identifier / UUID (16 bytes) */
    FT_OID,              /**< ASN.1 OBJECT IDENTIFIER */
    FT_EUI64,            /**< IEEE EUI-64 identifier (8 bytes) */
    FT_AX25,             /**< AX.25 amateur radio address (7 bytes) */
    FT_VINES,            /**< Banyan VINES network address (6 bytes) */
    FT_REL_OID,          /**< ASN.1 RELATIVE-OID */
    FT_SYSTEM_ID,        /**< IS-IS System Identifier */
    FT_STRINGZPAD,       /**< Fixed-length null-padded string */
    FT_FCWWN,            /**< Fibre Channel World Wide Name (8 bytes) */
    FT_STRINGZTRUNC,     /**< Fixed-length null-truncated string */
    FT_NUM_TYPES,        /**< Sentinel: one past the last real field type */
    FT_SCALAR,           /**< Pseudo-type used internally for arithmetic operations only; not a real field type */
    FT_ENUM_SIZE = FT_SCALAR /**< Must equal the last enumerator to size arrays correctly */
};


/**
 * @brief True if @p ft is a signed integer type backed by a 32-bit value.
 * @param ft An ftenum value to test.
 */
#define FT_IS_INT32(ft) \
    ((ft) == FT_INT8  || \
     (ft) == FT_INT16 || \
     (ft) == FT_INT24 || \
     (ft) == FT_INT32)

/**
 * @brief True if @p ft is a signed integer type backed by a 64-bit value.
 * @param ft An ftenum value to test.
 */
#define FT_IS_INT64(ft) \
    ((ft) == FT_INT40 || \
     (ft) == FT_INT48 || \
     (ft) == FT_INT56 || \
     (ft) == FT_INT64)

/**
 * @brief True if @p ft is any signed integer type (INT8 through INT64).
 * @param ft An ftenum value to test.
 */
#define FT_IS_INT(ft) (FT_IS_INT32(ft) || FT_IS_INT64(ft))

/**
 * @brief True if @p ft is an unsigned integer type backed by a 32-bit value.
 * @param ft An ftenum value to test.
 */
#define FT_IS_UINT32(ft) \
    ((ft) == FT_CHAR    || \
     (ft) == FT_UINT8   || \
     (ft) == FT_UINT16  || \
     (ft) == FT_UINT24  || \
     (ft) == FT_UINT32  || \
     (ft) == FT_FRAMENUM)

/**
 * @brief True if @p ft is an unsigned integer type backed by a 64-bit value.
 * @param ft An ftenum value to test.
 */
#define FT_IS_UINT64(ft) \
    ((ft) == FT_UINT40 || \
     (ft) == FT_UINT48 || \
     (ft) == FT_UINT56 || \
     (ft) == FT_UINT64)

/**
 * @brief True if @p ft is any unsigned integer type (CHAR, UINT8 through UINT64, FRAMENUM).
 * @param ft An ftenum value to test.
 */
#define FT_IS_UINT(ft) (FT_IS_UINT32(ft) || FT_IS_UINT64(ft))

/**
 * @brief True if @p ft is any signed or unsigned integer type.
 * @param ft An ftenum value to test.
 */
#define FT_IS_INTEGER(ft) (FT_IS_INT(ft) || FT_IS_UINT(ft))

/**
 * @brief True if @p ft is a floating-point type (FT_FLOAT or FT_DOUBLE).
 * @param ft An ftenum value to test.
 */
#define FT_IS_FLOATING(ft) ((ft) == FT_FLOAT || (ft) == FT_DOUBLE)

/**
 * @brief True if @p ft is a time type (FT_ABSOLUTE_TIME or FT_RELATIVE_TIME).
 * @param ft An ftenum value to test.
 */
#define FT_IS_TIME(ft) \
    ((ft) == FT_ABSOLUTE_TIME || (ft) == FT_RELATIVE_TIME)

/**
 * @brief True if @p ft is any string-like type.
 * @param ft An ftenum value to test.
 */
#define FT_IS_STRING(ft) \
    ((ft) == FT_STRING      || (ft) == FT_STRINGZ    || (ft) == FT_STRINGZPAD || \
     (ft) == FT_STRINGZTRUNC || (ft) == FT_UINT_STRING || (ft) == FT_AX25)

/**
 * @brief True if @p ft is a scalar type suitable for internal arithmetic (FT_INT64 or FT_DOUBLE).
 * @param ft An ftenum value to test.
 */
#define FT_IS_SCALAR(ft) ((ft) == FT_INT64 || (ft) == FT_DOUBLE)


/** @brief Fixed byte length of an FT_ETHER (IEEE 802 MAC address) field. */
#define FT_ETHER_LEN        6
/** @brief Fixed byte length of an FT_GUID (UUID) field. */
#define FT_GUID_LEN         16
/** @brief Fixed byte length of an FT_IPv4 address field. */
#define FT_IPv4_LEN         4
/** @brief Fixed byte length of an FT_IPv6 address field. */
#define FT_IPv6_LEN         16
/** @brief Fixed byte length of an FT_IPXNET address field. */
#define FT_IPXNET_LEN       4
/** @brief Fixed byte length of an FT_EUI64 identifier field. */
#define FT_EUI64_LEN        8
/** @brief Fixed byte length of an FT_AX25 address field. */
#define FT_AX25_ADDR_LEN    7
/** @brief Fixed byte length of an FT_VINES address field. */
#define FT_VINES_ADDR_LEN   6
/** @brief Fixed byte length of an FT_FCWWN (Fibre Channel WWN) field. */
#define FT_FCWWN_LEN        8
/** @brief Maximum byte length of a variable-length base-128 (varint) encoded uint64; ceil(64/7) = 10. */
#define FT_VARINT_MAX_LEN   10


/** @brief Convenience typedef for ftenum. */
typedef enum ftenum ftenum_t;


/**
 * @brief Semantic role of an FT_FRAMENUM field, describing the relationship it encodes.
 */
enum ft_framenum_type {
    FT_FRAMENUM_NONE,         /**< No specific semantic role */
    FT_FRAMENUM_REQUEST,      /**< References the request frame for this response */
    FT_FRAMENUM_RESPONSE,     /**< References the response frame for this request */
    FT_FRAMENUM_ACK,          /**< References the frame being acknowledged */
    FT_FRAMENUM_DUP_ACK,      /**< References a duplicate acknowledgement frame */
    FT_FRAMENUM_RETRANS_PREV, /**< References the previous retransmission of this frame */
    FT_FRAMENUM_RETRANS_NEXT, /**< References the next retransmission of this frame */
    FT_FRAMENUM_NUM_TYPES     /**< Sentinel: one past the last valid framenum type */
};

/** @brief Convenience typedef for ft_framenum_type. */
typedef enum ft_framenum_type ft_framenum_type_t;

struct _ftype_t;
typedef struct _ftype_t ftype_t;


/**
 * @brief Return codes for ftype operations such as conversion and comparison.
 */
enum ft_result {
    FT_OK        = 0, /**< Operation completed successfully */
    FT_OVERFLOW,      /**< Value exceeds the representable range (too large) */
    FT_UNDERFLOW,     /**< Value is below the representable range (too small) */
    FT_BADARG,        /**< One or more arguments are invalid */
    FT_ERROR,         /**< Generic unspecified error */
};


/**
 * @brief Three-state boolean type for ftype comparison results.
 *
 * Note that `ft_bool == FT_FALSE` and `ft_bool != FT_TRUE` are semantically
 * distinct results due to the three-state (true / false / error) logic.
 * Negative values indicate an error condition.
 */
typedef int ft_bool_t;
#define FT_TRUE  1 /**< Comparison result: true */
#define FT_FALSE 0 /**< Comparison result: false */


/**
 * @brief Output representation formats for field value serialization.
 */
enum ftrepr {
    FTREPR_DISPLAY, /**< Human-readable display string (as shown in the packet details pane) */
    FTREPR_DFILTER, /**< Display filter syntax representation (suitable for use in filter expressions) */
    FTREPR_JSON,    /**< Standard JSON value representation */
    FTREPR_RAW,     /**< Raw unformatted byte/value representation */
    FTREPR_EK,      /**< ElasticSearch/OpenSearch JSON representation */
};

typedef enum ftrepr ftrepr_t;

/* Initialize the ftypes subsystem. Called once. */

/**
 * @brief Initializes various field types in Wireshark.
 *
 * This function registers all built-in field types used by Wireshark for packet analysis.
 */
void
ftypes_initialize(void);

/**
 * @brief Registers pseudofields for various data types in Wireshark.
 *
 * This function registers a set of pseudofields that can be used to represent different data types within Wireshark.
 * This includes bytes, double, IEEE 11073 float, integers, IPv4, IPv6, GUIDs, none,
 * strings, time, and TV buffers.
 */
void
ftypes_register_pseudofields(void);

/* ---------------- FTYPE ----------------- */

/* given two types, are they similar - for example can two
 * duplicate fields be registered of these two types. */
/**
 * @brief Determine if two field types are similar.
 *
 * @param ftype_a The first field type to compare.
 * @param ftype_b The second field type to compare.
 * @return true If the field types are similar.
 * @return false If the field types are not similar.
 */
bool
ftype_similar_types(const enum ftenum ftype_a, const enum ftenum ftype_b);

/* Return a string representing the name of the type */
/**
 * @brief Get the name of a field type.
 *
 * @param ftype The field type to get the name for.
 * @return A const char* pointing to the name of the field type, or "(null)" if not recognized.
 */
WS_DLL_PUBLIC
const char*
ftype_name(ftenum_t ftype);

/* Return a string presenting a "pretty" representation of the
 * name of the type. The pretty name means more to the user than
 * that "FT_*" name. */

/**
 * @brief Returns a string representing the "pretty" name of the field type.
 *
 * The pretty name is more user-friendly than the internal "FT_*" name.
 *
 * @param ftype The field type to get the pretty name for.
 * @return A const char* pointing to the pretty name of the field type, or "(null)" if not found.
 */
WS_DLL_PUBLIC
const char*
ftype_pretty_name(ftenum_t ftype);

/* Returns length of field in packet, or 0 if not determinable/defined. */
/**
 * @brief Get the wire size of a field type.
 *
 * @param ftype The field type to query.
 * @return int The wire size of the field type.
 */
WS_DLL_PUBLIC
int
ftype_wire_size(ftenum_t ftype);

/**
 * @brief Determines if a given field type can have its length retrieved.
 *
 * @param ftype The field type to check.
 * @return true If the field type can have its length retrieved, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_length(enum ftenum ftype);

/**
 * @brief Determines if a given field type can be sliced.
 *
 * @param ftype The field type to check.
 * @return true If the field type can be sliced, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_slice(enum ftenum ftype);

/**
 * @brief Checks if a given field type can be compared.
 *
 * @param ftype The field type to check.
 * @return true If the field type can be compared, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_eq(enum ftenum ftype);

/**
 * @brief Determines if a given field type can be compared.
 *
 * @param ftype The field type to check.
 * @return true If the field type can be compared, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_cmp(enum ftenum ftype);

/**
 * @brief Checks if a given field type can perform bitwise AND operation.
 *
 * @param ftype The field type to check.
 * @return true If the field type supports bitwise AND, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_bitwise_and(enum ftenum ftype);

/**
 * @brief Check if a given ftenum can be negated using unary minus.
 *
 * @param ftype The ftenum to check.
 * @return true If the ftype can be negated using unary minus.
 * @return false If the ftype cannot be negated using unary minus.
 */
WS_DLL_PUBLIC
bool
ftype_can_unary_minus(enum ftenum ftype);

/**
 * @brief Checks if a given field type can be added.
 *
 * @param ftype The field type to check.
 * @return true If the field type can be added, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_add(enum ftenum ftype);

/**
 * @brief Checks if the given ftype can be subtracted.
 *
 * @param ftype The type to check.
 * @return true If the ftype can be subtracted, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_subtract(enum ftenum ftype);

/**
 * @brief Checks if the given field type can be multiplied.
 *
 * @param ftype The field type to check.
 * @return true If the field type can be multiplied.
 * @return false Otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_multiply(enum ftenum ftype);

/**
 * @brief Checks if a given field type can be divided.
 *
 * @param ftype The field type to check.
 * @return true If the field type can be divided, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_divide(enum ftenum ftype);

/**
 * @brief Check if a given ftype can perform modulo operation.
 *
 * @param ftype The type to check.
 * @return true If the ftype can perform modulo operation, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_modulo(enum ftenum ftype);

/**
 * @brief Checks if a given ftype can contain other types.
 *
 * @param ftype The type to check.
 * @return true If the ftype can contain other types, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_contains(enum ftenum ftype);

/**
 * @brief Checks if a given field type can match another.
 *
 * @param ftype The field type to check.
 * @return true If the field type can match, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_matches(enum ftenum ftype);

/**
 * @brief Determines if a given field type can be zero.
 *
 * @param ftype The field type to check.
 * @return true If the field type can be zero, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_is_zero(enum ftenum ftype);

/**
 * @brief Determines if a given field type can represent negative values.
 *
 * @param ftype The field type to check.
 * @return true If the field type can represent negative values, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_is_negative(enum ftenum ftype);

/**
 * @brief Check if the given ftenum can represent NaN values.
 *
 * @param ftype The ftenum to check.
 * @return true If the ftenum can represent NaN values, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_is_nan(enum ftenum ftype);

/**
 * @brief Checks if a given ftype can be converted to a signed integer.
 *
 * @param ftype The type of field to check.
 * @return true If the ftype can be converted to a signed integer, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_val_to_sinteger(enum ftenum ftype);

/**
 * @brief Checks if a given ftenum can be converted to an unsigned integer.
 *
 * @param ftype The ftenum type to check.
 * @return true If the ftype can be converted to an unsigned integer, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_val_to_uinteger(enum ftenum ftype);

/**
 * @brief Checks if a given field type can be converted to a signed 64-bit integer.
 *
 * @param ftype The field type to check.
 * @return true If the field type can be converted to a signed 64-bit integer, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_val_to_sinteger64(enum ftenum ftype);

/**
 * @brief Checks if a given ftenum can be converted to an unsigned 64-bit integer.
 *
 * @param ftype The ftenum to check.
 * @return true If the ftype can be converted to an unsigned 64-bit integer.
 * @return false Otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_val_to_uinteger64(enum ftenum ftype);

/**
 * @brief Determines if a given field type can be converted to a double.
 *
 * This function checks whether the specified field type supports conversion to a double value.
 *
 * @param ftype The field type to check.
 * @return true If the field type can be converted to a double, false otherwise.
 */
WS_DLL_PUBLIC
bool
ftype_can_val_to_double(enum ftenum ftype);

/* ---------------- FVALUE ----------------- */

#include <wsutil/inet_cidr.h>
#include <epan/guid-utils.h>

#include <epan/tvbuff.h>
#include <wsutil/nstime.h>
#include <epan/dfilter/drange.h>

/**
 * @brief Holds a protocol value's buffer and associated metadata for use in display filter evaluation.
 */
typedef struct _protocol_value_t
{
    tvbuff_t* tvb;            /**< Tvbuff containing the raw bytes of the protocol value. */
    int       length;         /**< Length in bytes of the protocol data within the tvbuff. */
    char*     proto_string;   /**< String representation of the protocol value, if applicable. */
    bool      tvb_is_private; /**< True if this struct owns the tvbuff and is responsible for freeing it. */
} protocol_value_t;

typedef struct _fvalue_t fvalue_t;

/**
 * @brief Creates a new fvalue_t structure.
 *
 * @param ftype The type of the fvalue to create.
 * @return A pointer to the newly created fvalue_t structure.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_new(ftenum_t ftype);

/**
 * @brief Duplicates a fvalue_t structure.
 *
 * Creates a new fvalue_t structure and copies the data from the original one.
 * If a deep copy is required, it uses the appropriate copy function.
 *
 * @param fv Pointer to the original fvalue_t structure.
 * @return A pointer to the newly created fvalue_t structure.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_dup(const fvalue_t *fv);

/**
 * @brief Initialize a fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure to initialize.
 * @param ftype The type of the value to be stored in the fvalue_t structure.
 */
WS_DLL_PUBLIC
void
fvalue_init(fvalue_t *fv, ftenum_t ftype);

/**
 * @brief Clean up a fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure to clean up.
 */
WS_DLL_PUBLIC
void
fvalue_cleanup(fvalue_t *fv);

/**
 * @brief Frees an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure to be freed.
 */
WS_DLL_PUBLIC
void
fvalue_free(fvalue_t *fv);

/**
 * @brief Create a new fvalue from a literal string.
 *
 * @param ftype The type of the fvalue to create.
 * @param s The literal string to convert.
 * @param allow_partial_value Whether partial values are allowed.
 * @param err_msg Pointer to store error message if conversion fails.
 * @return A new fvalue on success, NULL otherwise.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_from_literal(ftenum_t ftype, const char *s, bool allow_partial_value, char **err_msg);

/**
 * @brief Create a new fvalue_t from a string.
 *
 * @param ftype The type of the fvalue to create.
 * @param s The string to convert.
 * @param len The length of the string.
 * @param err_msg A pointer to a char pointer that will receive an error message if conversion fails.
 * @return A new fvalue_t or NULL on failure.
 *
 * @note String *MUST* be null-terminated. Length is optional (pass zero) and does not include the null terminator.
 */
fvalue_t*
fvalue_from_string(ftenum_t ftype, const char *s, size_t len, char **err_msg);

/**
 * @brief Create a new fvalue from a character constant.
 *
 * @param ftype The type of the fvalue to create.
 * @param number The character constant value.
 * @param err_msg A pointer to a string that will be set if an error occurs.
 * @return A pointer to the created fvalue, or NULL on failure.
 */
fvalue_t*
fvalue_from_charconst(ftenum_t ftype, unsigned long number, char **err_msg);

/**
 * @brief Creates a field value from a signed 64-bit integer.
 *
 * @param ftype The type of the field value to create.
 * @param s A string representation of the number.
 * @param number The signed 64-bit integer value.
 * @param err_msg Pointer to a string that will receive an error message if the conversion fails.
 * @return A pointer to the created field value, or NULL if the conversion fails.
 */
fvalue_t*
fvalue_from_sinteger64(ftenum_t ftype, const char *s, int64_t number, char **err_msg);

 /**
  * @brief Creates a new fvalue_t from an unsigned 64-bit integer.
  *
  * @param ftype The field type of the value to create.
  * @param s A string representation of the number (for error messages).
  * @param number The unsigned 64-bit integer value.
  * @param err_msg Pointer to a char pointer that will receive an error message if conversion fails.
  * @return A new fvalue_t containing the unsigned 64-bit integer, or NULL on failure.
  */

fvalue_t*
fvalue_from_uinteger64(ftenum_t ftype, const char *s, uint64_t number, char **err_msg);

/**
 * @brief Creates a floating-point field value from a string representation.
 *
 * @param ftype The type of the field.
 * @param s The string representation of the number.
 * @param number The numeric value to be converted.
 * @param err_msg A pointer to a buffer where an error message will be stored if conversion fails.
 * @return A new fvalue_t representing the floating-point value, or NULL on failure.
 */
fvalue_t*
fvalue_from_floating(ftenum_t ftype, const char *s, double number, char **err_msg);

/**
 * @brief Convert a fvalue to its string representation.
 *
 * Creates the string representation of the field value.
 * Memory for the buffer is allocated based on wmem allocator
 * provided.
 *
 * field_display parameter should be a BASE_ value (enum field_display_e)
 * BASE_NONE should be used if field information isn't available.
 *
 * Returns NULL if the string cannot be represented in the given rtype.
 *
 * @param scope Memory allocator scope.
 * @param fv The fvalue to convert.
 * @param rtype The type of representation required.
 * @param field_display Display options for the field.
 * @return A pointer to the string representation, or NULL if not available.
 */
WS_DLL_PUBLIC char *
fvalue_to_string_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display);

#define fvalue_to_debug_repr(scope, fv) \
	fvalue_to_string_repr(scope, fv, FTREPR_DFILTER, 0)

/**
 * @brief Convert a fvalue_t to an unsigned 32-bit integer.
 *
 * @param fv The fvalue_t to convert.
 * @param repr Pointer to store the resulting unsigned 32-bit integer.
 * @return enum ft_result FT_OK on success, FT_OVERFLOW if the value is too large for uint32_t.
 */
WS_DLL_PUBLIC enum ft_result
fvalue_to_uinteger(const fvalue_t *fv, uint32_t *repr);

 /**
  * @brief Convert a fvalue_t to a 32-bit signed integer.
  *
  * @param fv The fvalue_t to convert.
  * @param repr Pointer to store the converted 32-bit signed integer.
  * @return enum ft_result Result of the conversion.
  */

WS_DLL_PUBLIC enum ft_result
fvalue_to_sinteger(const fvalue_t *fv, int32_t *repr);

/**
 * @brief Convert a fvalue_t to an unsigned 64-bit integer.
 *
 * @param fv The fvalue_t to convert.
 * @param repr Pointer to store the converted value.
 * @return enum ft_result FT_OK on success, FT_BADARG if conversion is not supported.
 */
WS_DLL_PUBLIC enum ft_result
fvalue_to_uinteger64(const fvalue_t *fv, uint64_t *repr);

/**
 * @brief Convert a fvalue_t to an int64_t.
 *
 * @param fv The fvalue_t to convert.
 * @param repr Pointer to store the converted value.
 * @return enum ft_result FT_OK on success, FT_BADARG if conversion is not supported.
 */
WS_DLL_PUBLIC enum ft_result
fvalue_to_sinteger64(const fvalue_t *fv, int64_t *repr);

/**
 * @brief Convert a fvalue_t to its double representation.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param repr Pointer to store the double representation.
 * @return FTENUM_T The result of the conversion or an error code.
 */
WS_DLL_PUBLIC enum ft_result
fvalue_to_double(const fvalue_t *fv, double *repr);

/**
 * @brief Get the ftype of a fvalue_t.
 *
 * @param fv The fvalue_t to get the ftype from.
 * @return The ftype of the fvalue_t.
 */
WS_DLL_PUBLIC ftenum_t
fvalue_type_ftenum(const fvalue_t *fv);

/**
 * @brief Get the name of the type associated with a fvalue_t.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @return const char* The name of the type.
 */
WS_DLL_PUBLIC
const char*
fvalue_type_name(const fvalue_t *fv);

/* GBytes reference count is automatically incremented. */
/**
 * @brief Set the value of an fvalue_t to a GBytes object.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value Pointer to the GBytes object containing the data.
 */
WS_DLL_PUBLIC
void
fvalue_set_bytes(fvalue_t *fv, GBytes *value);

/**
 * @brief Set the byte array value of an fvalue_t.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value Pointer to the GByteArray containing the byte array data.
 */
WS_DLL_PUBLIC
void
fvalue_set_byte_array(fvalue_t *fv, GByteArray *value);

/**
 * @brief Set the bytes data for a fvalue_t.
 *
 * @param fv The fvalue_t to set.
 * @param data The data to set.
 * @param size The size of the data.
 */
WS_DLL_PUBLIC
void
fvalue_set_bytes_data(fvalue_t *fv, const void *data, size_t size);

/**
 * @brief Set the value of an fvalue_t to a FC-WWN (Fibre Channel World Wide Name).
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value Pointer to the uint8_t array containing the FC-WWN value.
 */
WS_DLL_PUBLIC
void
fvalue_set_fcwwn(fvalue_t *fv, const uint8_t *value);


/**
 * @brief Set the value of an fvalue_t to an AX.25 address.
 *
 * @param fv Pointer to the fvalue_t structure to be set.
 * @param value Pointer to the byte array containing the AX.25 address.
 */
WS_DLL_PUBLIC
void
fvalue_set_ax25(fvalue_t *fv, const uint8_t *value);


/**
 * @brief Set the value of an fvalue_t to a VINES address.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value Pointer to the uint8_t array containing the VINES address.
 */
WS_DLL_PUBLIC
void
fvalue_set_vines(fvalue_t *fv, const uint8_t *value);

/**
 * @brief Set the value of an fvalue_t to a new Ethernet address.
 *
 * @param fv Pointer to the fvalue_t structure to be modified.
 * @param value Pointer to the uint8_t array containing the Ethernet address.
 */
WS_DLL_PUBLIC
void
fvalue_set_ether(fvalue_t *fv, const uint8_t *value);

/**
 * @brief Set the value of a fvalue_t to a GUID.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value Pointer to the e_guid_t structure containing the GUID value.
 */
WS_DLL_PUBLIC
void
fvalue_set_guid(fvalue_t *fv, const e_guid_t *value);

/**
 * @brief Set the time value of an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure to be modified.
 * @param value Pointer to the nstime_t structure containing the new time value.
 */
WS_DLL_PUBLIC
void
fvalue_set_time(fvalue_t *fv, const nstime_t *value);

/**
 * @brief Set the string value of an fvalue_t.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value The string value to set.
 */
WS_DLL_PUBLIC
void
fvalue_set_string(fvalue_t *fv, const char *value);

/**
 * @brief Set the value of an fvalue_t to a string buffer.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value Pointer to the wmem_strbuf_t containing the new value.
 */
WS_DLL_PUBLIC
void
fvalue_set_strbuf(fvalue_t *fv, wmem_strbuf_t *value);

/**
 * @brief Set the protocol value for a field value.
 *
 * @param fv Pointer to the field value structure.
 * @param value Pointer to the tvbuff containing the protocol data.
 * @param name Name of the protocol.
 * @param length Length of the protocol data.
 */
WS_DLL_PUBLIC
void
fvalue_set_protocol(fvalue_t *fv, tvbuff_t *value, const char *name, int length);

/**
 * @brief Set the protocol length for a fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param length The new protocol length to set.
 */
WS_DLL_PUBLIC
void
fvalue_set_protocol_length(fvalue_t *fv, int length);


/**
 * @brief Set the value of a fvalue_t to an unsigned 32-bit integer.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value The unsigned 32-bit integer value to set.
 */
WS_DLL_PUBLIC
void
fvalue_set_uinteger(fvalue_t *fv, uint32_t value);

/**
 * @brief Set the value of an fvalue_t to a signed 32-bit integer.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value The signed 32-bit integer value to set.
 */
WS_DLL_PUBLIC
void
fvalue_set_sinteger(fvalue_t *fv, int32_t value);

/**
 * @brief Set the value of a fvalue_t to an unsigned 64-bit integer.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value The unsigned 64-bit integer value to set.
 */
WS_DLL_PUBLIC
void
fvalue_set_uinteger64(fvalue_t *fv, uint64_t value);

/**
 * @brief Set the value of an fvalue_t to a 64-bit signed integer.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value The 64-bit signed integer value to set.
 */
WS_DLL_PUBLIC
void
fvalue_set_sinteger64(fvalue_t *fv, int64_t value);

/**
 * @brief Set the floating-point value of an fvalue_t.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value The double value to set.
 */
WS_DLL_PUBLIC
void
fvalue_set_floating(fvalue_t *fv, double value);

/**
 * @brief Set the IPv4 value of an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value Pointer to the ipv4_addr_and_mask structure containing the new value.
 */
WS_DLL_PUBLIC
void
fvalue_set_ipv4(fvalue_t *fv, const ipv4_addr_and_mask *value);

/**
 * @brief Set the IPv6 value of an fvalue_t.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @param value Pointer to the ipv6_addr_and_prefix structure containing the new value.
 */
WS_DLL_PUBLIC
void
fvalue_set_ipv6(fvalue_t *fv, const ipv6_addr_and_prefix *value);

/* GBytes reference count is automatically incremented. */
/**
 * @brief Get the bytes value from an fvalue_t.
 *
 * @param fv The fvalue_t containing the bytes value.
 * @return const void* A pointer to the bytes data.
 */
WS_DLL_PUBLIC
GBytes *
fvalue_get_bytes(fvalue_t *fv);

/**
 * @brief Get the size of the bytes data stored in an fvalue_t.
 *
 * @param fv Pointer to the fvalue_t containing the bytes data.
 * @return The size of the bytes data.
 */
WS_DLL_PUBLIC
size_t
fvalue_get_bytes_size(fvalue_t *fv);

/* Same as fvalue_length() */

/**
 * @brief Retrieves the bytes data from an fvalue_t.
 *
 * @param fv The fvalue_t to retrieve the bytes data from.
 * @return const void* A pointer to the bytes data.
 */
WS_DLL_PUBLIC
const void *
fvalue_get_bytes_data(fvalue_t *fv);

/**
 * @brief Retrieves a GUID value from an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure containing the GUID value.
 * @return const char* The GUID value as a string, or NULL if not applicable.
 */
WS_DLL_PUBLIC
const e_guid_t *
fvalue_get_guid(fvalue_t *fv);

/**
 * @brief Retrieves a time value from an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure containing the time value.
 * @return The time value as a pointer to an nstime_t structure.
 */
WS_DLL_PUBLIC
const nstime_t *
fvalue_get_time(fvalue_t *fv);

/**
 * @brief Get a string representation of an fvalue.
 *
 * @param fv Pointer to the fvalue structure.
 * @return A pointer to the string representation of the fvalue.
 */
WS_DLL_PUBLIC
const char *
fvalue_get_string(fvalue_t *fv);

/**
 * @brief Retrieves the string buffer value from an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @return tvbuff_t* Pointer to the tvbuff_t containing the string buffer, or NULL if not applicable.
 */
WS_DLL_PUBLIC
const wmem_strbuf_t *
fvalue_get_strbuf(fvalue_t *fv);

/**
 * @brief Get the protocol value from an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure containing the protocol value.
 * @return The protocol value as a uint32_t.
 */
WS_DLL_PUBLIC
tvbuff_t *
fvalue_get_protocol(fvalue_t *fv);

/**
 * @brief Get the unsigned integer value from an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure containing the value.
 * @return The unsigned integer value.
 */
WS_DLL_PUBLIC
uint32_t
fvalue_get_uinteger(fvalue_t *fv);

/**
 * @brief Retrieves a signed integer value from an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure containing the value.
 * @return The signed integer value.
 */
WS_DLL_PUBLIC
int32_t
fvalue_get_sinteger(fvalue_t *fv);

/**
 * @brief Retrieves an unsigned 64-bit integer value from a fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure containing the value.
 * @return The retrieved unsigned 64-bit integer value.
 */
WS_DLL_PUBLIC
uint64_t
fvalue_get_uinteger64(fvalue_t *fv);

/**
 * @brief Get the 64-bit signed integer value from an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure containing the value.
 * @return The 64-bit signed integer value.
 */
WS_DLL_PUBLIC
int64_t
fvalue_get_sinteger64(fvalue_t *fv);

/**
 * @brief Retrieves the floating-point value from an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure containing the floating-point value.
 * @return The floating-point value.
 */
WS_DLL_PUBLIC
double
fvalue_get_floating(fvalue_t *fv);

/**
 * @brief Retrieves the IPv4 address from an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure containing the IPv4 address.
 * @return The IPv4 address as a pointer to ipv4_addr_and_mask.
 */
WS_DLL_PUBLIC
const ipv4_addr_and_mask *
fvalue_get_ipv4(fvalue_t *fv);

/**
 * @brief Retrieves the IPv6 value from an fvalue_t structure.
 *
 * @param fv Pointer to the fvalue_t structure containing the IPv6 value.
 * @return The IPv6 address as a string.
 */
WS_DLL_PUBLIC
const ipv6_addr_and_prefix *
fvalue_get_ipv6(fvalue_t *fv);

/**
 * @brief Compares two fvalue_t structures for equality.
 *
 * @param a Pointer to the first fvalue_t structure.
 * @param b Pointer to the second fvalue_t structure.
 * @return ft_bool_t FT_TRUE if the values are equal, FT_FALSE otherwise.
 */
WS_DLL_PUBLIC
ft_bool_t
fvalue_eq(const fvalue_t *a, const fvalue_t *b);

/**
 * @brief Compares two fvalue_t structures for inequality.
 *
 * @param a Pointer to the first fvalue_t structure.
 * @param b Pointer to the second fvalue_t structure.
 * @return ft_bool_t FT_TRUE if the values are not equal, FT_FALSE otherwise.
 */
WS_DLL_PUBLIC
ft_bool_t
fvalue_ne(const fvalue_t *a, const fvalue_t *b);

/**
 * @brief Compares two fvalue_t structures to determine if the first is greater than the second.
 *
 * @param a Pointer to the first fvalue_t structure.
 * @param b Pointer to the second fvalue_t structure.
 * @return ft_bool_t FT_TRUE if a > b, otherwise FT_FALSE.
 */
WS_DLL_PUBLIC
ft_bool_t
fvalue_gt(const fvalue_t *a, const fvalue_t *b);

/**
 * @brief Compares two fvalue_t structures for greater than or equal to.
 *
 * @param a Pointer to the first fvalue_t structure.
 * @param b Pointer to the second fvalue_t structure.
 * @return ft_bool_t True if a is greater than or equal to b, False otherwise.
 */
WS_DLL_PUBLIC
ft_bool_t
fvalue_ge(const fvalue_t *a, const fvalue_t *b);

/**
 * @brief Compares two fvalue_t objects to determine if the first is less than the second.
 *
 * @param a Pointer to the first fvalue_t object.
 * @param b Pointer to the second fvalue_t object.
 * @return ft_bool_t FT_TRUE if a < b, otherwise FT_FALSE.
 */
WS_DLL_PUBLIC
ft_bool_t
fvalue_lt(const fvalue_t *a, const fvalue_t *b);

/**
 * @brief Compares two fvalue_t objects lexicographically.
 *
 * @param a Pointer to the first fvalue_t object.
 * @param b Pointer to the second fvalue_t object.
 * @return ft_bool_t FT_TRUE if a is less than or equal to b, otherwise FT_FALSE.
 */
WS_DLL_PUBLIC
ft_bool_t
fvalue_le(const fvalue_t *a, const fvalue_t *b);

/**
 * @brief Checks if one fvalue_t contains another.
 *
 * @param a The first fvalue_t to check.
 * @param b The second fvalue_t to check for containment within the first.
 * @return true If 'a' contains 'b'.
 * @return false Otherwise.
 */
WS_DLL_PUBLIC
ft_bool_t
fvalue_contains(const fvalue_t *a, const fvalue_t *b);

/**
 * @brief Checks if a fvalue_t matches a regular expression.
 *
 * @param a The fvalue_t to check.
 * @param re The regular expression to match against.
 * @return true If the fvalue_t matches the regular expression.
 * @return false If the fvalue_t does not match the regular expression.
 */
WS_DLL_PUBLIC
ft_bool_t
fvalue_matches(const fvalue_t *a, const ws_regex_t *re);

WS_DLL_PUBLIC
bool

/**
 * @brief Checks if a fvalue_t is zero.
 *
 * @param a Pointer to the fvalue_t to check.
 * @return true If the fvalue_t is zero, false otherwise.
 */
fvalue_is_zero(const fvalue_t *a);

/**
 * @brief Checks if a fvalue_t is negative.
 *
 * @param a Pointer to the fvalue_t to check.
 * @return true If the fvalue_t is negative, false otherwise.
 */
WS_DLL_PUBLIC
bool
fvalue_is_negative(const fvalue_t *a);

/**
 * @brief Checks if a fvalue_t is NaN.
 *
 * @param a Pointer to the fvalue_t to check.
 * @return true If the fvalue_t is NaN, false otherwise.
 */
WS_DLL_PUBLIC
bool
fvalue_is_nan(const fvalue_t *a);

/**
 * @brief Get the length of a fvalue_t.
 *
 * @param fv The fvalue_t to get the length from.
 * @return size_t The length of the fvalue_t, or 0 if an error occurs.
 */
WS_DLL_PUBLIC
size_t
fvalue_length2(fvalue_t *fv);

/**
 * @brief Slices a fvalue_t based on a drange_t.
 *
 * @param fv The fvalue_t to slice.
 * @param dr The range to slice the fvalue_t by.
 * @return A new fvalue_t containing the sliced data, or NULL if an error occurs.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_slice(fvalue_t *fv, drange_t *dr);

/**
 * @brief Perform a bitwise AND operation on two fvalue_t objects.
 *
 * @param a Pointer to the first fvalue_t object.
 * @param b Pointer to the second fvalue_t object.
 * @param err_msg Pointer to a string that will hold any error message if an error occurs.
 * @return Pointer to the result of the bitwise AND operation, or NULL on failure.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_bitwise_and(const fvalue_t *a, const fvalue_t *b, char **err_msg);

/**
 * @brief Applies unary minus operation to a fvalue.
 *
 * @param fv Pointer to the fvalue to apply the unary minus operation on.
 * @param err_msg Pointer to a string that will hold any error message if an error occurs.
 * @return Pointer to the resulting fvalue after applying the unary minus, or NULL if an error occurred.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_unary_minus(const fvalue_t *fv, char **err_msg);

/**
 * @brief Adds two fvalue_t objects.
 *
 * @param a The first fvalue_t object to add.
 * @param b The second fvalue_t object to add.
 * @param err_msg A pointer to a char pointer that will store any error message.
 * @return fvalue_t* A new fvalue_t object containing the result of the addition, or NULL on failure.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_add(const fvalue_t *a, const fvalue_t *b, char **err_msg);

/**
 * @brief Subtracts one fvalue from another.
 *
 * @param a The first fvalue to subtract from.
 * @param b The fvalue to subtract.
 * @param err_msg Pointer to store error message if any.
 * @return The result of the subtraction or NULL on failure.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_subtract(const fvalue_t *a, const fvalue_t *b, char **err_msg);

/**
 * @brief Multiplies two fvalue_t objects.
 *
 * @param a Pointer to the first fvalue_t object.
 * @param b Pointer to the second fvalue_t object.
 * @param err_msg Pointer to a string that will hold any error message if an error occurs.
 * @return A new fvalue_t object containing the result of the multiplication, or NULL on failure.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_multiply(const fvalue_t *a, const fvalue_t *b, char **err_msg);

/**
 * @brief Divides two fvalue_t objects.
 *
 * @param a Pointer to the first fvalue_t object.
 * @param b Pointer to the second fvalue_t object.
 * @param err_msg Pointer to a string that will hold an error message if an error occurs.
 * @return The result of the division as an fvalue_t object, or NULL on error.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_divide(const fvalue_t *a, const fvalue_t *b, char **err_msg);

/**
 * @brief Calculate the modulo of two fvalue_t objects.
 *
 * @param a Pointer to the first fvalue_t object.
 * @param b Pointer to the second fvalue_t object.
 * @param err_msg Pointer to store error message if any.
 * @return The result of the modulo operation as an fvalue_t object.
 */
WS_DLL_PUBLIC
fvalue_t*
fvalue_modulo(const fvalue_t *a, const fvalue_t *b, char **err_msg);

/**
 * @brief Calculate the hash value for a fvalue_t.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @return The calculated hash value.
 */
WS_DLL_PUBLIC
unsigned
fvalue_hash(const fvalue_t *fv);

/**
 * @brief Compares two fvalue_t structures for equality.
 *
 * This function checks if two fvalue_t structures are equal based on their values and types.
 *
 * @param a Pointer to the first fvalue_t structure.
 * @param b Pointer to the second fvalue_t structure.
 * @return FT_TRUE if the two fvalue_t structures are equal, FT_FALSE otherwise.
 */
WS_DLL_PUBLIC
bool
fvalue_equal(const fvalue_t *a, const fvalue_t *b);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
