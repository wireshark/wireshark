/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FTYPES_INT_H
#define FTYPES_INT_H

#include "ftypes.h"
#include <epan/proto.h>
#include <epan/packet.h>

/**
 * @brief Represents a typed field value used in protocol dissection.
 *
 * This structure encapsulates a value of a specific field type (`ftype`)
 * and stores it in a union of supported primitive and complex types.
 * It is used extensively in the display filter engine and dissector logic.
 */
struct _fvalue_t {
	const ftype_t *ftype; /**< Pointer to the field type descriptor. */

	union {
		uint64_t uinteger64;              /**< Unsigned 64-bit integer value. */
		int64_t sinteger64;               /**< Signed 64-bit integer value. */
		double floating;                  /**< Floating-point value. */
		wmem_strbuf_t *strbuf;            /**< Pointer to a string buffer. */
		GBytes *bytes;                    /**< Pointer to a byte array. */
		ipv4_addr_and_mask ipv4;          /**< IPv4 address with subnet mask. */
		ipv6_addr_and_prefix ipv6;        /**< IPv6 address with prefix length. */
		e_guid_t guid;                    /**< Globally Unique Identifier (GUID). */
		nstime_t time;                    /**< Time value (seconds and nanoseconds). */
		protocol_value_t protocol;        /**< Protocol-specific value. */
		uint16_t sfloat_ieee_11073;       /**< IEEE 11073 16-bit SFLOAT format. */
		uint32_t float_ieee_11073;        /**< IEEE 11073 32-bit FLOAT format. */
	} value; /**< Union holding the actual field value. */
};

extern const ftype_t* type_list[FT_ENUM_SIZE + 1];

/* Given an ftenum number, return an ftype_t* */
#define FTYPE_LOOKUP(ftype, result)		\
	/* Check input */			\
	ws_assert(ftype < FT_NUM_TYPES);	\
	result = type_list[ftype];

typedef void (*FvalueNewFunc)(fvalue_t*);
typedef void (*FvalueCopyFunc)(fvalue_t*, const fvalue_t*);
typedef void (*FvalueFreeFunc)(fvalue_t*);

typedef bool (*FvalueFromLiteral)(fvalue_t*, const char*, bool, char **);
typedef bool (*FvalueFromString)(fvalue_t*, const char*, size_t, char **);
typedef bool (*FvalueFromCharConst)(fvalue_t*, unsigned long, char **);
typedef bool (*FvalueFromUnsignedInt64)(fvalue_t*, const char *, uint64_t, char **);
typedef bool (*FvalueFromSignedInt64)(fvalue_t*, const char *, int64_t, char **);
typedef bool (*FvalueFromDouble)(fvalue_t*, const char *, double, char **);

typedef char *(*FvalueToStringRepr)(wmem_allocator_t *, const fvalue_t*, ftrepr_t, int field_display);

typedef enum ft_result (*FvalueToUnsignedInt64)(const fvalue_t*, uint64_t *);
typedef enum ft_result (*FvalueToSignedInt64)(const fvalue_t*, int64_t *);
typedef enum ft_result (*FvalueToDouble)(const fvalue_t*, double *);

typedef void (*FvalueSetBytesFunc)(fvalue_t*, GBytes *);
typedef void (*FvalueSetGuidFunc)(fvalue_t*, const e_guid_t *);
typedef void (*FvalueSetTimeFunc)(fvalue_t*, const nstime_t *);
typedef void (*FvalueSetStrbufFunc)(fvalue_t*, wmem_strbuf_t *);
typedef void (*FvalueSetProtocolFunc)(fvalue_t*, tvbuff_t *value, const char *name, int length);
typedef void (*FvalueSetUnsignedIntegerFunc)(fvalue_t*, uint32_t);
typedef void (*FvalueSetSignedIntegerFunc)(fvalue_t*, int32_t);
typedef void (*FvalueSetUnsignedInteger64Func)(fvalue_t*, uint64_t);
typedef void (*FvalueSetSignedInteger64Func)(fvalue_t*, int64_t);
typedef void (*FvalueSetFloatingFunc)(fvalue_t*, double);
typedef void (*FvalueSetIpv4Func)(fvalue_t*, const ipv4_addr_and_mask *);
typedef void (*FvalueSetIpv6Func)(fvalue_t*, const ipv6_addr_and_prefix *);

typedef GBytes *(*FvalueGetBytesFunc)(fvalue_t*);
typedef const e_guid_t *(*FvalueGetGuidFunc)(fvalue_t*);
typedef const nstime_t *(*FvalueGetTimeFunc)(fvalue_t*);
typedef const wmem_strbuf_t *(*FvalueGetStrbufFunc)(fvalue_t*);
typedef tvbuff_t *(*FvalueGetProtocolFunc)(fvalue_t*);
typedef uint32_t (*FvalueGetUnsignedIntegerFunc)(fvalue_t*);
typedef int32_t (*FvalueGetSignedIntegerFunc)(fvalue_t*);
typedef uint64_t (*FvalueGetUnsignedInteger64Func)(fvalue_t*);
typedef int64_t (*FvalueGetSignedInteger64Func)(fvalue_t*);
typedef double (*FvalueGetFloatingFunc)(fvalue_t*);
typedef const ipv4_addr_and_mask *(*FvalueGetIpv4Func)(fvalue_t*);
typedef const ipv6_addr_and_prefix *(*FvalueGetIpv6Func)(fvalue_t*);

typedef enum ft_result (*FvalueCompare)(const fvalue_t*, const fvalue_t*, int*);
typedef enum ft_result (*FvalueContains)(const fvalue_t*, const fvalue_t*, bool*);
typedef enum ft_result (*FvalueMatches)(const fvalue_t*, const ws_regex_t*, bool*);

typedef bool (*FvalueIs)(const fvalue_t*);
typedef unsigned (*FvalueLen)(fvalue_t*);
typedef unsigned (*FvalueHashFunc)(const fvalue_t *);
typedef void (*FvalueSlice)(fvalue_t*, void *, unsigned offset, unsigned length);
typedef enum ft_result (*FvalueUnaryOp)(fvalue_t *, const fvalue_t*, char **);
typedef enum ft_result (*FvalueBinaryOp)(fvalue_t *, const fvalue_t*, const fvalue_t*, char **);

/**
 * @brief Describes a field type and its associated operations for display filtering.
 *
 * This structure defines the behavior of a specific field type (`ftenum_t`) used in
 * protocol dissection and display filtering. It includes functions for creating,
 * converting, comparing, and manipulating values of that type.
 */
struct _ftype_t {
	ftenum_t ftype;              /**< Enum identifier for the field type. */
	int wire_size;               /**< Size of the field on the wire, in bytes. */

	FvalueNewFunc new_value;     /**< Function to allocate a new value of this type. */
	FvalueCopyFunc copy_value;   /**< Function to copy a value of this type. */
	FvalueFreeFunc free_value;   /**< Function to free a value of this type. */

	FvalueFromLiteral val_from_literal;         /**< Converts from a literal token. */
	FvalueFromString val_from_string;           /**< Converts from a string representation. */
	FvalueFromCharConst val_from_charconst;     /**< Converts from a character constant. */
	FvalueFromUnsignedInt64 val_from_uinteger64;/**< Converts from a 64-bit unsigned integer. */
	FvalueFromSignedInt64 val_from_sinteger64;  /**< Converts from a 64-bit signed integer. */
	FvalueFromDouble val_from_double;           /**< Converts from a double-precision float. */

	FvalueToStringRepr val_to_string_repr;      /**< Converts to a string representation. */

	FvalueToUnsignedInt64 val_to_uinteger64;    /**< Converts to a 64-bit unsigned integer. */
	FvalueToSignedInt64 val_to_sinteger64;      /**< Converts to a 64-bit signed integer. */
	FvalueToDouble val_to_double;               /**< Converts to a double-precision float. */

	/**
	 * @brief Union of function pointers for setting typed field values.
	 *
	 * Provides type-specific setter functions for assigning values to `fvalue_t`.
	 */
	union {
		FvalueSetBytesFunc set_value_bytes;             /**< Sets a byte array value. */
		FvalueSetGuidFunc set_value_guid;               /**< Sets a GUID value. */
		FvalueSetTimeFunc set_value_time;               /**< Sets a time value. */
		FvalueSetStrbufFunc set_value_strbuf;           /**< Sets a string buffer value. */
		FvalueSetProtocolFunc set_value_protocol;       /**< Sets a protocol-specific value. */
		FvalueSetUnsignedIntegerFunc set_value_uinteger;/**< Sets an unsigned integer value. */
		FvalueSetSignedIntegerFunc set_value_sinteger;  /**< Sets a signed integer value. */
		FvalueSetUnsignedInteger64Func set_value_uinteger64; /**< Sets a 64-bit unsigned integer. */
		FvalueSetSignedInteger64Func set_value_sinteger64;   /**< Sets a 64-bit signed integer. */
		FvalueSetFloatingFunc set_value_floating;       /**< Sets a floating-point value. */
		FvalueSetIpv4Func set_value_ipv4;               /**< Sets an IPv4 address value. */
		FvalueSetIpv6Func set_value_ipv6;               /**< Sets an IPv6 address value. */
	} set_value;

    /**
     * @brief Union of function pointers for retrieving typed field values.
     *
     * Provides type-specific getter functions for extracting values from `fvalue_t`.
     */
	union {
		FvalueGetBytesFunc get_value_bytes;             /**< Gets a byte array value. */
		FvalueGetGuidFunc get_value_guid;               /**< Gets a GUID value. */
		FvalueGetTimeFunc get_value_time;               /**< Gets a time value. */
		FvalueGetStrbufFunc get_value_strbuf;           /**< Gets a string buffer value. */
		FvalueGetProtocolFunc get_value_protocol;       /**< Gets a protocol-specific value. */
		FvalueGetUnsignedIntegerFunc get_value_uinteger;/**< Gets an unsigned integer value. */
		FvalueGetSignedIntegerFunc get_value_sinteger;  /**< Gets a signed integer value. */
		FvalueGetUnsignedInteger64Func get_value_uinteger64; /**< Gets a 64-bit unsigned integer. */
		FvalueGetSignedInteger64Func get_value_sinteger64;   /**< Gets a 64-bit signed integer. */
		FvalueGetFloatingFunc get_value_floating;       /**< Gets a floating-point value. */
		FvalueGetIpv4Func get_value_ipv4;               /**< Gets an IPv4 address value. */
		FvalueGetIpv6Func get_value_ipv6;               /**< Gets an IPv6 address value. */
	} get_value;

	FvalueCompare compare;       /**< Compares two values of this type. */
	FvalueContains contains;     /**< Checks if one value contains another. */
	FvalueMatches matches;       /**< Checks if a value matches a pattern. */

	FvalueHashFunc hash;         /**< Computes a hash of the value. */
	FvalueIs is_zero;            /**< Checks if the value is zero. */
	FvalueIs is_negative;        /**< Checks if the value is negative. */
	FvalueIs is_nan;             /**< Checks if the value is NaN. */
	FvalueLen len;               /**< Returns the length of the value. */
	FvalueSlice slice;           /**< Extracts a slice from the value. */

	FvalueBinaryOp bitwise_and;  /**< Bitwise AND operation. */
	FvalueUnaryOp unary_minus;   /**< Unary negation operation. */
	FvalueBinaryOp add;          /**< Addition operation. */
	FvalueBinaryOp subtract;     /**< Subtraction operation. */
	FvalueBinaryOp multiply;     /**< Multiplication operation. */
	FvalueBinaryOp divide;       /**< Division operation. */
	FvalueBinaryOp modulo;       /**< Modulo operation. */
};

void ftype_register(enum ftenum ftype, const ftype_t *ft);

void ftype_register_bytes(void);
void ftype_register_double(void);
void ftype_register_ieee_11073_float(void);
void ftype_register_integers(void);
void ftype_register_ipv4(void);
void ftype_register_ipv6(void);
void ftype_register_guid(void);
void ftype_register_none(void);
void ftype_register_string(void);
void ftype_register_time(void);
void ftype_register_tvbuff(void);

/* For debugging. */
void ftype_register_pseudofields_bytes(int proto);
void ftype_register_pseudofields_double(int proto);
void ftype_register_pseudofields_ieee_11073_float(int proto);
void ftype_register_pseudofields_integer(int proto);
void ftype_register_pseudofields_ipv4(int proto);
void ftype_register_pseudofields_ipv6(int proto);
void ftype_register_pseudofields_guid(int proto);
void ftype_register_pseudofields_none(int proto);
void ftype_register_pseudofields_string(int proto);
void ftype_register_pseudofields_time(int proto);
void ftype_register_pseudofields_tvbuff(int proto);

GByteArray *
byte_array_from_literal(const char *s, char **err_msg);

GByteArray *
byte_array_from_charconst(unsigned long num, char **err_msg);

char *
bytes_to_dfilter_repr(wmem_allocator_t *scope,
			const uint8_t *src, size_t src_size);

#endif /* FTYPES_INT_H */

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
