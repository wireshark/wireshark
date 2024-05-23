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

struct _fvalue_t {
	const ftype_t	*ftype;
	union {
		/* Put a few basic types in here */
		uint64_t		uinteger64;
		int64_t			sinteger64;
		double			floating;
		wmem_strbuf_t		*strbuf;
		GBytes			*bytes;
		ipv4_addr_and_mask	ipv4;
		ipv6_addr_and_prefix	ipv6;
		e_guid_t		guid;
		nstime_t		time;
		protocol_value_t 	protocol;
		uint16_t		sfloat_ieee_11073;
		uint32_t		float_ieee_11073;
	} value;
};

extern const ftype_t* type_list[FT_NUM_TYPES];

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

struct _ftype_t {
	ftenum_t		ftype;
	int			wire_size;
	FvalueNewFunc		new_value;
	FvalueCopyFunc		copy_value;
	FvalueFreeFunc		free_value;

	FvalueFromLiteral	val_from_literal;
	FvalueFromString	val_from_string;
	FvalueFromCharConst	val_from_charconst;
	FvalueFromUnsignedInt64	val_from_uinteger64;
	FvalueFromSignedInt64	val_from_sinteger64;
	FvalueFromDouble	val_from_double;

	FvalueToStringRepr	val_to_string_repr;

	FvalueToUnsignedInt64	val_to_uinteger64;
	FvalueToSignedInt64	val_to_sinteger64;
	FvalueToDouble		val_to_double;

	union {
		FvalueSetBytesFunc		set_value_bytes;
		FvalueSetGuidFunc		set_value_guid;
		FvalueSetTimeFunc		set_value_time;
		FvalueSetStrbufFunc		set_value_strbuf;
		FvalueSetProtocolFunc		set_value_protocol;
		FvalueSetUnsignedIntegerFunc	set_value_uinteger;
		FvalueSetSignedIntegerFunc	set_value_sinteger;
		FvalueSetUnsignedInteger64Func	set_value_uinteger64;
		FvalueSetSignedInteger64Func	set_value_sinteger64;
		FvalueSetFloatingFunc		set_value_floating;
		FvalueSetIpv4Func		set_value_ipv4;
		FvalueSetIpv6Func		set_value_ipv6;
	} set_value;

	union {
		FvalueGetBytesFunc		get_value_bytes;
		FvalueGetGuidFunc		get_value_guid;
		FvalueGetTimeFunc		get_value_time;
		FvalueGetStrbufFunc		get_value_strbuf;
		FvalueGetProtocolFunc		get_value_protocol;
		FvalueGetUnsignedIntegerFunc	get_value_uinteger;
		FvalueGetSignedIntegerFunc	get_value_sinteger;
		FvalueGetUnsignedInteger64Func	get_value_uinteger64;
		FvalueGetSignedInteger64Func	get_value_sinteger64;
		FvalueGetFloatingFunc		get_value_floating;
		FvalueGetIpv4Func		get_value_ipv4;
		FvalueGetIpv6Func		get_value_ipv6;
	} get_value;

	FvalueCompare		compare;
	FvalueContains		contains;
	FvalueMatches		matches;

	FvalueHashFunc		hash;
	FvalueIs		is_zero;
	FvalueIs		is_negative;
	FvalueLen		len;
	FvalueSlice		slice;
	FvalueBinaryOp		bitwise_and;
	FvalueUnaryOp		unary_minus;
	FvalueBinaryOp		add;
	FvalueBinaryOp		subtract;
	FvalueBinaryOp		multiply;
	FvalueBinaryOp		divide;
	FvalueBinaryOp		modulo;
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
