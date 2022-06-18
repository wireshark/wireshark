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

extern ftype_t* type_list[FT_NUM_TYPES];

/* Given an ftenum number, return an ftype_t* */
#define FTYPE_LOOKUP(ftype, result)		\
	/* Check input */			\
	ws_assert(ftype < FT_NUM_TYPES);	\
	result = type_list[ftype];

enum ft_result {
	FT_OK,
	FT_ERROR,
};

typedef void (*FvalueNewFunc)(fvalue_t*);
typedef void (*FvalueCopyFunc)(fvalue_t*, const fvalue_t*);
typedef void (*FvalueFreeFunc)(fvalue_t*);

typedef gboolean (*FvalueFromLiteral)(fvalue_t*, const char*, gboolean, gchar **);
typedef gboolean (*FvalueFromString)(fvalue_t*, const char*, gchar **);
typedef gboolean (*FvalueFromCharConst)(fvalue_t*, unsigned long, gchar **);
typedef char *(*FvalueToStringRepr)(wmem_allocator_t *, const fvalue_t*, ftrepr_t, int field_display);

typedef void (*FvalueSetByteArrayFunc)(fvalue_t*, GByteArray *);
typedef void (*FvalueSetBytesFunc)(fvalue_t*, const guint8 *);
typedef void (*FvalueSetGuidFunc)(fvalue_t*, const e_guid_t *);
typedef void (*FvalueSetTimeFunc)(fvalue_t*, const nstime_t *);
typedef void (*FvalueSetStringFunc)(fvalue_t*, const gchar *value);
typedef void (*FvalueSetProtocolFunc)(fvalue_t*, tvbuff_t *value, const gchar *name, int length);
typedef void (*FvalueSetUnsignedIntegerFunc)(fvalue_t*, guint32);
typedef void (*FvalueSetSignedIntegerFunc)(fvalue_t*, gint32);
typedef void (*FvalueSetUnsignedInteger64Func)(fvalue_t*, guint64);
typedef void (*FvalueSetSignedInteger64Func)(fvalue_t*, gint64);
typedef void (*FvalueSetFloatingFunc)(fvalue_t*, gdouble);

typedef const guint8 *(*FvalueGetBytesFunc)(fvalue_t*);
typedef const e_guid_t *(*FvalueGetGuidFunc)(fvalue_t*);
typedef const nstime_t *(*FvalueGetTimeFunc)(fvalue_t*);
typedef const gchar *(*FvalueGetStringFunc)(fvalue_t*);
typedef tvbuff_t *(*FvalueGetProtocolFunc)(fvalue_t*);
typedef guint32 (*FvalueGetUnsignedIntegerFunc)(fvalue_t*);
typedef gint32  (*FvalueGetSignedIntegerFunc)(fvalue_t*);
typedef guint64 (*FvalueGetUnsignedInteger64Func)(fvalue_t*);
typedef gint64 (*FvalueGetSignedInteger64Func)(fvalue_t*);
typedef double (*FvalueGetFloatingFunc)(fvalue_t*);

typedef int (*FvalueCmp)(const fvalue_t*, const fvalue_t*);
typedef gboolean (*FvalueContains)(const fvalue_t*, const fvalue_t*);
typedef gboolean (*FvalueMatches)(const fvalue_t*, const ws_regex_t*);

typedef gboolean (*FvalueIs)(const fvalue_t*);
typedef guint (*FvalueLen)(fvalue_t*);
typedef void (*FvalueSlice)(fvalue_t*, GByteArray *, guint offset, guint length);
typedef enum ft_result (*FvalueUnaryOp)(fvalue_t *, const fvalue_t*, gchar **);
typedef enum ft_result (*FvalueBinaryOp)(fvalue_t *, const fvalue_t*, const fvalue_t*, gchar **);

struct _ftype_t {
	ftenum_t		ftype;
	const char		*name;
	const char		*pretty_name;
	int			wire_size;
	FvalueNewFunc		new_value;
	FvalueCopyFunc		copy_value;
	FvalueFreeFunc		free_value;
	FvalueFromLiteral	val_from_literal;
	FvalueFromString	val_from_string;
	FvalueFromCharConst	val_from_charconst;
	FvalueToStringRepr	val_to_string_repr;

	union {
		FvalueSetByteArrayFunc		set_value_byte_array;
		FvalueSetBytesFunc		set_value_bytes;
		FvalueSetGuidFunc		set_value_guid;
		FvalueSetTimeFunc		set_value_time;
		FvalueSetStringFunc		set_value_string;
		FvalueSetProtocolFunc		set_value_protocol;
		FvalueSetUnsignedIntegerFunc	set_value_uinteger;
		FvalueSetSignedIntegerFunc	set_value_sinteger;
		FvalueSetUnsignedInteger64Func	set_value_uinteger64;
		FvalueSetSignedInteger64Func	set_value_sinteger64;
		FvalueSetFloatingFunc		set_value_floating;
	} set_value;

	union {
		FvalueGetBytesFunc		get_value_bytes;
		FvalueGetGuidFunc		get_value_guid;
		FvalueGetTimeFunc		get_value_time;
		FvalueGetStringFunc		get_value_string;
		FvalueGetProtocolFunc		get_value_protocol;
		FvalueGetUnsignedIntegerFunc	get_value_uinteger;
		FvalueGetSignedIntegerFunc	get_value_sinteger;
		FvalueGetUnsignedInteger64Func	get_value_uinteger64;
		FvalueGetSignedInteger64Func	get_value_sinteger64;
		FvalueGetFloatingFunc		get_value_floating;
	} get_value;

	FvalueCmp		cmp_order;
	FvalueContains		cmp_contains;
	FvalueMatches		cmp_matches;

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

void ftype_register(enum ftenum ftype, ftype_t *ft);

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

void ftype_register_pseudofields_bytes(int proto);
void ftype_register_pseudofields_double(int proto);
void ftype_register_pseudofields_ieee_11073_float(int proto);
void ftype_register_pseudofields_integer(int proto);
void ftype_register_pseudofields_ipv4(int proto);
void ftype_register_pseudofields_ipv6(int proto);
void ftype_register_pseudofields_guid(int proto);
void ftype_register_pseudofields_string(int proto);
void ftype_register_pseudofields_time(int proto);
void ftype_register_pseudofields_tvbuff(int proto);

GByteArray *
byte_array_from_literal(const char *s, gchar **err_msg);

GByteArray *
byte_array_from_charconst(unsigned long num, gchar **err_msg);

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
