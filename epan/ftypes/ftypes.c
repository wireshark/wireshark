/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "ftypes-int.h"

#include <wsutil/ws_assert.h>

/* Keep track of ftype_t's via their ftenum number */
const ftype_t* type_list[FT_NUM_TYPES];

/* Initialize the ftype module. */
void
ftypes_initialize(void)
{
	ftype_register_bytes();
	ftype_register_double();
	ftype_register_ieee_11073_float();
	ftype_register_integers();
	ftype_register_ipv4();
	ftype_register_ipv6();
	ftype_register_guid();
	ftype_register_none();
	ftype_register_string();
	ftype_register_time();
	ftype_register_tvbuff();
}

void
ftypes_register_pseudofields(void)
{
	static int proto_ftypes;

	proto_ftypes = proto_register_protocol(
				"Wireshark Field/Fundamental Types",
				"Wireshark FTypes",
				"_ws.ftypes");

	ftype_register_pseudofields_bytes(proto_ftypes);
	ftype_register_pseudofields_double(proto_ftypes);
	ftype_register_pseudofields_ieee_11073_float(proto_ftypes);
	ftype_register_pseudofields_integer(proto_ftypes);
	ftype_register_pseudofields_ipv4(proto_ftypes);
	ftype_register_pseudofields_ipv6(proto_ftypes);
	ftype_register_pseudofields_guid(proto_ftypes);
	ftype_register_pseudofields_none(proto_ftypes);
	ftype_register_pseudofields_string(proto_ftypes);
	ftype_register_pseudofields_time(proto_ftypes);
	ftype_register_pseudofields_tvbuff(proto_ftypes);

	proto_set_cant_toggle(proto_ftypes);
}

/* Each ftype_t is registered via this function */
void
ftype_register(enum ftenum ftype, const ftype_t *ft)
{
	/* Check input */
	ws_assert(ftype < FT_NUM_TYPES);
	ws_assert(ftype == ft->ftype);

	/* Don't re-register. */
	ws_assert(type_list[ftype] == NULL);

	type_list[ftype] = ft;
}


/* from README.dissector:
	Note that the formats used must all belong to the same list as defined below:
	- FT_INT8, FT_INT16, FT_INT24 and FT_INT32
	- FT_UINT8, FT_UINT16, FT_UINT24, FT_UINT32, FT_IPXNET and FT_FRAMENUM
	- FT_UINT64 and FT_EUI64
	- FT_STRING, FT_STRINGZ and FT_UINT_STRING
	- FT_FLOAT and FT_DOUBLE
	- FT_BYTES, FT_UINT_BYTES, FT_AX25, FT_ETHER, FT_VINES, FT_OID and FT_REL_OID
	- FT_ABSOLUTE_TIME and FT_RELATIVE_TIME
*/
static enum ftenum
same_ftype(const enum ftenum ftype)
{
	switch (ftype) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			return FT_INT32;

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			return FT_UINT32;

		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			return FT_INT64;

		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
			return FT_UINT64;

		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
			return FT_STRING;

		case FT_FLOAT:
		case FT_DOUBLE:
			return FT_DOUBLE;

		case FT_BYTES:
		case FT_UINT_BYTES:
			return FT_BYTES;

		case FT_OID:
		case FT_REL_OID:
			return FT_OID;

		/* XXX: the following are unique for now */
		case FT_IPv4:
		case FT_IPv6:

		/* everything else is unique */
		default:
			return ftype;
	}
}

/* given two types, are they similar - for example can two
 * duplicate fields be registered of these two types. */
bool
ftype_similar_types(const enum ftenum ftype_a, const enum ftenum ftype_b)
{
	return (same_ftype(ftype_a) == same_ftype(ftype_b));
}

/* Returns a string representing the name of the type. Useful
 * for glossary production. */
const char*
ftype_name(enum ftenum ftype)
{
	const ftype_t	*ft;
	const char *s = "(null)";

	FTYPE_LOOKUP(ftype, ft);
	switch (ft->ftype) {
		case FT_NONE:		s = "FT_NONE"; break;
		case FT_PROTOCOL:	s = "FT_PROTOCOL"; break;
		case FT_BOOLEAN:	s = "FT_BOOLEAN"; break;
		case FT_CHAR:		s = "FT_CHAR"; break;
		case FT_UINT8:		s = "FT_UINT8"; break;
		case FT_UINT16:		s = "FT_UINT16"; break;
		case FT_UINT24:		s = "FT_UINT24"; break;
		case FT_UINT32:		s = "FT_UINT32"; break;
		case FT_UINT40:		s = "FT_UINT40"; break;
		case FT_UINT48:		s = "FT_UINT48"; break;
		case FT_UINT56:		s = "FT_UINT56"; break;
		case FT_UINT64:		s = "FT_UINT64"; break;
		case FT_INT8:		s = "FT_INT8"; break;
		case FT_INT16:		s = "FT_INT16"; break;
		case FT_INT24:		s = "FT_INT24"; break;
		case FT_INT32:		s = "FT_INT32"; break;
		case FT_INT40:		s = "FT_INT40"; break;
		case FT_INT48:		s = "FT_INT48"; break;
		case FT_INT56:		s = "FT_INT56"; break;
		case FT_INT64:		s = "FT_INT64"; break;
		case FT_IEEE_11073_SFLOAT: s = "FT_IEEE_11073_SFLOAT"; break;
		case FT_IEEE_11073_FLOAT: s = "FT_IEEE_11073_FLOAT"; break;
		case FT_FLOAT:		s = "FT_FLOAT"; break;
		case FT_DOUBLE:		s = "FT_DOUBLE"; break;
		case FT_ABSOLUTE_TIME:	s = "FT_ABSOLUTE_TIME"; break;
		case FT_RELATIVE_TIME:	s = "FT_RELATIVE_TIME"; break;
		case FT_STRING:		s = "FT_STRING"; break;
		case FT_STRINGZ:	s = "FT_STRINGZ"; break;
		case FT_UINT_STRING:	s = "FT_UINT_STRING"; break;
		case FT_ETHER:		s = "FT_ETHER"; break;
		case FT_BYTES:		s = "FT_BYTES"; break;
		case FT_UINT_BYTES:	s = "FT_UINT_BYTES"; break;
		case FT_IPv4:		s = "FT_IPv4"; break;
		case FT_IPv6:		s = "FT_IPv6"; break;
		case FT_IPXNET:		s = "FT_IPXNET"; break;
		case FT_FRAMENUM:	s = "FT_FRAMENUM"; break;
		case FT_GUID:		s = "FT_GUID"; break;
		case FT_OID:		s = "FT_OID"; break;
		case FT_EUI64:		s = "FT_EUI64"; break;
		case FT_AX25:		s = "FT_AX25"; break;
		case FT_VINES:		s = "FT_VINES"; break;
		case FT_REL_OID:	s = "FT_REL_OID"; break;
		case FT_SYSTEM_ID:	s = "FT_SYSTEM_ID"; break;
		case FT_STRINGZPAD:	s = "FT_STRINGZPAD"; break;
		case FT_FCWWN:		s = "FT_FCWWN"; break;
		case FT_STRINGZTRUNC:	s = "FT_STRINGZTRUNC"; break;
		case FT_NUM_TYPES:	s = "FT_NUM_TYPES"; break;
		case FT_SCALAR:		s = "FT_SCALAR"; break;
	}
	return s;
}

const char*
ftype_pretty_name(enum ftenum ftype)
{
	const ftype_t	*ft;
	const char *s = "(null)";

	FTYPE_LOOKUP(ftype, ft);
	switch (ft->ftype) {
		case FT_NONE:		s = "Label"; break;
		case FT_PROTOCOL:	s = "Protocol"; break;
		case FT_BOOLEAN:	s = "Boolean"; break;
		case FT_CHAR:		s = "Character (8 bits)"; break;
		case FT_UINT8:		s = "Unsigned integer (8 bits)"; break;
		case FT_UINT16:		s = "Unsigned integer (16 bits)"; break;
		case FT_UINT24:		s = "Unsigned integer (24 bits)"; break;
		case FT_UINT32:		s = "Unsigned integer (32 bits)"; break;
		case FT_UINT40:		s = "Unsigned integer (40 bits)"; break;
		case FT_UINT48:		s = "Unsigned integer (48 bits)"; break;
		case FT_UINT56:		s = "Unsigned integer (56 bits)"; break;
		case FT_UINT64:		s = "Unsigned integer (64 bits)"; break;
		case FT_INT8:		s = "Signed integer (8 bits)"; break;
		case FT_INT16:		s = "Signed integer (16 bits)"; break;
		case FT_INT24:		s = "Signed integer (24 bits)"; break;
		case FT_INT32:		s = "Signed integer (32 bits)"; break;
		case FT_INT40:		s = "Signed integer (40 bits)"; break;
		case FT_INT48:		s = "Signed integer (48 bits)"; break;
		case FT_INT56:		s = "Signed integer (56 bits)"; break;
		case FT_INT64:		s = "Signed integer (64 bits)"; break;
		case FT_IEEE_11073_SFLOAT: s = "IEEE-11073 floating point (16-bit)"; break;
		case FT_IEEE_11073_FLOAT: s = "IEEE-11073 Floating point (32-bit)"; break;
		case FT_FLOAT:		s = "Floating point (single-precision)"; break;
		case FT_DOUBLE:		s = "Floating point (double-precision)"; break;
		case FT_ABSOLUTE_TIME:	s = "Date and time"; break;
		case FT_RELATIVE_TIME:	s = "Time offset"; break;
		case FT_STRING:		s = "Character string"; break;
		case FT_STRINGZ:	s = "Character string"; break;
		case FT_UINT_STRING:	s = "Character string"; break;
		case FT_ETHER:		s = "Ethernet or other MAC address"; break;
		case FT_BYTES:		s = "Byte sequence"; break;
		case FT_UINT_BYTES:	s = "Byte sequence"; break;
		case FT_IPv4:		s = "IPv4 address"; break;
		case FT_IPv6:		s = "IPv6 address"; break;
		case FT_IPXNET:		s = "IPX network number"; break;
		case FT_FRAMENUM:	s = "Frame number"; break;
		case FT_GUID:		s = "Globally Unique Identifier"; break;
		case FT_OID:		s = "ASN.1 object identifier"; break;
		case FT_EUI64:		s = "EUI64 address"; break;
		case FT_AX25:		s = "AX.25 address"; break;
		case FT_VINES:		s = "VINES address"; break;
		case FT_REL_OID:	s = "ASN.1 relative object identifier"; break;
		case FT_SYSTEM_ID:	s = "OSI System-ID"; break;
		case FT_STRINGZPAD:	s = "Character string"; break;
		case FT_FCWWN:		s = "Fibre Channel WWN"; break;
		case FT_STRINGZTRUNC:	s = "Character string"; break;
		case FT_NUM_TYPES:	s = "(num types)"; break;
		case FT_SCALAR:		s = "Scalar"; break;
	}
	return s;
}

int
ftype_wire_size(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->wire_size;
}

bool
ftype_can_length(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->len ? true : false;
}

bool
ftype_can_slice(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->slice ? true : false;
}

bool
ftype_can_eq(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->compare != NULL;
}

bool
ftype_can_cmp(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->compare != NULL;
}

bool
ftype_can_bitwise_and(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->bitwise_and ? true : false;
}

bool
ftype_can_unary_minus(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->unary_minus != NULL;
}

bool
ftype_can_add(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->add != NULL;
}

bool
ftype_can_subtract(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->subtract != NULL;
}

bool
ftype_can_multiply(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->multiply != NULL;
}

bool
ftype_can_divide(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->divide != NULL;
}

bool
ftype_can_modulo(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->modulo != NULL;
}

bool
ftype_can_contains(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->contains ? true : false;
}

bool
ftype_can_matches(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->matches ? true : false;
}

bool
ftype_can_is_zero(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->is_zero ? true : false;
}

bool
ftype_can_is_negative(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->is_negative ? true : false;
}

bool
ftype_can_val_to_sinteger(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	/* We first convert to 64 bit and then check for overflow. */
	return ft->val_to_sinteger64 ? true : false;
}

bool
ftype_can_val_to_uinteger(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	/* We first convert to 64 bit and then check for overflow. */
	return ft->val_to_uinteger64 ? true : false;
}

bool
ftype_can_val_to_sinteger64(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->val_to_sinteger64 ? true : false;
}

bool
ftype_can_val_to_uinteger64(enum ftenum ftype)
{
	const ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->val_to_uinteger64 ? true : false;
}

/* ---------------------------------------------------------- */

/* Allocate and initialize an fvalue_t, given an ftype */
fvalue_t*
fvalue_new(ftenum_t ftype)
{
	fvalue_t		*fv;
	const ftype_t		*ft;
	FvalueNewFunc		new_value;

	fv = g_slice_new(fvalue_t);

	FTYPE_LOOKUP(ftype, ft);
	fv->ftype = ft;

	new_value = ft->new_value;
	if (new_value) {
		new_value(fv);
	}

	return fv;
}

fvalue_t*
fvalue_dup(const fvalue_t *fv_orig)
{
	fvalue_t		*fv_new;
	FvalueCopyFunc		copy_value;

	fv_new = g_slice_new(fvalue_t);
	fv_new->ftype = fv_orig->ftype;
	copy_value = fv_new->ftype->copy_value;
	if (copy_value != NULL) {
		/* deep copy */
		copy_value(fv_new, fv_orig);
	}
	else {
		/* shallow copy */
		memcpy(&fv_new->value, &fv_orig->value, sizeof(fv_orig->value));
	}

	return fv_new;
}

void
fvalue_init(fvalue_t *fv, ftenum_t ftype)
{
	const ftype_t		*ft;
	FvalueNewFunc		new_value;

	FTYPE_LOOKUP(ftype, ft);
	fv->ftype = ft;

	new_value = ft->new_value;
	if (new_value) {
		new_value(fv);
	}
}

void
fvalue_cleanup(fvalue_t *fv)
{
	if (!fv->ftype->free_value)
		return;
	fv->ftype->free_value(fv);
}

void
fvalue_free(fvalue_t *fv)
{
	fvalue_cleanup(fv);
	g_slice_free(fvalue_t, fv);
}

fvalue_t*
fvalue_from_literal(ftenum_t ftype, const char *s, bool allow_partial_value, char **err_msg)
{
	fvalue_t	*fv;
	bool ok = false;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_literal) {
		ok = fv->ftype->val_from_literal(fv, s, allow_partial_value, err_msg);
		if (ok) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			*err_msg = ws_strdup_printf("\"%s\" cannot be converted to %s.",
					s, ftype_pretty_name(ftype));
		}
	}
	fvalue_free(fv);
	return NULL;
}

fvalue_t*
fvalue_from_string(ftenum_t ftype, const char *str, size_t len, char **err_msg)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_string) {
		if (fv->ftype->val_from_string(fv, str, len, err_msg)) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			*err_msg = ws_strdup_printf("%s cannot be converted from a string (\"%s\").",
					ftype_pretty_name(ftype), str);
		}
	}
	fvalue_free(fv);
	return NULL;
}

fvalue_t*
fvalue_from_charconst(ftenum_t ftype, unsigned long num, char **err_msg)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_charconst) {
		if (fv->ftype->val_from_charconst(fv, num, err_msg)) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			if (num <= 0x7f && g_ascii_isprint(num)) {
				*err_msg = ws_strdup_printf("Character constant '%c' (0x%lx) cannot be converted to %s.",
						(int)num, num, ftype_pretty_name(ftype));
			}
			else {
				*err_msg = ws_strdup_printf("Character constant 0x%lx cannot be converted to %s.",
						num, ftype_pretty_name(ftype));
			}
		}
	}
	fvalue_free(fv);
	return NULL;
}

fvalue_t*
fvalue_from_sinteger64(ftenum_t ftype, const char *s, int64_t num, char **err_msg)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_sinteger64) {
		if (fv->ftype->val_from_sinteger64(fv, s, num, err_msg)) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			*err_msg = ws_strdup_printf("Integer %"PRId64" cannot be converted to %s.",
						num, ftype_pretty_name(ftype));
		}
	}
	fvalue_free(fv);
	return NULL;
}

fvalue_t*
fvalue_from_uinteger64(ftenum_t ftype, const char *s, uint64_t num, char **err_msg)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_uinteger64) {
		if (fv->ftype->val_from_uinteger64(fv, s, num, err_msg)) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			*err_msg = ws_strdup_printf("Unsigned integer 0x%"PRIu64" cannot be converted to %s.",
						num, ftype_pretty_name(ftype));
		}
	}
	fvalue_free(fv);
	return NULL;
}

fvalue_t*
fvalue_from_floating(ftenum_t ftype, const char *s, double num, char **err_msg)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_double) {
		if (fv->ftype->val_from_double(fv, s, num, err_msg)) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			*err_msg = ws_strdup_printf("Double %g cannot be converted to %s.",
						num, ftype_pretty_name(ftype));
		}
	}
	fvalue_free(fv);
	return NULL;
}

ftenum_t
fvalue_type_ftenum(const fvalue_t *fv)
{
	return fv->ftype->ftype;
}

const char*
fvalue_type_name(const fvalue_t *fv)
{
	return ftype_name(fv->ftype->ftype);
}


size_t
fvalue_length2(fvalue_t *fv)
{
	if (!fv->ftype->len) {
		ws_critical("fv->ftype->len is NULL");
		return 0;
	}
	return fv->ftype->len(fv);
}

char *
fvalue_to_string_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display)
{
	if (fv->ftype->val_to_string_repr == NULL) {
		/* no value-to-string-representation function, so the value cannot be represented */
		return NULL;
	}

	return fv->ftype->val_to_string_repr(scope, fv, rtype, field_display);
}

enum ft_result
fvalue_to_uinteger(const fvalue_t *fv, uint32_t *repr)
{
	uint64_t val;
	enum ft_result res = fv->ftype->val_to_uinteger64(fv, &val);
	if (res != FT_OK)
		return res;
	if (val > UINT32_MAX)
		return FT_OVERFLOW;

	*repr = (uint32_t)val;
	return FT_OK;
}

enum ft_result
fvalue_to_sinteger(const fvalue_t *fv, int32_t *repr)
{
	int64_t val;
	enum ft_result res = fv->ftype->val_to_sinteger64(fv, &val);
	if (res != FT_OK)
		return res;
	if (val > INT32_MAX)
		return FT_OVERFLOW;

	*repr = (int32_t)val;
	return FT_OK;
}

enum ft_result
fvalue_to_uinteger64(const fvalue_t *fv, uint64_t *repr)
{
	ws_assert(fv->ftype->val_to_uinteger64);
	return fv->ftype->val_to_uinteger64(fv, repr);
}

enum ft_result
fvalue_to_sinteger64(const fvalue_t *fv, int64_t *repr)
{
	ws_assert(fv->ftype->val_to_sinteger64);
	return fv->ftype->val_to_sinteger64(fv, repr);
}

enum ft_result
fvalue_to_double(const fvalue_t *fv, double *repr)
{
	ws_assert(fv->ftype->val_to_double);
	return fv->ftype->val_to_double(fv, repr);
}

typedef struct {
	fvalue_t	*fv;
	void		*ptr;
	bool	slice_failure;
} slice_data_t;

static bool
compute_drnode(size_t field_length, drange_node *drnode, size_t *offset_ptr, size_t *length_ptr)
{
	ssize_t		start_offset;
	ssize_t		length = 0;
	ssize_t		end_offset = 0;
	drange_node_end_t	ending;

	start_offset = drange_node_get_start_offset(drnode);
	ending = drange_node_get_ending(drnode);

	/* Check for negative start */
	if (start_offset < 0) {
		start_offset = field_length + start_offset;
		if (start_offset < 0) {
			return false;
		}
	}

	/* Check the end type and set the length */

	if (ending == DRANGE_NODE_END_T_TO_THE_END) {
		length = field_length - start_offset;
		if (length <= 0) {
			return false;
		}
	}
	else if (ending == DRANGE_NODE_END_T_LENGTH) {
		length = drange_node_get_length(drnode);
		if (start_offset + length > (int) field_length) {
			return false;
		}
	}
	else if (ending == DRANGE_NODE_END_T_OFFSET) {
		end_offset = drange_node_get_end_offset(drnode);
		if (end_offset < 0) {
			end_offset = field_length + end_offset;
			if (end_offset < start_offset) {
				return false;
			}
		} else if (end_offset >= (int) field_length) {
			return false;
		}
		length = end_offset - start_offset + 1;
	}
	else {
		ws_assert_not_reached();
	}

	*offset_ptr = start_offset;
	*length_ptr = length;
	return true;
}

static void
slice_func(void * data, void * user_data)
{
	drange_node	*drnode = (drange_node	*)data;
	slice_data_t	*slice_data = (slice_data_t *)user_data;
	size_t		start_offset;
	size_t		length = 0;
	fvalue_t	*fv;

	if (slice_data->slice_failure) {
		return;
	}

	fv = slice_data->fv;
	if (!compute_drnode((unsigned)fvalue_length2(fv), drnode, &start_offset, &length)) {
		slice_data->slice_failure = true;
		return;
	}

	ws_assert(length > 0);
	fv->ftype->slice(fv, slice_data->ptr, (unsigned)start_offset, (unsigned)length);
}

static fvalue_t *
slice_string(fvalue_t *fv, drange_t *d_range)
{
	slice_data_t	slice_data;
	fvalue_t	*new_fv;

	slice_data.fv = fv;
	slice_data.ptr = wmem_strbuf_create(NULL);
	slice_data.slice_failure = false;

	/* XXX - We could make some optimizations here based on
	 * drange_has_total_length() and
	 * drange_get_max_offset().
	 */

	drange_foreach_drange_node(d_range, slice_func, &slice_data);

	new_fv = fvalue_new(FT_STRING);
	fvalue_set_strbuf(new_fv, slice_data.ptr);
	return new_fv;
}

static fvalue_t *
slice_bytes(fvalue_t *fv, drange_t *d_range)
{
	slice_data_t	slice_data;
	fvalue_t	*new_fv;

	slice_data.fv = fv;
	slice_data.ptr = g_byte_array_new();
	slice_data.slice_failure = false;

	/* XXX - We could make some optimizations here based on
	 * drange_has_total_length() and
	 * drange_get_max_offset().
	 */

	drange_foreach_drange_node(d_range, slice_func, &slice_data);

	new_fv = fvalue_new(FT_BYTES);
	fvalue_set_byte_array(new_fv, slice_data.ptr);
	return new_fv;
}

/* Returns a new slice fvalue_t* if possible, otherwise NULL */
fvalue_t*
fvalue_slice(fvalue_t *fv, drange_t *d_range)
{
	if (FT_IS_STRING(fvalue_type_ftenum(fv))) {
		return slice_string(fv, d_range);
	}
	return slice_bytes(fv, d_range);
}

void
fvalue_set_bytes(fvalue_t *fv, GBytes *value)
{
	ws_assert(fv->ftype->ftype == FT_BYTES ||
			fv->ftype->ftype == FT_UINT_BYTES ||
			fv->ftype->ftype == FT_OID ||
			fv->ftype->ftype == FT_REL_OID ||
			fv->ftype->ftype == FT_SYSTEM_ID ||
			fv->ftype->ftype == FT_VINES ||
			fv->ftype->ftype == FT_ETHER ||
			fv->ftype->ftype == FT_FCWWN);
	ws_assert(fv->ftype->set_value.set_value_bytes);
	fv->ftype->set_value.set_value_bytes(fv, value);
}

void
fvalue_set_byte_array(fvalue_t *fv, GByteArray *value)
{
	GBytes *bytes = g_byte_array_free_to_bytes(value);
	fvalue_set_bytes(fv, bytes);
	g_bytes_unref(bytes);
}

void
fvalue_set_bytes_data(fvalue_t *fv, const void *data, size_t size)
{
	GBytes *bytes = g_bytes_new(data, size);
	fvalue_set_bytes(fv, bytes);
	g_bytes_unref(bytes);
}

void
fvalue_set_fcwwn(fvalue_t *fv, const uint8_t *value)
{
	GBytes *bytes = g_bytes_new(value, FT_FCWWN_LEN);
	fvalue_set_bytes(fv, bytes);
	g_bytes_unref(bytes);
}

void
fvalue_set_ax25(fvalue_t *fv, const uint8_t *value)
{
	wmem_strbuf_t *buf = wmem_strbuf_new(NULL, NULL);
	for (size_t i = 0; i < FT_AX25_ADDR_LEN - 1; i++) {
		if (value[i] != 0x40) {
			/* ignore space-padding */
			wmem_strbuf_append_c(buf, value[i] >> 1);
		}
	}
	/* Ignore C-bit and reserved bits, and end of address bits. */
	uint8_t ssid = (value[FT_AX25_ADDR_LEN - 1] >> 1) & 0x0f;
	if (ssid != 0) {
		wmem_strbuf_append_printf(buf, "-%u", ssid);
	}
	fvalue_set_strbuf(fv, buf);
}

void
fvalue_set_vines(fvalue_t *fv, const uint8_t *value)
{
	GBytes *bytes = g_bytes_new(value, FT_VINES_ADDR_LEN);
	fvalue_set_bytes(fv, bytes);
	g_bytes_unref(bytes);
}

void
fvalue_set_ether(fvalue_t *fv, const uint8_t *value)
{
	GBytes *bytes = g_bytes_new(value, FT_ETHER_LEN);
	fvalue_set_bytes(fv, bytes);
	g_bytes_unref(bytes);
}

void
fvalue_set_guid(fvalue_t *fv, const e_guid_t *value)
{
	ws_assert(fv->ftype->ftype == FT_GUID);
	ws_assert(fv->ftype->set_value.set_value_guid);
	fv->ftype->set_value.set_value_guid(fv, value);
}

void
fvalue_set_time(fvalue_t *fv, const nstime_t *value)
{
	ws_assert(FT_IS_TIME(fv->ftype->ftype));
	ws_assert(fv->ftype->set_value.set_value_time);
	fv->ftype->set_value.set_value_time(fv, value);
}

void
fvalue_set_string(fvalue_t *fv, const char *value)
{
	wmem_strbuf_t *buf = wmem_strbuf_new(NULL, value);
	fvalue_set_strbuf(fv, buf);
}

void
fvalue_set_strbuf(fvalue_t *fv, wmem_strbuf_t *value)
{
	if (value->allocator != NULL) {
		/* XXX Can this condition be relaxed? */
		ws_critical("Fvalue strbuf allocator must be NULL");
	}
	ws_assert(FT_IS_STRING(fv->ftype->ftype));
	ws_assert(fv->ftype->set_value.set_value_strbuf);
	fv->ftype->set_value.set_value_strbuf(fv, value);
}

void
fvalue_set_protocol(fvalue_t *fv, tvbuff_t *value, const char *name, int length)
{
	ws_assert(fv->ftype->ftype == FT_PROTOCOL);
	ws_assert(fv->ftype->set_value.set_value_protocol);
	fv->ftype->set_value.set_value_protocol(fv, value, name, length);
}

void
fvalue_set_uinteger(fvalue_t *fv, uint32_t value)
{
	ws_assert(fv->ftype->ftype == FT_IEEE_11073_SFLOAT ||
			fv->ftype->ftype == FT_IEEE_11073_FLOAT ||
			fv->ftype->ftype == FT_CHAR ||
			fv->ftype->ftype == FT_UINT8 ||
			fv->ftype->ftype == FT_UINT16 ||
			fv->ftype->ftype == FT_UINT24 ||
			fv->ftype->ftype == FT_UINT32 ||
			fv->ftype->ftype == FT_IPXNET ||
			fv->ftype->ftype == FT_FRAMENUM);
	ws_assert(fv->ftype->set_value.set_value_uinteger);
	fv->ftype->set_value.set_value_uinteger(fv, value);
}

void
fvalue_set_sinteger(fvalue_t *fv, int32_t value)
{
	ws_assert(fv->ftype->ftype == FT_INT8 ||
			fv->ftype->ftype == FT_INT16 ||
			fv->ftype->ftype == FT_INT24 ||
			fv->ftype->ftype == FT_INT32);
	ws_assert(fv->ftype->set_value.set_value_sinteger);
	fv->ftype->set_value.set_value_sinteger(fv, value);
}

void
fvalue_set_uinteger64(fvalue_t *fv, uint64_t value)
{
	ws_assert(fv->ftype->ftype == FT_UINT40 ||
			fv->ftype->ftype == FT_UINT48 ||
			fv->ftype->ftype == FT_UINT56 ||
			fv->ftype->ftype == FT_UINT64 ||
			fv->ftype->ftype == FT_BOOLEAN ||
			fv->ftype->ftype == FT_EUI64);
	ws_assert(fv->ftype->set_value.set_value_uinteger64);
	fv->ftype->set_value.set_value_uinteger64(fv, value);
}

void
fvalue_set_sinteger64(fvalue_t *fv, int64_t value)
{
	ws_assert(fv->ftype->ftype == FT_INT40 ||
			fv->ftype->ftype == FT_INT48 ||
			fv->ftype->ftype == FT_INT56 ||
			fv->ftype->ftype == FT_INT64);
	ws_assert(fv->ftype->set_value.set_value_sinteger64);
	fv->ftype->set_value.set_value_sinteger64(fv, value);
}

void
fvalue_set_floating(fvalue_t *fv, double value)
{
	ws_assert(fv->ftype->ftype == FT_FLOAT ||
			fv->ftype->ftype == FT_DOUBLE);
	ws_assert(fv->ftype->set_value.set_value_floating);
	fv->ftype->set_value.set_value_floating(fv, value);
}

void
fvalue_set_ipv4(fvalue_t *fv,  const ipv4_addr_and_mask *value)
{
	ws_assert(fv->ftype->ftype == FT_IPv4);
	ws_assert(fv->ftype->set_value.set_value_ipv4);
	fv->ftype->set_value.set_value_ipv4(fv, value);
}

void
fvalue_set_ipv6(fvalue_t *fv,  const ipv6_addr_and_prefix *value)
{
	ws_assert(fv->ftype->ftype == FT_IPv6);
	ws_assert(fv->ftype->set_value.set_value_ipv6);
	fv->ftype->set_value.set_value_ipv6(fv, value);
}

GBytes *
fvalue_get_bytes(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_BYTES ||
			fv->ftype->ftype == FT_UINT_BYTES ||
			fv->ftype->ftype == FT_VINES ||
			fv->ftype->ftype == FT_ETHER ||
			fv->ftype->ftype == FT_OID ||
			fv->ftype->ftype == FT_REL_OID ||
			fv->ftype->ftype == FT_SYSTEM_ID ||
			fv->ftype->ftype == FT_FCWWN ||
			fv->ftype->ftype == FT_IPv6);
	ws_assert(fv->ftype->get_value.get_value_bytes);
	return fv->ftype->get_value.get_value_bytes(fv);
}

size_t
fvalue_get_bytes_size(fvalue_t *fv)
{
	GBytes *bytes = fvalue_get_bytes(fv);
	size_t size = g_bytes_get_size(bytes);
	g_bytes_unref(bytes);
	return size;
}

const void *
fvalue_get_bytes_data(fvalue_t *fv)
{
	GBytes *bytes = fvalue_get_bytes(fv);
	const void *data = g_bytes_get_data(bytes, NULL);
	g_bytes_unref(bytes);
	return data;
}

const e_guid_t *
fvalue_get_guid(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_GUID);
	ws_assert(fv->ftype->get_value.get_value_guid);
	return fv->ftype->get_value.get_value_guid(fv);
}

const nstime_t *
fvalue_get_time(fvalue_t *fv)
{
	ws_assert(FT_IS_TIME(fv->ftype->ftype));
	ws_assert(fv->ftype->get_value.get_value_time);
	return fv->ftype->get_value.get_value_time(fv);
}

const char *
fvalue_get_string(fvalue_t *fv)
{
	return wmem_strbuf_get_str(fvalue_get_strbuf(fv));
}

const wmem_strbuf_t *
fvalue_get_strbuf(fvalue_t *fv)
{
	ws_assert(FT_IS_STRING(fv->ftype->ftype));
	ws_assert(fv->ftype->get_value.get_value_strbuf);
	return fv->ftype->get_value.get_value_strbuf(fv);
}

tvbuff_t *
fvalue_get_protocol(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_PROTOCOL);
	ws_assert(fv->ftype->get_value.get_value_protocol);
	return fv->ftype->get_value.get_value_protocol(fv);
}

uint32_t
fvalue_get_uinteger(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_IEEE_11073_SFLOAT ||
			fv->ftype->ftype == FT_IEEE_11073_FLOAT ||
			fv->ftype->ftype == FT_CHAR ||
			fv->ftype->ftype == FT_UINT8 ||
			fv->ftype->ftype == FT_UINT16 ||
			fv->ftype->ftype == FT_UINT24 ||
			fv->ftype->ftype == FT_UINT32 ||
			fv->ftype->ftype == FT_IPXNET ||
			fv->ftype->ftype == FT_FRAMENUM);
	ws_assert(fv->ftype->get_value.get_value_uinteger);
	return fv->ftype->get_value.get_value_uinteger(fv);
}

int32_t
fvalue_get_sinteger(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_INT8 ||
			fv->ftype->ftype == FT_INT16 ||
			fv->ftype->ftype == FT_INT24 ||
			fv->ftype->ftype == FT_INT32);
	ws_assert(fv->ftype->get_value.get_value_sinteger);
	return fv->ftype->get_value.get_value_sinteger(fv);
}

uint64_t
fvalue_get_uinteger64(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_UINT40 ||
			fv->ftype->ftype == FT_UINT48 ||
			fv->ftype->ftype == FT_UINT56 ||
			fv->ftype->ftype == FT_UINT64 ||
			fv->ftype->ftype == FT_BOOLEAN ||
			fv->ftype->ftype == FT_EUI64);
	ws_assert(fv->ftype->get_value.get_value_uinteger64);
	return fv->ftype->get_value.get_value_uinteger64(fv);
}

int64_t
fvalue_get_sinteger64(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_INT40 ||
			fv->ftype->ftype == FT_INT48 ||
			fv->ftype->ftype == FT_INT56 ||
			fv->ftype->ftype == FT_INT64);
	ws_assert(fv->ftype->get_value.get_value_sinteger64);
	return fv->ftype->get_value.get_value_sinteger64(fv);
}

double
fvalue_get_floating(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_FLOAT ||
			fv->ftype->ftype == FT_DOUBLE);
	ws_assert(fv->ftype->get_value.get_value_floating);
	return fv->ftype->get_value.get_value_floating(fv);
}

const ipv4_addr_and_mask *
fvalue_get_ipv4(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_IPv4);
	ws_assert(fv->ftype->get_value.get_value_ipv4);
	return fv->ftype->get_value.get_value_ipv4(fv);
}

const ipv6_addr_and_prefix *
fvalue_get_ipv6(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_IPv6);
	ws_assert(fv->ftype->get_value.get_value_ipv6);
	return fv->ftype->get_value.get_value_ipv6(fv);
}

ft_bool_t
fvalue_eq(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->compare);
	res = a->ftype->compare(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp == 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_ne(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->compare);
	res = a->ftype->compare(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp != 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_gt(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->compare);
	res = a->ftype->compare(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp > 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_ge(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->compare);
	res = a->ftype->compare(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp >= 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_lt(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->compare);
	res = a->ftype->compare(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp < 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_le(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->compare);
	res = a->ftype->compare(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp <= 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_contains(const fvalue_t *a, const fvalue_t *b)
{
	bool yes;
	enum ft_result res;

	ws_assert(a->ftype->contains);
	res = a->ftype->contains(a, b, &yes);
	if (res != FT_OK)
		return -res;
	return yes ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_matches(const fvalue_t *a, const ws_regex_t *re)
{
	bool yes;
	enum ft_result res;

	ws_assert(a->ftype->matches);
	res = a->ftype->matches(a, re, &yes);
	if (res != FT_OK)
		return -res;
	return yes ? FT_TRUE : FT_FALSE;
}

bool
fvalue_is_zero(const fvalue_t *a)
{
	return a->ftype->is_zero(a);
}

bool
fvalue_is_negative(const fvalue_t *a)
{
	return a->ftype->is_negative(a);
}

static fvalue_t *
_fvalue_binop(FvalueBinaryOp op, const fvalue_t *a, const fvalue_t *b, char **err_msg)
{
	fvalue_t *result;

	result = fvalue_new(a->ftype->ftype);
	if (op(result, a, b, err_msg) != FT_OK) {
		fvalue_free(result);
		return NULL;
	}
	return result;
}

fvalue_t *
fvalue_bitwise_and(const fvalue_t *a, const fvalue_t *b, char **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->bitwise_and);
	return _fvalue_binop(a->ftype->bitwise_and, a, b, err_msg);
}

fvalue_t *
fvalue_add(const fvalue_t *a, const fvalue_t *b, char **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->add);
	return _fvalue_binop(a->ftype->add, a, b, err_msg);
}

fvalue_t *
fvalue_subtract(const fvalue_t *a, const fvalue_t *b, char **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->subtract);
	return _fvalue_binop(a->ftype->subtract, a, b, err_msg);
}

fvalue_t *
fvalue_multiply(const fvalue_t *a, const fvalue_t *b, char **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->multiply);
	return _fvalue_binop(a->ftype->multiply, a, b, err_msg);
}

fvalue_t *
fvalue_divide(const fvalue_t *a, const fvalue_t *b, char **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->divide);
	return _fvalue_binop(a->ftype->divide, a, b, err_msg);
}

fvalue_t *
fvalue_modulo(const fvalue_t *a, const fvalue_t *b, char **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->modulo);
	return _fvalue_binop(a->ftype->modulo, a, b, err_msg);
}

fvalue_t*
fvalue_unary_minus(const fvalue_t *fv, char **err_msg)
{
	fvalue_t *result;

	ws_assert(fv->ftype->unary_minus);

	result = fvalue_new(fv->ftype->ftype);
	if (fv->ftype->unary_minus(result, fv, err_msg) != FT_OK) {
		fvalue_free(result);
		return NULL;
	}
	return result;
}

unsigned
fvalue_hash(const fvalue_t *fv)
{
	ws_assert(fv->ftype->hash);
	return fv->ftype->hash(fv);
}

bool
fvalue_equal(const fvalue_t *a, const fvalue_t *b)
{
	return fvalue_eq(a, b) == FT_TRUE;
}

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
