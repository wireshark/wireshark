#ifndef FTYPES_INT_H
#define FTYPES_INT_H

#include "packet.h"
#include "ftypes.h"

typedef void (*FtypeFromTvbuffFunc)(field_info*, tvbuff_t*, int, int, gboolean);
typedef void (*FvalueNewFunc)(fvalue_t*);
typedef void (*FvalueFreeFunc)(fvalue_t*);

typedef gboolean (*FvalueFromString)(fvalue_t*, char*, LogFunc);

typedef void (*FvalueSetFunc)(fvalue_t*, gpointer, gboolean);
typedef void (*FvalueSetIntegerFunc)(fvalue_t*, guint32);
typedef void (*FvalueSetFloatingFunc)(fvalue_t*, gdouble);

typedef gpointer (*FvalueGetFunc)(fvalue_t*);
typedef guint32 (*FvalueGetIntegerFunc)(fvalue_t*);
typedef double (*FvalueGetFloatingFunc)(fvalue_t*);

typedef gboolean (*FvalueCmp)(fvalue_t*, fvalue_t*);

typedef guint (*FvalueLen)(fvalue_t*);
typedef void (*FvalueSlice)(fvalue_t*, GByteArray *, guint, guint);

struct _ftype_t {
	const char		*name;
	const char		*pretty_name;
	int			wire_size;
	FvalueNewFunc		new_value;
	FvalueFreeFunc		free_value;
	FtypeFromTvbuffFunc	from_tvbuff;
	FvalueFromString	val_from_string;

	/* could be union */
	FvalueSetFunc		set_value;
	FvalueSetIntegerFunc	set_value_integer;
	FvalueSetFloatingFunc	set_value_floating;

	/* could be union */
	FvalueGetFunc		get_value;
	FvalueGetIntegerFunc	get_value_integer;
	FvalueGetFloatingFunc	get_value_floating;

	FvalueCmp		cmp_eq;
	FvalueCmp		cmp_ne;
	FvalueCmp		cmp_gt;
	FvalueCmp		cmp_ge;
	FvalueCmp		cmp_lt;
	FvalueCmp		cmp_le;

	FvalueLen		len;
	FvalueSlice		slice;
};


void
ftype_register(enum ftenum ftype, ftype_t *ft);

#endif
