
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ftypes-int.h>
#include "gdebug.h"

static void
value_new(fvalue_t *fv)
{
	fv->value.tvb = NULL;
}


static void
value_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(already_copied);
	fv->value.tvb = value;
}

static gpointer
value_get(fvalue_t *fv)
{
	return fv->value.tvb;
}

static guint
len(fvalue_t *fv)
{
	if (fv->value.tvb)
		return tvb_length(fv->value.tvb);
	else
		return 0;
}

static void
slice(fvalue_t *fv, GByteArray *bytes, guint offset, guint length)
{
	guint8* data;

	if (fv->value.tvb) {
		data = tvb_get_ptr(fv->value.tvb, offset, length);
		g_byte_array_append(bytes, data, length);
	}
}

void
ftype_register_tvbuff(void)
{

	static ftype_t protocol_type = {
		"FT_PROTOCOL",
		"protocol",
		0,
		value_new,
		NULL,
		NULL,
		NULL,

		value_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,

		len,
		slice,

	};


	ftype_register(FT_PROTOCOL, &protocol_type);
}
