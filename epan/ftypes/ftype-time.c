
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ftypes-int.h>

static void
ftype_from_tvbuff(field_info *fi, tvbuff_t *tvb, int start, int length,
	gboolean little_endian)
{
	/* XXX */
	g_assert_not_reached();
}


static void
time_fvalue_new(fvalue_t *fv)
{
	fv->value.time.tv_sec = 0;
	fv->value.time.tv_usec = 0;
}

static void
time_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(!already_copied);
	memcpy(&(fv->value.time), value, sizeof(struct timeval));
}

static gpointer
value_get(fvalue_t *fv)
{
	return &(fv->value.time);
}

void
ftype_register_time(void)
{

	static ftype_t abstime_type = {
		"FT_ABSOLUTE_TIME",
		"date/time",
		0,
		time_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		NULL,

		time_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL
	};
	static ftype_t reltime_type = {
		"FT_RELATIVE_TIME",
		"time offset",
		0,
		time_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		NULL,

		time_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL
	};

	ftype_register(FT_ABSOLUTE_TIME, &abstime_type);
	ftype_register(FT_RELATIVE_TIME, &reltime_type);
}
