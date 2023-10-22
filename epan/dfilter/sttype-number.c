/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/proto.h>
#include "sttype-number.h"
#include <wsutil/ws_assert.h>

typedef struct {
	uint32_t	magic;
	stnumber_t	type;
	union {
		int64_t		i64;
		uint64_t	u64;
		double		dbl;
	} value;
} number_t;

#define NUMBER_MAGIC	0xabf44fba

static void *
number_new(void *junk _U_)
{
	number_t *number = g_new0(number_t, 1);
	number->magic = NUMBER_MAGIC;
	return number;
}

static void *
number_dup(const void *data)
{
	const number_t *org = data;
	number_t *number;

	ws_assert_magic(org, NUMBER_MAGIC);
	number = number_new(NULL);
	number->type = org->type;
	number->value = org->value;
	return number;
}

static void
number_free(void *data)
{
	number_t *number = data;
	ws_assert_magic(number, NUMBER_MAGIC);
	g_free(number);
}

static char *
number_tostr(const void *data, bool pretty _U_)
{
	const number_t *number = data;
	ws_assert_magic(number, NUMBER_MAGIC);
	char *s = NULL;

	switch (number->type) {
		case STNUM_NONE:
			s = ws_strdup("<NULL>");
			break;
		case STNUM_INTEGER:
			s = ws_strdup_printf("%"PRId64, number->value.i64);
			break;
		case STNUM_UNSIGNED:
			s = ws_strdup_printf("%"PRIu64, number->value.u64);
			break;
		case STNUM_FLOAT:
			s = ws_strdup_printf("%g", number->value.dbl);
			break;
	}

	return s;
}

stnumber_t
sttype_number_get_type(stnode_t*st)
{
	number_t *number = stnode_data(st);
	ws_assert_magic(number, NUMBER_MAGIC);
	return number->type;
}

void
sttype_number_set_integer(stnode_t *st, int64_t value)
{
	number_t *number = stnode_data(st);
	ws_assert_magic(number, NUMBER_MAGIC);
	number->type = STNUM_INTEGER;
	number->value.i64 = value;
}

int64_t
sttype_number_get_integer(stnode_t *st)
{
	number_t *number = stnode_data(st);
	ws_assert_magic(number, NUMBER_MAGIC);
	ws_assert(number->type == STNUM_INTEGER);
	return number->value.i64;
}

void
sttype_number_set_unsigned(stnode_t *st, uint64_t value)
{
	number_t *number = stnode_data(st);
	ws_assert_magic(number, NUMBER_MAGIC);
	number->type = STNUM_UNSIGNED;
	number->value.u64 = value;
}

uint64_t
sttype_number_get_unsigned(stnode_t *st)
{
	number_t *number = stnode_data(st);
	ws_assert_magic(number, NUMBER_MAGIC);
	ws_assert(number->type == STNUM_UNSIGNED);
	return number->value.u64;
}

void
sttype_number_set_float(stnode_t *st, double value)
{
	number_t *number = stnode_data(st);
	ws_assert_magic(number, NUMBER_MAGIC);
	number->type = STNUM_FLOAT;
	number->value.dbl = value;
}

double
sttype_number_get_float(stnode_t *st)
{
	number_t *number = stnode_data(st);
	ws_assert_magic(number, NUMBER_MAGIC);
	ws_assert(number->type == STNUM_FLOAT);
	return number->value.dbl;
}

void
sttype_register_number(void)
{
	static sttype_t number_type = {
		STTYPE_NUMBER,
		number_new,
		number_free,
		number_dup,
		number_tostr
	};

	sttype_register(&number_type);
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
