/*
 * $Id: sttype-range.c,v 1.2 2001/02/01 20:31:18 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
 *
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* The ideas in this code came from Ed Warnicke's original implementation
 * of dranges for the old display filter code (Ethereal 0.8.15 and before).
 * The code is different, but definitely inspired by his code.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include "proto.h"
#include "sttype-range.h"

typedef struct {
	guint32			magic;
	header_field_info	*hfinfo;
	gint			start;
	gint			end;
	char			*start_error;
	char			*end_error;
} range_t;

#define RANGE_MAGIC	0xec0990ce

static gpointer
range_new(gpointer junk)
{
	range_t		*range;

	g_assert(junk == NULL);

	range = g_new(range_t, 1);

	range->magic = RANGE_MAGIC;
	range->hfinfo = NULL;
	range->start = 0;
	range->end = -1;
	range->start_error = NULL;
	range->end_error = NULL;

	return (gpointer) range;
}

static void
range_free(gpointer value)
{
	range_t	*range = value;
	assert_magic(range, RANGE_MAGIC);

	if (range->start_error)
		g_free(range->start_error);
	if (range->end_error)
		g_free(range->end_error);

	g_free(range);
}

static gint
string_to_gint(char *s, gboolean *success)
{
	char	*endptr;
	gint	val;

	*success = TRUE;
	val = strtol(s, &endptr, 0);

	if (endptr == s || *endptr != '\0') {
		*success = FALSE;
	}
	else if (errno == ERANGE) {
		*success = FALSE;
	}

	return val;
}

static void
range_set(stnode_t *node, stnode_t *field, char *start, char *end)
{
	range_t		*range;
	gboolean	success;

	range = stnode_data(node);
	assert_magic(range, RANGE_MAGIC);

	range->hfinfo = stnode_data(field);
	stnode_free(field);

	if (start) { 
		range->start = string_to_gint(start, &success);
		if (!success) {
			/* Save the error-causing string for later reporting */
			range->start_error = g_strdup(start);
		}
	}
	else {
		range->start = 0;
	}

	if (end) {
		range->end = string_to_gint(end, &success);

		if (!success) {
			/* Save the error-causing string for later reporting */
			range->end_error = g_strdup(end);
		}
	}
	else {
		range->end = G_MAXINT;
	}
}

void
sttype_range_set(stnode_t *node, stnode_t *field, stnode_t *start, stnode_t *end)
{
	char		*start_str, *end_str;

	if (start) { 
		start_str = stnode_data(start);
	}
	else {
		start_str = NULL;
	}

	if (end) {
		end_str = stnode_data(end);
	}
	else {
		end_str = NULL;
	}

	range_set(node, field, start_str, end_str);

	if (start)
		stnode_free(start);
	if (end)
		stnode_free(end);
}

void
sttype_range_set1(stnode_t *node, stnode_t *field, stnode_t *offset)
{
	char		*offset_str;
	
	g_assert(offset);

	offset_str = stnode_data(offset);
	range_set(node, field, offset_str, "1");
	stnode_free(offset);
}


STTYPE_ACCESSOR(header_field_info*, range, hfinfo, RANGE_MAGIC)
STTYPE_ACCESSOR(gint, range, start, RANGE_MAGIC)
STTYPE_ACCESSOR(gint, range, end, RANGE_MAGIC)
STTYPE_ACCESSOR(char*, range, start_error, RANGE_MAGIC)
STTYPE_ACCESSOR(char*, range, end_error, RANGE_MAGIC)


void
sttype_register_range(void)
{
	static sttype_t range_type = {
		STTYPE_RANGE,
		"RANGE",
		range_new,
		range_free,
	};

	sttype_register(&range_type);
}
