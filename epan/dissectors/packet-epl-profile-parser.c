/* packet-epl-profile-parser.c
 * Routines for reading in Ethernet POWERLINK XDD and CANopen EDS profiles
 * (Ethernet POWERLINK XML Device Description (DS301) Draft Standard v1.2.0)
 *
 * Copyright (c) 2017: Karlsruhe Institute of Technology (KIT)
 *                     Institute for Anthropomatics and Robotics (IAR)
 *                     Intelligent Process Control and Robotics (IPR)
 *                     http://rob.ipr.kit.edu/
 *
 *                     - Ahmad Fatoum <ahmad[AT]a3f.at>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include "packet-epl.h"

#include <wsutil/ws_printf.h>
#include <epan/range.h>

#include <glib.h>
#include <string.h>
#include <stdlib.h>

#include <epan/wmem/wmem.h>

/* XXX: Temporary. successive related change makes use of the functions here */
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

struct epl_wmem_iarray {
	GEqualFunc equal;
	wmem_allocator_t *scope;
	GArray *arr;
	guint cb_id;
	guint8 is_sorted :1;
};

static epl_wmem_iarray_t *epl_wmem_iarray_new(wmem_allocator_t *allocator, const guint elem_size, GEqualFunc cmp) G_GNUC_MALLOC;
static gboolean epl_wmem_iarray_is_empty(epl_wmem_iarray_t *iarr);
static gboolean epl_wmem_iarray_is_sorted(epl_wmem_iarray_t *iarr);
static void epl_wmem_iarray_insert(epl_wmem_iarray_t *iarr, guint32 where, range_admin_t *data);
static void epl_wmem_iarray_sort_and_compact(epl_wmem_iarray_t *iarr);
static range_admin_t * epl_wmem_iarray_find(epl_wmem_iarray_t *arr, guint32 value);


/**
 * A sorted array keyed by intervals
 * You keep inserting items, then sort the array.
 * sorting also combines items that compare equal into one and adjusts
 * the interval accordingly. find uses binary search to find the item
 *
 * This is particularly useful, if many similar items exist adjacent to each other
 * e.g. ObjectMapping subindices in EPL XDD (packet-epl-profile-parser.c)
 *
 * Interval Trees wouldn't work for this scenario, because they don't allow
 * expansion of existing intervals. Using an array instead of a tree,
 * may additionally offer a possible performance advantage

 * Much room for optimization in the creation process of the array,
 * but we assume this to be an infrequent operation, with space utilization and
 * finding speed being more important.
 */


static gboolean
free_garray(wmem_allocator_t *scope _U_, wmem_cb_event_t event _U_, void *data)
{
	GArray *arr = (GArray*)data;
	g_array_free(arr, TRUE);
	return FALSE;
}

/**
 * \param allocator wmem pool to use
 * \param elem_size size of elements to add into the iarray
 * \param cmp establishes whether two adjacent elements are equal and thus
 *            shall be combined at sort-time
 *
 * \returns a new interval array or NULL on failure
 *
 * Creates a new interval array.
 * Elements must have a range_admin_t as their first element,
 * which will be managed by the implementation.
 * \NOTE The cmp parameter can be used to free resources. When combining,
 * it's always the second argument that's getting removed.
 */

epl_wmem_iarray_t *
epl_wmem_iarray_new(wmem_allocator_t *scope, const guint elem_size, GEqualFunc equal)
{
	epl_wmem_iarray_t *iarr;

	if (elem_size < sizeof(range_t)) return NULL;

	iarr = wmem_new(scope, epl_wmem_iarray_t);
	if (!iarr) return NULL;

	iarr->equal = equal;
	iarr->scope = scope;
	iarr->arr = g_array_new(FALSE, FALSE, elem_size);
	iarr->is_sorted = TRUE;

	wmem_register_callback(scope, free_garray, iarr->arr);

	return iarr;
}


/** Returns true if the iarr is empty. */
static gboolean
epl_wmem_iarray_is_empty(epl_wmem_iarray_t *iarr)
{
	return iarr->arr->len == 0;
}

/** Returns true if the iarr is sorted. */
static gboolean
epl_wmem_iarray_is_sorted(epl_wmem_iarray_t *iarr)
{
	return iarr->is_sorted;
}

/** Inserts an element */
void
epl_wmem_iarray_insert(epl_wmem_iarray_t *iarr, guint32 where, range_admin_t *data)
{
	if (iarr->arr->len)
		iarr->is_sorted = FALSE;

	data->high = data->low = where;
	g_array_append_vals(iarr->arr, data, 1);
}

static int
epl_wmem_iarray_cmp(const void *a, const void *b)
{
	return *(const guint32*)a - *(const guint32*)b;
}

/** Makes array suitable for searching */
void
epl_wmem_iarray_sort_and_compact(epl_wmem_iarray_t *iarr)
{
	range_admin_t *elem, *prev = NULL;
	guint i, len;
	len = iarr->arr->len;
	if (iarr->is_sorted)
		return;

	g_array_sort(iarr->arr, epl_wmem_iarray_cmp);
	prev = elem = (range_admin_t*)iarr->arr->data;

	for (i = 1; i < len; i++) {
		elem = (range_admin_t*)((char*)elem + g_array_get_element_size(iarr->arr));

		/* neighbours' range must be within one of each other and their content equal */
		while (i < len && elem->low - prev->high <= 1 && iarr->equal(elem, prev)) {
			prev->high = elem->high;

			g_array_remove_index(iarr->arr, i);
			len--;
		}
		prev = elem;
	}

	iarr->is_sorted = 1;
}

static int
find_in_range(const void *_a, const void *_b)
{
	const range_admin_t *a = (const range_admin_t*)_a,
	                    *b = (const range_admin_t*)_b;

	if (a->low <= b->high && b->low <= a->high) /* overlap */
		return 0;

	return a->low - b->low;
}

static void*
bsearch_garray(const void *key, GArray *arr, int (*cmp)(const void*, const void*))
{
	return bsearch(key, arr->data, arr->len, g_array_get_element_size(arr), cmp);
}

/*
 * Finds an element in the interval array. Returns NULL if it doesn't exist
 * Calling this is unspecified if the array wasn't sorted before
 */
static range_admin_t *
epl_wmem_iarray_find(epl_wmem_iarray_t *iarr, guint32 value) {
	epl_wmem_iarray_sort_and_compact(iarr);

	range_admin_t needle;
	needle.low  = value;
	needle.high = value;
	return (range_admin_t*)bsearch_garray(&needle, iarr->arr, find_in_range);
}

#if 0
void
epl_wmem_print_iarr(epl_wmem_iarray_t *iarr)
{
	range_admin_t *elem;
	guint i, len;
	elem = (range_admin_t*)iarr->arr->data;
	len = iarr->arr->len;
	for (i = 0; i < len; i++)
	{

		ws_debug_printf("Range: low=%" G_GUINT32_FORMAT " high=%" G_GUINT32_FORMAT "\n", elem->low, elem->high);

		elem = (range_admin_t*)((char*)elem + g_array_get_element_size(iarr->arr));
	}
}
#endif

/*
 * Editor modelines  -	http://www.wireshark.org/tools/modelines.html
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
