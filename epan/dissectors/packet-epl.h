/* packet-epl.h
 * Routines for "Ethernet POWERLINK 2.0" dissection
 * (Ethernet POWERLINK V2.0 Communication Profile Specification Draft Standard Version 1.2.0)
 *
 * A dissector for:
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#ifndef __EPL_H_
#define __EPL_H_

#include <glib.h>
#include <epan/address.h>
#include <epan/wmem/wmem.h>
#include <epan/range.h>

struct epl_datatype;

struct profile {
	guint16 id;
	guint8 nodeid;
	address node_addr;

	guint32 vendor_id;
	guint32 product_code;

	wmem_map_t *objects;
	wmem_allocator_t *scope, *parent_scope;
	wmem_map_t *parent_map;

	char *name;
	char *path;
	void *data;
	guint cb_id;
	wmem_array_t *TPDO; /* CN->MN */
	wmem_array_t *RPDO; /* MN->CN */

	struct profile *next;
};

enum { OD_ENTRY_SCALAR = 7, OD_ENTRY_ARRAY = 8, OD_ENTRY_RECORD = 9 };
struct od_entry {
	guint16 idx;
	/* This is called the ObjectType in the standard,
	 * but this is too easy to be mistaken with the
	 * DataType.
	 * ObjectType specifies whether it's a scalar or
	 * an aggregate
	 */
	guint16 type_class;
	char name[64];
	/* Called DataType by the standard,
	 * Can be e.g. Unsigned32
	 */
	const struct epl_datatype *type;
	guint64 value;
};
#define OD_ENTRY_INITIALIZER { 0, 0, { 0 }, 0, 0 }

struct subobject {
	range_admin_t range;
	struct od_entry info;
};
#define SUBOBJECT_INITIALIZER { RANGE_ADMIN_T_INITIALIZER, OD_ENTRY_INITIALIZER }

typedef struct epl_wmem_iarray epl_wmem_iarray_t;

struct object {
	struct od_entry info;
	epl_wmem_iarray_t *subindices;
};

struct profile;

const struct epl_datatype *epl_type_to_hf(const char *name);

static inline gboolean
subobject_equal(gconstpointer _a, gconstpointer _b)
{
	const struct od_entry *a = &((const struct subobject*)_a)->info;
	const struct od_entry *b = &((const struct subobject*)_b)->info;

	return a->type_class == b->type_class
	    && a->type == b->type
	    && g_str_equal(a->name, b->name);
}

void epl_xdd_init(void);
struct profile *epl_xdd_load(struct profile *profile, const char *xml_file);

void epl_eds_init(void);
struct profile *epl_eds_load(struct profile *profile, const char *eds_file);


struct object *epl_profile_object_add(struct profile *profile, guint16 idx);
struct object *epl_profile_object_lookup_or_add(struct profile *profile, guint16 idx);

gboolean epl_profile_object_mapping_add(struct profile *profile, guint16 idx, guint8 subindex, guint64 mapping);
gboolean epl_profile_object_mappings_update(struct profile *profile);

range_admin_t * epl_wmem_iarray_find(epl_wmem_iarray_t *arr, guint32 value);
gboolean epl_wmem_iarray_is_empty(epl_wmem_iarray_t *iarr);
gboolean epl_wmem_iarray_is_sorted(epl_wmem_iarray_t *iarr);

#define EPL_OBJECT_MAPPING_SIZE ((guint)sizeof (guint64))

#define CHECK_OVERLAP_ENDS(x1, x2, y1, y2) ((x1) < (y2) && (y1) < (x2))
#define CHECK_OVERLAP_LENGTH(x, x_len, y, y_len) \
	CHECK_OVERLAP_ENDS((x), (x) + (x_len), (y), (y) + (y_len))


#endif
