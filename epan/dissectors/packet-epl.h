/* packet-epl.h
 * Routines for "Ethernet POWERLINK 2.0" dissection
 * (Ethernet POWERLINK V2.0 Communication Profile Specification Draft Standard Version 1.2.0)
 *
 * A dissector for:
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EPL_H_
#define __EPL_H_

#include <epan/address.h>
#include <epan/wmem_scopes.h>
#include <epan/range.h>

struct epl_datatype;

struct profile {
	uint16_t id;
	uint8_t nodeid;
	address node_addr;

	uint32_t vendor_id;
	uint32_t product_code;

	wmem_map_t *objects;
	wmem_allocator_t *scope, *parent_scope;
	wmem_map_t *parent_map;

	char *name;
	char *path;
	void *data;
	unsigned cb_id;
	wmem_array_t *TPDO; /* CN->MN */
	wmem_array_t *RPDO; /* MN->CN */

	struct profile *next;
};

enum { OD_ENTRY_SCALAR = 7, OD_ENTRY_ARRAY = 8, OD_ENTRY_RECORD = 9 };
struct od_entry {
	uint16_t idx;
	/* This is called the ObjectType in the standard,
	 * but this is too easy to be mistaken with the
	 * DataType.
	 * ObjectType specifies whether it's a scalar or
	 * an aggregate
	 */
	uint16_t type_class;
	char name[64];
	/* Called DataType by the standard,
	 * Can be e.g. Unsigned32
	 */
	const struct epl_datatype *type;
	uint64_t value;
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
subobject_equal(const void *_a, const void *_b)
{
	const struct od_entry *a = &((const struct subobject*)_a)->info;
	const struct od_entry *b = &((const struct subobject*)_b)->info;

	return a->type_class == b->type_class
	    && a->type == b->type
	    && g_str_equal(a->name, b->name);
}

struct profile *epl_xdd_load(struct profile *profile, const char *xml_file);

void epl_eds_init(void);
struct profile *epl_eds_load(struct profile *profile, const char *eds_file);


struct object *epl_profile_object_add(struct profile *profile, uint16_t idx);
struct object *epl_profile_object_lookup_or_add(struct profile *profile, uint16_t idx);

bool epl_profile_object_mapping_add(struct profile *profile, uint16_t idx, uint8_t subindex, uint64_t mapping);
bool epl_profile_object_mappings_update(struct profile *profile);

range_admin_t * epl_wmem_iarray_find(epl_wmem_iarray_t *arr, uint32_t value);
bool epl_wmem_iarray_is_empty(epl_wmem_iarray_t *iarr);
bool epl_wmem_iarray_is_sorted(epl_wmem_iarray_t *iarr);

#define EPL_OBJECT_MAPPING_SIZE ((unsigned)sizeof (uint64_t))

#define CHECK_OVERLAP_ENDS(x1, x2, y1, y2) ((x1) < (y2) && (y1) < (x2))
#define CHECK_OVERLAP_LENGTH(x, x_len, y, y_len) \
	CHECK_OVERLAP_ENDS((x), (x) + (x_len), (y), (y) + (y_len))


#endif
