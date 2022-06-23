/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* The ideas in this code came from Ed Warnicke's original implementation
 * of dranges for the old display filter code (Ethereal 0.8.15 and before).
 * The code is different, but definitely inspired by his code.
 */

#include "config.h"

#include <glib.h>

#include <epan/proto.h>
#include "sttype-field.h"
#include <wsutil/ws_assert.h>

typedef struct {
	guint32	   magic;
	header_field_info *hfinfo;
	drange_t  *drange;
} field_t;

#define FIELD_MAGIC	0xfc2002cf

static gpointer
field_new(gpointer hfinfo)
{
	field_t *field;

	field = g_new(field_t, 1);
	field->magic = FIELD_MAGIC;
	field->hfinfo = hfinfo;
	field->drange = NULL;

	return field;
}

static gpointer
field_dup(gconstpointer data)
{
	const field_t *org = data;
	field_t       *field;

	ws_assert_magic(org, FIELD_MAGIC);
	field = field_new(NULL);
	field->hfinfo = org->hfinfo;
	field->drange = drange_dup(org->drange);

	return field;
}

static void
field_free(gpointer data)
{
	field_t *field = data;
	ws_assert_magic(field, FIELD_MAGIC);

	if (field->drange)
		drange_free(field->drange);
	g_free(field);
}

static char *
field_tostr(const void *data, gboolean pretty _U_)
{
	const field_t *field = data;
	ws_assert_magic(field, FIELD_MAGIC);
	char *repr, *drange_str;

	if (field->drange && (drange_str = drange_tostr(field->drange))) {
		repr = ws_strdup_printf("%s#[%s] <%s>",
				field->hfinfo->abbrev,
				drange_str,
				ftype_name(field->hfinfo->type));
		g_free(drange_str);
	}
	else {
		repr = ws_strdup_printf("%s <%s>", field->hfinfo->abbrev,
					ftype_name(field->hfinfo->type));
	}

	return repr;
}

header_field_info *
sttype_field_hfinfo(stnode_t *node)
{
	field_t *field = node->data;
	ws_assert_magic(field, FIELD_MAGIC);
	return field->hfinfo;
}

ftenum_t
sttype_field_ftenum(stnode_t *node)
{
	field_t *field = node->data;
	ws_assert_magic(field, FIELD_MAGIC);
	return field->hfinfo->type;
}

drange_t *
sttype_field_drange(stnode_t *node)
{
	field_t *field = node->data;
	ws_assert_magic(field, FIELD_MAGIC);
	return field->drange;
}

drange_t *
sttype_field_drange_steal(stnode_t *node)
{
	field_t		*field;
	drange_t	*dr;

	field = stnode_data(node);
	ws_assert_magic(field, FIELD_MAGIC);
	dr = field->drange;
	field->drange = NULL;
	return dr;
}

/* Set a field */
void
sttype_field_set_range(stnode_t *node, GSList* drange_list)
{
	field_t *field = stnode_data(node);
	ws_assert_magic(field, FIELD_MAGIC);
	ws_assert(field->drange == NULL);
	field->drange = drange_new_from_list(drange_list);
}

void
sttype_field_set_range1(stnode_t *node, drange_node *rn)
{
	field_t *field = stnode_data(node);
	ws_assert_magic(field, FIELD_MAGIC);
	ws_assert(field->drange == NULL);
	field->drange = drange_new(rn);
}

void
sttype_field_set_drange(stnode_t *node, drange_t *dr)
{
	field_t *field = stnode_data(node);
	ws_assert_magic(field, FIELD_MAGIC);
	ws_assert(field->drange == NULL);
	field->drange = dr;
}

char *
sttype_field_set_number(stnode_t *node, const char *number_str)
{
	char *err_msg = NULL;
	drange_node *rn = drange_node_from_str(number_str, &err_msg);
	if (err_msg != NULL)
		return err_msg;

	sttype_field_set_range1(node, rn);
	return NULL;
}

void
sttype_register_field(void)
{
	static sttype_t field_type = {
		STTYPE_FIELD,
		"FIELD",
		field_new,
		field_free,
		field_dup,
		field_tostr
	};
	static sttype_t reference_type = {
		STTYPE_REFERENCE,
		"REFERENCE",
		field_new,
		field_free,
		field_dup,
		field_tostr
	};

	sttype_register(&field_type);
	sttype_register(&reference_type);
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
