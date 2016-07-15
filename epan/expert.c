/* expert.c
 * Collecting Expert information.
 *
 * Implemented as a tap named "expert".
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

#include <stdio.h>
#include <stdlib.h>

#include <wsutil/ws_printf.h>

#include "packet.h"
#include "expert.h"
#include "uat.h"
#include "prefs.h"
#include "wmem/wmem.h"
#include "tap.h"

/* proto_expert cannot be static because it's referenced in the
 * print routines
 */
int proto_expert              = -1;

static int proto_malformed    = -1;

static int expert_tap         = -1;
static int highest_severity   =  0;

static int ett_expert         = -1;
static int ett_subexpert      = -1;

static int hf_expert_msg      = -1;
static int hf_expert_group    = -1;
static int hf_expert_severity = -1;

struct expert_module
{
	const char *proto_name;
	int         proto_id;      /* Cache this for registering hfs */
};

/* List which stores protocols and expert_info that have been registered */
typedef struct _gpa_expertinfo_t {
	guint32             len;
	guint32             allocated_len;
	expert_field_info **ei;
} gpa_expertinfo_t;
static gpa_expertinfo_t gpa_expertinfo;

/* Hash table of abbreviations and IDs */
static GHashTable *gpa_name_map = NULL;

/* Deregistered expert infos */
static GPtrArray *deregistered_expertinfos = NULL;

const value_string expert_group_vals[] = {
	{ PI_CHECKSUM,          "Checksum" },
	{ PI_SEQUENCE,          "Sequence" },
	{ PI_RESPONSE_CODE,     "Response" },
	{ PI_REQUEST_CODE,      "Request" },
	{ PI_UNDECODED,         "Undecoded" },
	{ PI_REASSEMBLE,        "Reassemble" },
	{ PI_MALFORMED,         "Malformed" },
	{ PI_DEBUG,             "Debug" },
	{ PI_PROTOCOL,          "Protocol" },
	{ PI_SECURITY,          "Security" },
	{ PI_COMMENTS_GROUP,    "Comment" },
	{ PI_DECRYPTION,        "Decryption" },
	{ PI_ASSUMPTION,        "Assumption" },
	{ 0, NULL }
};

const value_string expert_severity_vals[] = {
	{ PI_ERROR,             "Error" },
	{ PI_WARN,              "Warning" },
	{ PI_NOTE,              "Note" },
	{ PI_CHAT,              "Chat" },
	{ PI_COMMENT,           "Comment" },
	{ 1,                    "Ok" },
	{ 0, NULL }
};

/* Possible values for a checksum evaluation */
const value_string expert_checksum_vals[] = {
	{ EXPERT_CHECKSUM_DISABLED,   "Disabled"  },
	{ EXPERT_CHECKSUM_UNKNOWN,    "Unknown"  },
	{ EXPERT_CHECKSUM_GOOD,       "Good"  },
	{ EXPERT_CHECKSUM_BAD,        "Bad" },
	{ 0,        NULL }
};

static expert_field_info *expert_registrar_get_byname(const char *field_name);

/*----------------------------------------------------------------------------*/
/* UAT for customizing severity levels.                                       */
/*----------------------------------------------------------------------------*/
typedef struct
{
	char    *field;
	guint32  severity;
} expert_level_entry_t;

static expert_level_entry_t *uat_expert_entries = NULL;
static guint expert_level_entry_count = 0;
/* Array of field names currently in UAT */
static GArray *uat_saved_fields = NULL;

UAT_CSTRING_CB_DEF(uat_expert_entries, field, expert_level_entry_t)
UAT_VS_DEF(uat_expert_entries, severity, expert_level_entry_t, guint32, PI_ERROR, "Error")

static gboolean uat_expert_update_cb(void *r, char **err)
{
	expert_level_entry_t *rec = (expert_level_entry_t *)r;

	if (expert_registrar_get_byname(rec->field) == NULL) {
		*err = g_strdup_printf("Expert Info field doesn't exist");
		return FALSE;
	}
	return TRUE;
}

static void *uat_expert_copy_cb(void *n, const void *o, size_t siz _U_)
{
	expert_level_entry_t       *new_record = (expert_level_entry_t*)n;
	const expert_level_entry_t *old_record = (const expert_level_entry_t *)o;

	if (old_record->field) {
		new_record->field = g_strdup(old_record->field);
	} else {
		new_record->field = NULL;
	}

	new_record->severity = old_record->severity;

	return new_record;
}

static void uat_expert_free_cb(void*r)
{
	expert_level_entry_t *rec = (expert_level_entry_t *)r;

	if (rec->field)
		g_free(rec->field);
}

static void uat_expert_post_update_cb(void)
{
	guint              i;
	expert_field_info *field;

	/* Reset any of the previous list of expert info fields to their original severity */
	for ( i = 0 ; i < uat_saved_fields->len; i++ ) {
		field = g_array_index(uat_saved_fields, expert_field_info*, i);
		if (field != NULL) {
			field->severity = field->orig_severity;
		}
	}

	g_array_set_size(uat_saved_fields, 0);

	for (i = 0; i < expert_level_entry_count; i++)
	{
		field = expert_registrar_get_byname(uat_expert_entries[i].field);
		if (field != NULL)
		{
			field->severity = uat_expert_entries[i].severity;
			g_array_append_val(uat_saved_fields, field);
		}
	}
}

#define EXPERT_REGISTRAR_GET_NTH(eiindex, expinfo)                                               \
	if((guint)eiindex >= gpa_expertinfo.len && getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG"))   \
		g_error("Unregistered expert info! index=%d", eiindex);                          \
	DISSECTOR_ASSERT_HINT((guint)eiindex < gpa_expertinfo.len, "Unregistered expert info!"); \
	DISSECTOR_ASSERT_HINT(gpa_expertinfo.ei[eiindex] != NULL, "Unregistered expert info!");	\
	expinfo = gpa_expertinfo.ei[eiindex];

void
expert_packet_init(void)
{
	module_t *module_expert;
	uat_t    *expert_uat;

	static hf_register_info hf[] = {
		{ &hf_expert_msg,
			{ "Message", "_ws.expert.message", FT_STRING, BASE_NONE, NULL, 0, "Wireshark expert information", HFILL }
		},
		{ &hf_expert_group,
			{ "Group", "_ws.expert.group", FT_UINT32, BASE_NONE, VALS(expert_group_vals), 0, "Wireshark expert group", HFILL }
		},
		{ &hf_expert_severity,
			{ "Severity level", "_ws.expert.severity", FT_UINT32, BASE_NONE, VALS(expert_severity_vals), 0, "Wireshark expert severity level", HFILL }
		}
	};
	static gint *ett[] = {
		&ett_expert,
		&ett_subexpert
	};

	/* UAT for overriding severity levels */
	static uat_field_t custom_expert_fields[] = {
		UAT_FLD_CSTRING(uat_expert_entries, field, "Field name", "Expert Info filter name"),
		UAT_FLD_VS(uat_expert_entries, severity, "Severity", expert_severity_vals, "Custom severity level"),
		UAT_END_FIELDS
	};

	if (expert_tap == -1) {
		expert_tap = register_tap("expert");
	}

	if (proto_expert == -1) {
		proto_expert = proto_register_protocol("Expert Info", "Expert", "_ws.expert");
		proto_register_field_array(proto_expert, hf, array_length(hf));
		proto_register_subtree_array(ett, array_length(ett));
		proto_set_cant_toggle(proto_expert);

		module_expert = prefs_register_protocol(proto_expert, NULL);

		expert_uat = uat_new("Expert Info Severity Level Configuration",
			sizeof(expert_level_entry_t),
			"expert_severity",
			TRUE,
			(void **)&uat_expert_entries,
			&expert_level_entry_count,
			UAT_AFFECTS_DISSECTION,
			NULL,
			uat_expert_copy_cb,
			uat_expert_update_cb,
			uat_expert_free_cb,
			uat_expert_post_update_cb,
			custom_expert_fields);

		prefs_register_uat_preference(module_expert,
			"expert_severity_levels",
			"Severity Level Configuration",
			"A table that overrides Expert Info field severity levels to user configured levels",
			expert_uat);

	}

	highest_severity = 0;

	proto_malformed = proto_get_id_by_filter_name("_ws.malformed");
}

void
expert_init(void)
{
	gpa_expertinfo.len           = 0;
	gpa_expertinfo.allocated_len = 0;
	gpa_expertinfo.ei            = NULL;
	gpa_name_map                 = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
	uat_saved_fields             = g_array_new(FALSE, FALSE, sizeof(expert_field_info*));
	deregistered_expertinfos     = g_ptr_array_new();
}

void
expert_packet_cleanup(void)
{
}

void
expert_cleanup(void)
{
	if (gpa_expertinfo.allocated_len) {
		gpa_expertinfo.len           = 0;
		gpa_expertinfo.allocated_len = 0;
		g_free(gpa_expertinfo.ei);
		gpa_expertinfo.ei          = NULL;
	}

	/* Free the abbrev/ID GTree */
	if (gpa_name_map) {
		g_hash_table_destroy(gpa_name_map);
		gpa_name_map = NULL;
	}

	/* Free the UAT saved fields */
	if (uat_saved_fields) {
		g_array_free(uat_saved_fields, TRUE);
		uat_saved_fields = NULL;
	}

	if (deregistered_expertinfos) {
		g_ptr_array_free(deregistered_expertinfos, FALSE);
		deregistered_expertinfos = NULL;
	}
}


int
expert_get_highest_severity(void)
{
	return highest_severity;
}

void
expert_update_comment_count(guint64 count)
{
	if (count==0 && highest_severity==PI_COMMENT)
		highest_severity = 0;
}

expert_module_t *expert_register_protocol(int id)
{
	expert_module_t *module;
	protocol_t      *protocol;

	protocol = find_protocol_by_id(id);

	module = wmem_new(wmem_epan_scope(), expert_module_t);
	module->proto_id = id;
	module->proto_name = proto_get_protocol_short_name(protocol);

	return module;
}

void
expert_deregister_expertinfo (const char *abbrev)
{
	expert_field_info *expinfo = (expert_field_info*)g_hash_table_lookup(gpa_name_map, abbrev);
	if (expinfo) {
		g_ptr_array_add(deregistered_expertinfos, gpa_expertinfo.ei[expinfo->id]);
		g_hash_table_steal(gpa_name_map, abbrev);
	}
}

void
expert_deregister_protocol (expert_module_t *module)
{
	wmem_free(wmem_epan_scope(), module);
}

static void
free_deregistered_expertinfo (gpointer data, gpointer user_data _U_)
{
	expert_field_info *expinfo = (expert_field_info *) data;
	gpa_expertinfo.ei[expinfo->id] = NULL; /* Invalidate this id */
}

void
expert_free_deregistered_expertinfos (void)
{
	g_ptr_array_foreach(deregistered_expertinfos, free_deregistered_expertinfo, NULL);
	g_ptr_array_free(deregistered_expertinfos, TRUE);
	deregistered_expertinfos = g_ptr_array_new();
}

static int
expert_register_field_init(expert_field_info *expinfo, expert_module_t *module)
{
	expinfo->protocol      = module->proto_name;

	/* if we always add and never delete, then id == len - 1 is correct */
	if (gpa_expertinfo.len >= gpa_expertinfo.allocated_len) {
		if (!gpa_expertinfo.ei) {
			gpa_expertinfo.allocated_len = PRE_ALLOC_EXPERT_FIELDS_MEM;
			gpa_expertinfo.ei = (expert_field_info **)g_malloc(sizeof(expert_field_info *)*PRE_ALLOC_EXPERT_FIELDS_MEM);
		} else {
			gpa_expertinfo.allocated_len += 1000;
			gpa_expertinfo.ei = (expert_field_info **)g_realloc(gpa_expertinfo.ei,
						   sizeof(expert_field_info *)*gpa_expertinfo.allocated_len);
		}
	}
	gpa_expertinfo.ei[gpa_expertinfo.len] = expinfo;
	gpa_expertinfo.len++;
	expinfo->id = gpa_expertinfo.len - 1;
	/* Save the original severity so it can be restored by the UAT */
	expinfo->orig_severity = expinfo->severity;

	/* save field name for lookup */
	g_hash_table_insert(gpa_name_map, (gpointer) (expinfo->name), expinfo);

	return expinfo->id;
}


/* for use with static arrays only, since we don't allocate our own copies
of the expert_field_info struct contained within the exp_register_info struct */
void
expert_register_field_array(expert_module_t *module, ei_register_info *exp, const int num_records)
{
	int		  i;
	ei_register_info *ptr = exp;

	for (i = 0; i < num_records; i++, ptr++) {
		/*
		 * Make sure we haven't registered this yet.
		 * Most fields have variables associated with them
		 * that are initialized to -1; some have array elements,
		 * or possibly uninitialized variables, so we also allow
		 * 0 (which is unlikely to be the field ID we get back
		 * from "expert_register_field_init()").
		 */
		if (ptr->ids->ei != -1 && ptr->ids->ei != 0) {
			fprintf(stderr,
				"Duplicate field detected in call to expert_register_field_array: '%s' is already registered, name=%s\n",
				ptr->eiinfo.summary, ptr->eiinfo.name);
			return;
		}

		/* Register the field with the experts */
		ptr->ids->ei = expert_register_field_init(&ptr->eiinfo, module);

		/* Register with the header field info, so it's display filterable */
		ptr->eiinfo.hf_info.p_id = &ptr->ids->hf;
		ptr->eiinfo.hf_info.hfinfo.abbrev = ptr->eiinfo.name;
		ptr->eiinfo.hf_info.hfinfo.blurb = ptr->eiinfo.summary;

		proto_register_field_array(module->proto_id, &ptr->eiinfo.hf_info, 1);
	}
}

/* Finds a record in the expert array by name.
 * For the moment, this function is only used "internally"
 * but may find a reason to be exported
 */
static expert_field_info *
expert_registrar_get_byname(const char *field_name)
{
	expert_field_info *hfinfo;

	if (!field_name)
		return NULL;

	hfinfo = (expert_field_info*)g_hash_table_lookup(gpa_name_map, field_name);

	return hfinfo;
}

/**
 * Get summary text of an expert_info field.
 * This is intended for use in expert_add_info_format or proto_tree_add_expert_format
 * to get the "base" string to then append additional information
 */
const gchar* expert_get_summary(expert_field *eiindex)
{
	expert_field_info *eiinfo;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(eiindex->ei, eiinfo);

    return eiinfo->summary;
}

/** clear flags according to the mask and set new flag values */
#define FI_REPLACE_FLAGS(fi, mask, flags_in) { \
	(fi->flags = (fi)->flags & ~(mask)); \
	(fi->flags = (fi)->flags | (flags_in)); \
}

/* set's the PI_ flags to a protocol item
 * (and its parent items till the toplevel) */
static void
expert_set_item_flags(proto_item *pi, const int group, const guint severity)
{
	if (pi != NULL && PITEM_FINFO(pi) != NULL && (severity >= FI_GET_FLAG(PITEM_FINFO(pi), PI_SEVERITY_MASK))) {
		FI_REPLACE_FLAGS(PITEM_FINFO(pi), PI_GROUP_MASK, group);
		FI_REPLACE_FLAGS(PITEM_FINFO(pi), PI_SEVERITY_MASK, severity);

		/* propagate till toplevel item */
		pi = proto_item_get_parent(pi);
		expert_set_item_flags(pi, group, severity);
	}
}

static proto_tree*
expert_create_tree(proto_item *pi, int group, int severity, const char *msg)
{
	proto_tree *tree;
	proto_item *ti;

	tree = proto_item_add_subtree(pi, ett_expert);
	ti = proto_tree_add_protocol_format(tree, proto_expert, NULL, 0, 0, "Expert Info (%s/%s): %s",
					    val_to_str(severity, expert_severity_vals, "Unknown (%u)"),
					    val_to_str(group, expert_group_vals, "Unknown (%u)"),
					    msg);
	PROTO_ITEM_SET_GENERATED(ti);

	if (group == PI_MALFORMED) {
		/* Add hidden malformed protocol filter */
		proto_item *malformed_ti = proto_tree_add_item(tree, proto_malformed, NULL, 0, 0, ENC_NA);
		PROTO_ITEM_SET_HIDDEN(malformed_ti);
	}

	return proto_item_add_subtree(ti, ett_subexpert);
}

static void
expert_set_info_vformat(packet_info *pinfo, proto_item *pi, int group, int severity, int hf_index, gboolean use_vaformat,
			const char *format, va_list ap)
{
	char           formatted[ITEM_LABEL_LENGTH];
	int            tap;
	expert_info_t *ei;
	proto_tree    *tree;
	proto_item    *ti;

	if (pinfo == NULL && pi && pi->tree_data) {
		pinfo = PTREE_DATA(pi)->pinfo;
	}

	/* if this packet isn't loaded because of a read filter, don't output anything */
	if (pinfo == NULL || pinfo->num == 0) {
		return;
	}

	if (severity > highest_severity) {
		highest_severity = severity;
	}

	/* XXX: can we get rid of these checks and make them programming errors instead now? */
	if (pi != NULL && PITEM_FINFO(pi) != NULL) {
		expert_set_item_flags(pi, group, severity);
	}

	if ((pi == NULL) || (PITEM_FINFO(pi) == NULL) ||
		((guint)severity >= FI_GET_FLAG(PITEM_FINFO(pi), PI_SEVERITY_MASK))) {
		col_add_str(pinfo->cinfo, COL_EXPERT, val_to_str(severity, expert_severity_vals, "Unknown (%u)"));
	}

	if (use_vaformat) {
		ws_vsnprintf(formatted, ITEM_LABEL_LENGTH, format, ap);
	} else {
		g_strlcpy(formatted, format, ITEM_LABEL_LENGTH);
	}

	tree = expert_create_tree(pi, group, severity, formatted);

	if (hf_index == -1) {
		/* If no filterable expert info, just add the message */
		ti = proto_tree_add_string(tree, hf_expert_msg, NULL, 0, 0, formatted);
		PROTO_ITEM_SET_GENERATED(ti);
	} else {
		/* If filterable expert info, hide the "generic" form of the message,
		   and generate the formatted filterable expert info */
		ti = proto_tree_add_none_format(tree, hf_index, NULL, 0, 0, "%s", formatted);
		PROTO_ITEM_SET_GENERATED(ti);
		ti = proto_tree_add_string(tree, hf_expert_msg, NULL, 0, 0, formatted);
		PROTO_ITEM_SET_HIDDEN(ti);
	}

	ti = proto_tree_add_uint_format_value(tree, hf_expert_severity, NULL, 0, 0, severity,
					      "%s", val_to_str_const(severity, expert_severity_vals, "Unknown"));
	PROTO_ITEM_SET_GENERATED(ti);
	ti = proto_tree_add_uint_format_value(tree, hf_expert_group, NULL, 0, 0, group,
					      "%s", val_to_str_const(group, expert_group_vals, "Unknown"));
	PROTO_ITEM_SET_GENERATED(ti);

	tap = have_tap_listener(expert_tap);

	if (!tap)
		return;

	ei = wmem_new(wmem_packet_scope(), expert_info_t);

	ei->packet_num  = pinfo->num;
	ei->group       = group;
	ei->severity    = severity;
	ei->hf_index    = hf_index;
	ei->protocol    = pinfo->current_proto;
	ei->summary     = wmem_strdup(wmem_packet_scope(), formatted);

	/* if we have a proto_item (not a faked item), set expert attributes to it */
	if (pi != NULL && PITEM_FINFO(pi) != NULL) {
		ei->pitem = pi;
	}
	/* XXX: remove this because we don't have an internal-only function now? */
	else {
		ei->pitem = NULL;
	}

	tap_queue_packet(expert_tap, pinfo, ei);
}

/* Helper function for expert_add_info() to work around compiler's special needs on ARM */
static inline void
expert_add_info_internal(packet_info *pinfo, proto_item *pi, expert_field *expindex, ...)
{
	/* the va_list is ignored */
	va_list            unused;
	expert_field_info *eiinfo;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	va_start(unused, expindex);
	expert_set_info_vformat(pinfo, pi, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, FALSE, eiinfo->summary, unused);
	va_end(unused);
}

void
expert_add_info(packet_info *pinfo, proto_item *pi, expert_field *expindex)
{
	expert_add_info_internal(pinfo, pi, expindex);
}

void
expert_add_info_format(packet_info *pinfo, proto_item *pi, expert_field *expindex, const char *format, ...)
{
	va_list            ap;
	expert_field_info *eiinfo;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	va_start(ap, format);
	expert_set_info_vformat(pinfo, pi, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, TRUE, format, ap);
	va_end(ap);
}

/* Helper function for expert_add_expert() to work around compiler's special needs on ARM */
static inline proto_item *
proto_tree_add_expert_internal(proto_tree *tree, packet_info *pinfo, expert_field *expindex,
		tvbuff_t *tvb, gint start, gint length, ...)
{
	expert_field_info *eiinfo;
	proto_item        *ti;
	va_list            unused;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	ti = proto_tree_add_text_internal(tree, tvb, start, length, "%s", eiinfo->summary);
	va_start(unused, length);
	expert_set_info_vformat(pinfo, ti, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, FALSE, eiinfo->summary, unused);
	va_end(unused);
	return ti;
}

proto_item *
proto_tree_add_expert(proto_tree *tree, packet_info *pinfo, expert_field *expindex,
		tvbuff_t *tvb, gint start, gint length)
{
	return proto_tree_add_expert_internal(tree, pinfo, expindex, tvb, start, length);
}

proto_item *
proto_tree_add_expert_format(proto_tree *tree, packet_info *pinfo, expert_field *expindex,
		tvbuff_t *tvb, gint start, gint length, const char *format, ...)
{
	va_list            ap;
	expert_field_info *eiinfo;
	proto_item        *ti;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	va_start(ap, format);
	ti = proto_tree_add_text_valist_internal(tree, tvb, start, length, format, ap);
	va_end(ap);

	va_start(ap, format);
	expert_set_info_vformat(pinfo, ti, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, TRUE, format, ap);
	va_end(ap);

	return ti;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
