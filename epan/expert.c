/* expert.c
 * Collecting Expert information.
 *
 * Implemented as a tap named "expert".
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_EPAN

#include <stdio.h>
#include <stdlib.h>

#include "packet.h"
#include "expert.h"
#include "uat.h"
#include "prefs.h"
#include <epan/prefs-int.h>
#include <epan/wmem_scopes.h>
#include "tap.h"

#include <wsutil/str_util.h>
#include <wsutil/wslog.h>

/* proto_expert cannot be static because it's referenced in the
 * print routines
 */
int proto_expert;

static int proto_malformed;

static int expert_tap;
static int highest_severity;

static int ett_expert;
static int ett_subexpert;

static int hf_expert_msg;
static int hf_expert_group;
static int hf_expert_severity;

struct expert_module
{
	const char *proto_name;
	int         proto_id;      /* Cache this for registering hfs */
};

/* List which stores protocols and expert_info that have been registered */
typedef struct _gpa_expertinfo_t {
	uint32_t            len;
	uint32_t            allocated_len;
	expert_field_info **ei;
} gpa_expertinfo_t;
static gpa_expertinfo_t gpa_expertinfo;

/* Hash table of abbreviations and IDs */
static GHashTable *gpa_name_map;

/* Deregistered expert infos */
static GPtrArray *deregistered_expertinfos;

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
	{ PI_DEPRECATED,        "Deprecated" },
	{ PI_RECEIVE,           "Receive" },
	{ PI_INTERFACE,         "Interface" },
	{ PI_DISSECTOR_BUG,     "Dissector bug" },
	{ 0, NULL }
};

const value_string expert_severity_vals[] = {
	{ PI_ERROR,             "Error" },
	{ PI_WARN,              "Warning" },
	{ PI_NOTE,              "Note" },
	{ PI_CHAT,              "Chat" },
	{ PI_COMMENT,           "Comment" },
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
	uint32_t severity;
} expert_level_entry_t;

static expert_level_entry_t *uat_expert_entries;
static unsigned expert_level_entry_count;
/* Array of field names currently in UAT */
static GArray *uat_saved_fields;

UAT_CSTRING_CB_DEF(uat_expert_entries, field, expert_level_entry_t)
UAT_VS_DEF(uat_expert_entries, severity, expert_level_entry_t, uint32_t, PI_ERROR, "Error")

static bool uat_expert_update_cb(void *r, char **err)
{
	expert_level_entry_t *rec = (expert_level_entry_t *)r;

	if (expert_registrar_get_byname(rec->field) == NULL) {
		*err = ws_strdup_printf("Expert Info field doesn't exist: %s", rec->field);
		return false;
	}
	return true;
}

static void *uat_expert_copy_cb(void *n, const void *o, size_t siz _U_)
{
	expert_level_entry_t       *new_record = (expert_level_entry_t*)n;
	const expert_level_entry_t *old_record = (const expert_level_entry_t *)o;

	new_record->field = g_strdup(old_record->field);

	new_record->severity = old_record->severity;

	return new_record;
}

static void uat_expert_free_cb(void*r)
{
	expert_level_entry_t *rec = (expert_level_entry_t *)r;

	g_free(rec->field);
}

static void uat_expert_post_update_cb(void)
{
	unsigned           i;
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
	if((unsigned)eiindex >= gpa_expertinfo.len && wireshark_abort_on_dissector_bug)   \
		ws_error("Unregistered expert info! index=%d", eiindex);                          \
	DISSECTOR_ASSERT_HINT((unsigned)eiindex < gpa_expertinfo.len, "Unregistered expert info!"); \
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
	static int *ett[] = {
		&ett_expert,
		&ett_subexpert
	};

	/* UAT for overriding severity levels */
	static uat_field_t custom_expert_fields[] = {
		UAT_FLD_CSTRING(uat_expert_entries, field, "Field name", "Expert Info filter name"),
		UAT_FLD_VS(uat_expert_entries, severity, "Severity", expert_severity_vals, "Custom severity level"),
		UAT_END_FIELDS
	};

	if (expert_tap == 0) {
		expert_tap = register_tap("expert");
	}

	if (proto_expert <= 0) {
		proto_expert = proto_register_protocol("Expert Info", "Expert", "_ws.expert");
		proto_register_field_array(proto_expert, hf, array_length(hf));
		proto_register_subtree_array(ett, array_length(ett));
		proto_set_cant_toggle(proto_expert);

		module_expert = prefs_register_protocol(proto_expert, NULL);
		//Since "expert" is really a pseudo protocol, it shouldn't be
		//categorized with other "real" protocols when it comes to
		//preferences.  Since it's just a UAT, don't bury it in
		//with the other protocols
		module_expert->use_gui = false;

		expert_uat = uat_new("Expert Info Severity Level Configuration",
			sizeof(expert_level_entry_t),
			"expert_severity",
			true,
			(void **)&uat_expert_entries,
			&expert_level_entry_count,
			UAT_AFFECTS_DISSECTION,
			NULL,
			uat_expert_copy_cb,
			uat_expert_update_cb,
			uat_expert_free_cb,
			uat_expert_post_update_cb,
			NULL,
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
	uat_saved_fields             = g_array_new(false, false, sizeof(expert_field_info*));
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
		g_array_free(uat_saved_fields, true);
		uat_saved_fields = NULL;
	}

	if (deregistered_expertinfos) {
		g_ptr_array_free(deregistered_expertinfos, true);
		deregistered_expertinfos = NULL;
	}
}


int
expert_get_highest_severity(void)
{
	return highest_severity;
}

void
expert_update_comment_count(uint64_t count)
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
free_deregistered_expertinfo (void *data, void *user_data _U_)
{
	expert_field_info *expinfo = (expert_field_info *) data;
	gpa_expertinfo.ei[expinfo->id] = NULL; /* Invalidate this id */
}

void
expert_free_deregistered_expertinfos (void)
{
	g_ptr_array_foreach(deregistered_expertinfos, free_deregistered_expertinfo, NULL);
	g_ptr_array_free(deregistered_expertinfos, true);
	deregistered_expertinfos = g_ptr_array_new();
}

static int
expert_register_field_init(expert_field_info *expinfo, expert_module_t *module)
{
	/* Check for valid group and severity vals */
	switch (expinfo->group) {
		case PI_CHECKSUM:
		case PI_SEQUENCE:
		case PI_RESPONSE_CODE:
		case PI_REQUEST_CODE:
		case PI_UNDECODED:
		case PI_REASSEMBLE:
		case PI_MALFORMED:
		case PI_DEBUG:
		case PI_PROTOCOL:
		case PI_SECURITY:
		case PI_COMMENTS_GROUP:
		case PI_DECRYPTION:
		case PI_ASSUMPTION:
		case PI_DEPRECATED:
		case PI_RECEIVE:
		case PI_INTERFACE:
		case PI_DISSECTOR_BUG:
			break;
		default:
			REPORT_DISSECTOR_BUG("Expert info for %s has invalid group=0x%08x\n", expinfo->name, expinfo->group);
	}
	switch (expinfo->severity) {
		case PI_COMMENT:
		case PI_CHAT:
		case PI_NOTE:
		case PI_WARN:
		case PI_ERROR:
			break;
		default:
			REPORT_DISSECTOR_BUG("Expert info for %s has invalid severity=0x%08x\n", expinfo->name, expinfo->severity);
	}

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
	g_hash_table_insert(gpa_name_map, (void *) (expinfo->name), expinfo);

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
		ptr->eiinfo.hf_info.hfinfo.name = ptr->eiinfo.summary;
		ptr->eiinfo.hf_info.hfinfo.abbrev = ptr->eiinfo.name;

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
const char* expert_get_summary(expert_field *eiindex)
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
// NOLINTNEXTLINE(misc-no-recursion)
expert_set_item_flags(proto_item *pi, const int group, const unsigned severity)
{
	if (pi != NULL && PITEM_FINFO(pi) != NULL && (severity >= FI_GET_FLAG(PITEM_FINFO(pi), PI_SEVERITY_MASK))) {
		FI_REPLACE_FLAGS(PITEM_FINFO(pi), PI_GROUP_MASK, group);
		FI_REPLACE_FLAGS(PITEM_FINFO(pi), PI_SEVERITY_MASK, severity);

		/* propagate till toplevel item */
		pi = proto_item_get_parent(pi);
		// We recurse here, but we're limited by our tree depth checks in proto.c
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
	proto_item_set_generated(ti);

	if (group == PI_MALFORMED) {
		/* Add hidden malformed protocol filter */
		proto_item *malformed_ti = proto_tree_add_item(tree, proto_malformed, NULL, 0, 0, ENC_NA);
		proto_item_set_hidden(malformed_ti);
	}

	return proto_item_add_subtree(ti, ett_subexpert);
}

static proto_tree*
expert_set_info_vformat(packet_info *pinfo, proto_item *pi, int group, int severity, int hf_index, bool use_vaformat,
			const char *format, va_list ap)
{
	char           formatted[ITEM_LABEL_LENGTH];
	int            pos;
	int            tap;
	expert_info_t *ei;
	proto_tree    *tree;
	proto_item    *ti;

	if (pinfo == NULL && pi && pi->tree_data) {
		pinfo = PTREE_DATA(pi)->pinfo;
	}

	/* if this packet isn't loaded because of a read filter, don't output anything */
	if (pinfo == NULL || pinfo->num == 0) {
		return NULL;
	}

	if (severity > highest_severity) {
		highest_severity = severity;
	}

	/* XXX: can we get rid of these checks and make them programming errors instead now? */
	if (pi != NULL && PITEM_FINFO(pi) != NULL) {
		expert_set_item_flags(pi, group, severity);
	}

	if ((pi == NULL) || (PITEM_FINFO(pi) == NULL) ||
		((unsigned)severity >= FI_GET_FLAG(PITEM_FINFO(pi), PI_SEVERITY_MASK))) {
		col_add_str(pinfo->cinfo, COL_EXPERT, val_to_str(severity, expert_severity_vals, "Unknown (%u)"));
	}

	if (use_vaformat) {
		pos = vsnprintf(formatted, ITEM_LABEL_LENGTH, format, ap);
	} else {
		pos = (int)g_strlcpy(formatted, format, ITEM_LABEL_LENGTH);
	}

	/* Both vsnprintf and g_strlcpy return the number of bytes attempted
         * to write.
         */
        if (pos >= ITEM_LABEL_LENGTH) {
		/* Truncation occurred. It might have split a UTF-8 character. */
		ws_utf8_truncate(formatted, ITEM_LABEL_LENGTH - 1);
	}

	tree = expert_create_tree(pi, group, severity, formatted);

	if (hf_index <= 0) {
		/* If no filterable expert info, just add the message */
		ti = proto_tree_add_string(tree, hf_expert_msg, NULL, 0, 0, formatted);
		proto_item_set_generated(ti);
	} else {
		/* If filterable expert info, hide the "generic" form of the message,
		   and generate the formatted filterable expert info */
		ti = proto_tree_add_none_format(tree, hf_index, NULL, 0, 0, "%s", formatted);
		proto_item_set_generated(ti);
		ti = proto_tree_add_string(tree, hf_expert_msg, NULL, 0, 0, formatted);
		proto_item_set_hidden(ti);
	}

	ti = proto_tree_add_uint_format_value(tree, hf_expert_severity, NULL, 0, 0, severity,
					      "%s", val_to_str_const(severity, expert_severity_vals, "Unknown"));
	proto_item_set_generated(ti);
	ti = proto_tree_add_uint_format_value(tree, hf_expert_group, NULL, 0, 0, group,
					      "%s", val_to_str_const(group, expert_group_vals, "Unknown"));
	proto_item_set_generated(ti);

	tap = have_tap_listener(expert_tap);

	if (!tap)
		return tree;

	ei = wmem_new(pinfo->pool, expert_info_t);

	ei->packet_num  = pinfo->num;
	ei->group       = group;
	ei->severity    = severity;
	ei->hf_index    = hf_index;
	ei->protocol    = pinfo->current_proto;
	ei->summary     = wmem_strdup(pinfo->pool, formatted);

	/* if we have a proto_item (not a faked item), set expert attributes to it */
	if (pi != NULL && PITEM_FINFO(pi) != NULL) {
		ei->pitem = pi;
	}
	/* XXX: remove this because we don't have an internal-only function now? */
	else {
		ei->pitem = NULL;
	}

	tap_queue_packet(expert_tap, pinfo, ei);
	return tree;
}

/* Helper function for expert_add_info() to work around compiler's special needs on ARM */
static inline proto_tree*
expert_add_info_internal(packet_info *pinfo, proto_item *pi, expert_field *expindex, ...)
{
	/* the va_list is ignored */
	va_list            unused;
	expert_field_info *eiinfo;
	proto_tree        *tree;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	va_start(unused, expindex);
	tree = expert_set_info_vformat(pinfo, pi, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, false, eiinfo->summary, unused);
	va_end(unused);
	return tree;
}

proto_item *
expert_add_info(packet_info *pinfo, proto_item *pi, expert_field *expindex)
{
	proto_tree        *tree;
	tree = expert_add_info_internal(pinfo, pi, expindex);
	return (proto_item *)tree;
}

proto_item *
expert_add_info_format(packet_info *pinfo, proto_item *pi, expert_field *expindex, const char *format, ...)
{
	va_list            ap;
	expert_field_info *eiinfo;
	proto_tree        *tree;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	va_start(ap, format);
	tree = expert_set_info_vformat(pinfo, pi, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, true, format, ap);
	va_end(ap);
	return (proto_item *)tree;
}

/* Helper function for expert_add_expert() to work around compiler's special needs on ARM */
static inline proto_item *
proto_tree_add_expert_internal(proto_tree *tree, packet_info *pinfo, expert_field *expindex,
		tvbuff_t *tvb, int start, int length, ...)
{
	expert_field_info *eiinfo;
	proto_item        *ti;
	int                item_length, captured_length;
	va_list            unused;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	/* Make sure this doesn't throw an exception when adding the item */
	item_length = length;
	captured_length = tvb_captured_length_remaining(tvb, start);
	if (captured_length < 0)
		item_length = 0;
	else if (captured_length < item_length)
		item_length = captured_length;
	ti = proto_tree_add_text_internal(tree, tvb, start, item_length, "%s", eiinfo->summary);
	va_start(unused, length);
	expert_set_info_vformat(pinfo, ti, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, false, eiinfo->summary, unused);
	va_end(unused);

	/* But make sure it throws an exception *after* adding the item */
	if (length != -1) {
		tvb_ensure_bytes_exist(tvb, start, length);
	}
	return ti;
}

proto_item *
proto_tree_add_expert(proto_tree *tree, packet_info *pinfo, expert_field *expindex,
		tvbuff_t *tvb, int start, int length)
{
	return proto_tree_add_expert_internal(tree, pinfo, expindex, tvb, start, length);
}

proto_item *
proto_tree_add_expert_format(proto_tree *tree, packet_info *pinfo, expert_field *expindex,
		tvbuff_t *tvb, int start, int length, const char *format, ...)
{
	va_list            ap;
	expert_field_info *eiinfo;
	int                item_length, captured_length;
	proto_item        *ti;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	/* Make sure this doesn't throw an exception when adding the item */
	item_length = length;
	captured_length = tvb_captured_length_remaining(tvb, start);
	if (captured_length < 0)
		item_length = 0;
	else if (captured_length < item_length)
		item_length = captured_length;
	va_start(ap, format);
	ti = proto_tree_add_text_valist_internal(tree, tvb, start, item_length, format, ap);
	va_end(ap);

	va_start(ap, format);
	expert_set_info_vformat(pinfo, ti, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, true, format, ap);
	va_end(ap);

	/* But make sure it throws an exception *after* adding the item */
	if (length != -1) {
		tvb_ensure_bytes_exist(tvb, start, length);
	}
	return ti;
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
