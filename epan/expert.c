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

#include "packet.h"
#include "expert.h"
#include "emem.h"
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
	const char* proto_name;
	int         proto_id;      /* Cache this for registering hfs */
};

/* List which stores protocols and expert_info that have been registered */
typedef struct _gpa_expertinfo_t {
	guint32             len;
	guint32             allocated_len;
	expert_field_info **ei;
} gpa_expertinfo_t;
static gpa_expertinfo_t gpa_expertinfo;

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
        { 0, NULL }
};

const value_string expert_severity_vals[] = {
        { PI_ERROR,             "Error" },
        { PI_WARN,              "Warn" },
        { PI_NOTE,              "Note" },
        { PI_CHAT,              "Chat" },
        { PI_COMMENT,           "Comment" },
        { 0,                    "Ok" },
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


#define EXPERT_REGISTRAR_GET_NTH(eiindex, expinfo)						\
	if((guint)eiindex >= gpa_expertinfo.len && getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG"))	\
		g_error("Unregistered expert info! index=%d", eiindex);					\
	DISSECTOR_ASSERT_HINT((guint)eiindex < gpa_expertinfo.len, "Unregistered expert info!");\
	expinfo = gpa_expertinfo.ei[eiindex];

void
expert_packet_init(void)
{
	static hf_register_info hf[] = {
		{ &hf_expert_msg,
			{ "Message", "_ws.expert.message", FT_STRING, BASE_NONE, NULL, 0, "Wireshark expert information", HFILL }
		},
		{ &hf_expert_group,
			{ "Group", "_ws.expert.group", FT_UINT32, BASE_HEX, VALS(expert_group_vals), 0, "Wireshark expert group", HFILL }
		},
		{ &hf_expert_severity,
			{ "Severity level", "_ws.expert.severity", FT_UINT32, BASE_HEX, VALS(expert_severity_vals), 0, "Wireshark expert severity level", HFILL }
		}
	};
	static gint *ett[] = {
		&ett_expert,
		&ett_subexpert
	};

	if (expert_tap == -1) {
		expert_tap = register_tap("expert");
	}

	if (proto_expert == -1) {
		proto_expert = proto_register_protocol("Expert Info", "Expert", "_ws.expert");
		proto_register_field_array(proto_expert, hf, array_length(hf));
		proto_register_subtree_array(ett, array_length(ett));
		proto_set_cant_toggle(proto_expert);
	}

	highest_severity = 0;

	proto_malformed = proto_get_id_by_filter_name("_ws.malformed");
}

void
expert_init(void)
{
	gpa_expertinfo.len           = 0;
	gpa_expertinfo.allocated_len = 0;
	gpa_expertinfo.ei          = NULL;
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
	protocol_t *protocol;

	protocol = find_protocol_by_id(id);

	module = wmem_new(wmem_epan_scope(), expert_module_t);
	module->proto_id = id;
	module->proto_name = proto_get_protocol_short_name(protocol);

	return module;
}

static int
expert_register_field_init(expert_field_info *expinfo, expert_module_t* module)
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

	return expinfo->id;
}


/* for use with static arrays only, since we don't allocate our own copies
of the expert_field_info struct contained within the exp_register_info struct */
void
expert_register_field_array(expert_module_t* module, ei_register_info *exp, const int num_records)
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
				"Duplicate field detected in call to expert_register_field_array: '%s' is already registered\n",
				ptr->eiinfo.summary);
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
	char            formatted[ITEM_LABEL_LENGTH];
	int             tap;
	expert_info_t   *ei;
	proto_tree      *tree;
	proto_item      *ti;

	if (pinfo == NULL && pi && pi->tree_data) {
		pinfo = PTREE_DATA(pi)->pinfo;
	}

	/* if this packet isn't loaded because of a read filter, don't output anything */
	if (pinfo == NULL || PINFO_FD_NUM(pinfo) == 0) {
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
		g_vsnprintf(formatted, ITEM_LABEL_LENGTH, format, ap);
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

	ei = ep_new(expert_info_t);

	ei->packet_num  = PINFO_FD_NUM(pinfo);
	ei->group       = group;
	ei->severity    = severity;
	ei->protocol    = pinfo->current_proto;
	ei->summary     = ep_strdup(formatted);

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

void
expert_add_info(packet_info *pinfo, proto_item *pi, expert_field *expindex)
{
	expert_field_info* eiinfo;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	expert_set_info_vformat(pinfo, pi, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, FALSE, eiinfo->summary, NULL);
}

void
expert_add_info_format(packet_info *pinfo, proto_item *pi, expert_field *expindex, const char *format, ...)
{
	va_list ap;
	expert_field_info* eiinfo;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	va_start(ap, format);
	expert_set_info_vformat(pinfo, pi, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, TRUE, format, ap);
	va_end(ap);
}

proto_item *
proto_tree_add_expert(proto_tree *tree, packet_info *pinfo, expert_field* expindex,
		tvbuff_t *tvb, gint start, gint length)
{
	expert_field_info* eiinfo;
	proto_item *ti;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	ti = proto_tree_add_text(tree, tvb, start, length, "%s", eiinfo->summary);
	expert_set_info_vformat(pinfo, ti, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, FALSE, eiinfo->summary, NULL);
	return ti;
}

proto_item *
proto_tree_add_expert_format(proto_tree *tree, packet_info *pinfo, expert_field* expindex,
		tvbuff_t *tvb, gint start, gint length, const char *format, ...)
{
	va_list ap;
	expert_field_info* eiinfo;
	proto_item *ti;

	/* Look up the item */
	EXPERT_REGISTRAR_GET_NTH(expindex->ei, eiinfo);

	va_start(ap, format);
	ti = proto_tree_add_text_valist(tree, tvb, start, length, format, ap);
	va_end(ap);

	va_start(ap, format);
	expert_set_info_vformat(pinfo, ti, eiinfo->group, eiinfo->severity, *eiinfo->hf_info.p_id, TRUE, format, ap);
	va_end(ap);

	return ti;
}
