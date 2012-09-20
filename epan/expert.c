/* expert.c
 * Collecting Expert information.
 *
 * Implemented as a tap named "expert".
 *
 * $Id$
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

#include "packet.h"
#include "expert.h"
#include "emem.h"
#include "tap.h"


/* proto_expert cannot be static because it's referenced in the
 * print routines
 */
int proto_expert              = -1;

static int expert_tap         = -1;
static int highest_severity   =  0;

static int ett_expert         = -1;
static int ett_subexpert      = -1;

static int hf_expert_msg      = -1;
static int hf_expert_group    = -1;
static int hf_expert_severity = -1;

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

void
expert_init(void)
{
	static hf_register_info hf[] = {
		{ &hf_expert_msg,
			{ "Message", "expert.message", FT_STRING, BASE_NONE, NULL, 0, "Wireshark expert information", HFILL }
		},
		{ &hf_expert_group,
			{ "Group", "expert.group", FT_UINT32, BASE_HEX, VALS(expert_group_vals), 0, "Wireshark expert group", HFILL }
		},
		{ &hf_expert_severity,
			{ "Severity level", "expert.severity", FT_UINT32, BASE_HEX, VALS(expert_severity_vals), 0, "Wireshark expert severity level", HFILL }
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
		proto_expert = proto_register_protocol("Expert Info", "Expert", "expert");
		proto_register_field_array(proto_expert, hf, array_length(hf));
		proto_register_subtree_array(ett, array_length(ett));
		proto_set_cant_toggle(proto_expert);
	}

	highest_severity = 0;
}


void
expert_cleanup(void)
{

}


int
expert_get_highest_severity(void)
{
	return highest_severity;
}


/* set's the PI_ flags to a protocol item
 * (and its parent items till the toplevel) */
static void
expert_set_item_flags(proto_item *pi, int group, int severity)
{
	if (proto_item_set_expert_flags(pi, group, severity)) {
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
		gint proto_malformed = proto_get_id_by_filter_name("malformed");
		proto_item *malformed_ti = proto_tree_add_item(tree, proto_malformed, NULL, 0, 0, ENC_NA);
		PROTO_ITEM_SET_HIDDEN(malformed_ti);
	}

	return proto_item_add_subtree(ti, ett_subexpert);
}

static void
expert_set_info_vformat(packet_info *pinfo, proto_item *pi, int group, int severity, const char *format, va_list ap)
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

	if (pi != NULL && PITEM_FINFO(pi) != NULL) {
		expert_set_item_flags(pi, group, severity);
	}

	col_add_str(pinfo->cinfo, COL_EXPERT, val_to_str(severity, expert_severity_vals, "Unknown (%u)"));

	g_vsnprintf(formatted, ITEM_LABEL_LENGTH, format, ap);

	tree = expert_create_tree(pi, group, severity, formatted);

	ti = proto_tree_add_string(tree, hf_expert_msg, NULL, 0, 0, formatted);
	PROTO_ITEM_SET_GENERATED(ti);
	ti = proto_tree_add_uint_format_value(tree, hf_expert_severity, NULL, 0, 0, severity,
					      "%s", val_to_str_const(severity, expert_severity_vals, "Unknown"));
	PROTO_ITEM_SET_GENERATED(ti);
	ti = proto_tree_add_uint_format_value(tree, hf_expert_group, NULL, 0, 0, group,
					      "%s", val_to_str_const(group, expert_group_vals, "Unknown"));
	PROTO_ITEM_SET_GENERATED(ti);

	tap = have_tap_listener(expert_tap);

	if (!tap)
		return;

	ei = ep_alloc(sizeof(expert_info_t));

	ei->packet_num  = PINFO_FD_NUM(pinfo);
	ei->group       = group;
	ei->severity    = severity;
	ei->protocol    = pinfo->current_proto;
	ei->summary     = ep_strdup(formatted);

	/* if we have a proto_item (not a faked item), set expert attributes to it */
	if (pi != NULL && PITEM_FINFO(pi) != NULL) {
		ei->pitem = pi;
	} else {
		ei->pitem = NULL;
	}

	tap_queue_packet(expert_tap, pinfo, ei);
}


void
expert_add_info_format(packet_info *pinfo, proto_item *pi, int group, int severity, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	expert_set_info_vformat(pinfo, pi, group, severity, format, ap);
	va_end(ap);
}

void
expert_add_undecoded_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length, const int severity)
{

	proto_item *expert_item;

	expert_item = proto_tree_add_text(tree, tvb, offset, length, "Not dissected yet");

	expert_add_info_format(pinfo, expert_item, PI_UNDECODED, severity, "Not dissected yet(report to wireshark.org)"); \
	PROTO_ITEM_SET_GENERATED(expert_item); \

}
