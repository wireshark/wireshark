/* show_exception.c
 *
 * Routines to put exception information into the protocol tree
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/show_exception.h>

static int proto_short = -1;
static int proto_malformed = -1;
static int proto_unreassembled = -1;

static expert_field ei_malformed_dissector_bug = EI_INIT;
static expert_field ei_malformed_reassembly = EI_INIT;
static expert_field ei_malformed = EI_INIT;

void
register_show_exception(void)
{
	static ei_register_info ei[] = {
		{ &ei_malformed_dissector_bug, { "_ws.malformed.dissector_bug", PI_MALFORMED, PI_ERROR, "Dissector bug", EXPFILL }},
		{ &ei_malformed_reassembly, { "_ws.malformed.reassembly", PI_MALFORMED, PI_ERROR, "Reassembly error", EXPFILL }},
		{ &ei_malformed, { "_ws.malformed.expert", PI_MALFORMED, PI_ERROR, "Malformed Packet (Exception occurred)", EXPFILL }},
	};

	expert_module_t* expert_malformed;

	proto_short = proto_register_protocol("Short Frame", "Short frame", "_ws.short");
	proto_malformed = proto_register_protocol("Malformed Packet",
	    "Malformed packet", "_ws.malformed");
	proto_unreassembled = proto_register_protocol(
	    "Unreassembled Fragmented Packet",
	    "Unreassembled fragmented packet", "_ws.unreassembled");

	expert_malformed = expert_register_protocol(proto_malformed);
	expert_register_field_array(expert_malformed, ei, array_length(ei));

	/* "Short Frame", "Malformed Packet", and "Unreassembled Fragmented
	   Packet" aren't really protocols, they're error indications;
	   disabling them makes no sense. */
	proto_set_cant_toggle(proto_short);
	proto_set_cant_toggle(proto_malformed);
	proto_set_cant_toggle(proto_unreassembled);
}

void
show_exception(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	       unsigned long exception, const char *exception_message)
{
	static const char dissector_error_nomsg[] =
		"Dissector writer didn't bother saying what the error was";
	proto_item *item;

	if (exception == ReportedBoundsError && pinfo->fragmented)
		exception = FragmentBoundsError;

	switch (exception) {

	case ScsiBoundsError:
		col_append_str(pinfo->cinfo, COL_INFO, "[SCSI transfer limited due to allocation_length too small]");
		proto_tree_add_protocol_format(tree, proto_short, tvb, 0, 0,
				"SCSI transfer limited due to allocation_length too small: %s truncated]", pinfo->current_proto);
		/* Don't record ScsiBoundsError exceptions as expert events - they merely
		 * reflect a normal SCSI condition.
		 * (any case where it's caused by something else is a bug). */
		break;

	case BoundsError:
		col_append_str(pinfo->cinfo, COL_INFO, "[Packet size limited during capture]");
		proto_tree_add_protocol_format(tree, proto_short, tvb, 0, 0,
				"[Packet size limited during capture: %s truncated]", pinfo->current_proto);
		/* Don't record BoundsError exceptions as expert events - they merely
		 * reflect a capture done with a snapshot length too short to capture
		 * all of the packet
		 * (any case where it's caused by something else is a bug). */
		break;

	case FragmentBoundsError:
		col_append_fstr(pinfo->cinfo, COL_INFO, "[Unreassembled Packet%s]", pinfo->noreassembly_reason);
		proto_tree_add_protocol_format(tree, proto_unreassembled,
		    tvb, 0, 0, "[Unreassembled Packet%s: %s]",
		    pinfo->noreassembly_reason, pinfo->current_proto);
		/* Don't record FragmentBoundsError exceptions as expert events - they merely
		 * reflect dissection done with reassembly turned off
		 * (any case where it's caused by something else is a bug). */
		break;

	case ReportedBoundsError:
		show_reported_bounds_error(tvb, pinfo, tree);
		break;

	case DissectorError:
		col_append_fstr(pinfo->cinfo, COL_INFO,
		    "[Dissector bug, protocol %s: %s]",
		    pinfo->current_proto,
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		item = proto_tree_add_protocol_format(tree, proto_malformed, tvb, 0, 0,
		    "[Dissector bug, protocol %s: %s]",
		    pinfo->current_proto,
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		g_warning("Dissector bug, protocol %s, in packet %u: %s",
		    pinfo->current_proto, pinfo->fd->num,
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		expert_add_info_format(pinfo, item, &ei_malformed_dissector_bug, "%s",
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		break;

	case ReassemblyError:
		col_append_fstr(pinfo->cinfo, COL_INFO,
		    "[Reassembly error, protocol %s: %s]",
		    pinfo->current_proto,
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		item = proto_tree_add_protocol_format(tree, proto_malformed, tvb, 0, 0,
		    "[Reassembly error, protocol %s: %s]",
		    pinfo->current_proto,
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		expert_add_info_format(pinfo, item, &ei_malformed_reassembly, "%s",
		    exception_message == NULL ?
		        dissector_error_nomsg : exception_message);
		break;

	default:
		/* XXX - we want to know, if an unknown exception passed until here, don't we? */
		g_assert_not_reached();
	}
}

void
show_reported_bounds_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;

	col_append_str(pinfo->cinfo, COL_INFO,
	    "[Malformed Packet]");
	item = proto_tree_add_protocol_format(tree, proto_malformed,
	    tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
	expert_add_info(pinfo, item, &ei_malformed);
}
