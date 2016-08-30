/* packet.c
 * Routines for packet disassembly
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <glib.h>

#include <stdio.h>
#include <stdlib.h>

#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "packet.h"
#include "timestamp.h"

#include "osi-utils.h"
#include "to_str.h"

#include "addr_resolv.h"
#include "tvbuff.h"
#include "epan_dissect.h"

#include "wmem/wmem.h"

#include <epan/exceptions.h>
#include <epan/reassemble.h>
#include <epan/stream.h>
#include <epan/expert.h>
#include <epan/range.h>
#include <epan/asm_utils.h>

#include <wsutil/str_util.h>

static gint proto_malformed = -1;
static dissector_handle_t frame_handle = NULL;
static dissector_handle_t file_handle = NULL;
static dissector_handle_t data_handle = NULL;

/**
 * A data source.
 * Has a tvbuff and a name.
 */
struct data_source {
	tvbuff_t *tvb;
	char *name;
};

/*
 * A dissector table.
 *
 * "hash_table" is a hash table, indexed by port number, supplying
 * a "struct dtbl_entry"; it records what dissector is assigned to
 * that uint or string value in that table.
 *
 * "dissector_handles" is a list of all dissectors that *could* be
 * used in that table; not all of them are necessarily in the table,
 * as they may be for protocols that don't have a fixed uint value,
 * e.g. for TCP or UDP port number tables and protocols with no fixed
 * port number.
 *
 * "ui_name" is the name the dissector table has in the user interface.
 *
 * "type" is a field type giving the width of the uint value for that
 * dissector table, if it's a uint dissector table.
 *
 * "param" is the base in which to display the uint value for that
 * dissector table, if it's a uint dissector table, or if it's a string
 * table, TRUE/FALSE to indicate case-insensitive or not.
 *
 * "protocol" is the protocol associated with the dissector table. Used
 * for determining dependencies.
 */
struct dissector_table {
	GHashTable	*hash_table;
	GSList		*dissector_handles;
	const char	*ui_name;
	ftenum_t	type;
	int		param;
	protocol_t	*protocol;
	GHashFunc	hash_func;
	gboolean	supports_decode_as;
};

static GHashTable *dissector_tables = NULL;

/*
 * List of registered dissectors.
 */
static GHashTable *registered_dissectors = NULL;

/*
 * A dissector dependency list.
 */
struct depend_dissector_list {
	GSList		*dissectors;
};

/* Maps char *dissector_name to depend_dissector_list_t */
static GHashTable *depend_dissector_lists = NULL;

static void
destroy_depend_dissector_list(void *data)
{
	depend_dissector_list_t dissector_list = (depend_dissector_list_t)data;
	GSList **list = &(dissector_list->dissectors);

	g_slist_foreach(*list, (GFunc)g_free, NULL);
	g_slist_free(*list);
	g_slice_free(struct depend_dissector_list, dissector_list);
}

/*
 * A heuristics dissector list.
 */
struct heur_dissector_list {
	protocol_t	*protocol;
	GSList		*dissectors;
};

static GHashTable *heur_dissector_lists = NULL;

/* Name hashtables for fast detection of duplicate names */
static GHashTable* heuristic_short_names  = NULL;

static void
destroy_heuristic_dissector_entry(gpointer data, gpointer user_data _U_)
{
	g_free(((heur_dtbl_entry_t*)data)->list_name);
	g_slice_free(heur_dtbl_entry_t, data);
}

static void
destroy_heuristic_dissector_list(void *data)
{
	heur_dissector_list_t dissector_list = (heur_dissector_list_t)data;
	GSList **list = &(dissector_list->dissectors);

	g_slist_foreach(*list, destroy_heuristic_dissector_entry, NULL);
	g_slist_free(*list);
	g_slice_free(struct heur_dissector_list, dissector_list);
}

static void
destroy_dissector_table(void *data)
{
	struct dissector_table *table = (struct dissector_table *)data;

	g_hash_table_destroy(table->hash_table);
	g_slist_free(table->dissector_handles);
	g_slice_free(struct dissector_table, data);
}

void
packet_init(void)
{
	dissector_tables = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, destroy_dissector_table);

	registered_dissectors = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, NULL);

	depend_dissector_lists = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, destroy_depend_dissector_list);

	heur_dissector_lists = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, destroy_heuristic_dissector_list);

	heuristic_short_names  = g_hash_table_new(wrs_str_hash, g_str_equal);
}

void
packet_cache_proto_handles(void)
{
	frame_handle = find_dissector("frame");
	g_assert(frame_handle != NULL);

	file_handle = find_dissector("file");
	g_assert(file_handle != NULL);

	data_handle = find_dissector("data");
	g_assert(data_handle != NULL);

	proto_malformed = proto_get_id_by_filter_name("_ws.malformed");
	g_assert(proto_malformed != -1);
}

void
packet_cleanup(void)
{
	g_hash_table_destroy(dissector_tables);
	g_hash_table_destroy(registered_dissectors);
	g_hash_table_destroy(depend_dissector_lists);
	g_hash_table_destroy(heur_dissector_lists);
	g_hash_table_destroy(heuristic_short_names);
}

/*
 * Given a tvbuff, and a length from a packet header, adjust the length
 * of the tvbuff to reflect the specified length.
 */
void
set_actual_length(tvbuff_t *tvb, const guint specified_len)
{
	if (specified_len < tvb_reported_length(tvb)) {
		/* Adjust the length of this tvbuff to include only the specified
		   payload length.

		   The dissector above the one calling us (the dissector above is
		   probably us) may use that to determine how much of its packet
		   was padding. */
		tvb_set_reported_length(tvb, specified_len);
	}
}

/* List of routines that are called before we make a pass through a capture file
 * and dissect all its packets. See register_init_routine and
 * register_cleanup_routine in packet.h */
static GSList *init_routines;
static GSList *cleanup_routines;

void
register_init_routine(void (*func)(void))
{
	init_routines = g_slist_prepend(init_routines, (gpointer)func);
}

void
register_cleanup_routine(void (*func)(void))
{
	cleanup_routines = g_slist_prepend(cleanup_routines, (gpointer)func);
}

typedef void (*void_func_t)(void);

/* Initialize all data structures used for dissection. */
static void
call_routine(gpointer routine, gpointer dummy _U_)
{
	void_func_t func = (void_func_t)routine;
	(*func)();
}

void
init_dissection(void)
{
	wmem_enter_file_scope();

	/*
	 * Reinitialize resolution information. We do initialization here in
	 * case we need to resolve between captures.
	 */
	host_name_lookup_init();

	/* Initialize the table of conversations. */
	epan_conversation_init();

	/* Initialize the table of circuits. */
	epan_circuit_init();

	/* Initialize protocol-specific variables. */
	g_slist_foreach(init_routines, &call_routine, NULL);

	/* Initialize the stream-handling tables */
	stream_init();

	/* Initialize the expert infos */
	expert_packet_init();
}

void
cleanup_dissection(void)
{
	/* Cleanup the table of conversations. Do this before freeing seasonal
	 * memory (at least until conversation's use of g_slist is changed).
	 */
	epan_conversation_cleanup();

	/* Cleanup the table of circuits. */
	epan_circuit_cleanup();

	/* Cleanup protocol-specific variables. */
	g_slist_foreach(cleanup_routines, &call_routine, NULL);

	/* Cleanup the stream-handling tables */
	stream_cleanup();

	/* Cleanup the expert infos */
	expert_packet_cleanup();

	wmem_leave_file_scope();

	/*
	 * Reinitialize resolution information. We do initialization here in
	 * case we need to resolve between captures.
	 */
	host_name_lookup_cleanup();
}

/* Allow protocols to register a "cleanup" routine to be
 * run after the initial sequential run through the packets.
 * Note that the file can still be open after this; this is not
 * the final cleanup. */
static GSList *postseq_cleanup_routines;

void
register_postseq_cleanup_routine(void_func_t func)
{
	postseq_cleanup_routines = g_slist_prepend(postseq_cleanup_routines,
			(gpointer)func);
}

/* Call all the registered "postseq_cleanup" routines. */
static void
call_postseq_cleanup_routine(gpointer routine, gpointer dummy _U_)
{
	void_func_t func = (void_func_t)routine;
	(*func)();
}

void
postseq_cleanup_all_protocols(void)
{
	g_slist_foreach(postseq_cleanup_routines,
			&call_postseq_cleanup_routine, NULL);
}

/*
 * Add a new data source to the list of data sources for a frame, given
 * the tvbuff for the data source and its name.
 */
void
add_new_data_source(packet_info *pinfo, tvbuff_t *tvb, const char *name)
{
	struct data_source *src;

	src = wmem_new(pinfo->pool, struct data_source);
	src->tvb = tvb;
	src->name = wmem_strdup(pinfo->pool, name);
	/* This could end up slow, but we should never have that many data
	 * sources so it probably doesn't matter */
	pinfo->data_src = g_slist_append(pinfo->data_src, src);
}

void
remove_last_data_source(packet_info *pinfo)
{
	GSList *last;

	last = g_slist_last(pinfo->data_src);
	pinfo->data_src = g_slist_delete_link(pinfo->data_src, last);
}

char*
get_data_source_name(const struct data_source *src)
{
	guint length = tvb_captured_length(src->tvb);

	return wmem_strdup_printf(NULL, "%s (%u byte%s)", src->name, length,
				plurality(length, "", "s"));
}

tvbuff_t *
get_data_source_tvb(const struct data_source *src)
{
	return src->tvb;
}

/*
 * Free up a frame's list of data sources.
 */
void
free_data_sources(packet_info *pinfo)
{
	if (pinfo->data_src) {
		g_slist_free(pinfo->data_src);
		pinfo->data_src = NULL;
	}
}

void
mark_frame_as_depended_upon(packet_info *pinfo, guint32 frame_num)
{
	/* Don't mark a frame as dependent on itself */
	if (frame_num != pinfo->num) {
		pinfo->dependent_frames = g_slist_prepend(pinfo->dependent_frames, GUINT_TO_POINTER(frame_num));
	}
}

/* Allow dissectors to register a "final_registration" routine
 * that is run like the proto_register_XXX() routine, but at the
 * end of the epan_init() function; that is, *after* all other
 * subsystems, like dfilters, have finished initializing. This is
 * useful for dissector registration routines which need to compile
 * display filters. dfilters can't initialize itself until all protocols
 * have registered themselves. */
static GSList *final_registration_routines;

void
register_final_registration_routine(void (*func)(void))
{
	final_registration_routines = g_slist_prepend(final_registration_routines,
			(gpointer)func);
}

/* Call all the registered "final_registration" routines. */
static void
call_final_registration_routine(gpointer routine, gpointer dummy _U_)
{
	void_func_t func = (void_func_t)routine;

	(*func)();
}

void
final_registration_all_protocols(void)
{
	g_slist_foreach(final_registration_routines,
			&call_final_registration_routine, NULL);
}


/* Creates the top-most tvbuff and calls dissect_frame() */
void
dissect_record(epan_dissect_t *edt, int file_type_subtype,
    struct wtap_pkthdr *phdr, tvbuff_t *tvb, frame_data *fd, column_info *cinfo)
{
	const char *volatile record_type;
	frame_data_t frame_dissector_data;

	switch (phdr->rec_type) {

	case REC_TYPE_PACKET:
		record_type = "Frame";
		break;

	case REC_TYPE_FT_SPECIFIC_EVENT:
		record_type = "Event";
		break;

	case REC_TYPE_FT_SPECIFIC_REPORT:
		record_type = "Report";
		break;

	case REC_TYPE_SYSCALL:
		record_type = "System Call";
		break;

	default:
		/*
		 * XXX - if we add record types that shouldn't be
		 * dissected and displayed, but that need to at
		 * least be processed somewhere, we need to somehow
		 * indicate that to our caller.
		 */
		g_assert_not_reached();
		break;
	}

	if (cinfo != NULL)
		col_init(cinfo, edt->session);
	edt->pi.epan = edt->session;
	/* edt->pi.pool created in epan_dissect_init() */
	edt->pi.current_proto = "<Missing Protocol Name>";
	edt->pi.cinfo = cinfo;
	edt->pi.presence_flags = 0;
	edt->pi.num = fd->num;
	if (fd->flags.has_ts) {
		edt->pi.presence_flags |= PINFO_HAS_TS;
		edt->pi.abs_ts = fd->abs_ts;
	}
	edt->pi.pkt_encap     = phdr->pkt_encap;
	edt->pi.fd            = fd;
	edt->pi.phdr          = phdr;
	edt->pi.pseudo_header = &phdr->pseudo_header;
	clear_address(&edt->pi.dl_src);
	clear_address(&edt->pi.dl_dst);
	clear_address(&edt->pi.net_src);
	clear_address(&edt->pi.net_dst);
	clear_address(&edt->pi.src);
	clear_address(&edt->pi.dst);
	edt->pi.ctype = CT_NONE;
	edt->pi.noreassembly_reason = "";
	edt->pi.ptype = PT_NONE;
	edt->pi.p2p_dir = P2P_DIR_UNKNOWN;
	edt->pi.link_dir = LINK_DIR_UNKNOWN;
	edt->pi.layers = wmem_list_new(edt->pi.pool);
	edt->tvb = tvb;


	frame_delta_abs_time(edt->session, fd, fd->frame_ref_num, &edt->pi.rel_ts);

	/* pkt comment use first user, later from phdr */
	if (fd->flags.has_user_comment)
		frame_dissector_data.pkt_comment = epan_get_user_comment(edt->session, fd);
	else if (fd->flags.has_phdr_comment)
		frame_dissector_data.pkt_comment = phdr->opt_comment;
	else
		frame_dissector_data.pkt_comment = NULL;
	frame_dissector_data.file_type_subtype = file_type_subtype;
	frame_dissector_data.color_edt = edt; /* Used strictly for "coloring rules" */

	TRY {
		/* Add this tvbuffer into the data_src list */
		add_new_data_source(&edt->pi, edt->tvb, record_type);

		/* Even though dissect_frame() catches all the exceptions a
		 * sub-dissector can throw, dissect_frame() itself may throw
		 * a ReportedBoundsError in bizarre cases. Thus, we catch the exception
		 * in this function. */
		call_dissector_with_data(frame_handle, edt->tvb, &edt->pi, edt->tree, &frame_dissector_data);
	}
	CATCH(BoundsError) {
		g_assert_not_reached();
	}
	CATCH2(FragmentBoundsError, ReportedBoundsError) {
		proto_tree_add_protocol_format(edt->tree, proto_malformed, edt->tvb, 0, 0,
					       "[Malformed %s: Packet Length]",
					       record_type);
	}
	ENDTRY;

	fd->flags.visited = 1;
}

/* Creates the top-most tvbuff and calls dissect_file() */
void
dissect_file(epan_dissect_t *edt, struct wtap_pkthdr *phdr,
	       tvbuff_t *tvb, frame_data *fd, column_info *cinfo)
{
	file_data_t file_dissector_data;

	if (cinfo != NULL)
		col_init(cinfo, edt->session);
	edt->pi.epan = edt->session;
	/* edt->pi.pool created in epan_dissect_init() */
	edt->pi.current_proto = "<Missing Filetype Name>";
	edt->pi.cinfo = cinfo;
	edt->pi.fd    = fd;
	edt->pi.phdr  = phdr;
	edt->pi.pseudo_header = &phdr->pseudo_header;
	clear_address(&edt->pi.dl_src);
	clear_address(&edt->pi.dl_dst);
	clear_address(&edt->pi.net_src);
	clear_address(&edt->pi.net_dst);
	clear_address(&edt->pi.src);
	clear_address(&edt->pi.dst);
	edt->pi.ctype = CT_NONE;
	edt->pi.noreassembly_reason = "";
	edt->pi.ptype = PT_NONE;
	edt->pi.p2p_dir = P2P_DIR_UNKNOWN;
	edt->pi.link_dir = LINK_DIR_UNKNOWN;
	edt->pi.layers = wmem_list_new(edt->pi.pool);
	edt->tvb = tvb;


	frame_delta_abs_time(edt->session, fd, fd->frame_ref_num, &edt->pi.rel_ts);


	TRY {
		/* pkt comment use first user, later from phdr */
		if (fd->flags.has_user_comment)
			file_dissector_data.pkt_comment = epan_get_user_comment(edt->session, fd);
		else if (fd->flags.has_phdr_comment)
			file_dissector_data.pkt_comment = phdr->opt_comment;
		else
			file_dissector_data.pkt_comment = NULL;
		file_dissector_data.color_edt = edt; /* Used strictly for "coloring rules" */


		/* Add this tvbuffer into the data_src list */
		add_new_data_source(&edt->pi, edt->tvb, "File");

		/* Even though dissect_file() catches all the exceptions a
		 * sub-dissector can throw, dissect_frame() itself may throw
		 * a ReportedBoundsError in bizarre cases. Thus, we catch the exception
		 * in this function. */
		call_dissector_with_data(file_handle, edt->tvb, &edt->pi, edt->tree, &file_dissector_data);

	}
	CATCH(BoundsError) {
		g_assert_not_reached();
	}
	CATCH2(FragmentBoundsError, ReportedBoundsError) {
		proto_tree_add_protocol_format(edt->tree, proto_malformed, edt->tvb, 0, 0,
					       "[Malformed Record: Packet Length]" );
	}
	ENDTRY;

	fd->flags.visited = 1;
}

/*********************** code added for sub-dissector lookup *********************/

/*
 * A dissector handle.
 */
struct dissector_handle {
	const char	*name;		/* dissector name */
	dissector_t	dissector;
	protocol_t	*protocol;
};

/* This function will return
 * old style dissector :
 *   length of the payload or 1 of the payload is empty
 * new dissector :
 *   >0  this protocol was successfully dissected and this was this protocol.
 *   0   this packet did not match this protocol.
 *
 * The only time this function will return 0 is if it is a new style dissector
 * and if the dissector rejected the packet.
 */
static int
call_dissector_through_handle(dissector_handle_t handle, tvbuff_t *tvb,
			      packet_info *pinfo, proto_tree *tree, void *data)
{
	const char *saved_proto;
	int         len;

	saved_proto = pinfo->current_proto;

	if (handle->protocol != NULL) {
		pinfo->current_proto =
			proto_get_protocol_short_name(handle->protocol);
	}

	len = (*handle->dissector)(tvb, pinfo, tree, data);
	pinfo->current_proto = saved_proto;

	return len;
}

/*
 * Call a dissector through a handle.
 * If the protocol for that handle isn't enabled, return 0 without
 * calling the dissector.
 * Otherwise, if the handle refers to a new-style dissector, call the
 * dissector and return its return value, otherwise call it and return
 * the length of the tvbuff pointed to by the argument.
 */

static int
call_dissector_work_error(dissector_handle_t handle, tvbuff_t *tvb,
			  packet_info *pinfo_arg, proto_tree *tree, void *);

static int
call_dissector_work(dissector_handle_t handle, tvbuff_t *tvb, packet_info *pinfo_arg,
		    proto_tree *tree, gboolean add_proto_name, void *data)
{
 	packet_info *pinfo = pinfo_arg;
	const char  *saved_proto;
	guint16      saved_can_desegment;
	int          len;
	guint        saved_layers_len = 0;

	if (handle->protocol != NULL &&
	    !proto_is_protocol_enabled(handle->protocol)) {
		/*
		 * The protocol isn't enabled.
		 */
		return 0;
	}

	saved_proto = pinfo->current_proto;
	saved_can_desegment = pinfo->can_desegment;
	saved_layers_len = wmem_list_count(pinfo->layers);

	/*
	 * can_desegment is set to 2 by anyone which offers the
	 * desegmentation api/service.
	 * Then everytime a subdissector is called it is decremented
	 * by one.
	 * Thus only the subdissector immediately on top of whoever
	 * offers this service can use it.
	 * We save the current value of "can_desegment" for the
	 * benefit of TCP proxying dissectors such as SOCKS, so they
	 * can restore it and allow the dissectors they call to use
	 * the desegmentation service.
	 */
	pinfo->saved_can_desegment = saved_can_desegment;
	pinfo->can_desegment = saved_can_desegment-(saved_can_desegment>0);
	if (handle->protocol != NULL) {
		pinfo->current_proto =
			proto_get_protocol_short_name(handle->protocol);

		/*
		 * Add the protocol name to the layers
		 * if not told not to. Asn2wrs generated dissectors may be added multiple times otherwise.
		 */
		if (add_proto_name) {
			pinfo->curr_layer_num++;
			wmem_list_append(pinfo->layers, GINT_TO_POINTER(proto_get_id(handle->protocol)));
		}
	}

	if (pinfo->flags.in_error_pkt) {
		len = call_dissector_work_error(handle, tvb, pinfo, tree, data);
	} else {
		/*
 		 * Just call the subdissector.
 		 */
		len = call_dissector_through_handle(handle, tvb, pinfo, tree, data);
	}
	if (len == 0) {
		/*
 		 * That dissector didn't accept the packet, so
 		 * remove its protocol's name from the list
 		 * of protocols.
		 */
		while (wmem_list_count(pinfo->layers) > saved_layers_len) {
			wmem_list_remove_frame(pinfo->layers, wmem_list_tail(pinfo->layers));
		}
 	}
 	pinfo->current_proto = saved_proto;
 	pinfo->can_desegment = saved_can_desegment;
	return len;
}


static int
call_dissector_work_error(dissector_handle_t handle, tvbuff_t *tvb,
			  packet_info *pinfo_arg, proto_tree *tree, void *data)
{
	packet_info  *pinfo = pinfo_arg;
	const char   *saved_proto;
	guint16       saved_can_desegment;
	volatile int  len = 0;
	gboolean      save_writable;
	address       save_dl_src;
	address       save_dl_dst;
	address       save_net_src;
	address       save_net_dst;
	address       save_src;
	address       save_dst;

	/*
	* This isn't a packet being transported inside
	* the protocol whose dissector is calling us,
	* it's a copy of a packet that caused an error
	* in some protocol included in a packet that
	* reports the error (e.g., an ICMP Unreachable
	* packet).
	*/

	/*
	* Save the current state of the writability of
	* the columns, and restore them after the
	* dissector returns, so that the columns
	* don't reflect the packet that got the error,
	* they reflect the packet that reported the
	* error.
	*/
	saved_proto = pinfo->current_proto;
	saved_can_desegment = pinfo->can_desegment;

	save_writable = col_get_writable(pinfo->cinfo, -1);
	col_set_writable(pinfo->cinfo, -1, FALSE);
	copy_address_shallow(&save_dl_src, &pinfo->dl_src);
	copy_address_shallow(&save_dl_dst, &pinfo->dl_dst);
	copy_address_shallow(&save_net_src, &pinfo->net_src);
	copy_address_shallow(&save_net_dst, &pinfo->net_dst);
	copy_address_shallow(&save_src, &pinfo->src);
	copy_address_shallow(&save_dst, &pinfo->dst);

	/* Dissect the contained packet. */
	TRY {
		len = call_dissector_through_handle(handle, tvb,pinfo, tree, data);
	}
	CATCH(BoundsError) {
		/*
		* Restore the column writability and addresses.
		*/
		col_set_writable(pinfo->cinfo, -1, save_writable);
		copy_address_shallow(&pinfo->dl_src, &save_dl_src);
		copy_address_shallow(&pinfo->dl_dst, &save_dl_dst);
		copy_address_shallow(&pinfo->net_src, &save_net_src);
		copy_address_shallow(&pinfo->net_dst, &save_net_dst);
		copy_address_shallow(&pinfo->src, &save_src);
		copy_address_shallow(&pinfo->dst, &save_dst);

		/*
		* Restore the current protocol, so any
		* "Short Frame" indication reflects that
		* protocol, not the protocol for the
		* packet that got the error.
		*/
		pinfo->current_proto = saved_proto;

		/*
		* Restore the desegmentability state.
		*/
		pinfo->can_desegment = saved_can_desegment;

		/*
		* Rethrow the exception, so this will be
		* reported as a short frame.
		*/
		RETHROW;
	}
	CATCH2(FragmentBoundsError, ReportedBoundsError) {
		/*
		* "ret" wasn't set because an exception was thrown
		* before "call_dissector_through_handle()" returned.
		* As it called something, at least one dissector
		* accepted the packet, and, as an exception was
		* thrown, not only was all the tvbuff dissected,
		* a dissector tried dissecting past the end of
		* the data in some tvbuff, so we'll assume that
		* the entire tvbuff was dissected.
		*/
		len = tvb_captured_length(tvb);
	}
	ENDTRY;

	col_set_writable(pinfo->cinfo, -1, save_writable);
	copy_address_shallow(&pinfo->dl_src, &save_dl_src);
	copy_address_shallow(&pinfo->dl_dst, &save_dl_dst);
	copy_address_shallow(&pinfo->net_src, &save_net_src);
	copy_address_shallow(&pinfo->net_dst, &save_net_dst);
	copy_address_shallow(&pinfo->src, &save_src);
	copy_address_shallow(&pinfo->dst, &save_dst);
	pinfo->want_pdu_tracking = 0;
	return len;
}

/*
 * An entry in the hash table portion of a dissector table.
 */
struct dtbl_entry {
	dissector_handle_t initial;
	dissector_handle_t current;
};

/* Finds a dissector table by table name. */
dissector_table_t
find_dissector_table(const char *name)
{
	return (dissector_table_t)g_hash_table_lookup( dissector_tables, name );
}

/* Find an entry in a uint dissector table. */
static dtbl_entry_t *
find_uint_dtbl_entry(dissector_table_t sub_dissectors, const guint32 pattern)
{
	switch (sub_dissectors->type) {

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		/*
		 * You can do a uint lookup in these tables.
		 */
		break;

	default:
		/*
		 * But you can't do a uint lookup in any other types
		 * of tables.
		 */
		g_assert_not_reached();
	}

	/*
	 * Find the entry.
	 */
	return (dtbl_entry_t *)g_hash_table_lookup(sub_dissectors->hash_table,
				   GUINT_TO_POINTER(pattern));
}

#if 0
static void
dissector_add_uint_sanity_check(const char *name, guint32 pattern, dissector_handle_t handle, dissector_table_t sub_dissectors)
{
	dtbl_entry_t *dtbl_entry;

	if (pattern == 0) {
		g_warning("%s: %s registering using a pattern of 0",
			  name, proto_get_protocol_filter_name(proto_get_id(handle->protocol)));
	}

	dtbl_entry = g_hash_table_lookup(sub_dissectors->hash_table, GUINT_TO_POINTER(pattern));
	if (dtbl_entry != NULL) {
		g_warning("%s: %s registering using pattern %d already registered by %s",
			  name, proto_get_protocol_filter_name(proto_get_id(handle->protocol)),
			  pattern, proto_get_protocol_filter_name(proto_get_id(dtbl_entry->initial->protocol)));
	}
}
#endif

/* Add an entry to a uint dissector table. */
void
dissector_add_uint(const char *name, const guint32 pattern, dissector_handle_t handle)
{
	dissector_table_t  sub_dissectors;
	dtbl_entry_t      *dtbl_entry;

	sub_dissectors = find_dissector_table(name);

	/*
	 * Make sure the handle and the dissector table exist.
	 */
	if (handle == NULL) {
		fprintf(stderr, "OOPS: handle to register \"%s\" to doesn't exist\n",
		    name);
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		return;
	}
	if (sub_dissectors == NULL) {
		fprintf(stderr, "OOPS: dissector table \"%s\" doesn't exist\n",
		    name);
		fprintf(stderr, "Protocol being registered is \"%s\"\n",
		    proto_get_protocol_long_name(handle->protocol));
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		return;
	}

	switch (sub_dissectors->type) {

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		/*
		 * You can do a uint lookup in these tables.
		 */
		break;

	default:
		/*
		 * But you can't do a uint lookup in any other types
		 * of tables.
		 */
		g_assert_not_reached();
	}

#if 0
	dissector_add_uint_sanity_check(name, pattern, handle, sub_dissectors);
#endif

	dtbl_entry = (dtbl_entry_t *)g_malloc(sizeof (dtbl_entry_t));
	dtbl_entry->current = handle;
	dtbl_entry->initial = dtbl_entry->current;

	/* do the table insertion */
	g_hash_table_insert( sub_dissectors->hash_table,
			     GUINT_TO_POINTER( pattern), (gpointer)dtbl_entry);

	/*
	 * Now, if this table supports "Decode As", add this handle
	 * to the list of handles that could be used for "Decode As"
	 * with this table, because it *is* being used with this table.
	 */
	if (sub_dissectors->supports_decode_as)
		dissector_add_for_decode_as(name, handle);
}



void dissector_add_uint_range(const char *abbrev, range_t *range,
			      dissector_handle_t handle)
{
	guint32 i, j;

	if (range) {
		for (i = 0; i < range->nranges; i++) {
			for (j = range->ranges[i].low; j < range->ranges[i].high; j++)
				dissector_add_uint(abbrev, j, handle);
			dissector_add_uint(abbrev, range->ranges[i].high, handle);
		}
	}
}

/* Delete the entry for a dissector in a uint dissector table
   with a particular pattern. */

/* NOTE: this doesn't use the dissector call variable. It is included to */
/*	be consistant with the dissector_add_uint and more importantly to be used */
/*	if the technique of adding a temporary dissector is implemented.  */
/*	If temporary dissectors are deleted, then the original dissector must */
/*	be available. */
void
dissector_delete_uint(const char *name, const guint32 pattern,
	dissector_handle_t handle _U_)
{
	dissector_table_t sub_dissectors = find_dissector_table( name);
	dtbl_entry_t *dtbl_entry;

	/* sanity check */
	g_assert( sub_dissectors);

	/*
	 * Find the entry.
	 */
	dtbl_entry = find_uint_dtbl_entry(sub_dissectors, pattern);

	if (dtbl_entry != NULL) {
		/*
		 * Found - remove it.
		 */
		g_hash_table_remove(sub_dissectors->hash_table,
				    GUINT_TO_POINTER(pattern));
	}
}

void dissector_delete_uint_range(const char *abbrev, range_t *range,
				 dissector_handle_t handle)
{
	guint32 i, j;

	if (range) {
		for (i = 0; i < range->nranges; i++) {
			for (j = range->ranges[i].low; j < range->ranges[i].high; j++)
				dissector_delete_uint(abbrev, j, handle);
			dissector_delete_uint(abbrev, range->ranges[i].high, handle);
		}
	}
}

static gboolean
dissector_delete_all_check (gpointer key _U_, gpointer value, gpointer user_data)
{
	dtbl_entry_t *dtbl_entry = (dtbl_entry_t *) value;
	dissector_handle_t handle = (dissector_handle_t) user_data;

	if (!dtbl_entry->current->protocol) {
		/*
		 * Not all dissectors are registered with a protocol, so we need this
		 * check when running from dissector_delete_from_all_tables.
		 */
		return FALSE;
	}

	return (proto_get_id (dtbl_entry->current->protocol) == proto_get_id (handle->protocol));
}

/* Delete all entries from a dissector table. */
void dissector_delete_all(const char *name, dissector_handle_t handle)
{
	dissector_table_t sub_dissectors = find_dissector_table(name);
	g_assert (sub_dissectors);

	g_hash_table_foreach_remove (sub_dissectors->hash_table, dissector_delete_all_check, handle);
}

static void
dissector_delete_from_table(gpointer key _U_, gpointer value, gpointer user_data)
{
	dissector_table_t sub_dissectors = (dissector_table_t) value;
	g_assert (sub_dissectors);

	g_hash_table_foreach_remove(sub_dissectors->hash_table, dissector_delete_all_check, user_data);
	sub_dissectors->dissector_handles = g_slist_remove(sub_dissectors->dissector_handles, user_data);
}

/* Delete handle from all tables and dissector_handles lists */
static void
dissector_delete_from_all_tables(dissector_handle_t handle)
{
	g_hash_table_foreach(dissector_tables, dissector_delete_from_table, handle);
}

/* Change the entry for a dissector in a uint dissector table
   with a particular pattern to use a new dissector handle. */
void
dissector_change_uint(const char *name, const guint32 pattern, dissector_handle_t handle)
{
	dissector_table_t sub_dissectors = find_dissector_table( name);
	dtbl_entry_t *dtbl_entry;

	/* sanity check */
	g_assert( sub_dissectors);

	/*
	 * See if the entry already exists. If so, reuse it.
	 */
	dtbl_entry = find_uint_dtbl_entry(sub_dissectors, pattern);
	if (dtbl_entry != NULL) {
		dtbl_entry->current = handle;
		return;
	}

	/*
	 * Don't create an entry if there is no dissector handle - I.E. the
	 * user said not to decode something that wasn't being decoded
	 * in the first place.
	 */
	if (handle == NULL)
		return;

	dtbl_entry = (dtbl_entry_t *)g_malloc(sizeof (dtbl_entry_t));
	dtbl_entry->initial = NULL;
	dtbl_entry->current = handle;

	/* do the table insertion */
	g_hash_table_insert( sub_dissectors->hash_table,
			     GUINT_TO_POINTER( pattern), (gpointer)dtbl_entry);
}

/* Reset an entry in a uint dissector table to its initial value. */
void
dissector_reset_uint(const char *name, const guint32 pattern)
{
	dissector_table_t  sub_dissectors = find_dissector_table( name);
	dtbl_entry_t      *dtbl_entry;

	/* sanity check */
	g_assert( sub_dissectors);

	/*
	 * Find the entry.
	 */
	dtbl_entry = find_uint_dtbl_entry(sub_dissectors, pattern);

	if (dtbl_entry == NULL)
		return;

	/*
	 * Found - is there an initial value?
	 */
	if (dtbl_entry->initial != NULL) {
		dtbl_entry->current = dtbl_entry->initial;
	} else {
		g_hash_table_remove(sub_dissectors->hash_table,
				    GUINT_TO_POINTER(pattern));
	}
}

/* Look for a given value in a given uint dissector table and, if found,
   call the dissector with the arguments supplied, and return TRUE,
   otherwise return FALSE. */

int
dissector_try_uint_new(dissector_table_t sub_dissectors, const guint32 uint_val,
		       tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		       const gboolean add_proto_name, void *data)
{
	dtbl_entry_t            *dtbl_entry;
	struct dissector_handle *handle;
	guint32                  saved_match_uint;
	int len;

	dtbl_entry = find_uint_dtbl_entry(sub_dissectors, uint_val);
	if (dtbl_entry != NULL) {
		/*
		 * Is there currently a dissector handle for this entry?
		 */
		handle = dtbl_entry->current;
		if (handle == NULL) {
			/*
			 * No - pretend this dissector didn't exist,
			 * so that other dissectors might have a chance
			 * to dissect this packet.
			 */
			return 0;
		}

		/*
		 * Save the current value of "pinfo->match_uint",
		 * set it to the uint_val that matched, call the
		 * dissector, and restore "pinfo->match_uint".
		 */
		saved_match_uint  = pinfo->match_uint;
		pinfo->match_uint = uint_val;
		len = call_dissector_work(handle, tvb, pinfo, tree, add_proto_name, data);
		pinfo->match_uint = saved_match_uint;

		/*
		 * If a new-style dissector returned 0, it means that
		 * it didn't think this tvbuff represented a packet for
		 * its protocol, and didn't dissect anything.
		 *
		 * Old-style dissectors can't reject the packet.
		 *
		 * 0 is also returned if the protocol wasn't enabled.
		 *
		 * If the packet was rejected, we return 0, so that
		 * other dissectors might have a chance to dissect this
		 * packet, otherwise we return the dissected length.
		 */
		return len;
	}
	return 0;
}

int
dissector_try_uint(dissector_table_t sub_dissectors, const guint32 uint_val,
		   tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	return dissector_try_uint_new(sub_dissectors, uint_val, tvb, pinfo, tree, TRUE, NULL);
}

/* Look for a given value in a given uint dissector table and, if found,
   return the dissector handle for that value. */
dissector_handle_t
dissector_get_uint_handle(dissector_table_t const sub_dissectors, const guint32 uint_val)
{
	dtbl_entry_t *dtbl_entry;

	dtbl_entry = find_uint_dtbl_entry(sub_dissectors, uint_val);
	if (dtbl_entry != NULL)
		return dtbl_entry->current;
	else
		return NULL;
}

dissector_handle_t
dissector_get_default_uint_handle(const char *name, const guint32 uint_val)
{
	dissector_table_t sub_dissectors = find_dissector_table(name);

	if (sub_dissectors != NULL) {
		dtbl_entry_t *dtbl_entry = find_uint_dtbl_entry(sub_dissectors, uint_val);
		if (dtbl_entry != NULL)
			return dtbl_entry->initial;
	}
	return NULL;
}

/* Find an entry in a string dissector table. */
static dtbl_entry_t *
find_string_dtbl_entry(dissector_table_t const sub_dissectors, const gchar *pattern)
{
	dtbl_entry_t *ret;
	char *key;

	switch (sub_dissectors->type) {

	case FT_STRING:
	case FT_STRINGZ:
	case FT_STRINGZPAD:
		/*
		 * You can do a string lookup in these tables.
		 */
		break;

	default:
		/*
		 * But you can't do a string lookup in any other types
		 * of tables.
		 */
		g_assert_not_reached();
	}

	if (sub_dissectors->param == TRUE) {
		key = g_ascii_strdown(pattern, -1);
	} else {
		key = g_strdup(pattern);
	}

	/*
	 * Find the entry.
	 */
	ret = (dtbl_entry_t *)g_hash_table_lookup(sub_dissectors->hash_table, key);

	g_free(key);

	return ret;
}

/* Add an entry to a string dissector table. */
void
dissector_add_string(const char *name, const gchar *pattern,
		     dissector_handle_t handle)
{
	dissector_table_t  sub_dissectors = find_dissector_table( name);
	dtbl_entry_t      *dtbl_entry;
	char *key;

	/*
	 * Make sure the handle and the dissector table exist.
	 */
	if (handle == NULL) {
		fprintf(stderr, "OOPS: handle to register \"%s\" to doesn't exist\n",
		    name);
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		return;
	}
	if (sub_dissectors == NULL) {
		fprintf(stderr, "OOPS: dissector table \"%s\" doesn't exist\n",
		    name);
		fprintf(stderr, "Protocol being registered is \"%s\"\n",
		    proto_get_protocol_long_name(handle->protocol));
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		return;
	}

	switch (sub_dissectors->type) {

	case FT_STRING:
	case FT_STRINGZ:
	case FT_STRINGZPAD:
		/*
		 * You can do a string lookup in these tables.
		 */
		break;

	default:
		/*
		 * But you can't do a string lookup in any other types
		 * of tables.
		 */
		g_assert_not_reached();
	}

	dtbl_entry = (dtbl_entry_t *)g_malloc(sizeof (dtbl_entry_t));
	dtbl_entry->current = handle;
	dtbl_entry->initial = dtbl_entry->current;

	if (sub_dissectors->param == TRUE) {
		key = g_ascii_strdown(pattern, -1);
	} else {
		key = g_strdup(pattern);
	}

	/* do the table insertion */
	g_hash_table_insert( sub_dissectors->hash_table, (gpointer)key,
			     (gpointer)dtbl_entry);

	/*
	 * Now, if this table supports "Decode As", add this handle
	 * to the list of handles that could be used for "Decode As"
	 * with this table, because it *is* being used with this table.
	 */
	if (sub_dissectors->supports_decode_as)
		dissector_add_for_decode_as(name, handle);
}

/* Delete the entry for a dissector in a string dissector table
   with a particular pattern. */

/* NOTE: this doesn't use the dissector call variable. It is included to */
/*	be consistant with the dissector_add_string and more importantly to */
/*      be used if the technique of adding a temporary dissector is */
/*      implemented.  */
/*	If temporary dissectors are deleted, then the original dissector must */
/*	be available. */
void
dissector_delete_string(const char *name, const gchar *pattern,
	dissector_handle_t handle _U_)
{
	dissector_table_t  sub_dissectors = find_dissector_table( name);
	dtbl_entry_t      *dtbl_entry;

	/* sanity check */
	g_assert( sub_dissectors);

	/*
	 * Find the entry.
	 */
	dtbl_entry = find_string_dtbl_entry(sub_dissectors, pattern);

	if (dtbl_entry != NULL) {
		/*
		 * Found - remove it.
		 */
		g_hash_table_remove(sub_dissectors->hash_table, pattern);
	}
}

/* Change the entry for a dissector in a string dissector table
   with a particular pattern to use a new dissector handle. */
void
dissector_change_string(const char *name, const gchar *pattern,
			dissector_handle_t handle)
{
	dissector_table_t  sub_dissectors = find_dissector_table( name);
	dtbl_entry_t      *dtbl_entry;

	/* sanity check */
	g_assert( sub_dissectors);

	/*
	 * See if the entry already exists. If so, reuse it.
	 */
	dtbl_entry = find_string_dtbl_entry(sub_dissectors, pattern);
	if (dtbl_entry != NULL) {
		dtbl_entry->current = handle;
		return;
	}

	/*
	 * Don't create an entry if there is no dissector handle - I.E. the
	 * user said not to decode something that wasn't being decoded
	 * in the first place.
	 */
	if (handle == NULL)
		return;

	dtbl_entry = (dtbl_entry_t *)g_malloc(sizeof (dtbl_entry_t));
	dtbl_entry->initial = NULL;
	dtbl_entry->current = handle;

	/* do the table insertion */
	g_hash_table_insert( sub_dissectors->hash_table, (gpointer)g_strdup(pattern),
			     (gpointer)dtbl_entry);
}

/* Reset an entry in a string sub-dissector table to its initial value. */
void
dissector_reset_string(const char *name, const gchar *pattern)
{
	dissector_table_t  sub_dissectors = find_dissector_table( name);
	dtbl_entry_t      *dtbl_entry;

	/* sanity check */
	g_assert( sub_dissectors);

	/*
	 * Find the entry.
	 */
	dtbl_entry = find_string_dtbl_entry(sub_dissectors, pattern);

	if (dtbl_entry == NULL)
		return;

	/*
	 * Found - is there an initial value?
	 */
	if (dtbl_entry->initial != NULL) {
		dtbl_entry->current = dtbl_entry->initial;
	} else {
		g_hash_table_remove(sub_dissectors->hash_table, pattern);
	}
}

/* Look for a given string in a given dissector table and, if found, call
   the dissector with the arguments supplied, and return length of dissected data,
   otherwise return 0. */
int
dissector_try_string(dissector_table_t sub_dissectors, const gchar *string,
		     tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	dtbl_entry_t            *dtbl_entry;
	struct dissector_handle *handle;
	int                      len;
	const gchar             *saved_match_string;

	/* XXX ASSERT instead ? */
	if (!string) return 0;
	dtbl_entry = find_string_dtbl_entry(sub_dissectors, string);
	if (dtbl_entry != NULL) {
		/*
		 * Is there currently a dissector handle for this entry?
		 */
		handle = dtbl_entry->current;
		if (handle == NULL) {
			/*
			 * No - pretend this dissector didn't exist,
			 * so that other dissectors might have a chance
			 * to dissect this packet.
			 */
			return 0;
		}

		/*
		 * Save the current value of "pinfo->match_string",
		 * set it to the string that matched, call the
		 * dissector, and restore "pinfo->match_string".
		 */
		saved_match_string = pinfo->match_string;
		pinfo->match_string = string;
		len = call_dissector_work(handle, tvb, pinfo, tree, TRUE, data);
		pinfo->match_string = saved_match_string;

		/*
		 * If a new-style dissector returned 0, it means that
		 * it didn't think this tvbuff represented a packet for
		 * its protocol, and didn't dissect anything.
		 *
		 * Old-style dissectors can't reject the packet.
		 *
		 * 0 is also returned if the protocol wasn't enabled.
		 *
		 * If the packet was rejected, we return 0, so that
		 * other dissectors might have a chance to dissect this
		 * packet, otherwise we return the dissected length.
		 */
		return len;
	}
	return 0;
}

/* Look for a given value in a given string dissector table and, if found,
   return the dissector handle for that value. */
dissector_handle_t
dissector_get_string_handle(dissector_table_t sub_dissectors,
			    const gchar *string)
{
	dtbl_entry_t *dtbl_entry;

	/* XXX ASSERT instead ? */
	if (!string) return NULL;
	dtbl_entry = find_string_dtbl_entry(sub_dissectors, string);
	if (dtbl_entry != NULL)
		return dtbl_entry->current;
	else
		return NULL;
}

dissector_handle_t
dissector_get_default_string_handle(const char *name, const gchar *string)
{
	dissector_table_t sub_dissectors;

	/* XXX ASSERT instead ? */
	if (!string) return NULL;
	sub_dissectors = find_dissector_table(name);
	if (sub_dissectors != NULL) {
		dtbl_entry_t *dtbl_entry = find_string_dtbl_entry(sub_dissectors, string);
		if (dtbl_entry != NULL)
			return dtbl_entry->initial;
	}
	return NULL;
}

/* Add an entry to a "custom" dissector table. */
void dissector_add_custom_table_handle(const char *name, void *pattern, dissector_handle_t handle)
{
	dissector_table_t  sub_dissectors = find_dissector_table( name);
	dtbl_entry_t      *dtbl_entry;

	/*
	 * Make sure the dissector table exists.
	 */
	if (sub_dissectors == NULL) {
		fprintf(stderr, "OOPS: dissector table \"%s\" doesn't exist\n",
		    name);
		fprintf(stderr, "Protocol being registered is \"%s\"\n",
		    proto_get_protocol_long_name(handle->protocol));
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		return;
	}

	g_assert(sub_dissectors->type == FT_BYTES);

	dtbl_entry = (dtbl_entry_t *)g_malloc(sizeof (dtbl_entry_t));
	dtbl_entry->current = handle;
	dtbl_entry->initial = dtbl_entry->current;

	/* do the table insertion */
	g_hash_table_insert( sub_dissectors->hash_table, (gpointer)pattern,
			     (gpointer)dtbl_entry);

	/*
	 * Now, if this table supports "Decode As", add this handle
	 * to the list of handles that could be used for "Decode As"
	 * with this table, because it *is* being used with this table.
	 */
	if (sub_dissectors->supports_decode_as)
		dissector_add_for_decode_as(name, handle);
}

dissector_handle_t dissector_get_custom_table_handle(dissector_table_t sub_dissectors, void *key)
{
	dtbl_entry_t *dtbl_entry = (dtbl_entry_t *)g_hash_table_lookup(sub_dissectors->hash_table, key);

	if (dtbl_entry != NULL)
		return dtbl_entry->current;

	return NULL;
}
/* Add an entry to a guid dissector table. */
void dissector_add_guid(const char *name, guid_key* guid_val, dissector_handle_t handle)
{
	dissector_table_t  sub_dissectors;
	dtbl_entry_t      *dtbl_entry;

	sub_dissectors = find_dissector_table(name);

	/*
	 * Make sure the handle and the dissector table exist.
	 */
	if (handle == NULL) {
		fprintf(stderr, "OOPS: handle to register \"%s\" to doesn't exist\n",
		    name);
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		return;
	}
	if (sub_dissectors == NULL) {
		fprintf(stderr, "OOPS: dissector table \"%s\" doesn't exist\n",
		    name);
		fprintf(stderr, "Protocol being registered is \"%s\"\n",
		    proto_get_protocol_long_name(handle->protocol));
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		return;
	}

	if (sub_dissectors->type != FT_GUID) {
		g_assert_not_reached();
	}

	dtbl_entry = (dtbl_entry_t *)g_malloc(sizeof (dtbl_entry_t));
	dtbl_entry->current = handle;
	dtbl_entry->initial = dtbl_entry->current;

	/* do the table insertion */
	g_hash_table_insert( sub_dissectors->hash_table,
			     guid_val, (gpointer)dtbl_entry);

	/*
	 * Now, if this table supports "Decode As", add this handle
	 * to the list of handles that could be used for "Decode As"
	 * with this table, because it *is* being used with this table.
	 */
	if (sub_dissectors->supports_decode_as)
		dissector_add_for_decode_as(name, handle);
}

/* Look for a given value in a given guid dissector table and, if found,
   call the dissector with the arguments supplied, and return TRUE,
   otherwise return FALSE. */
int dissector_try_guid_new(dissector_table_t sub_dissectors,
    guid_key* guid_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const gboolean add_proto_name, void *data)
{
	dtbl_entry_t            *dtbl_entry;
	struct dissector_handle *handle;
	int len;

	dtbl_entry = (dtbl_entry_t *)g_hash_table_lookup(sub_dissectors->hash_table, guid_val);
	if (dtbl_entry != NULL) {
		/*
		 * Is there currently a dissector handle for this entry?
		 */
		handle = dtbl_entry->current;
		if (handle == NULL) {
			/*
			 * No - pretend this dissector didn't exist,
			 * so that other dissectors might have a chance
			 * to dissect this packet.
			 */
			return 0;
		}

		/*
		 * Save the current value of "pinfo->match_uint",
		 * set it to the uint_val that matched, call the
		 * dissector, and restore "pinfo->match_uint".
		 */
		len = call_dissector_work(handle, tvb, pinfo, tree, add_proto_name, data);

		/*
		 * If a new-style dissector returned 0, it means that
		 * it didn't think this tvbuff represented a packet for
		 * its protocol, and didn't dissect anything.
		 *
		 * Old-style dissectors can't reject the packet.
		 *
		 * 0 is also returned if the protocol wasn't enabled.
		 *
		 * If the packet was rejected, we return 0, so that
		 * other dissectors might have a chance to dissect this
		 * packet, otherwise we return the dissected length.
		 */
		return len;
	}
	return 0;
}

int dissector_try_guid(dissector_table_t sub_dissectors,
    guid_key* guid_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    return dissector_try_guid_new(sub_dissectors, guid_val, tvb, pinfo, tree, TRUE, NULL);
}

/** Look for a given value in a given guid dissector table and, if found,
 * return the current dissector handle for that value.
 *
 * @param[in] sub_dissectors Dissector table to search.
 * @param[in] uint_val Value to match, e.g. the port number for the TCP dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
dissector_handle_t dissector_get_guid_handle(
    dissector_table_t const sub_dissectors, guid_key* guid_val)
{
	dtbl_entry_t *dtbl_entry;

	dtbl_entry = (dtbl_entry_t *)g_hash_table_lookup(sub_dissectors->hash_table, guid_val);
	if (dtbl_entry != NULL)
		return dtbl_entry->current;
	else
		return NULL;
}


dissector_handle_t
dtbl_entry_get_handle (dtbl_entry_t *dtbl_entry)
{
	return dtbl_entry->current;
}

static gint
dissector_compare_filter_name(gconstpointer dissector_a, gconstpointer dissector_b)
{
	const struct dissector_handle *a = (const struct dissector_handle *)dissector_a;
	const struct dissector_handle *b = (const struct dissector_handle *)dissector_b;
	const char *a_name, *b_name;
	gint ret;

	if (a->protocol == NULL)
		a_name = "";
	else
		a_name = proto_get_protocol_filter_name(proto_get_id(a->protocol));

	if (b->protocol == NULL)
		b_name = "";
	else
		b_name = proto_get_protocol_filter_name(proto_get_id(b->protocol));

	ret = strcmp(a_name, b_name);
	return ret;
}

/* Add a handle to the list of handles that *could* be used with this
   table.  That list is used by the "Decode As"/"-d" code in the UI. */
void
dissector_add_for_decode_as(const char *name, dissector_handle_t handle)
{
	dissector_table_t  sub_dissectors = find_dissector_table( name);
	GSList            *entry;
	dissector_handle_t dup_handle;

	/*
	 * Make sure the dissector table exists.
	 */
	if (sub_dissectors == NULL) {
		fprintf(stderr, "OOPS: dissector table \"%s\" doesn't exist\n",
		    name);
		fprintf(stderr, "Protocol being registered is \"%s\"\n",
		    proto_get_protocol_long_name(handle->protocol));
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		return;
	}

	/*
	 * Make sure it supports Decode As.
	 */
	if (!sub_dissectors->supports_decode_as) {
		const char *dissector_name;

		dissector_name = dissector_handle_get_dissector_name(handle);
		if (dissector_name == NULL)
			dissector_name = "(anonymous)";
		fprintf(stderr, "Registering dissector %s for protocol %s in dissector table %s, which doesn't support Decode As\n",
				    dissector_name,
				    proto_get_protocol_short_name(handle->protocol),
				    name);
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		return;
	}

	/* Add the dissector as a dependency
	  (some dissector tables don't have protocol association, so there is
	  the need for the NULL check */
	if (sub_dissectors->protocol != NULL)
		register_depend_dissector(proto_get_protocol_short_name(sub_dissectors->protocol), proto_get_protocol_short_name(handle->protocol));

	/* Is it already in this list? */
	entry = g_slist_find(sub_dissectors->dissector_handles, (gpointer)handle);
	if (entry != NULL) {
		/*
		 * Yes - don't insert it again.
		 */
		return;
	}

	/* Ensure the protocol is unique.  This prevents confusion when
	   using Decode As with duplicative entries.

	   FT_STRING can at least show the string value in the dialog,
	   so we don't do the check for them. */
	if (sub_dissectors->type != FT_STRING)
	{
		for (entry = sub_dissectors->dissector_handles; entry != NULL; entry = g_slist_next(entry))
		{
			dup_handle = (dissector_handle_t)entry->data;
			if (dup_handle->protocol == handle->protocol)
			{
				const char *dissector_name, *dup_dissector_name;

				dissector_name = dissector_handle_get_dissector_name(handle);
				if (dissector_name == NULL)
					dissector_name = "(anonymous)";
				dup_dissector_name = dissector_handle_get_dissector_name(dup_handle);
				if (dup_dissector_name == NULL)
					dup_dissector_name = "(anonymous)";
				fprintf(stderr, "Duplicate dissectors %s and %s for protocol %s in dissector table %s\n",
				    dissector_name, dup_dissector_name,
				    proto_get_protocol_short_name(handle->protocol),
				    name);
				if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
					abort();
			}
		}
	}

	/* Add it to the list. */
	sub_dissectors->dissector_handles =
		g_slist_insert_sorted(sub_dissectors->dissector_handles, (gpointer)handle, (GCompareFunc)dissector_compare_filter_name);
}

dissector_handle_t
dtbl_entry_get_initial_handle (dtbl_entry_t *dtbl_entry)
{
	return dtbl_entry->initial;
}

GSList *
dissector_table_get_dissector_handles(dissector_table_t dissector_table) {
	if (!dissector_table) return NULL;
	return dissector_table->dissector_handles;
}

ftenum_t
dissector_table_get_type(dissector_table_t dissector_table) {
	if (!dissector_table) return FT_NONE;
	return dissector_table->type;
}

void
dissector_table_allow_decode_as(dissector_table_t dissector_table)
{
	dissector_table->supports_decode_as = TRUE;
}

static gint
uuid_equal(gconstpointer k1, gconstpointer k2)
{
    const guid_key *key1 = (const guid_key *)k1;
    const guid_key *key2 = (const guid_key *)k2;
    return ((memcmp(&key1->guid, &key2->guid, sizeof (e_guid_t)) == 0)
            && (key1->ver == key2->ver));
}

static guint
uuid_hash(gconstpointer k)
{
    const guid_key *key = (const guid_key *)k;
    /* This isn't perfect, but the Data1 part of these is almost always
       unique. */
    return key->guid.data1;
}

/**************************************************/
/*                                                */
/*       Routines to walk dissector tables        */
/*                                                */
/**************************************************/

typedef struct dissector_foreach_info {
	gpointer      caller_data;
	DATFunc       caller_func;
	GHFunc        next_func;
	const gchar  *table_name;
	ftenum_t      selector_type;
} dissector_foreach_info_t;

/*
 * Called for each entry in a dissector table.
 */
static void
dissector_table_foreach_func (gpointer key, gpointer value, gpointer user_data)
{
	dissector_foreach_info_t *info;
	dtbl_entry_t             *dtbl_entry;

	g_assert(value);
	g_assert(user_data);

	dtbl_entry = (dtbl_entry_t *)value;
	if (dtbl_entry->current == NULL ||
	    dtbl_entry->current->protocol == NULL) {
		/*
		 * Either there is no dissector for this entry, or
		 * the dissector doesn't have a protocol associated
		 * with it.
		 *
		 * XXX - should the latter check be done?
		 */
		return;
	}

	info = (dissector_foreach_info_t *)user_data;
	info->caller_func(info->table_name, info->selector_type, key, value,
			  info->caller_data);
}

/*
 * Called for each entry in the table of all dissector tables.
 */
static void
dissector_all_tables_foreach_func (gpointer key, gpointer value, gpointer user_data)
{
	dissector_table_t         sub_dissectors;
	dissector_foreach_info_t *info;

	g_assert(value);
	g_assert(user_data);

	sub_dissectors = (dissector_table_t)value;
	info = (dissector_foreach_info_t *)user_data;
	info->table_name = (gchar*) key;
	info->selector_type = get_dissector_table_selector_type(info->table_name);
	g_hash_table_foreach(sub_dissectors->hash_table, info->next_func, info);
}

/*
 * Walk all dissector tables calling a user supplied function on each
 * entry.
 */
static void
dissector_all_tables_foreach (DATFunc func,
			      gpointer user_data)
{
	dissector_foreach_info_t info;

	info.caller_data = user_data;
	info.caller_func = func;
	info.next_func   = dissector_table_foreach_func;
	g_hash_table_foreach(dissector_tables, dissector_all_tables_foreach_func, &info);
}

/*
 * Walk one dissector table's hash table calling a user supplied function
 * on each entry.
 */
void
dissector_table_foreach (const char *table_name,
			 DATFunc     func,
			 gpointer    user_data)
{
	dissector_foreach_info_t info;
	dissector_table_t        sub_dissectors = find_dissector_table(table_name);

	info.table_name    = table_name;
	info.selector_type = sub_dissectors->type;
	info.caller_func   = func;
	info.caller_data   = user_data;
	g_hash_table_foreach(sub_dissectors->hash_table, dissector_table_foreach_func, &info);
}

/*
 * Walk one dissector table's list of handles calling a user supplied
 * function on each entry.
 */
void
dissector_table_foreach_handle(const char     *table_name,
			       DATFunc_handle  func,
			       gpointer        user_data)
{
	dissector_table_t sub_dissectors = find_dissector_table(table_name);
	GSList *tmp;

	for (tmp = sub_dissectors->dissector_handles; tmp != NULL;
	     tmp = g_slist_next(tmp))
        func(table_name, tmp->data, user_data);
}

/*
 * Called for each entry in a dissector table.
 */
static void
dissector_table_foreach_changed_func (gpointer key, gpointer value, gpointer user_data)
{
	dtbl_entry_t             *dtbl_entry;
	dissector_foreach_info_t *info;

	g_assert(value);
	g_assert(user_data);

	dtbl_entry = (dtbl_entry_t *)value;
	if (dtbl_entry->initial == dtbl_entry->current) {
		/*
		 * Entry hasn't changed - don't call the function.
		 */
		return;
	}

	info = (dissector_foreach_info_t *)user_data;
	info->caller_func(info->table_name, info->selector_type, key, value,
			  info->caller_data);
}

/*
 * Walk all dissector tables calling a user supplied function only on
 * any entry that has been changed from its original state.
 */
void
dissector_all_tables_foreach_changed (DATFunc  func,
				      gpointer user_data)
{
	dissector_foreach_info_t info;

	info.caller_data = user_data;
	info.caller_func = func;
	info.next_func   = dissector_table_foreach_changed_func;
	g_hash_table_foreach(dissector_tables, dissector_all_tables_foreach_func, &info);
}

/*
 * Walk one dissector table calling a user supplied function only on
 * any entry that has been changed from its original state.
 */
void
dissector_table_foreach_changed (const char *table_name,
				 DATFunc     func,
				 gpointer    user_data)
{
	dissector_foreach_info_t info;
	dissector_table_t sub_dissectors = find_dissector_table(table_name);

	info.table_name    = table_name;
	info.selector_type = sub_dissectors->type;
	info.caller_func   = func;
	info.caller_data   = user_data;
	g_hash_table_foreach(sub_dissectors->hash_table,
			     dissector_table_foreach_changed_func, &info);
}

typedef struct dissector_foreach_table_info {
	gpointer      caller_data;
	DATFunc_table caller_func;
} dissector_foreach_table_info_t;

/*
 * Called for each entry in the table of all dissector tables.
 * This is used if we directly process the hash table.
 */
static void
dissector_all_tables_foreach_table_func (gpointer key, gpointer value, gpointer user_data)
{
	dissector_table_t               table;
	dissector_foreach_table_info_t *info;

	table = (dissector_table_t)value;
	info  = (dissector_foreach_table_info_t *)user_data;
	(*info->caller_func)((gchar *)key, table->ui_name, info->caller_data);
}

/*
 * Called for each key in the table of all dissector tables.
 * This is used if we get a list of table names, sort it, and process the list.
 */
static void
dissector_all_tables_foreach_list_func (gpointer key, gpointer user_data)
{
	dissector_table_t               table;
	dissector_foreach_table_info_t *info;

	table = (dissector_table_t)g_hash_table_lookup( dissector_tables, key );
	info  = (dissector_foreach_table_info_t *)user_data;
	(*info->caller_func)((gchar*)key, table->ui_name, info->caller_data);
}

/*
 * Walk all dissector tables calling a user supplied function on each
 * table.
 */
void
dissector_all_tables_foreach_table (DATFunc_table func,
				    gpointer      user_data,
				    GCompareFunc  compare_key_func)
{
	dissector_foreach_table_info_t info;
	GList *list;

	info.caller_data = user_data;
	info.caller_func = func;
	if (compare_key_func != NULL)
	{
		list = g_hash_table_get_keys(dissector_tables);
		list = g_list_sort(list, compare_key_func);
		g_list_foreach(list, dissector_all_tables_foreach_list_func, &info);
		g_list_free(list);
	}
	else
	{
		g_hash_table_foreach(dissector_tables, dissector_all_tables_foreach_table_func, &info);
	}
}

dissector_table_t
register_dissector_table(const char *name, const char *ui_name, const int proto, const ftenum_t type,
			 const int param)
{
	dissector_table_t	sub_dissectors;

	/* Make sure the registration is unique */
	if(g_hash_table_lookup( dissector_tables, name )) {
		g_error("The dissector table %s (%s) is already registered - are you using a buggy plugin?", name, ui_name);
	}

	/* Create and register the dissector table for this name; returns */
	/* a pointer to the dissector table. */
	sub_dissectors = g_slice_new(struct dissector_table);
	switch (type) {

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		/*
		 * XXX - there's no "g_uint_hash()" or "g_uint_equal()",
		 * so we use "g_direct_hash()" and "g_direct_equal()".
		 */
		sub_dissectors->hash_func = g_direct_hash;
		sub_dissectors->hash_table = g_hash_table_new_full( g_direct_hash,
							       g_direct_equal,
							       NULL,
							       &g_free );
		break;

	case FT_STRING:
	case FT_STRINGZ:
	case FT_STRINGZPAD:
		sub_dissectors->hash_func = g_str_hash;
		sub_dissectors->hash_table = g_hash_table_new_full( g_str_hash,
							       g_str_equal,
							       &g_free,
							       &g_free );
		break;
	case FT_GUID:
		sub_dissectors->hash_table = g_hash_table_new_full( uuid_hash,
							       uuid_equal,
							       NULL,
							       &g_free );
		break;
	default:
		g_error("The dissector table %s (%s) is registering an unsupported type - are you using a buggy plugin?", name, ui_name);
		g_assert_not_reached();
	}
	sub_dissectors->dissector_handles = NULL;
	sub_dissectors->ui_name = ui_name;
	sub_dissectors->type    = type;
	sub_dissectors->param   = param;
	sub_dissectors->protocol  = find_protocol_by_id(proto);
	sub_dissectors->supports_decode_as = FALSE;
	g_hash_table_insert( dissector_tables, (gpointer)name, (gpointer) sub_dissectors );
	return sub_dissectors;
}

dissector_table_t register_custom_dissector_table(const char *name,
	const char *ui_name, const int proto, GHashFunc hash_func, GEqualFunc key_equal_func)
{
	dissector_table_t	sub_dissectors;

	/* Make sure the registration is unique */
	if(g_hash_table_lookup( dissector_tables, name )) {
		g_error("The dissector table %s (%s) is already registered - are you using a buggy plugin?", name, ui_name);
	}

	/* Create and register the dissector table for this name; returns */
	/* a pointer to the dissector table. */
	sub_dissectors = g_slice_new(struct dissector_table);
	sub_dissectors->hash_func = hash_func;
	sub_dissectors->hash_table = g_hash_table_new_full(hash_func,
							       key_equal_func,
							       &g_free,
							       &g_free );

	sub_dissectors->dissector_handles = NULL;
	sub_dissectors->ui_name = ui_name;
	sub_dissectors->type    = FT_BYTES; /* Consider key a "blob" of data, no need to really create new type */
	sub_dissectors->param   = BASE_NONE;
	sub_dissectors->protocol  = find_protocol_by_id(proto);
	sub_dissectors->supports_decode_as = FALSE;
	g_hash_table_insert( dissector_tables, (gpointer)name, (gpointer) sub_dissectors );
	return sub_dissectors;
}

void
deregister_dissector_table(const char *name)
{
	dissector_table_t sub_dissectors = find_dissector_table(name);
	if (!sub_dissectors) return;

	g_hash_table_remove(dissector_tables, name);
}

const char *
get_dissector_table_ui_name(const char *name)
{
	dissector_table_t sub_dissectors = find_dissector_table(name);
	if (!sub_dissectors) return NULL;

	return sub_dissectors->ui_name;
}

ftenum_t
get_dissector_table_selector_type(const char *name)
{
	dissector_table_t sub_dissectors = find_dissector_table(name);
	if (!sub_dissectors) return FT_NONE;

	return sub_dissectors->type;
}

int
get_dissector_table_param(const char *name)
{
	dissector_table_t sub_dissectors = find_dissector_table(name);
	if (!sub_dissectors) return 0;

	return sub_dissectors->param;
}

/* Finds a heuristic dissector table by table name. */
heur_dissector_list_t
find_heur_dissector_list(const char *name)
{
	return (heur_dissector_list_t)g_hash_table_lookup(heur_dissector_lists, name);
}

gboolean
has_heur_dissector_list(const gchar *name) {
	return (find_heur_dissector_list(name) != NULL);
}

heur_dtbl_entry_t* find_heur_dissector_by_unique_short_name(const char *short_name)
{
	return (heur_dtbl_entry_t*)g_hash_table_lookup(heuristic_short_names, short_name);
}

void
heur_dissector_add(const char *name, heur_dissector_t dissector, const char *display_name, const char *short_name, const int proto, heuristic_enable_e enable)
{
	heur_dissector_list_t  sub_dissectors = find_heur_dissector_list(name);
	const char            *proto_name;
	heur_dtbl_entry_t     *hdtbl_entry;
	guint                  i, list_size;
	GSList                *list_entry;

	/*
	 * Make sure the dissector table exists.
	 */
	if (sub_dissectors == NULL) {
		fprintf(stderr, "OOPS: dissector table \"%s\" doesn't exist\n",
		    name);
		proto_name = proto_get_protocol_name(proto);
		if (proto_name != NULL) {
			fprintf(stderr, "Protocol being registered is \"%s\"\n",
			    proto_name);
		}
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		return;
	}

	/* Verify that sub-dissector is not already in the list */
	list_size = g_slist_length(sub_dissectors->dissectors);
	for (i = 0; i < list_size; i++)
	{
		list_entry = g_slist_nth(sub_dissectors->dissectors, i);
		hdtbl_entry = (heur_dtbl_entry_t *)list_entry->data;
		if ((hdtbl_entry->dissector == dissector) &&
			(hdtbl_entry->protocol == find_protocol_by_id(proto)))
		{
			proto_name = proto_get_protocol_name(proto);
			if (proto_name != NULL) {
				fprintf(stderr, "Protocol %s is already registered in \"%s\" table\n",
				    proto_name, name);
			}
			if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
				abort();
			return;
		}
	}

	/* Ensure short_name is unique */
	if (g_hash_table_lookup(heuristic_short_names, short_name) != NULL) {
		g_error("Duplicate heuristic short_name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", short_name);
	}

	hdtbl_entry = g_slice_new(heur_dtbl_entry_t);
	hdtbl_entry->dissector = dissector;
	hdtbl_entry->protocol  = find_protocol_by_id(proto);
	hdtbl_entry->display_name = display_name;
	hdtbl_entry->short_name = short_name;
	hdtbl_entry->list_name = g_strdup(name);
	hdtbl_entry->enabled   = (enable == HEURISTIC_ENABLE);

	/* do the table insertion */
	g_hash_table_insert(heuristic_short_names, (gpointer)short_name, hdtbl_entry);

	sub_dissectors->dissectors = g_slist_prepend(sub_dissectors->dissectors,
	    (gpointer)hdtbl_entry);

	/* XXX - could be optimized to pass hdtbl_entry directly */
	proto_add_heuristic_dissector(hdtbl_entry->protocol, short_name);

	/* Add the dissector as a dependency
	  (some heuristic tables don't have protocol association, so there is
	  the need for the NULL check */
	if (sub_dissectors->protocol != NULL)
		register_depend_dissector(proto_get_protocol_short_name(sub_dissectors->protocol), proto_get_protocol_short_name(hdtbl_entry->protocol));
}



static int
find_matching_heur_dissector( gconstpointer a, gconstpointer b) {
	const heur_dtbl_entry_t *hdtbl_entry_a = (const heur_dtbl_entry_t *) a;
	const heur_dtbl_entry_t *hdtbl_entry_b = (const heur_dtbl_entry_t *) b;

	return (hdtbl_entry_a->dissector == hdtbl_entry_b->dissector) &&
		(hdtbl_entry_a->protocol == hdtbl_entry_b->protocol) ? 0 : 1;
}

void
heur_dissector_delete(const char *name, heur_dissector_t dissector, const int proto) {
	heur_dissector_list_t  sub_dissectors = find_heur_dissector_list(name);
	heur_dtbl_entry_t      hdtbl_entry;
	GSList                *found_entry;

	/* sanity check */
	g_assert(sub_dissectors != NULL);

	hdtbl_entry.dissector = dissector;
	hdtbl_entry.protocol  = find_protocol_by_id(proto);

	found_entry = g_slist_find_custom(sub_dissectors->dissectors,
	    (gpointer) &hdtbl_entry, find_matching_heur_dissector);

	if (found_entry) {
		heur_dtbl_entry_t *found_hdtbl_entry = (heur_dtbl_entry_t *)(found_entry->data);
		g_free(found_hdtbl_entry->list_name);
		g_hash_table_remove(heuristic_short_names, found_hdtbl_entry->short_name);
		g_slice_free(heur_dtbl_entry_t, found_entry->data);
		sub_dissectors->dissectors = g_slist_delete_link(sub_dissectors->dissectors,
		    found_entry);
	}
}

gboolean
dissector_try_heuristic(heur_dissector_list_t sub_dissectors, tvbuff_t *tvb,
			packet_info *pinfo, proto_tree *tree, heur_dtbl_entry_t **heur_dtbl_entry, void *data)
{
	gboolean           status;
	const char        *saved_curr_proto;
	const char        *saved_heur_list_name;
	GSList            *entry;
	guint16            saved_can_desegment;
	guint              saved_layers_len = 0;
	heur_dtbl_entry_t *hdtbl_entry;
	int                proto_id;

	/* can_desegment is set to 2 by anyone which offers this api/service.
	   then everytime a subdissector is called it is decremented by one.
	   thus only the subdissector immediately ontop of whoever offers this
	   service can use it.
	   We save the current value of "can_desegment" for the
	   benefit of TCP proxying dissectors such as SOCKS, so they
	   can restore it and allow the dissectors they call to use
	   the desegmentation service.
	*/
	saved_can_desegment        = pinfo->can_desegment;
	pinfo->saved_can_desegment = saved_can_desegment;
	pinfo->can_desegment       = saved_can_desegment-(saved_can_desegment>0);

	status      = FALSE;
	saved_curr_proto = pinfo->current_proto;
	saved_heur_list_name = pinfo->heur_list_name;

	saved_layers_len = wmem_list_count(pinfo->layers);
	*heur_dtbl_entry = NULL;

	for (entry = sub_dissectors->dissectors; entry != NULL;
	    entry = g_slist_next(entry)) {
		/* XXX - why set this now and above? */
		pinfo->can_desegment = saved_can_desegment-(saved_can_desegment>0);
		hdtbl_entry = (heur_dtbl_entry_t *)entry->data;

		if (hdtbl_entry->protocol != NULL &&
			(!proto_is_protocol_enabled(hdtbl_entry->protocol)||(hdtbl_entry->enabled==FALSE))) {
			/*
			 * No - don't try this dissector.
			 */
			continue;
		}

		if (hdtbl_entry->protocol != NULL) {
			proto_id = proto_get_id(hdtbl_entry->protocol);
			/* do NOT change this behavior - wslua uses the protocol short name set here in order
			   to determine which Lua-based heurisitc dissector to call */
			pinfo->current_proto =
				proto_get_protocol_short_name(hdtbl_entry->protocol);

			/*
			 * Add the protocol name to the layers; we'll remove it
			 * if the dissector fails.
			 */
			wmem_list_append(pinfo->layers, GINT_TO_POINTER(proto_id));
		}

		pinfo->heur_list_name = hdtbl_entry->list_name;

		if ((hdtbl_entry->dissector)(tvb, pinfo, tree, data)) {
			*heur_dtbl_entry = hdtbl_entry;
			status = TRUE;
			break;
		} else {
			/*
			 * That dissector didn't accept the packet, so
			 * remove its protocol's name from the list
			 * of protocols.
			 */
			while (wmem_list_count(pinfo->layers) > saved_layers_len) {
				wmem_list_remove_frame(pinfo->layers, wmem_list_tail(pinfo->layers));
			}
		}
	}

	pinfo->current_proto = saved_curr_proto;
	pinfo->heur_list_name = saved_heur_list_name;
	pinfo->can_desegment = saved_can_desegment;
	return status;
}

typedef struct heur_dissector_foreach_info {
	gpointer      caller_data;
	DATFunc_heur  caller_func;
	GHFunc        next_func;
	const gchar  *table_name;
} heur_dissector_foreach_info_t;

/*
 * Called for each entry in a heuristic dissector table.
 */
static void
heur_dissector_table_foreach_func (gpointer data, gpointer user_data)
{
	heur_dissector_foreach_info_t *info;

	g_assert(data);
	g_assert(user_data);

	info = (heur_dissector_foreach_info_t *)user_data;
	info->caller_func(info->table_name, (heur_dtbl_entry_t *)data,
			  info->caller_data);
}

/*
 * Walk one heuristic dissector table's list calling a user supplied function
 * on each entry.
 */
void
heur_dissector_table_foreach (const char  *table_name,
			      DATFunc_heur func,
			      gpointer     user_data)
{
	heur_dissector_foreach_info_t info;
	heur_dissector_list_t         sub_dissectors = find_heur_dissector_list(table_name);

	info.table_name    = table_name;
	info.caller_func   = func;
	info.caller_data   = user_data;
	g_slist_foreach(sub_dissectors->dissectors,
			heur_dissector_table_foreach_func, &info);
}

/*
 * Called for each entry in the table of all heuristic dissector tables.
 */
typedef struct heur_dissector_foreach_table_info {
	gpointer           caller_data;
	DATFunc_heur_table caller_func;
} heur_dissector_foreach_table_info_t;

/*
 * Called for each entry in the table of all heuristic dissector tables.
 * This is used if we directly process the hash table.
 */
static void
dissector_all_heur_tables_foreach_table_func (gpointer key, gpointer value, gpointer user_data)
{
	heur_dissector_foreach_table_info_t *info;

	info = (heur_dissector_foreach_table_info_t *)user_data;
    (*info->caller_func)((gchar *)key, (struct heur_dissector_list *)value, info->caller_data);
}

/*
 * Called for each key in the table of all dissector tables.
 * This is used if we get a list of table names, sort it, and process the list.
 */
static void
dissector_all_heur_tables_foreach_list_func (gpointer key, gpointer user_data)
{
    struct heur_dissector_list          *list;
	heur_dissector_foreach_table_info_t *info;

    list = (struct heur_dissector_list *)g_hash_table_lookup(heur_dissector_lists, key);
	info = (heur_dissector_foreach_table_info_t *)user_data;
	(*info->caller_func)((gchar*)key, list, info->caller_data);
}

/*
 * Walk all heuristic dissector tables calling a user supplied function on each
 * table.
 */
void
dissector_all_heur_tables_foreach_table (DATFunc_heur_table func,
					 gpointer           user_data,
					 GCompareFunc       compare_key_func)
{
	heur_dissector_foreach_table_info_t info;
	GList *list;

	info.caller_data = user_data;
	info.caller_func = func;
	if (compare_key_func != NULL)
	{
		list = g_hash_table_get_keys(dissector_tables);
		list = g_list_sort(list, compare_key_func);
		g_list_foreach(list, dissector_all_heur_tables_foreach_list_func, &info);
		g_list_free(list);
	}
	else
	{
		g_hash_table_foreach(heur_dissector_lists, dissector_all_heur_tables_foreach_table_func, &info);
	}
}

static void
display_heur_dissector_table_entries(const char *table_name,
    heur_dtbl_entry_t *hdtbl_entry, gpointer user_data _U_)
{
	if (hdtbl_entry->protocol != NULL) {
		printf("%s\t%s\t%c\n",
		       table_name,
		       proto_get_protocol_filter_name(proto_get_id(hdtbl_entry->protocol)),
		       (proto_is_protocol_enabled(hdtbl_entry->protocol) && hdtbl_entry->enabled) ? 'T' : 'F');
	}
}

static void
dissector_dump_heur_decodes_display(const gchar *table_name, struct heur_dissector_list *listptr _U_, gpointer user_data _U_)
{
	heur_dissector_table_foreach(table_name, display_heur_dissector_table_entries, NULL);
}

/*
 * For each heuristic dissector table, dump list of dissectors (filter_names) for that table
 */
void
dissector_dump_heur_decodes(void)
{
	dissector_all_heur_tables_foreach_table(dissector_dump_heur_decodes_display, NULL, NULL);
}


heur_dissector_list_t
register_heur_dissector_list(const char *name, const int proto)
{
	heur_dissector_list_t sub_dissectors;

	/* Make sure the registration is unique */
	if (g_hash_table_lookup(heur_dissector_lists, name) != NULL) {
		g_error("The heuristic dissector list %s is already registered - are you using a buggy plugin?", name);
	}

	/* Create and register the dissector table for this name; returns */
	/* a pointer to the dissector table. */
	sub_dissectors = g_slice_new(struct heur_dissector_list);
	sub_dissectors->protocol  = find_protocol_by_id(proto);
	sub_dissectors->dissectors = NULL;	/* initially empty */
	g_hash_table_insert(heur_dissector_lists, (gpointer)name,
			    (gpointer) sub_dissectors);
	return sub_dissectors;
}

/*
 * Register dissectors by name; used if one dissector always calls a
 * particular dissector, or if it bases the decision of which dissector
 * to call on something other than a numerical value or on "try a bunch
 * of dissectors until one likes the packet".
 */

/* Get the long name of the protocol for a dissector handle, if it has
   a protocol. */
const char *
dissector_handle_get_long_name(const dissector_handle_t handle)
{
	if (handle == NULL || handle->protocol == NULL) {
		return NULL;
	}
	return proto_get_protocol_long_name(handle->protocol);
}

/* Get the short name of the protocol for a dissector handle, if it has
   a protocol. */
const char *
dissector_handle_get_short_name(const dissector_handle_t handle)
{
	if (handle->protocol == NULL) {
		/*
		 * No protocol (see, for example, the handle for
		 * dissecting the set of protocols where the first
		 * octet of the payload is an OSI network layer protocol
		 * ID).
		 */
		return NULL;
	}
	return proto_get_protocol_short_name(handle->protocol);
}

/* Get the index of the protocol for a dissector handle, if it has
   a protocol. */
int
dissector_handle_get_protocol_index(const dissector_handle_t handle)
{
	if (handle->protocol == NULL) {
		/*
		 * No protocol (see, for example, the handle for
		 * dissecting the set of protocols where the first
		 * octet of the payload is an OSI network layer protocol
		 * ID).
		 */
		return -1;
	}
	return proto_get_id(handle->protocol);
}

/* Get a GList of all registered dissector names. The content of the list
   is owned by the hash table and should not be modified or freed.
   Use g_list_free() when done using the list. */
GList*
get_dissector_names(void)
{
	return g_hash_table_get_keys(registered_dissectors);
}

/* Find a registered dissector by name. */
dissector_handle_t
find_dissector(const char *name)
{
	return (dissector_handle_t)g_hash_table_lookup(registered_dissectors, name);
}

/** Find a dissector by name and add parent protocol as a depedency*/
dissector_handle_t find_dissector_add_dependency(const char *name, const int parent_proto)
{
	dissector_handle_t handle = (dissector_handle_t)g_hash_table_lookup(registered_dissectors, name);
	if ((handle != NULL) && (parent_proto > 0))
	{
		register_depend_dissector(proto_get_protocol_short_name(find_protocol_by_id(parent_proto)), dissector_handle_get_short_name(handle));
	}

	return handle;
}

/* Get a dissector name from handle. */
const char *
dissector_handle_get_dissector_name(const dissector_handle_t handle)
{
	if (handle == NULL) {
		return NULL;
	}
	return handle->name;
}

/* Create an anonymous handle for a new dissector. */
dissector_handle_t
create_dissector_handle(dissector_t dissector, const int proto)
{
	struct dissector_handle *handle;

	handle			= wmem_new(wmem_epan_scope(), struct dissector_handle);
	handle->name		= NULL;
	handle->dissector	= dissector;
	handle->protocol	= find_protocol_by_id(proto);

	return handle;
}

dissector_handle_t create_dissector_handle_with_name(dissector_t dissector,
    const int proto, const char* name)
{
	struct dissector_handle *handle;

	handle			= wmem_new(wmem_epan_scope(), struct dissector_handle);
	handle->name		= name;
	handle->dissector	= dissector;
	handle->protocol	= find_protocol_by_id(proto);

	return handle;
}

/* Destroy an anonymous handle for a dissector. */
static void
destroy_dissector_handle(dissector_handle_t handle)
{
	if (handle == NULL) return;

	dissector_delete_from_all_tables(handle);
	deregister_postdissector(handle);
	wmem_free(wmem_epan_scope(), handle);
}

/* Register a new dissector by name. */
dissector_handle_t
register_dissector(const char *name, dissector_t dissector, const int proto)
{
	struct dissector_handle *handle;

	/* Make sure the registration is unique */
	g_assert(g_hash_table_lookup(registered_dissectors, name) == NULL);

	handle                = wmem_new(wmem_epan_scope(), struct dissector_handle);
	handle->name          = name;
	handle->dissector     = dissector;
	handle->protocol      = find_protocol_by_id(proto);

	g_hash_table_insert(registered_dissectors, (gpointer)name,
			    (gpointer) handle);

	return handle;
}

static gboolean
remove_depend_dissector_from_list(depend_dissector_list_t sub_dissectors, const char *dependent)
{
	GSList *found_entry;

	found_entry = g_slist_find_custom(sub_dissectors->dissectors,
		dependent, (GCompareFunc)strcmp);

	if (found_entry) {
		g_free(found_entry->data);
		sub_dissectors->dissectors = g_slist_delete_link(sub_dissectors->dissectors, found_entry);
		return TRUE;
	}

	return FALSE;
}

static void
remove_depend_dissector_ghfunc(gpointer key _U_, gpointer value, gpointer user_data)
{
	depend_dissector_list_t sub_dissectors = (depend_dissector_list_t) value;
	const char *dependent = (const char *)user_data;

	remove_depend_dissector_from_list(sub_dissectors, dependent);
}

/* Deregister a dissector by name. */
void
deregister_dissector(const char *name)
{
	dissector_handle_t handle = find_dissector(name);
	if (handle == NULL) return;

	g_hash_table_remove(registered_dissectors, name);
	g_hash_table_remove(depend_dissector_lists, name);
	g_hash_table_foreach(depend_dissector_lists, remove_depend_dissector_ghfunc, (gpointer)name);
	g_hash_table_remove(heur_dissector_lists, name);

	destroy_dissector_handle(handle);
}

/* Call a dissector through a handle but if the dissector rejected it
 * return 0.
 */
int
call_dissector_only(dissector_handle_t handle, tvbuff_t *tvb,
		    packet_info *pinfo, proto_tree *tree, void *data)
{
	int ret;

	g_assert(handle != NULL);
	ret = call_dissector_work(handle, tvb, pinfo, tree, TRUE, data);
	return ret;
}

/* Call a dissector through a handle and if this fails call the "data"
 * dissector.
 */
int
call_dissector_with_data(dissector_handle_t handle, tvbuff_t *tvb,
	                 packet_info *pinfo, proto_tree *tree, void *data)
{
	int ret;

	ret = call_dissector_only(handle, tvb, pinfo, tree, data);
	if (ret == 0) {
		/*
		 * The protocol was disabled, or the dissector rejected
		 * it.  Just dissect this packet as data.
		 */
		g_assert(data_handle->protocol != NULL);
		call_dissector_work(data_handle, tvb, pinfo, tree, TRUE, NULL);
		return tvb_captured_length(tvb);
	}
	return ret;
}

int
call_dissector(dissector_handle_t handle, tvbuff_t *tvb,
	       packet_info *pinfo, proto_tree *tree)
{
	return call_dissector_with_data(handle, tvb, pinfo, tree, NULL);
}

int
call_data_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return call_dissector_work(data_handle, tvb, pinfo, tree, TRUE, NULL);
}

/*
 * Call a heuristic dissector through a heur_dtbl_entry
 */
void call_heur_dissector_direct(heur_dtbl_entry_t *heur_dtbl_entry, tvbuff_t *tvb,
	packet_info *pinfo, proto_tree *tree, void *data)
{
	const char        *saved_curr_proto;
	const char        *saved_heur_list_name;
	guint16            saved_can_desegment;

	g_assert(heur_dtbl_entry);

	/* can_desegment is set to 2 by anyone which offers this api/service.
	   then everytime a subdissector is called it is decremented by one.
	   thus only the subdissector immediately ontop of whoever offers this
	   service can use it.
	   We save the current value of "can_desegment" for the
	   benefit of TCP proxying dissectors such as SOCKS, so they
	   can restore it and allow the dissectors they call to use
	   the desegmentation service.
	*/
	saved_can_desegment        = pinfo->can_desegment;
	pinfo->saved_can_desegment = saved_can_desegment;
	pinfo->can_desegment       = saved_can_desegment-(saved_can_desegment>0);

	saved_curr_proto = pinfo->current_proto;
	saved_heur_list_name = pinfo->heur_list_name;

	if (!heur_dtbl_entry->enabled ||
		(heur_dtbl_entry->protocol != NULL && !proto_is_protocol_enabled(heur_dtbl_entry->protocol))) {
		g_assert(data_handle->protocol != NULL);
		call_dissector_work(data_handle, tvb, pinfo, tree, TRUE, NULL);
		return;
	}

	if (heur_dtbl_entry->protocol != NULL) {
		/* do NOT change this behavior - wslua uses the protocol short name set here in order
			to determine which Lua-based heuristic dissector to call */
		pinfo->current_proto = proto_get_protocol_short_name(heur_dtbl_entry->protocol);
		wmem_list_append(pinfo->layers, GINT_TO_POINTER(proto_get_id(heur_dtbl_entry->protocol)));
	}

	pinfo->heur_list_name = heur_dtbl_entry->list_name;

	/* call the dissector, in case of failure call data handle (might happen with exported PDUs) */
	if(!(*heur_dtbl_entry->dissector)(tvb, pinfo, tree, data))
		call_dissector_work(data_handle, tvb, pinfo, tree, TRUE, NULL);

	/* Restore info from caller */
	pinfo->can_desegment = saved_can_desegment;
	pinfo->current_proto = saved_curr_proto;
	pinfo->heur_list_name = saved_heur_list_name;

}

gboolean register_depend_dissector(const char* parent, const char* dependent)
{
	guint                  i, list_size;
	GSList                *list_entry;
	const char            *protocol_name;
	depend_dissector_list_t sub_dissectors;

	if ((parent == NULL) || (dependent == NULL))
	{
		/* XXX - assert on parent? */
		return FALSE;
	}

	sub_dissectors = find_depend_dissector_list(parent);
	if (sub_dissectors == NULL) {
		/* parent protocol doesn't exist, create it */
		sub_dissectors = g_slice_new(struct depend_dissector_list);
		sub_dissectors->dissectors = NULL;	/* initially empty */
		g_hash_table_insert(depend_dissector_lists, (gpointer)g_strdup(parent), (gpointer) sub_dissectors);
	}

	/* Verify that sub-dissector is not already in the list */
	list_size = g_slist_length(sub_dissectors->dissectors);
	for (i = 0; i < list_size; i++)
	{
		list_entry = g_slist_nth(sub_dissectors->dissectors, i);
		protocol_name = (const char*)list_entry->data;
		if (strcmp(dependent, protocol_name) == 0)
			return TRUE; /* Dependency already exists */
	}

	sub_dissectors->dissectors = g_slist_prepend(sub_dissectors->dissectors, (gpointer)g_strdup(dependent));
	return TRUE;
}

gboolean deregister_depend_dissector(const char* parent, const char* dependent)
{
	depend_dissector_list_t  sub_dissectors = find_depend_dissector_list(parent);

	/* sanity check */
	g_assert(sub_dissectors != NULL);

	return remove_depend_dissector_from_list(sub_dissectors, dependent);
}

depend_dissector_list_t find_depend_dissector_list(const char* name)
{
	return (depend_dissector_list_t)g_hash_table_lookup(depend_dissector_lists, name);
}

/*
 * Dumps the "layer type"/"decode as" associations to stdout, similar
 * to the proto_registrar_dump_*() routines.
 *
 * There is one record per line. The fields are tab-delimited.
 *
 * Field 1 = layer type, e.g. "tcp.port"
 * Field 2 = selector in decimal
 * Field 3 = "decode as" name, e.g. "http"
 */


static void
dissector_dump_decodes_display(const gchar *table_name,
			       ftenum_t selector_type _U_, gpointer key, gpointer value,
			       gpointer user_data _U_)
{
	guint32             selector       = GPOINTER_TO_UINT (key);
	dissector_table_t   sub_dissectors = find_dissector_table(table_name);
	dtbl_entry_t       *dtbl_entry;
	dissector_handle_t  handle;
	gint                proto_id;
	const gchar        *decode_as;

	g_assert(sub_dissectors);
	switch (sub_dissectors->type) {

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			dtbl_entry = (dtbl_entry_t *)value;
			g_assert(dtbl_entry);

			handle   = dtbl_entry->current;
			g_assert(handle);

			proto_id = dissector_handle_get_protocol_index(handle);

			if (proto_id != -1) {
				decode_as = proto_get_protocol_filter_name(proto_id);
				g_assert(decode_as != NULL);
				printf("%s\t%u\t%s\n", table_name, selector, decode_as);
			}
			break;

	default:
		break;
	}
}

void
dissector_dump_decodes(void)
{
	dissector_all_tables_foreach(dissector_dump_decodes_display, NULL);
}

/*
 * Dumps the "layer type"/"decode as" associations to stdout, similar
 * to the proto_registrar_dump_*() routines.
 *
 * There is one record per line. The fields are tab-delimited.
 *
 * Field 1 = layer type, e.g. "tcp.port"
 * Field 2 = selector in decimal
 * Field 3 = "decode as" name, e.g. "http"
 */


static void
dissector_dump_dissector_tables_display (gpointer key, gpointer user_data _U_)
{
	const char		*table_name = (const char *)key;
	dissector_table_t	table;

	table = (dissector_table_t)g_hash_table_lookup(dissector_tables, key);
	printf("%s\t%s\t%s", table_name, table->ui_name, ftype_name(table->type));
	switch (table->type) {

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		switch(table->param) {

		case BASE_NONE:
			printf("\tBASE_NONE");
			break;

		case BASE_DEC:
			printf("\tBASE_DEC");
			break;

		case BASE_HEX:
			printf("\tBASE_HEX");
			break;

		case BASE_DEC_HEX:
			printf("\tBASE_DEC_HEX");
			break;

		case BASE_HEX_DEC:
			printf("\tBASE_HEX_DEC");
			break;

		default:
			printf("\t%d", table->param);
			break;
		}
		break;

	default:
		break;
	}
	printf("\n");
}

static gint
compare_dissector_key_name(gconstpointer dissector_a, gconstpointer dissector_b)
{
  return strcmp((const char*)dissector_a, (const char*)dissector_b);
}

void
dissector_dump_dissector_tables(void)
{
	GList *list;

	list = g_hash_table_get_keys(dissector_tables);
	list = g_list_sort(list, compare_dissector_key_name);
	g_list_foreach(list, dissector_dump_dissector_tables_display, NULL);
	g_list_free(list);
}

static GPtrArray* post_dissectors = NULL;
static guint num_of_postdissectors = 0;

void
register_postdissector(dissector_handle_t handle)
{
	if (!post_dissectors)
		post_dissectors = g_ptr_array_new();

	g_ptr_array_add(post_dissectors, handle);
	num_of_postdissectors++;
}

void
deregister_postdissector(dissector_handle_t handle)
{
    if (!post_dissectors) return;

    if (g_ptr_array_remove(post_dissectors, handle)) {
        num_of_postdissectors--;
    }
}

gboolean
have_postdissector(void)
{
	guint i;
	dissector_handle_t handle;

	for(i = 0; i < num_of_postdissectors; i++) {
		handle = (dissector_handle_t) g_ptr_array_index(post_dissectors,i);

		if (handle->protocol != NULL
		    && proto_is_protocol_enabled(handle->protocol)) {
			/* We have at least one enabled postdissector */
			return TRUE;
		}
	}
	return FALSE;
}

void
call_all_postdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint i;

	for(i = 0; i < num_of_postdissectors; i++) {
		call_dissector_only((dissector_handle_t) g_ptr_array_index(post_dissectors,i),
				    tvb,pinfo,tree, NULL);
	}
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
