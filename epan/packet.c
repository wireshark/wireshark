/* packet.c
 * Routines for packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_EPAN

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

#include <epan/wmem_scopes.h>

#include <epan/column-info.h>
#include <epan/exceptions.h>
#include <epan/reassemble.h>
#include <epan/stream.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/range.h>

#include <wsutil/str_util.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>

static int proto_malformed;
static dissector_handle_t frame_handle;
static dissector_handle_t file_handle;
static dissector_handle_t data_handle;

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
 * table, true/false to indicate case-insensitive or not.
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
	bool	supports_decode_as;
};

/*
 * Dissector tables. const char * -> dissector_table *
 */
static GHashTable *dissector_tables;

/*
 * Dissector table aliases. const char * -> const char *
 */
static GHashTable *dissector_table_aliases;

/*
 * List of registered dissectors.
 */
static GHashTable *registered_dissectors;

/*
 * A dissector dependency list.
 */
struct depend_dissector_list {
	GSList		*dissectors;
};

/* Maps char *dissector_name to depend_dissector_list_t */
static GHashTable *depend_dissector_lists;

/* Allow protocols to register a "cleanup" routine to be
 * run after the initial sequential run through the packets.
 * Note that the file can still be open after this; this is not
 * the final cleanup. */
static GSList *postseq_cleanup_routines;

/*
 * Post-dissector information - handle for the dissector and a list
 * of hfids for the fields the post-dissector wants.
 */
typedef struct {
	dissector_handle_t handle;
	GArray *wanted_hfids;
} postdissector;

/*
 * Array of all postdissectors.
 */
static GArray *postdissectors;

/*
 * i-th element of that array.
 */
#define POSTDISSECTORS(i)	g_array_index(postdissectors, postdissector, i)

static void
destroy_depend_dissector_list(void *data)
{
	depend_dissector_list_t dissector_list = (depend_dissector_list_t)data;
	GSList **list = &(dissector_list->dissectors);

	g_slist_free_full(*list, g_free);
	g_slice_free(struct depend_dissector_list, dissector_list);
}

/*
 * A heuristics dissector list.
 */
struct heur_dissector_list {
	const char	*ui_name;
	protocol_t	*protocol;
	GSList		*dissectors;
};

static GHashTable *heur_dissector_lists;

/* Name hashtables for fast detection of duplicate names */
static GHashTable* heuristic_short_names;

static void
destroy_heuristic_dissector_entry(void *data)
{
	heur_dtbl_entry_t *hdtbl_entry = (heur_dtbl_entry_t *)data;
	g_free(hdtbl_entry->list_name);
	g_free(hdtbl_entry->short_name);
	g_slice_free(heur_dtbl_entry_t, data);
}

static void
destroy_heuristic_dissector_list(void *data)
{
	heur_dissector_list_t dissector_list = (heur_dissector_list_t)data;
	GSList **list = &(dissector_list->dissectors);

	g_slist_free_full(*list, destroy_heuristic_dissector_entry);
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

	dissector_table_aliases = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, NULL);

	registered_dissectors = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, NULL);

	depend_dissector_lists = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, destroy_depend_dissector_list);

	heur_dissector_lists = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, destroy_heuristic_dissector_list);

	heuristic_short_names  = g_hash_table_new(g_str_hash, g_str_equal);
}

void
packet_cache_proto_handles(void)
{
	frame_handle = find_dissector("frame");
	ws_assert(frame_handle != NULL);

	file_handle = find_dissector("file");
	ws_assert(file_handle != NULL);

	data_handle = find_dissector("data");
	ws_assert(data_handle != NULL);

	proto_malformed = proto_get_id_by_filter_name("_ws.malformed");
	ws_assert(proto_malformed != -1);
}

/* List of routines that are called before we make a pass through a capture file
 * and dissect all its packets. See register_init_routine, register_cleanup_routine
 * and register_shutdown_routine in packet.h */
/**
 * List of "init" routines, which are called before we make a pass through
 * a capture file and dissect all its packets (e.g., when we read in a
 * new capture file, or run a "filter packets" or "colorize packets"
 * pass over the current capture file or when the preferences are changed).
 *
 * See register_init_routine().
 */
static GSList *init_routines;

/**
 * List of "cleanup" routines, which are called after closing a capture
 * file (or when preferences are changed; in that case these routines
 * are called before the init routines are executed). They can be used
 * to release resources that are allocated in an "init" routine.
 *
 * See register_cleanup_routine().
 */
static GSList *cleanup_routines;

/*
 * List of "shutdown" routines, which are called once, just before
 * program exit.
 *
 * See register_shutdown_routine().
 */
static GSList *shutdown_routines;

typedef void (*void_func_t)(void);

/* Initialize all data structures used for dissection. */
static void
call_routine(void *routine, void *dummy _U_)
{
	void_func_t func = (void_func_t)routine;
	(*func)();
}

void
packet_cleanup(void)
{
	g_slist_free(init_routines);
	g_slist_free(cleanup_routines);
	g_slist_free(postseq_cleanup_routines);
	g_hash_table_destroy(dissector_tables);
	g_hash_table_destroy(dissector_table_aliases);
	g_hash_table_destroy(registered_dissectors);
	g_hash_table_destroy(depend_dissector_lists);
	g_hash_table_destroy(heur_dissector_lists);
	g_hash_table_destroy(heuristic_short_names);
	g_slist_foreach(shutdown_routines, &call_routine, NULL);
	g_slist_free(shutdown_routines);
	if (postdissectors) {
		for (unsigned i = 0; i < postdissectors->len; i++) {
			if (POSTDISSECTORS(i).wanted_hfids) {
				g_array_free(POSTDISSECTORS(i).wanted_hfids, true);
			}
		}
		g_array_free(postdissectors, true);
	}
}

/*
 * Given a tvbuff, and a length from a packet header, adjust the length
 * of the tvbuff to reflect the specified length.
 */
void
set_actual_length(tvbuff_t *tvb, const unsigned specified_len)
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

void
register_init_routine(void (*func)(void))
{
	init_routines = g_slist_prepend(init_routines, (void *)func);
}

void
register_cleanup_routine(void (*func)(void))
{
	cleanup_routines = g_slist_prepend(cleanup_routines, (void *)func);
}

/* register a new shutdown routine */
void
register_shutdown_routine(void (*func)(void))
{
	shutdown_routines = g_slist_prepend(shutdown_routines, (void *)func);
}

/* Initialize all data structures used for dissection. */
void
init_dissection(void)
{
	/*
	 * Reinitialize resolution information. Don't leak host entries from
	 * one file to another (e.g. embarrassing-host-name.example.com from
	 * file1.pcapng into a name resolution block in file2.pcapng).
	 */
	host_name_lookup_reset();

	wmem_enter_file_scope();

	/* Initialize the table of conversations. */
	epan_conversation_init();

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
	/* Cleanup protocol-specific variables. */
	g_slist_foreach(cleanup_routines, &call_routine, NULL);

	/* Cleanup the stream-handling tables */
	stream_cleanup();

	/* Cleanup the expert infos */
	expert_packet_cleanup();

	wmem_leave_file_scope();

	/*
	 * Keep the name resolution info around until we start the next
	 * dissection. Lua scripts may potentially do name resolution at
	 * any time, even if we're not dissecting and have no capture
	 * file open.
	 */
}

void
register_postseq_cleanup_routine(void_func_t func)
{
	postseq_cleanup_routines = g_slist_prepend(postseq_cleanup_routines,
			(void *)func);
}

/* Call all the registered "postseq_cleanup" routines. */
void
postseq_cleanup_all_protocols(void)
{
	g_slist_foreach(postseq_cleanup_routines,
			&call_routine, NULL);
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
	unsigned length = tvb_captured_length(src->tvb);

	return wmem_strdup_printf(NULL, "%s (%u byte%s)", src->name, length,
				plurality(length, "", "s"));
}

tvbuff_t *
get_data_source_tvb(const struct data_source *src)
{
	return src->tvb;
}

/*
 * Find and return the tvb associated with the given data source name
 */
tvbuff_t *
get_data_source_tvb_by_name(packet_info *pinfo, const char *name)
{
	GSList *source;
	for (source = pinfo->data_src; source; source = source->next) {
		struct data_source *this_source = (struct data_source *)source->data;
		if (this_source->name && strcmp(this_source->name, name) == 0) {
			return this_source->tvb;
		}
	}
	return NULL;
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
mark_frame_as_depended_upon(frame_data *fd, uint32_t frame_num)
{
	/* Don't mark a frame as dependent on itself */
	if (frame_num != fd->num) {
		/* ws_assert(frame_num < fd->num) - we assume in several other
		 * places in the code that frames don't depend on future
		 * frames. */
		if (fd->dependent_frames == NULL) {
			fd->dependent_frames = g_hash_table_new(g_direct_hash, g_direct_equal);
		}
		g_hash_table_add(fd->dependent_frames, GUINT_TO_POINTER(frame_num));
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
			(void *)func);
}

/* Call all the registered "final_registration" routines. */
void
final_registration_all_protocols(void)
{
	g_slist_foreach(final_registration_routines,
			&call_routine, NULL);
}


/* Creates the top-most tvbuff and calls dissect_frame() */
void
dissect_record(epan_dissect_t *edt, int file_type_subtype,
    wtap_rec *rec, tvbuff_t *tvb, frame_data *fd, column_info *cinfo)
{
	const char *volatile record_type;
	frame_data_t frame_dissector_data;

	switch (rec->rec_type) {

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

	case REC_TYPE_SYSTEMD_JOURNAL_EXPORT:
		record_type = "Systemd Journal Entry";
		break;

	case REC_TYPE_CUSTOM_BLOCK:
		switch (rec->rec_header.custom_block_header.pen) {
		case PEN_NFLX:
			record_type = "Black Box Log Block";
			break;
		default:
			record_type = "PCAPNG Custom Block";
			break;
		}
		break;

	default:
		/*
		 * XXX - if we add record types that shouldn't be
		 * dissected and displayed, but that need to at
		 * least be processed somewhere, we need to somehow
		 * indicate that to our caller.
		 */
		ws_assert_not_reached();
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
	/*
	 * XXX - this doesn't check the wtap_rec because, for
	 * some capture files, time stamps are supplied only
	 * when reading sequentially, so we keep the time stamp
	 * in the frame_data structure.
	 */
	if (fd->has_ts) {
		edt->pi.presence_flags |= PINFO_HAS_TS;
		edt->pi.abs_ts = fd->abs_ts;
	}
	switch (rec->rec_type) {

	case REC_TYPE_PACKET:
		edt->pi.pseudo_header = &rec->rec_header.packet_header.pseudo_header;
		break;

	case REC_TYPE_FT_SPECIFIC_EVENT:
	case REC_TYPE_FT_SPECIFIC_REPORT:
		edt->pi.pseudo_header = NULL;
		break;

	case REC_TYPE_SYSCALL:
		edt->pi.pseudo_header = NULL;
		break;

	case REC_TYPE_SYSTEMD_JOURNAL_EXPORT:
		edt->pi.pseudo_header = NULL;
		break;

	case REC_TYPE_CUSTOM_BLOCK:
		switch (rec->rec_header.custom_block_header.pen) {
		case PEN_NFLX:
			edt->pi.pseudo_header = NULL;
			break;
		default:
			edt->pi.pseudo_header = NULL;
			break;
		}
		break;

	}

	edt->pi.fd            = fd;
	edt->pi.rec           = rec;
	clear_address(&edt->pi.dl_src);
	clear_address(&edt->pi.dl_dst);
	clear_address(&edt->pi.net_src);
	clear_address(&edt->pi.net_dst);
	clear_address(&edt->pi.src);
	clear_address(&edt->pi.dst);
	edt->pi.noreassembly_reason = "";
	edt->pi.ptype = PT_NONE;
	edt->pi.use_conv_addr_port_endpoints = false;
	edt->pi.conv_addr_port_endpoints = NULL;
	edt->pi.conv_elements = NULL;
	edt->pi.p2p_dir = P2P_DIR_UNKNOWN;
	edt->pi.link_dir = LINK_DIR_UNKNOWN;
	edt->pi.src_win_scale = -1; /* unknown Rcv.Wind.Shift */
	edt->pi.dst_win_scale = -1; /* unknown Rcv.Wind.Shift */
	edt->pi.layers = wmem_list_new(edt->pi.pool);
	edt->tvb = tvb;

	frame_delta_abs_time(edt->session, fd, fd->frame_ref_num, &edt->pi.rel_ts);

	if (rec->ts_rel_cap_valid) {
		nstime_copy(&edt->pi.rel_cap_ts, &rec->ts_rel_cap);
		edt->pi.rel_cap_ts_present = true;
	}

	/*
	 * If the block has been modified, use the modified block,
	 * otherwise use the block from the file.
	 */
	if (fd->has_modified_block) {
		frame_dissector_data.pkt_block = epan_get_modified_block(edt->session, fd);
	}
	else {
		frame_dissector_data.pkt_block = rec->block;
	}
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
		ws_assert_not_reached();
	}
	CATCH2(FragmentBoundsError, ReportedBoundsError) {
		proto_tree_add_protocol_format(edt->tree, proto_malformed, edt->tvb, 0, 0,
					       "[Malformed %s: Packet Length]",
					       record_type);
	}
	ENDTRY;
	wtap_block_unref(rec->block);
	rec->block = NULL;

	fd->visited = 1;
}

/* Creates the top-most tvbuff and calls dissect_file() */
void
dissect_file(epan_dissect_t *edt, wtap_rec *rec,
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
	edt->pi.rec   = rec;
	edt->pi.pseudo_header = NULL;
	clear_address(&edt->pi.dl_src);
	clear_address(&edt->pi.dl_dst);
	clear_address(&edt->pi.net_src);
	clear_address(&edt->pi.net_dst);
	clear_address(&edt->pi.src);
	clear_address(&edt->pi.dst);
	edt->pi.noreassembly_reason = "";
	edt->pi.ptype = PT_NONE;
	edt->pi.use_conv_addr_port_endpoints = false;
	edt->pi.conv_addr_port_endpoints = NULL;
	edt->pi.conv_elements = NULL;
	edt->pi.p2p_dir = P2P_DIR_UNKNOWN;
	edt->pi.link_dir = LINK_DIR_UNKNOWN;
	edt->pi.layers = wmem_list_new(edt->pi.pool);
	edt->tvb = tvb;


	frame_delta_abs_time(edt->session, fd, fd->frame_ref_num, &edt->pi.rel_ts);


	TRY {
		/*
		 * If the block has been modified, use the modified block,
		 * otherwise use the block from the file.
		 */
		if (fd->has_modified_block) {
			file_dissector_data.pkt_block = epan_get_modified_block(edt->session, fd);
		}
		else {
			file_dissector_data.pkt_block = rec->block;
		}
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
		ws_assert_not_reached();
	}
	CATCH3(FragmentBoundsError, ContainedBoundsError, ReportedBoundsError) {
		proto_tree_add_protocol_format(edt->tree, proto_malformed, edt->tvb, 0, 0,
					       "[Malformed Record: Packet Length]");
	}
	ENDTRY;
	wtap_block_unref(rec->block);
	rec->block = NULL;

	fd->visited = 1;
}

/*********************** code added for sub-dissector lookup *********************/

enum dissector_e {
	DISSECTOR_TYPE_SIMPLE,
	DISSECTOR_TYPE_CALLBACK
};

/*
 * A dissector handle.
 */
struct dissector_handle {
	const char	*name;		/* dissector name */
	const char	*description;	/* dissector description */
	char            *pref_suffix;
	enum dissector_e dissector_type;
	union {
		dissector_t	dissector_type_simple;
		dissector_cb_t	dissector_type_callback;
	} dissector_func;
	void		*dissector_data;
	protocol_t	*protocol;
};

static void
add_layer(packet_info *pinfo, int proto_id)
{
	int *proto_layer_num_ptr;

	pinfo->curr_layer_num++;
	wmem_list_append(pinfo->layers, GINT_TO_POINTER(proto_id));

	/* Increment layer number for this proto id. */
	if (pinfo->proto_layers == NULL) {
		pinfo->proto_layers = wmem_map_new(pinfo->pool, g_direct_hash, g_direct_equal);
	}

	proto_layer_num_ptr = wmem_map_lookup(pinfo->proto_layers, GINT_TO_POINTER(proto_id));
	if (proto_layer_num_ptr == NULL) {
		/* Insert new layer */
		proto_layer_num_ptr = wmem_new(pinfo->pool, int);
		*proto_layer_num_ptr = 1;
		wmem_map_insert(pinfo->proto_layers, GINT_TO_POINTER(proto_id), proto_layer_num_ptr);
	}
	else {
		/* Increment layer number */
		(*proto_layer_num_ptr)++;
	}
	pinfo->curr_proto_layer_num = *proto_layer_num_ptr;
}

static void
remove_last_layer(packet_info *pinfo, bool reduce_count)
{
	int *proto_layer_num_ptr;
	wmem_list_frame_t *frame;
	int proto_id;

	if (reduce_count) {
		pinfo->curr_layer_num--;
	}

	frame = wmem_list_tail(pinfo->layers);
	proto_id = GPOINTER_TO_INT(wmem_list_frame_data(frame));
	wmem_list_remove_frame(pinfo->layers, frame);

	if (reduce_count) {
		/* Reduce count for removed protocol layer. */
		proto_layer_num_ptr = wmem_map_lookup(pinfo->proto_layers, GINT_TO_POINTER(proto_id));
		if (proto_layer_num_ptr && *proto_layer_num_ptr > 0) {
			(*proto_layer_num_ptr)--;
		}
	}

	/* Restore count for new last (protocol) layer. */
	frame = wmem_list_tail(pinfo->layers);
	if (frame) {
		proto_id = GPOINTER_TO_INT(wmem_list_frame_data(frame));
		proto_layer_num_ptr = wmem_map_lookup(pinfo->proto_layers, GINT_TO_POINTER(proto_id));
		ws_assert(proto_layer_num_ptr);
		pinfo->curr_proto_layer_num = *proto_layer_num_ptr;
	}
}


/* This function will return
 *   >0  this protocol was successfully dissected and this was this protocol.
 *   0   this packet did not match this protocol.
 *
 * XXX - if the dissector only dissects metadata passed through the data
 * pointer, and dissects none of the packet data, that's indistinguishable
 * from "packet did not match this protocol".  See issues #12366 and
 * #12368.
 */
static int
call_dissector_through_handle(dissector_handle_t handle, tvbuff_t *tvb,
			      packet_info *pinfo, proto_tree *tree, void *data)
{
	const char *saved_proto;
	int         len;

	saved_proto = pinfo->current_proto;

	if ((handle->protocol != NULL) && (!proto_is_pino(handle->protocol))) {
		pinfo->current_proto =
			proto_get_protocol_short_name(handle->protocol);
	}

	switch (handle->dissector_type) {

	case DISSECTOR_TYPE_SIMPLE:
		len = (handle->dissector_func.dissector_type_simple)(tvb, pinfo, tree, data);
		break;

	case DISSECTOR_TYPE_CALLBACK:
		len = (handle->dissector_func.dissector_type_callback)(tvb, pinfo, tree, data, handle->dissector_data);
		break;

	default:
		ws_assert_not_reached();
	}
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
call_dissector_work(dissector_handle_t handle, tvbuff_t *tvb, packet_info *pinfo,
		    proto_tree *tree, bool add_proto_name, void *data)
{
	const char  *saved_proto;
	uint16_t     saved_can_desegment;
	int          len;
	unsigned     saved_layers_len = 0;
	unsigned     saved_tree_count = tree ? tree->tree_data->count : 0;
	unsigned     saved_desegment_len = pinfo->desegment_len;
	bool         consumed_none;

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
	DISSECTOR_ASSERT(saved_layers_len < prefs.gui_max_tree_depth);

	/*
	 * can_desegment is set to 2 by anyone which offers the
	 * desegmentation api/service.
	 * Then every time a subdissector is called it is decremented
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
	if ((handle->protocol != NULL) && (!proto_is_pino(handle->protocol))) {
		pinfo->current_proto =
			proto_get_protocol_short_name(handle->protocol);

		/*
		 * Add the protocol name to the layers only if told to
		 * do so. Asn2wrs generated dissectors may be added
		 * multiple times otherwise.
		 */
		/* XXX Should we check for a duplicate layer here? */
		if (add_proto_name) {
			add_layer(pinfo, proto_get_id(handle->protocol));
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
	consumed_none = len == 0 || (pinfo->desegment_len != saved_desegment_len && pinfo->desegment_offset == 0);
	/* If len == 0, then the dissector didn't accept the packet.
	 * In the latter case, the dissector accepted the packet, but didn't
	 * consume any bytes because they all belong in a later segment.
	 * In the latter case, we probably won't call a dissector here again
	 * on the next pass, so removing the layer keeps any *further* layers
	 * past this one the same on subsequent passes.
	 *
	 * XXX: DISSECTOR_ASSERT that the tree count didn't change? If the
	 * dissector didn't consume any bytes but added items to the tree,
	 * that's improper behavior and needs a rethink. We could also move the
	 * test that the packet didn't change desegment_offset and desegment_len
	 * while rejecting the packet from packet-tcp.c decode_tcp_ports to here.
	 */
	if (handle->protocol != NULL && !proto_is_pino(handle->protocol) && add_proto_name &&
		(consumed_none || (tree && saved_tree_count == tree->tree_data->count))) {
		/*
		 * We've added a layer and either the dissector didn't
		 * consume any data or we didn't add any items to the
		 * tree. Remove it.
		 */
		while (wmem_list_count(pinfo->layers) > saved_layers_len) {
			/*
			 * Only reduce the layer number if the dissector didn't
			 * consume any data. Since tree can be NULL on
			 * the first pass, we cannot check it or it will
			 * break dissectors that rely on a stable value.
			 */
			remove_last_layer(pinfo, consumed_none);
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
	uint16_t      saved_can_desegment;
	volatile int  len = 0;
	bool          save_writable;
	address       save_dl_src;
	address       save_dl_dst;
	address       save_net_src;
	address       save_net_dst;
	address       save_src;
	address       save_dst;
	uint32_t	      save_ptype;
	uint32_t	      save_srcport;
	uint32_t	      save_destport;

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
	col_set_writable(pinfo->cinfo, -1, false);
	copy_address_shallow(&save_dl_src, &pinfo->dl_src);
	copy_address_shallow(&save_dl_dst, &pinfo->dl_dst);
	copy_address_shallow(&save_net_src, &pinfo->net_src);
	copy_address_shallow(&save_net_dst, &pinfo->net_dst);
	copy_address_shallow(&save_src, &pinfo->src);
	copy_address_shallow(&save_dst, &pinfo->dst);
	save_ptype = pinfo->ptype;
	save_srcport = pinfo->srcport;
	save_destport = pinfo->destport;

	/* Dissect the contained packet. */
	TRY {
		len = call_dissector_through_handle(handle, tvb,pinfo, tree, data);
	}
	CATCH(BoundsError) {
		/*
		* Restore the column writability and addresses and ports.
		*/
		col_set_writable(pinfo->cinfo, -1, save_writable);
		copy_address_shallow(&pinfo->dl_src, &save_dl_src);
		copy_address_shallow(&pinfo->dl_dst, &save_dl_dst);
		copy_address_shallow(&pinfo->net_src, &save_net_src);
		copy_address_shallow(&pinfo->net_dst, &save_net_dst);
		copy_address_shallow(&pinfo->src, &save_src);
		copy_address_shallow(&pinfo->dst, &save_dst);
		pinfo->ptype = save_ptype;
		pinfo->srcport = save_srcport;
		pinfo->destport = save_destport;

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
	CATCH3(FragmentBoundsError, ContainedBoundsError, ReportedBoundsError) {
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
	pinfo->ptype = save_ptype;
	pinfo->srcport = save_srcport;
	pinfo->destport = save_destport;
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
	dissector_table_t dissector_table = (dissector_table_t) g_hash_table_lookup(dissector_tables, name);
	if (! dissector_table) {
		const char *new_name = (const char *) g_hash_table_lookup(dissector_table_aliases, name);
		if (new_name) {
			dissector_table = (dissector_table_t) g_hash_table_lookup(dissector_tables, new_name);
		}
		if (dissector_table) {
			ws_warning("%s is now %s", name, new_name);
		}
	}
	return dissector_table;
}

/* Find an entry in a uint dissector table. */
static dtbl_entry_t *
find_uint_dtbl_entry(dissector_table_t sub_dissectors, const uint32_t pattern)
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
	case FT_NONE:
		/* For now treat as uint */
		break;

	default:
		/*
		 * But you can't do a uint lookup in any other types
		 * of tables.
		 */
		ws_assert_not_reached();
	}

	/*
	 * Find the entry.
	 */
	return (dtbl_entry_t *)g_hash_table_lookup(sub_dissectors->hash_table,
				   GUINT_TO_POINTER(pattern));
}

#if 0
static void
dissector_add_uint_sanity_check(const char *name, uint32_t pattern, dissector_handle_t handle, dissector_table_t sub_dissectors)
{
	dtbl_entry_t *dtbl_entry;

	if (pattern == 0) {
		ws_warning("%s: %s registering using a pattern of 0",
			  name, proto_get_protocol_filter_name(proto_get_id(handle->protocol)));
	}

	dtbl_entry = g_hash_table_lookup(sub_dissectors->hash_table, GUINT_TO_POINTER(pattern));
	if (dtbl_entry != NULL) {
		ws_warning("%s: %s registering using pattern %d already registered by %s",
			  name, proto_get_protocol_filter_name(proto_get_id(handle->protocol)),
			  pattern, proto_get_protocol_filter_name(proto_get_id(dtbl_entry->initial->protocol)));
	}
}
#endif

/* Add an entry to a uint dissector table. */
void
dissector_add_uint(const char *name, const uint32_t pattern, dissector_handle_t handle)
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
		if (wireshark_abort_on_dissector_bug)
			abort();
		return;
	}
	if (sub_dissectors == NULL) {
		fprintf(stderr, "OOPS: dissector table \"%s\" doesn't exist\n",
		    name);
		fprintf(stderr, "Protocol being registered is \"%s\"\n",
		    proto_get_protocol_long_name(handle->protocol));
		if (wireshark_abort_on_dissector_bug)
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
		ws_assert_not_reached();
	}

#if 0
	dissector_add_uint_sanity_check(name, pattern, handle, sub_dissectors);
#endif

	dtbl_entry = g_new(dtbl_entry_t, 1);
	dtbl_entry->current = handle;
	dtbl_entry->initial = dtbl_entry->current;

	/* do the table insertion */
	g_hash_table_insert(sub_dissectors->hash_table,
			     GUINT_TO_POINTER(pattern), (void *)dtbl_entry);

	/*
	 * Now, if this table supports "Decode As", add this handle
	 * to the list of handles that could be used for "Decode As"
	 * with this table, because it *is* being used with this table.
	 */
	if (sub_dissectors->supports_decode_as)
		dissector_add_for_decode_as(name, handle);
}



void dissector_add_uint_range(const char *name, range_t *range,
			      dissector_handle_t handle)
{
	dissector_table_t  sub_dissectors;
	uint32_t i, j;

	if (range) {
		if (range->nranges == 0) {
			/*
			 * Even an empty range would want a chance for
			 * Decode As, if the dissector table supports
			 * it.
			 */
			sub_dissectors = find_dissector_table(name);
			if (sub_dissectors->supports_decode_as)
				dissector_add_for_decode_as(name, handle);
		}
		else {
			for (i = 0; i < range->nranges; i++) {
				for (j = range->ranges[i].low; j < range->ranges[i].high; j++)
					dissector_add_uint(name, j, handle);
				dissector_add_uint(name, range->ranges[i].high, handle);
			}
		}
	}
}

static range_t*
dissector_add_range_preference(const char *name, dissector_handle_t handle, const char* range_str)
{
	range_t** range;
	module_t *module;
	char *description, *title;
	dissector_table_t  pref_dissector_table = find_dissector_table(name);
	int proto_id = proto_get_id(handle->protocol);
	uint32_t max_value = 0;

	/* If a dissector is added for Decode As only, it's dissector
		table value would default to 0.
		Set up a preference value with that information
	 */
	range = wmem_new0(wmem_epan_scope(), range_t*);

	/* If the dissector's protocol already has a preference module, use it */
	const char* module_name = proto_get_protocol_filter_name(proto_id);
	module = prefs_find_module(module_name);
	if (module == NULL) {
		/* Otherwise create a new one */
		module = prefs_register_protocol(proto_id, NULL);
	}

	const char *fullname = wmem_strdup_printf(wmem_epan_scope(), "%s%s", name, dissector_handle_get_pref_suffix(handle));

	/* Some preference callback functions use the proto_reg_handoff_
		routine to apply preferences, which could duplicate the
		registration of a preference.  Check for that here */
	if (prefs_find_preference(module, fullname) == NULL) {
		const char *handle_desc = dissector_handle_get_description(handle);
		if (g_strcmp0(range_str, "") > 0) {
			description = wmem_strdup_printf(wmem_epan_scope(), "%s %s(s) (default: %s)",
									    handle_desc, pref_dissector_table->ui_name, range_str);
		} else {
			description = wmem_strdup_printf(wmem_epan_scope(), "%s %s(s)",
									    handle_desc, pref_dissector_table->ui_name);
		}
		title = wmem_strdup_printf(wmem_epan_scope(), "%s %s(s)", handle_desc, pref_dissector_table->ui_name);

		/* Max value is based on datatype of dissector table */
		switch (pref_dissector_table->type) {

		case FT_UINT8:
			max_value = 0xFF;
			break;
		case FT_UINT16:
			max_value = 0xFFFF;
			break;
		case FT_UINT24:
			max_value = 0xFFFFFF;
			break;
		case FT_UINT32:
			max_value = 0xFFFFFFFF;
			break;

		default:
			ws_error("The dissector table %s (%s) is not an integer type - are you using a buggy plugin?", name, pref_dissector_table->ui_name);
			ws_assert_not_reached();
		}

		range_convert_str(wmem_epan_scope(), range, range_str, max_value);
		prefs_register_decode_as_range_preference(module, fullname, title, description, range, max_value, name, handle_desc);
	}

	return *range;
}

void dissector_add_uint_with_preference(const char *name, const uint32_t pattern,
    dissector_handle_t handle)
{
	char* range_str;

	range_str = wmem_strdup_printf(NULL, "%d", pattern);
	dissector_add_range_preference(name, handle, range_str);
	wmem_free(NULL, range_str);
	dissector_add_uint(name, pattern, handle);
}

void dissector_add_uint_range_with_preference(const char *name, const char* range_str,
    dissector_handle_t handle)
{
	range_t* range;

	range = dissector_add_range_preference(name, handle, range_str);
	dissector_add_uint_range(name, range, handle);
}

/* Delete the entry for a dissector in a uint dissector table
   with a particular pattern. */

/* NOTE: this doesn't use the dissector call variable. It is included to */
/*	be consistent with the dissector_add_uint and more importantly to be used */
/*	if the technique of adding a temporary dissector is implemented.  */
/*	If temporary dissectors are deleted, then the original dissector must */
/*	be available. */
void
dissector_delete_uint(const char *name, const uint32_t pattern,
	dissector_handle_t handle _U_)
{
	dissector_table_t sub_dissectors = find_dissector_table(name);
	dtbl_entry_t *dtbl_entry;

	/* sanity check */
	ws_assert(sub_dissectors);

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

void dissector_delete_uint_range(const char *name, range_t *range,
				 dissector_handle_t handle)
{
	uint32_t i, j;

	if (range) {
		for (i = 0; i < range->nranges; i++) {
			for (j = range->ranges[i].low; j < range->ranges[i].high; j++)
				dissector_delete_uint(name, j, handle);
			dissector_delete_uint(name, range->ranges[i].high, handle);
		}
	}
}

/* Remove an entry from a guid dissector table. */
void dissector_delete_guid(const char *name, guid_key* guid_val, dissector_handle_t handle)
{
	dissector_table_t  sub_dissectors;
	dtbl_entry_t      *dtbl_entry;

	sub_dissectors = find_dissector_table(name);

	/* sanity check */
	ws_assert(sub_dissectors);

	/* Find the table entry */
	dtbl_entry = (dtbl_entry_t *)g_hash_table_lookup(sub_dissectors->hash_table, guid_val);

	if (dtbl_entry == NULL) {
		fprintf(stderr, "OOPS: guid not found in dissector table \"%s\"\n", name);
		return;
	}

	/* Make sure the handles match */
	if (dtbl_entry->current != handle) {
		fprintf(stderr, "OOPS: handle does not match for guid in dissector table \"%s\"\n", name);
		return;
	}

	/* Remove the table entry */
	g_hash_table_remove(sub_dissectors->hash_table, guid_val);
}


static gboolean
dissector_delete_all_check (void *key _U_, void *value, void *user_data)
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
	ws_assert (sub_dissectors);

	g_hash_table_foreach_remove (sub_dissectors->hash_table, dissector_delete_all_check, handle);
}

static void
dissector_delete_from_table(gpointer key _U_, gpointer value, gpointer user_data)
{
	dissector_table_t sub_dissectors = (dissector_table_t) value;
	ws_assert (sub_dissectors);

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
dissector_change_uint(const char *name, const uint32_t pattern, dissector_handle_t handle)
{
	dissector_table_t sub_dissectors = find_dissector_table(name);
	dtbl_entry_t *dtbl_entry;

	/* sanity check */
	ws_assert(sub_dissectors);

	/*
	 * See if the entry already exists. If so, reuse it.
	 */
	dtbl_entry = find_uint_dtbl_entry(sub_dissectors, pattern);
	if (dtbl_entry != NULL) {
		/*
		 * If there's no initial value, and the user said not
		 * to decode it, just remove the entry to save memory.
		 */
		if (handle == NULL && dtbl_entry->initial == NULL) {
			g_hash_table_remove(sub_dissectors->hash_table,
					    GUINT_TO_POINTER(pattern));
			return;
		}
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

	dtbl_entry = g_new(dtbl_entry_t, 1);
	dtbl_entry->initial = NULL;
	dtbl_entry->current = handle;

	/* do the table insertion */
	g_hash_table_insert(sub_dissectors->hash_table,
			     GUINT_TO_POINTER(pattern), (void *)dtbl_entry);
}

/* Reset an entry in a uint dissector table to its initial value. */
void
dissector_reset_uint(const char *name, const uint32_t pattern)
{
	dissector_table_t  sub_dissectors = find_dissector_table(name);
	dtbl_entry_t      *dtbl_entry;

	/* sanity check */
	ws_assert(sub_dissectors);

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

/* Return true if an entry in a uint dissector table is found and has been
 * changed (i.e. dissector_change_uint() has been called, such as from
 * Decode As, prefs registered via dissector_add_uint_[range_]with_preference),
 * etc.), otherwise return false.
 */
bool
dissector_is_uint_changed(dissector_table_t const sub_dissectors, const uint32_t uint_val)
{
	if (sub_dissectors != NULL) {
		dtbl_entry_t *dtbl_entry = find_uint_dtbl_entry(sub_dissectors, uint_val);
		if (dtbl_entry != NULL)
			return (dtbl_entry->current != dtbl_entry->initial);
	}
	return false;
}

/* Look for a given value in a given uint dissector table and, if found,
   call the dissector with the arguments supplied, and return the number
   of bytes consumed by the dissector, otherwise return 0. */

int
dissector_try_uint_new(dissector_table_t sub_dissectors, const uint32_t uint_val,
		       tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		       const bool add_proto_name, void *data)
{
	dtbl_entry_t            *dtbl_entry;
	struct dissector_handle *handle;
	uint32_t                 saved_match_uint;
	int len;

	dtbl_entry = find_uint_dtbl_entry(sub_dissectors, uint_val);
	if (dtbl_entry == NULL) {
		/*
		 * There's no entry in the table for our value.
		 */
		return 0;
	}

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

int
dissector_try_uint(dissector_table_t sub_dissectors, const uint32_t uint_val,
		   tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	return dissector_try_uint_new(sub_dissectors, uint_val, tvb, pinfo, tree, true, NULL);
}

/* Look for a given value in a given uint dissector table and, if found,
   return the dissector handle for that value. */
dissector_handle_t
dissector_get_uint_handle(dissector_table_t const sub_dissectors, const uint32_t uint_val)
{
	dtbl_entry_t *dtbl_entry;

	dtbl_entry = find_uint_dtbl_entry(sub_dissectors, uint_val);
	if (dtbl_entry != NULL)
		return dtbl_entry->current;
	else
		return NULL;
}

dissector_handle_t
dissector_get_default_uint_handle(const char *name, const uint32_t uint_val)
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
find_string_dtbl_entry(dissector_table_t const sub_dissectors, const char *pattern)
{
	dtbl_entry_t *ret;
	char *key;

	switch (sub_dissectors->type) {

	case FT_STRING:
	case FT_STRINGZ:
	case FT_STRINGZPAD:
	case FT_STRINGZTRUNC:
		/*
		 * You can do a string lookup in these tables.
		 */
		break;

	default:
		/*
		 * But you can't do a string lookup in any other types
		 * of tables.
		 */
		ws_assert_not_reached();
	}

	if (sub_dissectors->param == STRING_CASE_INSENSITIVE) {
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
dissector_add_string(const char *name, const char *pattern,
		     dissector_handle_t handle)
{
	dissector_table_t  sub_dissectors = find_dissector_table(name);
	dtbl_entry_t      *dtbl_entry;
	char *key;

	/*
	 * Make sure the handle and the dissector table exist.
	 */
	if (handle == NULL) {
		fprintf(stderr, "OOPS: handle to register \"%s\" to doesn't exist\n",
		    name);
		if (wireshark_abort_on_dissector_bug)
			abort();
		return;
	}
	if (sub_dissectors == NULL) {
		fprintf(stderr, "OOPS: dissector table \"%s\" doesn't exist\n",
		    name);
		fprintf(stderr, "Protocol being registered is \"%s\"\n",
		    proto_get_protocol_long_name(handle->protocol));
		if (wireshark_abort_on_dissector_bug)
			abort();
		return;
	}

	switch (sub_dissectors->type) {

	case FT_STRING:
	case FT_STRINGZ:
	case FT_STRINGZPAD:
	case FT_STRINGZTRUNC:
		/*
		 * You can do a string lookup in these tables.
		 */
		break;

	default:
		/*
		 * But you can't do a string lookup in any other types
		 * of tables.
		 */
		ws_assert_not_reached();
	}

	dtbl_entry = g_new(dtbl_entry_t, 1);
	dtbl_entry->current = handle;
	dtbl_entry->initial = dtbl_entry->current;

	if (sub_dissectors->param == STRING_CASE_INSENSITIVE) {
		key = g_ascii_strdown(pattern, -1);
	} else {
		key = g_strdup(pattern);
	}

	/* do the table insertion */
	g_hash_table_insert(sub_dissectors->hash_table, (void *)key,
			     (void *)dtbl_entry);

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
/*	be consistent with the dissector_add_string and more importantly to */
/*      be used if the technique of adding a temporary dissector is */
/*      implemented.  */
/*	If temporary dissectors are deleted, then the original dissector must */
/*	be available. */
void
dissector_delete_string(const char *name, const char *pattern,
	dissector_handle_t handle _U_)
{
	dissector_table_t  sub_dissectors = find_dissector_table(name);
	dtbl_entry_t      *dtbl_entry;

	/* sanity check */
	ws_assert(sub_dissectors);

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
dissector_change_string(const char *name, const char *pattern,
			dissector_handle_t handle)
{
	dissector_table_t  sub_dissectors = find_dissector_table(name);
	dtbl_entry_t      *dtbl_entry;

	/* sanity check */
	ws_assert(sub_dissectors);

	/*
	 * See if the entry already exists. If so, reuse it.
	 */
	dtbl_entry = find_string_dtbl_entry(sub_dissectors, pattern);
	if (dtbl_entry != NULL) {
		/*
		 * If there's no initial value, and the user said not
		 * to decode it, just remove the entry to save memory.
		 */
		if (handle == NULL && dtbl_entry->initial == NULL) {
			g_hash_table_remove(sub_dissectors->hash_table,
					    pattern);
			return;
		}
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

	dtbl_entry = g_new(dtbl_entry_t, 1);
	dtbl_entry->initial = NULL;
	dtbl_entry->current = handle;

	/* do the table insertion */
	g_hash_table_insert(sub_dissectors->hash_table, (void *)g_strdup(pattern),
			     (void *)dtbl_entry);
}

/* Reset an entry in a string sub-dissector table to its initial value. */
void
dissector_reset_string(const char *name, const char *pattern)
{
	dissector_table_t  sub_dissectors = find_dissector_table(name);
	dtbl_entry_t      *dtbl_entry;

	/* sanity check */
	ws_assert(sub_dissectors);

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

/* Return true if an entry in a uint dissector table is found and has been
 * changed (i.e. dissector_change_uint() has been called, such as from
 * Decode As, prefs registered via dissector_add_uint_[range_]with_preference),
 * etc.), otherwise return false.
 */
bool
dissector_is_string_changed(dissector_table_t const sub_dissectors, const char *string)
{
	if (sub_dissectors != NULL) {
		dtbl_entry_t *dtbl_entry = find_string_dtbl_entry(sub_dissectors, string);
		if (dtbl_entry != NULL)
			return (dtbl_entry->current != dtbl_entry->initial);
	}
	return false;
}

/* Look for a given string in a given dissector table and, if found, call
   the dissector with the arguments supplied, and return length of dissected data,
   otherwise return 0. */
int
dissector_try_string_new(dissector_table_t sub_dissectors, const char *string,
		     tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const bool add_proto_name, void *data)
{
	dtbl_entry_t            *dtbl_entry;
	struct dissector_handle *handle;
	int                      len;
	const char              *saved_match_string;

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
		len = call_dissector_work(handle, tvb, pinfo, tree, add_proto_name, data);
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

int
dissector_try_string(dissector_table_t sub_dissectors, const char *string,
		     tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	return dissector_try_string_new(sub_dissectors, string, tvb, pinfo, tree, true, data);
}

/* Look for a given value in a given string dissector table and, if found,
   return the dissector handle for that value. */
dissector_handle_t
dissector_get_string_handle(dissector_table_t sub_dissectors,
			    const char *string)
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
dissector_get_default_string_handle(const char *name, const char *string)
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
	dissector_table_t  sub_dissectors = find_dissector_table(name);
	dtbl_entry_t      *dtbl_entry;

	/*
	 * Make sure the handle and the dissector table exist.
	 */
	if (handle == NULL) {
		fprintf(stderr, "OOPS: handle to register \"%s\" to doesn't exist\n",
		    name);
		if (wireshark_abort_on_dissector_bug)
			abort();
		return;
	}
	if (sub_dissectors == NULL) {
		fprintf(stderr, "OOPS: dissector table \"%s\" doesn't exist\n",
		    name);
		fprintf(stderr, "Protocol being registered is \"%s\"\n",
		    proto_get_protocol_long_name(handle->protocol));
		if (wireshark_abort_on_dissector_bug)
			abort();
		return;
	}

	ws_assert(sub_dissectors->type == FT_BYTES);

	dtbl_entry = g_new(dtbl_entry_t, 1);
	dtbl_entry->current = handle;
	dtbl_entry->initial = dtbl_entry->current;

	/* do the table insertion */
	g_hash_table_insert(sub_dissectors->hash_table, (void *)pattern,
			     (void *)dtbl_entry);

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
		if (wireshark_abort_on_dissector_bug)
			abort();
		return;
	}
	if (sub_dissectors == NULL) {
		fprintf(stderr, "OOPS: dissector table \"%s\" doesn't exist\n",
		    name);
		fprintf(stderr, "Protocol being registered is \"%s\"\n",
		    proto_get_protocol_long_name(handle->protocol));
		if (wireshark_abort_on_dissector_bug)
			abort();
		return;
	}

	if (sub_dissectors->type != FT_GUID) {
		ws_assert_not_reached();
	}

	dtbl_entry = g_new(dtbl_entry_t, 1);
	dtbl_entry->current = handle;
	dtbl_entry->initial = dtbl_entry->current;

	/* do the table insertion */
	g_hash_table_insert(sub_dissectors->hash_table,
			     guid_val, (void *)dtbl_entry);

	/*
	 * Now, if this table supports "Decode As", add this handle
	 * to the list of handles that could be used for "Decode As"
	 * with this table, because it *is* being used with this table.
	 */
	if (sub_dissectors->supports_decode_as)
		dissector_add_for_decode_as(name, handle);
}

/* Look for a given value in a given guid dissector table and, if found,
   call the dissector with the arguments supplied, and return true,
   otherwise return false. */
int dissector_try_guid_new(dissector_table_t sub_dissectors,
    guid_key* guid_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const bool add_proto_name, void *data)
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
	return dissector_try_guid_new(sub_dissectors, guid_val, tvb, pinfo, tree, true, NULL);
}

/** Look for a given value in a given guid dissector table and, if found,
 * return the current dissector handle for that value.
 *
 * @param[in] sub_dissectors Dissector table to search.
 * @param[in] guid_val Value to match.
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

/* Use the currently assigned payload dissector for the dissector table and,
   if any, call the dissector with the arguments supplied, and return the
   number of bytes consumed, otherwise return 0. */
int dissector_try_payload(dissector_table_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissector_try_uint(sub_dissectors, 0, tvb, pinfo, tree);
}

/* Use the currently assigned payload dissector for the dissector table and,
   if any, call the dissector with the arguments supplied, and return the
   number of bytes consumed, otherwise return 0. */
int dissector_try_payload_new(dissector_table_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const bool add_proto_name, void *data)
{
	return dissector_try_uint_new(sub_dissectors, 0, tvb, pinfo, tree, add_proto_name, data);
}

/* Change the entry for a dissector in a payload (FT_NONE) dissector table
   with a particular pattern to use a new dissector handle. */
void dissector_change_payload(const char *name, dissector_handle_t handle)
{
	dissector_change_uint(name, 0, handle);
}

/* Reset payload (FT_NONE) dissector table to its initial value. */
void dissector_reset_payload(const char *name)
{
	dissector_reset_uint(name, 0);
}

/* Given a payload dissector table (type FT_NONE), return the handle of
   the dissector that is currently active, i.e. that was selected via
   Decode As. */
dissector_handle_t
dissector_get_payload_handle(dissector_table_t const dissector_table)
{
	return dissector_get_uint_handle(dissector_table, 0);
}

dissector_handle_t
dtbl_entry_get_handle (dtbl_entry_t *dtbl_entry)
{
	return dtbl_entry->current;
}

static int
dissector_compare_filter_name(const void *dissector_a, const void *dissector_b)
{
	const struct dissector_handle *a = (const struct dissector_handle *)dissector_a;
	const struct dissector_handle *b = (const struct dissector_handle *)dissector_b;
	const char *a_name, *b_name;
	int ret;

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
	dissector_table_t  sub_dissectors = find_dissector_table(name);
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
		if (wireshark_abort_on_dissector_bug)
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
		if (wireshark_abort_on_dissector_bug)
			abort();
		return;
	}

	/* Add the dissector as a dependency
	  (some dissector tables don't have protocol association, so there is
	  the need for the NULL check */
	if (sub_dissectors->protocol != NULL)
		register_depend_dissector(proto_get_protocol_short_name(sub_dissectors->protocol), proto_get_protocol_short_name(handle->protocol));

	/* Is it already in this list? */
	entry = g_slist_find(sub_dissectors->dissector_handles, (void *)handle);
	if (entry != NULL) {
		/*
		 * Yes - don't insert it again.
		 */
		return;
	}

	/* Ensure the dissector's description is unique.  This prevents
	   confusion when using Decode As; duplicate descriptions would
	   make it impossible to distinguish between the dissectors
	   with the same descriptions.

	   FT_STRING can at least show the string value in the dialog,
	   so we don't do the check for them. XXX - ? It can show the
	   string value the dissector is being set to, but can't distinguish
	   the dissectors. See the Decode As table for Internet media types
	   (which packet-obex.c adds.)

	 */
	const char *dissector_name;
	dissector_name = dissector_handle_get_dissector_name(handle);

	if (sub_dissectors->type != FT_STRING)
	{
		for (entry = sub_dissectors->dissector_handles; entry != NULL; entry = g_slist_next(entry))
		{
			dup_handle = (dissector_handle_t)entry->data;
			if (dup_handle->description != NULL &&
			    strcmp(dup_handle->description, handle->description) == 0)
			{
				const char *dup_dissector_name;

				dup_dissector_name = dissector_handle_get_dissector_name(dup_handle);
				if (dup_dissector_name == NULL)
					dup_dissector_name = "(anonymous)";
				fprintf(stderr, "Dissectors %s and %s in dissector table %s have the same description %s\n",
				    dissector_name ? dissector_name : "(anonymous)",
				    dup_dissector_name,
				    name, handle->description);
				if (wireshark_abort_on_dissector_bug)
					abort();
			}
		}
	}

	/* We support adding automatic Decode As preferences on 32-bit
	 * integer tables. Make sure that the preference we would generate has
	 * a unique name. That means that for a given table's entries, each
	 * dissector handle for the same protocol must have a unique pref suffix.
	 */
	if (FT_IS_UINT32(sub_dissectors->type)) {
		const char* pref_suffix = dissector_handle_get_pref_suffix(handle);
		for (entry = sub_dissectors->dissector_handles; entry != NULL; entry = g_slist_next(entry))
		{
			dup_handle = (dissector_handle_t)entry->data;
			if (handle->protocol != dup_handle->protocol) {
				continue;
			}
			if (g_strcmp0(pref_suffix, dissector_handle_get_pref_suffix(dup_handle)) == 0)
			{
				const char *dup_dissector_name;
				dup_dissector_name = dissector_handle_get_dissector_name(dup_handle);
				if (dup_dissector_name == NULL) {
					dup_dissector_name = "(anonymous)";
					fprintf(stderr, "Dissector for %s is anonymous", proto_get_protocol_short_name(dup_handle->protocol));
				}
				fprintf(stderr, "Dissectors %s and %s in dissector table %s would have the same Decode As preference\n",
				    dissector_name ? dissector_name : "(anonymous)",
				    dup_dissector_name,
				    name);
				if (wireshark_abort_on_dissector_bug)
					abort();
			}
		}
	}

	/* Add it to the list. */
	sub_dissectors->dissector_handles =
		g_slist_insert_sorted(sub_dissectors->dissector_handles, (void *)handle, (GCompareFunc)dissector_compare_filter_name);
}

void dissector_add_for_decode_as_with_preference(const char *name,
    dissector_handle_t handle)
{
	/* If a dissector is added for Decode As only, it's dissector
	   table value would default to 0.
	   Set up a preference value with that information
	 */
	dissector_add_range_preference(name, handle, "");

	dissector_add_for_decode_as(name, handle);
}

dissector_handle_t
dtbl_entry_get_initial_handle (dtbl_entry_t *dtbl_entry)
{
	return dtbl_entry->initial;
}

GSList *
dissector_table_get_dissector_handles(dissector_table_t dissector_table) {
	if (!dissector_table)
		return NULL;

	return dissector_table->dissector_handles;
}

/*
 * Data structure used as user data when iterating dissector handles
 */
typedef struct lookup_entry {
	const char* dissector_description;
	dissector_handle_t handle;
} lookup_entry_t;

/*
 * A callback function to changed a dissector_handle if matched
 * This is used when iterating a dissector table
 */
static void
find_dissector_in_table(void *item, void *user_data)
{
	dissector_handle_t handle = (dissector_handle_t)item;
	lookup_entry_t * lookup = (lookup_entry_t *)user_data;
	const char *description = dissector_handle_get_description(handle);
	if (description && strcmp(lookup->dissector_description, description) == 0) {
		lookup->handle = handle;
	}
}

dissector_handle_t dissector_table_get_dissector_handle(dissector_table_t dissector_table, const char* description)
{
	lookup_entry_t lookup;

	lookup.dissector_description = description;
	lookup.handle = NULL;

	g_slist_foreach(dissector_table->dissector_handles, find_dissector_in_table, &lookup);
	return lookup.handle;
}

ftenum_t
dissector_table_get_type(dissector_table_t dissector_table) {
	if (!dissector_table) return FT_NONE;
	return dissector_table->type;
}

void
dissector_table_allow_decode_as(dissector_table_t dissector_table)
{
	dissector_table->supports_decode_as = true;
}

bool
dissector_table_supports_decode_as(dissector_table_t dissector_table)
{
	return dissector_table->supports_decode_as;
}

static int
uuid_equal(const void *k1, const void *k2)
{
	const guid_key *key1 = (const guid_key *)k1;
	const guid_key *key2 = (const guid_key *)k2;
	return ((memcmp(&key1->guid, &key2->guid, sizeof (e_guid_t)) == 0)
		&& (key1->ver == key2->ver));
}

static unsigned
uuid_hash(const void *k)
{
	const guid_key *key = (const guid_key *)k;
	/* This isn't perfect, but the Data1 part of these is almost always unique. */
	return key->guid.data1;
}

/**************************************************/
/*                                                */
/*       Routines to walk dissector tables        */
/*                                                */
/**************************************************/

typedef struct dissector_foreach_info {
	void *        caller_data;
	DATFunc       caller_func;
	GHFunc        next_func;
	const char   *table_name;
	ftenum_t      selector_type;
} dissector_foreach_info_t;

/*
 * Called for each entry in a dissector table.
 */
static void
dissector_table_foreach_func (void *key, void *value, void *user_data)
{
	dissector_foreach_info_t *info;
	dtbl_entry_t             *dtbl_entry;

	ws_assert(value);
	ws_assert(user_data);

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
dissector_all_tables_foreach_func (void *key, void *value, void *user_data)
{
	dissector_table_t         sub_dissectors;
	dissector_foreach_info_t *info;

	ws_assert(value);
	ws_assert(user_data);

	sub_dissectors = (dissector_table_t)value;
	info = (dissector_foreach_info_t *)user_data;
	info->table_name = (char*) key;
	info->selector_type = get_dissector_table_selector_type(info->table_name);
	g_hash_table_foreach(sub_dissectors->hash_table, info->next_func, info);
}

/*
 * Walk all dissector tables calling a user supplied function on each
 * entry.
 */
static void
dissector_all_tables_foreach (DATFunc func,
			      void *user_data)
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
			 void *      user_data)
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
			       void *          user_data)
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
dissector_table_foreach_changed_func (void *key, void *value, void *user_data)
{
	dtbl_entry_t             *dtbl_entry;
	dissector_foreach_info_t *info;

	ws_assert(value);
	ws_assert(user_data);

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
				      void *user_data)
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
				 void *      user_data)
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
	void *        caller_data;
	DATFunc_table caller_func;
} dissector_foreach_table_info_t;

/*
 * Called for each entry in the table of all dissector tables.
 * This is used if we directly process the hash table.
 */
static void
dissector_all_tables_foreach_table_func (void *key, void *value, void *user_data)
{
	dissector_table_t               table;
	dissector_foreach_table_info_t *info;

	table = (dissector_table_t)value;
	info  = (dissector_foreach_table_info_t *)user_data;
	(*info->caller_func)((char *)key, table->ui_name, info->caller_data);
}

/*
 * Called for each key in the table of all dissector tables.
 * This is used if we get a list of table names, sort it, and process the list.
 */
static void
dissector_all_tables_foreach_list_func (void *key, void *user_data)
{
	dissector_table_t               table;
	dissector_foreach_table_info_t *info;

	table = (dissector_table_t)g_hash_table_lookup(dissector_tables, key);
	info  = (dissector_foreach_table_info_t *)user_data;
	(*info->caller_func)((char*)key, table->ui_name, info->caller_data);
}

/*
 * Walk all dissector tables calling a user supplied function on each
 * table.
 */
void
dissector_all_tables_foreach_table (DATFunc_table func,
				    void *        user_data,
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
	if (g_hash_table_lookup(dissector_tables, name)) {
		ws_error("The dissector table %s (%s) is already registered - are you using a buggy plugin?", name, ui_name);
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
		sub_dissectors->hash_table = g_hash_table_new_full(g_direct_hash,
							       g_direct_equal,
							       NULL,
							       &g_free);
		break;

	case FT_STRING:
	case FT_STRINGZ:
	case FT_STRINGZPAD:
	case FT_STRINGZTRUNC:
		sub_dissectors->hash_func = g_str_hash;
		sub_dissectors->hash_table = g_hash_table_new_full(g_str_hash,
							       g_str_equal,
							       &g_free,
							       &g_free);
		break;
	case FT_GUID:
		sub_dissectors->hash_table = g_hash_table_new_full(uuid_hash,
							       uuid_equal,
							       NULL,
							       &g_free);
		break;

	case FT_NONE:
		/* Dissector tables with FT_NONE don't have values associated with
		   dissectors so this will always be a hash table size of 1 just
		   to store the single dtbl_entry_t */
		sub_dissectors->hash_func = g_direct_hash;
		sub_dissectors->hash_table = g_hash_table_new_full(g_direct_hash,
							       g_direct_equal,
							       NULL,
							       &g_free);
		break;

	default:
		ws_error("The dissector table %s (%s) is registering an unsupported type - are you using a buggy plugin?", name, ui_name);
		ws_assert_not_reached();
	}
	sub_dissectors->dissector_handles = NULL;
	sub_dissectors->ui_name = ui_name;
	sub_dissectors->type    = type;
	sub_dissectors->param   = param;
	sub_dissectors->protocol  = (proto == -1) ? NULL : find_protocol_by_id(proto);
	sub_dissectors->supports_decode_as = false;
	g_hash_table_insert(dissector_tables, (void *)name, (void *) sub_dissectors);
	return sub_dissectors;
}

dissector_table_t register_custom_dissector_table(const char *name,
	const char *ui_name, const int proto, GHashFunc hash_func, GEqualFunc key_equal_func,
	GDestroyNotify key_destroy_func)
{
	dissector_table_t	sub_dissectors;

	/* Make sure the registration is unique */
	if (g_hash_table_lookup(dissector_tables, name)) {
		ws_error("The dissector table %s (%s) is already registered - are you using a buggy plugin?", name, ui_name);
	}

	/* Create and register the dissector table for this name; returns */
	/* a pointer to the dissector table. */
	sub_dissectors = g_slice_new(struct dissector_table);
	sub_dissectors->hash_func = hash_func;
	sub_dissectors->hash_table = g_hash_table_new_full(hash_func,
							       key_equal_func,
							       key_destroy_func,
							       &g_free);

	sub_dissectors->dissector_handles = NULL;
	sub_dissectors->ui_name = ui_name;
	sub_dissectors->type    = FT_BYTES; /* Consider key a "blob" of data, no need to really create new type */
	sub_dissectors->param   = BASE_NONE;
	sub_dissectors->protocol  = (proto == -1) ? NULL : find_protocol_by_id(proto);
	sub_dissectors->supports_decode_as = false;
	g_hash_table_insert(dissector_tables, (void *)name, (void *) sub_dissectors);
	return sub_dissectors;
}

void
register_dissector_table_alias(dissector_table_t dissector_table, const char *alias_name) {
	if (!dissector_table || !alias_name) return;

	const char *name = NULL;
	GList *list = g_hash_table_get_keys(dissector_tables);
	for (GList *cur = list; cur; cur = cur->next) {
		if (g_hash_table_lookup(dissector_tables, cur->data) == dissector_table) {
			name = (const char *) cur->data;
			break;
		}
	}
	g_list_free(list);
	if (!name) return;

	g_hash_table_insert(dissector_table_aliases, (void *) alias_name, (void *) name);
}

void
deregister_dissector_table(const char *name)
{
	dissector_table_t sub_dissectors = (dissector_table_t) g_hash_table_lookup(dissector_tables, name);
	if (!sub_dissectors) return;

	g_hash_table_remove(dissector_tables, name);

	GList *list = g_hash_table_get_keys(dissector_table_aliases);
	for (GList *cur = list; cur; cur = cur->next) {
		void *alias_name = cur->data;
		if (g_hash_table_lookup(dissector_table_aliases, alias_name) == name) {
			g_hash_table_remove(dissector_table_aliases, alias_name);
		}
	}
	g_list_free(list);
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

static void
check_valid_heur_name_or_fail(const char *heur_name)
{
	if (proto_check_field_name_lower(heur_name)) {
		ws_error("Heuristic Protocol internal name \"%s\" has one or more invalid characters."
			" Allowed are lowercase, digits, '-', '_' and non-repeating '.'."
			" This might be caused by an inappropriate plugin or a development error.", heur_name);
	}
}

/* Finds a heuristic dissector table by table name. */
heur_dissector_list_t
find_heur_dissector_list(const char *name)
{
	return (heur_dissector_list_t)g_hash_table_lookup(heur_dissector_lists, name);
}

bool
has_heur_dissector_list(const char *name) {
	return (find_heur_dissector_list(name) != NULL);
}

heur_dtbl_entry_t* find_heur_dissector_by_unique_short_name(const char *short_name)
{
	return (heur_dtbl_entry_t*)g_hash_table_lookup(heuristic_short_names, short_name);
}

void
heur_dissector_add(const char *name, heur_dissector_t dissector, const char *display_name, const char *internal_name, const int proto, heuristic_enable_e enable)
{
	heur_dissector_list_t  sub_dissectors = find_heur_dissector_list(name);
	const char            *proto_name;
	heur_dtbl_entry_t     *hdtbl_entry;
	unsigned               i, list_size;
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
		if (wireshark_abort_on_dissector_bug)
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
			if (wireshark_abort_on_dissector_bug)
				abort();
			return;
		}
	}

	/* Make sure short_name is "parsing friendly" since it should only be used internally */
	check_valid_heur_name_or_fail(internal_name);

	/* Ensure short_name is unique */
	if (g_hash_table_lookup(heuristic_short_names, internal_name) != NULL) {
		ws_error("Duplicate heuristic short_name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", internal_name);
	}

	hdtbl_entry = g_slice_new(heur_dtbl_entry_t);
	hdtbl_entry->dissector = dissector;
	hdtbl_entry->protocol  = find_protocol_by_id(proto);
	hdtbl_entry->display_name = display_name;
	hdtbl_entry->short_name = g_strdup(internal_name);
	hdtbl_entry->list_name = g_strdup(name);
	hdtbl_entry->enabled   = (enable == HEURISTIC_ENABLE);
	hdtbl_entry->enabled_by_default = (enable == HEURISTIC_ENABLE);

	/* do the table insertion */
	g_hash_table_insert(heuristic_short_names, (void *)hdtbl_entry->short_name, hdtbl_entry);

	sub_dissectors->dissectors = g_slist_prepend(sub_dissectors->dissectors,
	    (void *)hdtbl_entry);

	/* XXX - could be optimized to pass hdtbl_entry directly */
	proto_add_heuristic_dissector(hdtbl_entry->protocol, hdtbl_entry->short_name);

	/* Add the dissector as a dependency
	  (some heuristic tables don't have protocol association, so there is
	  the need for the NULL check */
	if (sub_dissectors->protocol != NULL)
		register_depend_dissector(proto_get_protocol_short_name(sub_dissectors->protocol), proto_get_protocol_short_name(hdtbl_entry->protocol));
}



static int
find_matching_heur_dissector(const void *a, const void *b) {
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
	ws_assert(sub_dissectors != NULL);

	hdtbl_entry.dissector = dissector;
	hdtbl_entry.protocol  = find_protocol_by_id(proto);

	found_entry = g_slist_find_custom(sub_dissectors->dissectors,
	    (void *) &hdtbl_entry, find_matching_heur_dissector);

	if (found_entry) {
		heur_dtbl_entry_t *found_hdtbl_entry = (heur_dtbl_entry_t *)(found_entry->data);
		proto_add_deregistered_data(found_hdtbl_entry->list_name);
		g_hash_table_remove(heuristic_short_names, found_hdtbl_entry->short_name);
		proto_add_deregistered_data(found_hdtbl_entry->short_name);
		proto_add_deregistered_slice(sizeof(heur_dtbl_entry_t), found_hdtbl_entry);
		sub_dissectors->dissectors = g_slist_delete_link(sub_dissectors->dissectors,
		    found_entry);
	}
}

bool
dissector_try_heuristic(heur_dissector_list_t sub_dissectors, tvbuff_t *tvb,
			packet_info *pinfo, proto_tree *tree, heur_dtbl_entry_t **heur_dtbl_entry, void *data)
{
	bool               status;
	const char        *saved_curr_proto;
	const char        *saved_heur_list_name;
	GSList            *entry;
	GSList            *prev_entry = NULL;
	uint16_t           saved_can_desegment;
	unsigned           saved_layers_len = 0;
	heur_dtbl_entry_t *hdtbl_entry;
	int                proto_id;
	int                len;
	bool               consumed_none;
	unsigned           saved_desegment_len;
	unsigned           saved_tree_count = tree ? tree->tree_data->count : 0;

	/* can_desegment is set to 2 by anyone which offers this api/service.
	   then every time a subdissector is called it is decremented by one.
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

	status      = false;
	saved_curr_proto = pinfo->current_proto;
	saved_heur_list_name = pinfo->heur_list_name;

	saved_layers_len = wmem_list_count(pinfo->layers);
	*heur_dtbl_entry = NULL;

	DISSECTOR_ASSERT(saved_layers_len < prefs.gui_max_tree_depth);

	for (entry = sub_dissectors->dissectors; entry != NULL;
	    entry = g_slist_next(entry)) {
		/* XXX - why set this now and above? */
		pinfo->can_desegment = saved_can_desegment-(saved_can_desegment>0);
		hdtbl_entry = (heur_dtbl_entry_t *)entry->data;

		if (hdtbl_entry->protocol != NULL &&
			(!proto_is_protocol_enabled(hdtbl_entry->protocol)||(hdtbl_entry->enabled==false))) {
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
			add_layer(pinfo, proto_id);
		}

		pinfo->heur_list_name = hdtbl_entry->list_name;

		saved_desegment_len = pinfo->desegment_len;
		len = (hdtbl_entry->dissector)(tvb, pinfo, tree, data);
		consumed_none = len == 0 || (pinfo->desegment_len != saved_desegment_len && pinfo->desegment_offset == 0);
		if (hdtbl_entry->protocol != NULL &&
			(consumed_none || (tree && saved_tree_count == tree->tree_data->count))) {
			/*
			 * We added a protocol layer above. The dissector
			 * didn't consume any data or it didn't add any
			 * items to the tree so remove it from the list.
			 */
			while (wmem_list_count(pinfo->layers) > saved_layers_len) {
				/*
				 * Only reduce the layer number if the dissector
				 * didn't consume data. Since tree can be NULL on
				 * the first pass, we cannot check it or it will
				 * break dissectors that rely on a stable value.
				 */
				remove_last_layer(pinfo, consumed_none);
			}
		}
		if (len) {
			if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
				ws_debug("Frame: %d | Layers: %s | Dissector: %s\n", pinfo->num, proto_list_layers(pinfo), hdtbl_entry->short_name);
			}

			*heur_dtbl_entry = hdtbl_entry;

			/* Bubble the matched entry to the top for faster search next time. */
			if (prev_entry != NULL) {
				sub_dissectors->dissectors = g_slist_remove_link(sub_dissectors->dissectors, entry);
				sub_dissectors->dissectors = g_slist_concat(entry, sub_dissectors->dissectors);
			}
			status = true;
			break;
		}
		prev_entry = entry;
	}

	pinfo->current_proto = saved_curr_proto;
	pinfo->heur_list_name = saved_heur_list_name;
	pinfo->can_desegment = saved_can_desegment;
	return status;
}

typedef struct heur_dissector_foreach_info {
	void *        caller_data;
	DATFunc_heur  caller_func;
	GHFunc        next_func;
	const char   *table_name;
} heur_dissector_foreach_info_t;

/*
 * Called for each entry in a heuristic dissector table.
 */
static void
heur_dissector_table_foreach_func (void *data, void *user_data)
{
	heur_dissector_foreach_info_t *info;

	ws_assert(data);
	ws_assert(user_data);

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
			      void *       user_data)
{
	heur_dissector_foreach_info_t info;
	heur_dissector_list_t         sub_dissectors = find_heur_dissector_list(table_name);
	DISSECTOR_ASSERT(sub_dissectors != NULL);

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
	void *             caller_data;
	DATFunc_heur_table caller_func;
} heur_dissector_foreach_table_info_t;

/*
 * Called for each entry in the table of all heuristic dissector tables.
 * This is used if we directly process the hash table.
 */
static void
dissector_all_heur_tables_foreach_table_func (void *key, void *value, void *user_data)
{
	heur_dissector_foreach_table_info_t *info;

	info = (heur_dissector_foreach_table_info_t *)user_data;
	(*info->caller_func)((char *)key, (struct heur_dissector_list *)value, info->caller_data);
}

/*
 * Called for each key in the table of all dissector tables.
 * This is used if we get a list of table names, sort it, and process the list.
 */
static void
dissector_all_heur_tables_foreach_list_func (void *key, void *user_data)
{
	struct heur_dissector_list          *list;
	heur_dissector_foreach_table_info_t *info;

	list = (struct heur_dissector_list *)g_hash_table_lookup(heur_dissector_lists, key);
	info = (heur_dissector_foreach_table_info_t *)user_data;
	(*info->caller_func)((char*)key, list, info->caller_data);
}

/*
 * Walk all heuristic dissector tables calling a user supplied function on each
 * table.
 */
void
dissector_all_heur_tables_foreach_table (DATFunc_heur_table func,
					 void *             user_data,
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
    heur_dtbl_entry_t *hdtbl_entry, void *user_data _U_)
{
	if (hdtbl_entry->protocol != NULL) {
		printf("%s\t%s\t%c\t%c\t%s\t%s\n",
		       table_name,
		       proto_get_protocol_filter_name(proto_get_id(hdtbl_entry->protocol)),
		       (proto_is_protocol_enabled(hdtbl_entry->protocol) && hdtbl_entry->enabled) ? 'T' : 'F',
		       (proto_is_protocol_enabled_by_default(hdtbl_entry->protocol) && hdtbl_entry->enabled_by_default) ? 'T' : 'F',
		       hdtbl_entry->short_name,
		       hdtbl_entry->display_name);
	}
}

static void
dissector_dump_heur_decodes_display(const char *table_name, struct heur_dissector_list *listptr _U_, void *user_data _U_)
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
register_heur_dissector_list_with_description(const char *name, const char *ui_name, const int proto)
{
	heur_dissector_list_t sub_dissectors;

	/* Make sure the registration is unique */
	if (g_hash_table_lookup(heur_dissector_lists, name) != NULL) {
		ws_error("The heuristic dissector list %s is already registered - are you using a buggy plugin?", name);
	}

	/* Create and register the dissector table for this name; returns */
	/* a pointer to the dissector table. */
	sub_dissectors = g_slice_new(struct heur_dissector_list);
	sub_dissectors->protocol  = (proto == -1) ? NULL : find_protocol_by_id(proto);
	sub_dissectors->ui_name = ui_name;
	sub_dissectors->dissectors = NULL;	/* initially empty */
	g_hash_table_insert(heur_dissector_lists, (void *)name,
			    (void *) sub_dissectors);
	return sub_dissectors;
}

heur_dissector_list_t
register_heur_dissector_list(const char *name, const int proto)
{
	return register_heur_dissector_list_with_description(name, NULL, proto);
}

void
deregister_heur_dissector_list(const char *name)
{
	heur_dissector_list_t sub_dissectors = find_heur_dissector_list(name);
	if (sub_dissectors == NULL) {
		return;
	}

	g_hash_table_remove(heur_dissector_lists, name);
}

const char *
heur_dissector_list_get_description(heur_dissector_list_t list)
{
	return list ? list->ui_name : NULL;
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
dissector_handle_get_protocol_long_name(const dissector_handle_t handle)
{
	if (handle == NULL || handle->protocol == NULL) {
		return NULL;
	}
	return proto_get_protocol_long_name(handle->protocol);
}

/* Get the short name of the protocol for a dissector handle, if it has
   a protocol. */
const char *
dissector_handle_get_protocol_short_name(const dissector_handle_t handle)
{
	if (handle == NULL || handle->protocol == NULL) {
		return NULL;
	}
	return proto_get_protocol_short_name(handle->protocol);
}

/* For backwards source and binary compatibility */
const char *
dissector_handle_get_short_name(const dissector_handle_t handle)
{
	return dissector_handle_get_protocol_short_name(handle);
}

/* Get the description for what the dissector in the dissector handle
   dissects, if it has one. */
const char *
dissector_handle_get_description(const dissector_handle_t handle)
{
	if (handle == NULL) {
		return NULL;
	}
	return handle->description;
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
	if (!registered_dissectors) {
		return NULL;
	}

	return g_hash_table_get_keys(registered_dissectors);
}

/* Find a registered dissector by name. */
dissector_handle_t
find_dissector(const char *name)
{
	return (dissector_handle_t)g_hash_table_lookup(registered_dissectors, name);
}

/** Find a dissector by name and add parent protocol as a dependency*/
dissector_handle_t find_dissector_add_dependency(const char *name, const int parent_proto)
{
	dissector_handle_t handle = (dissector_handle_t)g_hash_table_lookup(registered_dissectors, name);
	if ((handle != NULL) && (parent_proto > 0))
	{
		register_depend_dissector(proto_get_protocol_short_name(find_protocol_by_id(parent_proto)), dissector_handle_get_protocol_short_name(handle));
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

const char *
dissector_handle_get_pref_suffix(const dissector_handle_t handle)
{
	if (handle == NULL) {
		return "";
	}
	return handle->pref_suffix ? handle->pref_suffix : "";
}

static void
check_valid_dissector_name_or_fail(const char *name)
{
	if (proto_check_field_name(name)) {
		ws_error("Dissector name \"%s\" has one or more invalid characters."
			" Allowed are letters, digits, '-', '_' and non-repeating '.'."
			" This might be caused by an inappropriate plugin or a development error.", name);
	}
}

static dissector_handle_t
new_dissector_handle(const int proto, const char *name, const char *description)
{
	struct dissector_handle *handle;

	/* Make sure name is "parsing friendly" - descriptions should be
	 * used for complicated phrases. NULL for anonymous unregistered
	 * dissectors is allowed; we check for that in various places.
	 *
	 * (It might be safer to have a default name used for anonymous
	 * dissectors rather than NULL checks scattered in the code.)
	 */
	if (name) {
		check_valid_dissector_name_or_fail(name);
	}

	handle			= wmem_new(wmem_epan_scope(), struct dissector_handle);
	handle->name		= name;
	handle->description	= description;
	handle->protocol	= find_protocol_by_id(proto);
	handle->pref_suffix     = NULL;

	if (handle->description == NULL) {
		/*
		 * No description for what this dissector dissects
		 * was supplied; use the short name for the protocol,
		 * if we have the protocol.
		 *
		 * (We may have no protocol; see, for example, the handle
		 * for dissecting the set of protocols where the first
		 * octet of the payload is an OSI network layer protocol
		 * ID.)
		 */
		if (handle->protocol != NULL)
			handle->description = proto_get_protocol_short_name(handle->protocol);
	} else {
		if (name && g_strcmp0(name, proto_get_protocol_filter_name(proto)) != 0) {
			handle->pref_suffix = ascii_strdown_inplace(wmem_strdup_printf(wmem_epan_scope(), ".%s", name));
			char *pos = handle->pref_suffix;
			while ((pos = strchr(pos, '-')) != NULL) {
				*pos++ = '_';
			}
		}
	}
	return handle;
}

dissector_handle_t
create_dissector_handle_with_name_and_description(dissector_t dissector,
						const int proto,
						const char* name,
						const char* description)
{
	dissector_handle_t handle;

	handle = new_dissector_handle(proto, name, description);
	handle->dissector_type = DISSECTOR_TYPE_SIMPLE;
	handle->dissector_func.dissector_type_simple = dissector;
	handle->dissector_data = NULL;
	return handle;
}

dissector_handle_t
create_dissector_handle_with_name(dissector_t dissector,
				const int proto, const char* name)
{
	return create_dissector_handle_with_name_and_description(dissector, proto, name, NULL);
}

/* Create an anonymous handle for a new dissector. */
dissector_handle_t
create_dissector_handle(dissector_t dissector, const int proto)
{
	return create_dissector_handle_with_name_and_description(dissector, proto, NULL, NULL);
}

static dissector_handle_t
create_dissector_handle_with_name_and_data(dissector_cb_t dissector, const int proto, const char *name, void* cb_data)
{
	dissector_handle_t handle;

	handle = new_dissector_handle(proto, name, NULL);
	handle->dissector_type = DISSECTOR_TYPE_CALLBACK;
	handle->dissector_func.dissector_type_callback = dissector;
	handle->dissector_data = cb_data;
	return handle;
}

dissector_handle_t
create_dissector_handle_with_data(dissector_cb_t dissector, const int proto, void* cb_data)
{
	return create_dissector_handle_with_name_and_data(dissector, proto, NULL, cb_data);
}

/* Destroy an anonymous handle for a dissector. */
static void
destroy_dissector_handle(dissector_handle_t handle)
{
	if (handle == NULL) return;

	dissector_delete_from_all_tables(handle);
	deregister_postdissector(handle);
	if (handle->pref_suffix) {
		wmem_free(wmem_epan_scope(), handle->pref_suffix);
	}
	wmem_free(wmem_epan_scope(), handle);
}

static dissector_handle_t
register_dissector_handle(const char *name, dissector_handle_t handle)
{
	bool new_entry;

	/* A registered dissector should have a name. */
	if (name == NULL || name[0] == '\0') {
		ws_error("A registered dissector name cannot be NULL or the empty string."
			" Anonymous dissector handles can be created with create_dissector_handle()."
			" This might be caused by an inappropriate plugin or a development error.");
	}

	new_entry = g_hash_table_insert(registered_dissectors, (void *)name, handle);
	if (!new_entry) {
		/* Make sure the registration is unique */
		ws_error("dissector handle name \"%s\" is already registered", name);
	}

	return handle;
}

/* Register a new dissector by name. */
dissector_handle_t
register_dissector(const char *name, dissector_t dissector, const int proto)
{
	dissector_handle_t handle;

	handle = create_dissector_handle_with_name(dissector, proto, name);

	return register_dissector_handle(name, handle);
}

dissector_handle_t
register_dissector_with_description(const char *name, const char *description, dissector_t dissector, const int proto)
{
	dissector_handle_t handle;

	handle = create_dissector_handle_with_name_and_description(dissector, proto, name, description);

	return register_dissector_handle(name, handle);
}

dissector_handle_t
register_dissector_with_data(const char *name, dissector_cb_t dissector, const int proto, void *cb_data)
{
	dissector_handle_t handle;

	handle = create_dissector_handle_with_name_and_data(dissector, proto, name, cb_data);

	return register_dissector_handle(name, handle);
}

static bool
remove_depend_dissector_from_list(depend_dissector_list_t sub_dissectors, const char *dependent)
{
	GSList *found_entry;

	found_entry = g_slist_find_custom(sub_dissectors->dissectors,
		dependent, (GCompareFunc)strcmp);

	if (found_entry) {
		g_free(found_entry->data);
		sub_dissectors->dissectors = g_slist_delete_link(sub_dissectors->dissectors, found_entry);
		return true;
	}

	return false;
}

static void
remove_depend_dissector_ghfunc(void *key _U_, void *value, void *user_data)
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
	g_hash_table_foreach(depend_dissector_lists, remove_depend_dissector_ghfunc, (void *)name);

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

	DISSECTOR_ASSERT(handle != NULL);
	ret = call_dissector_work(handle, tvb, pinfo, tree, true, data);
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
		DISSECTOR_ASSERT(data_handle->protocol != NULL);
		call_dissector_work(data_handle, tvb, pinfo, tree, true, NULL);
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
	return call_dissector_work(data_handle, tvb, pinfo, tree, true, NULL);
}

/*
 * Call a heuristic dissector through a heur_dtbl_entry
 */
void call_heur_dissector_direct(heur_dtbl_entry_t *heur_dtbl_entry, tvbuff_t *tvb,
	packet_info *pinfo, proto_tree *tree, void *data)
{
	const char        *saved_curr_proto;
	const char        *saved_heur_list_name;
	uint16_t           saved_can_desegment;
	unsigned           saved_layers_len = 0;

	DISSECTOR_ASSERT(heur_dtbl_entry);

	/* can_desegment is set to 2 by anyone which offers this api/service.
	   then every time a subdissector is called it is decremented by one.
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

	saved_layers_len = wmem_list_count(pinfo->layers);

	if (!heur_dtbl_entry->enabled ||
		(heur_dtbl_entry->protocol != NULL && !proto_is_protocol_enabled(heur_dtbl_entry->protocol))) {
		DISSECTOR_ASSERT(data_handle->protocol != NULL);
		call_dissector_work(data_handle, tvb, pinfo, tree, true, NULL);
		return;
	}

	if (heur_dtbl_entry->protocol != NULL) {
		/* do NOT change this behavior - wslua uses the protocol short name set here in order
			to determine which Lua-based heuristic dissector to call */
		pinfo->current_proto = proto_get_protocol_short_name(heur_dtbl_entry->protocol);
		add_layer(pinfo, proto_get_id(heur_dtbl_entry->protocol));
	}

	pinfo->heur_list_name = heur_dtbl_entry->list_name;

	/* call the dissector, in case of failure call data handle (might happen with exported PDUs) */
	if (!(*heur_dtbl_entry->dissector)(tvb, pinfo, tree, data)) {
		/*
		 * We added a protocol layer above. The dissector
		 * didn't accept the packet or it didn't add any
		 * items to the tree so remove it from the list.
		 */
		while (wmem_list_count(pinfo->layers) > saved_layers_len) {
			remove_last_layer(pinfo, true);
		}

		call_dissector_work(data_handle, tvb, pinfo, tree, true, NULL);
	}

	/* XXX: Remove layers if it was accepted but didn't actually consume
	 * data due to desegmentation? (Currently the only callers of this
	 * are UDP and exported PDUs, so not yet necessary.)
	 */

	/* Restore info from caller */
	pinfo->can_desegment = saved_can_desegment;
	pinfo->current_proto = saved_curr_proto;
	pinfo->heur_list_name = saved_heur_list_name;

}

static int
find_matching_proto_name(const void *arg1, const void *arg2)
{
	const char    *protocol_name = (const char*)arg1;
	const char    *name   = (const char *)arg2;

	return strcmp(protocol_name, name);
}

bool register_depend_dissector(const char* parent, const char* dependent)
{
	GSList                *list_entry;
	depend_dissector_list_t sub_dissectors;

	if ((parent == NULL) || (dependent == NULL))
	{
		/* XXX - assert on parent? */
		return false;
	}

	sub_dissectors = find_depend_dissector_list(parent);
	if (sub_dissectors == NULL) {
		/* parent protocol doesn't exist, create it */
		sub_dissectors = g_slice_new(struct depend_dissector_list);
		sub_dissectors->dissectors = NULL;	/* initially empty */
		g_hash_table_insert(depend_dissector_lists, (void *)g_strdup(parent), (void *) sub_dissectors);
	}

	/* Verify that sub-dissector is not already in the list */
	list_entry = g_slist_find_custom(sub_dissectors->dissectors, (void *)dependent, find_matching_proto_name);
	if (list_entry != NULL)
		return true; /* Dependency already exists */

	sub_dissectors->dissectors = g_slist_prepend(sub_dissectors->dissectors, (void *)g_strdup(dependent));
	return true;
}

bool deregister_depend_dissector(const char* parent, const char* dependent)
{
	depend_dissector_list_t  sub_dissectors = find_depend_dissector_list(parent);

	/* sanity check */
	ws_assert(sub_dissectors != NULL);

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
dissector_dump_decodes_display(const char *table_name,
			       ftenum_t selector_type _U_, void *key, void *value,
			       void *user_data _U_)
{
	uint32_t            selector       = GPOINTER_TO_UINT (key);
	dissector_table_t   sub_dissectors = find_dissector_table(table_name);
	dtbl_entry_t       *dtbl_entry;
	dissector_handle_t  handle;
	int                 proto_id;
	const char         *decode_as;

	ws_assert(sub_dissectors);
	switch (sub_dissectors->type) {

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			dtbl_entry = (dtbl_entry_t *)value;
			ws_assert(dtbl_entry);

			handle   = dtbl_entry->current;
			ws_assert(handle);

			proto_id = dissector_handle_get_protocol_index(handle);

			if (proto_id != -1) {
				decode_as = proto_get_protocol_filter_name(proto_id);
				ws_assert(decode_as != NULL);
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
 * Dumps information about dissector tables to stdout.
 *
 * There is one record per line. The fields are tab-delimited.
 *
 * Field 1 = dissector table name, e.g. "tcp.port"
 * Field 2 = name used for the dissector table in the GUI
 * Field 3 = type (textual representation of the ftenum type)
 * Field 4 = base for display (for integer types)
 * Field 5 = protocol name
 * Field 6 = "decode as" support
 *
 * This does not dump the *individual entries* in the dissector tables,
 * i.e. it doesn't show what dissector handles what particular value
 * of the key in the dissector table.
 */

static void
dissector_dump_dissector_tables_display (void *key, void *user_data _U_)
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
	if (table->protocol != NULL) {
		printf("\t%s",
		    proto_get_protocol_short_name(table->protocol));
	} else
		printf("\t(no protocol)");
	printf("\tDecode As %ssupported",
	    table->supports_decode_as ? "" : "not ");
	printf("\n");
}

/** The output format of this function is meant to parallel
 * that of dissector_dump_dissector_tables_display().
 * Field 3 is shown as "heuristic".
 * Field 4 is omitted, as it is for FT_STRING dissector tables above.
 * Field 6 is omitted since "Decode As" doesn't apply.
 */

static void
dissector_dump_heur_dissector_tables_display (void *key, void *user_data _U_)
{
	const char		*list_name = (const char *)key;
	heur_dissector_list_t	list;

	list = (heur_dissector_list_t)g_hash_table_lookup(heur_dissector_lists, key);
	printf("%s\t%s\theuristic", list_name, list->ui_name ? list->ui_name : list_name);

	if (list->protocol != NULL) {
		printf("\t%s",
		    proto_get_protocol_short_name(list->protocol));
	} else
		printf("\t(no protocol)");
	printf("\n");
}

static int
compare_dissector_key_name(const void *dissector_a, const void *dissector_b)
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

	list = g_hash_table_get_keys(heur_dissector_lists);
	list = g_list_sort(list, compare_dissector_key_name);
	g_list_foreach(list, dissector_dump_heur_dissector_tables_display, NULL);
	g_list_free(list);
}

/*
 * Dumps the entries in the table of registered dissectors.
 *
 * There is one record per line. The fields are tab-delimited.
 *
 * Field 1 = dissector name
 * Field 2 = dissector description
 */

struct dissector_info {
	const char *name;
	const char *description;
};

static int
compare_dissector_info_names(const void *arg1, const void *arg2)
{
	const struct dissector_info *info1 = (const struct dissector_info *) arg1;
	const struct dissector_info *info2 = (const struct dissector_info *) arg2;

	return strcmp(info1->name, info2->name);
}

void
dissector_dump_dissectors(void)
{
	GHashTableIter iter;
	struct dissector_info *dissectors_info;
	unsigned num_protocols;
	gpointer key, value;
	unsigned proto_index;

	g_hash_table_iter_init(&iter, registered_dissectors);
	num_protocols = g_hash_table_size(registered_dissectors);
	dissectors_info = g_new(struct dissector_info, num_protocols);
	proto_index = 0;
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		dissectors_info[proto_index].name = (const char *)key;
		dissectors_info[proto_index].description =
		    ((dissector_handle_t) value)->description;
		proto_index++;
	}
	qsort(dissectors_info, num_protocols, sizeof(struct dissector_info),
	    compare_dissector_info_names);
	for (proto_index = 0; proto_index < num_protocols; proto_index++) {
		printf("%s\t%s\n", dissectors_info[proto_index].name,
		    dissectors_info[proto_index].description);
	}
	g_free(dissectors_info);
}

void
register_postdissector(dissector_handle_t handle)
{
	postdissector p;

	if (!postdissectors)
		postdissectors = g_array_sized_new(false, false, (unsigned)sizeof(postdissector), 1);

	p.handle = handle;
	p.wanted_hfids = NULL;
	postdissectors = g_array_append_val(postdissectors, p);
}

void
set_postdissector_wanted_hfids(dissector_handle_t handle, GArray *wanted_hfids)
{
	unsigned i;

	if (!postdissectors) return;

	for (i = 0; i < postdissectors->len; i++) {
		if (POSTDISSECTORS(i).handle == handle) {
			if (POSTDISSECTORS(i).wanted_hfids) {
				g_array_free(POSTDISSECTORS(i).wanted_hfids, true);
			}
			POSTDISSECTORS(i).wanted_hfids = wanted_hfids;
			break;
		}
	}
}

void
deregister_postdissector(dissector_handle_t handle)
{
	unsigned i;

	if (!postdissectors) return;

	for (i = 0; i < postdissectors->len; i++) {
		if (POSTDISSECTORS(i).handle == handle) {
			if (POSTDISSECTORS(i).wanted_hfids) {
				g_array_free(POSTDISSECTORS(i).wanted_hfids, true);
			}
			postdissectors = g_array_remove_index_fast(postdissectors, i);
			break;
		}
	}
}

bool
have_postdissector(void)
{
	unsigned i;
	dissector_handle_t handle;

	for (i = 0; i < postdissectors->len; i++) {
		handle = POSTDISSECTORS(i).handle;

		if (handle->protocol != NULL
		    && proto_is_protocol_enabled(handle->protocol)) {
			/* We have at least one enabled postdissector */
			return true;
		}
	}
	return false;
}

void
call_all_postdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	unsigned i;

	for (i = 0; i < postdissectors->len; i++) {
		call_dissector_only(POSTDISSECTORS(i).handle,
				    tvb, pinfo, tree, NULL);
	}
}

bool
postdissectors_want_hfids(void)
{
	unsigned i;

	for (i = 0; i < postdissectors->len; i++) {
		if (POSTDISSECTORS(i).wanted_hfids != NULL &&
		    POSTDISSECTORS(i).wanted_hfids->len != 0)
			return true;
	}
	return false;
}

void
prime_epan_dissect_with_postdissector_wanted_hfids(epan_dissect_t *edt)
{
	unsigned i;

	if (postdissectors == NULL) {
		/*
		 * No postdissector expressed an interest in any hfids.
		 */
		return;
	}
	for (i = 0; i < postdissectors->len; i++) {
		if (POSTDISSECTORS(i).wanted_hfids != NULL &&
		    POSTDISSECTORS(i).wanted_hfids->len != 0)
			epan_dissect_prime_with_hfid_array(edt,
			    POSTDISSECTORS(i).wanted_hfids);
	}
}

void
increment_dissection_depth(packet_info *pinfo) {
	pinfo->dissection_depth++;
	DISSECTOR_ASSERT(pinfo->dissection_depth < (int)prefs.gui_max_tree_depth);
}

void
decrement_dissection_depth(packet_info *pinfo) {
	pinfo->dissection_depth--;
	DISSECTOR_ASSERT(pinfo->dissection_depth >= 0);
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
