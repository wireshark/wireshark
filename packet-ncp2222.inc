/* packet-ncp2222.inc
 *
 * Routines for NetWare Core Protocol. This C code gets #include'd
 * into packet-ncp2222.c, which is generated from ncp2222.py. It's
 * #include'd instead of being in a separate compilation unit so
 * that all the data tables in packet-ncp2222.c can remain static.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id: packet-ncp2222.inc,v 1.11 2002/05/11 23:04:53 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define NCP_PACKET_INIT_COUNT	200
#define PROTO_LENGTH_UNTIL_END -1

static void
process_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
		int *req_cond_results, gboolean really_decode,
		const ncp_record *ncp_rec);

/* NCP packets come in request/reply pairs. The request packets tell the type
 * of NCP request and give a sequence ID. The response, unfortunately, only
 * identifies itself via the sequence ID; you have to know what type of NCP
 * request the request packet contained in order to successfully parse the NCP
 * response. A global method for doing this does not exist in ethereal yet
 * (NFS also requires it), so for now the NCP section will keep its own hash
 * table keeping track of NCP packet types.
 *
 * We construct a conversation specified by the client and server
 * addresses and the connection number; the key representing the unique
 * NCP request then is composed of the pointer to the conversation
 * structure, cast to a "guint" (which may throw away the upper 32
 * bits of the pointer on a P64 platform, but the low-order 32 bits
 * are more likely to differ between conversations than the upper 32 bits),
 * and the sequence number.
 *
 * The value stored in the hash table is the ncp_req_hash_value pointer. This
 * struct tells us the NCP type and gives the ncp2222_record pointer, if
 * ncp_type == 0x2222.
 */
typedef struct {
	conversation_t	*conversation;
	guint8		nw_sequence;
} ncp_req_hash_key;

typedef struct {
	const ncp_record	*ncp_rec;
	gboolean		*req_cond_results;
} ncp_req_hash_value;

static GHashTable *ncp_req_hash = NULL;
static GMemChunk *ncp_req_hash_keys = NULL;
static GMemChunk *ncp_req_hash_values = NULL;

/* Hash Functions */
gint
ncp_equal(gconstpointer v, gconstpointer v2)
{
	ncp_req_hash_key	*val1 = (ncp_req_hash_key*)v;
	ncp_req_hash_key	*val2 = (ncp_req_hash_key*)v2;

	if (val1->conversation == val2->conversation &&
	    val1->nw_sequence  == val2->nw_sequence ) {
		return 1;
	}
	return 0;
}

guint
ncp_hash(gconstpointer v)
{
	ncp_req_hash_key	*ncp_key = (ncp_req_hash_key*)v;
	return GPOINTER_TO_UINT(ncp_key->conversation) + ncp_key->nw_sequence;
}

/* Frees memory used by the ncp_req_hash_value's */
static void
ncp_req_hash_cleanup(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
	ncp_req_hash_value	*request_value = (ncp_req_hash_value*) value;

	if (request_value->req_cond_results) {
		g_free(request_value->req_cond_results);
	}
}

/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in ethereal */
static void
ncp_init_protocol(void)
{
	if (ncp_req_hash) {
		g_hash_table_foreach(ncp_req_hash, ncp_req_hash_cleanup, NULL);
		g_hash_table_destroy(ncp_req_hash);
	}
	if (ncp_req_hash_keys)
		g_mem_chunk_destroy(ncp_req_hash_keys);
	if (ncp_req_hash_values)
		g_mem_chunk_destroy(ncp_req_hash_values);

	ncp_req_hash = g_hash_table_new(ncp_hash, ncp_equal);
	ncp_req_hash_keys = g_mem_chunk_new("ncp_req_hash_keys",
			sizeof(ncp_req_hash_key),
			NCP_PACKET_INIT_COUNT * sizeof(ncp_req_hash_key),
			G_ALLOC_ONLY);
	ncp_req_hash_values = g_mem_chunk_new("ncp_req_hash_values",
			sizeof(ncp_req_hash_value),
			NCP_PACKET_INIT_COUNT * sizeof(ncp_req_hash_value),
			G_ALLOC_ONLY);
}

/* After the sequential run, we don't need the ncp_request hash and keys
 * anymore; the lookups have already been done and the vital info
 * saved in the reply-packets' private_data in the frame_data struct. */
static void
ncp_postseq_cleanup(void)
{
	if (ncp_req_hash) {
		/* Destroy the hash, but don't clean up request_condition data. */
		g_hash_table_destroy(ncp_req_hash);
		ncp_req_hash = NULL;
	}
	if (ncp_req_hash_keys) {
		g_mem_chunk_destroy(ncp_req_hash_keys);
		ncp_req_hash_keys = NULL;
	}
	/* Don't free the ncp_req_hash_values, as they're
	 * needed during random-access processing of the proto_tree.*/
}

ncp_req_hash_value*
ncp_hash_insert(conversation_t *conversation, guint8 nw_sequence,
		const ncp_record *ncp_rec)
{
	ncp_req_hash_key		*request_key;
	ncp_req_hash_value		*request_value;

	/* Now remember the request, so we can find it if we later
	   a reply to it. */
	request_key = g_mem_chunk_alloc(ncp_req_hash_keys);
	request_key->conversation = conversation;
	request_key->nw_sequence = nw_sequence;

	request_value = g_mem_chunk_alloc(ncp_req_hash_values);
	request_value->ncp_rec = ncp_rec;
	request_value->req_cond_results = NULL;

	g_hash_table_insert(ncp_req_hash, request_key, request_value);

	return request_value;
}

/* Returns the ncp_rec*, or NULL if not found. */
ncp_req_hash_value*
ncp_hash_lookup(conversation_t *conversation, guint8 nw_sequence)
{
	ncp_req_hash_key		request_key;

	request_key.conversation = conversation;
	request_key.nw_sequence = nw_sequence;

	return g_hash_table_lookup(ncp_req_hash, &request_key);
}

/* Does NCP func require a subfunction code? */
static gboolean
ncp_requires_subfunc(guint8 func)
{
	const guint8 *ncp_func_requirement = ncp_func_requires_subfunc;

	while (*ncp_func_requirement != 0) {
		if (*ncp_func_requirement == func) {
			return TRUE;
		}
		ncp_func_requirement++;
	}
	return FALSE;
}

/* Does the NCP func have a length parameter? */
static gboolean
ncp_has_length_parameter(guint8 func)
{
	const guint8 *ncp_func_requirement = ncp_func_has_no_length_parameter;

	while (*ncp_func_requirement != 0) {
		if (*ncp_func_requirement == func) {
			return FALSE;
		}
		ncp_func_requirement++;
	}
	return TRUE;
}
		

/* Return a ncp_record* based on func and possibly subfunc */
static const ncp_record *
ncp_record_find(guint8 func, guint8 subfunc)
{
	const ncp_record *ncp_rec = ncp_packets;

	while(ncp_rec->func != 0 || ncp_rec->subfunc != 0 ||
		ncp_rec->name != NULL ) {
		if (ncp_rec->func == func) {
			if (ncp_rec->has_subfunc) {
				if (ncp_rec->subfunc == subfunc) {
					return ncp_rec;
				}
			}
			else {
				return ncp_rec;
			}
		}
		ncp_rec++;
	}
	return NULL;
}

/* Given a proto_item*, assume it contains an integer value
 * and return a guint from it. */
guint
get_item_value(proto_item *item)
{
	return fvalue_get_integer(PITEM_FINFO(item)->value);
}

char*
get_item_name(proto_item *item)
{
	return PITEM_FINFO(item)->hfinfo->name;
}


typedef proto_item* (*padd_func_t)(ptvcursor_t*, const ptvc_record*);

/*
 * XXX - are these just DOS-format dates and times?
 *
 * Should we put code to understand various date and time formats (UNIX,
 * DOS, SMB weird mutant UNIX, NT, Mac, etc. into libethereal, and have
 * the "display" member of an HF_ABSOLUTE_TIME field specify whether
 * it's DOS date/DOS time, DOS time/DOS date, NT time, UNIX time_t,
 * UNIX "struct timeval", NFSv3/NFSv4 seconds/nanoseconds, Mac, etc.?
 *
 * What about hijacking the "bitmask" field to specify the precision of
 * the time stamp, or putting a combination of precision and format
 * into the "display" member?
 *
 * What about relative times?  Should they have units (seconds, milliseconds,
 * microseconds, nanoseconds, etc.), precision, and format in there?
 */
typedef struct {
	guint	year;
	guint	month;
	guint	day;
} nw_date_t;

typedef struct {
	guint	hour;
	guint	minute;
	guint	second;
} nw_time_t;

/* Given an integer, fill in a nw_date_t struct. */
static void
uint_to_nwdate(guint data, nw_date_t *nwdate)
{
	nwdate->day   =  data & 0x001f;
	nwdate->month = (data & 0x01e0) >> 5;
	nwdate->year  = ((data & 0xfe00) >> 9) + 1980;
}

/* Given an integer, fill in a nw_time_t struct. */
static void
uint_to_nwtime(guint data, nw_time_t *nwtime)
{
	/* 2-second resolution */
	nwtime->second = (data & 0x001f) * 2;
	nwtime->minute = ((data & 0x07e0) >> 5) + 1;
	nwtime->hour   = ((data & 0xf800) >> 11) + 1;
}


static proto_item*
padd_normal(ptvcursor_t *ptvc, const ptvc_record *rec)
{
	return ptvcursor_add(ptvc, *rec->hf_ptr,
		rec->length, rec->endianness);
}


static proto_item*
padd_date(ptvcursor_t *ptvc, const ptvc_record *rec)
{
	proto_item	*item;
	nw_date_t	nw_date;
	gint		offset;

	offset = ptvcursor_current_offset(ptvc);

	item = ptvcursor_add(ptvc, *rec->hf_ptr,
		rec->length, rec->endianness);

	uint_to_nwdate(get_item_value(item), &nw_date);
	
	proto_item_set_text(item, get_item_name(item)); 
	proto_item_append_text(item, ": %04u/%02u/%02u",
			nw_date.year, nw_date.month, nw_date.day);
	return item;
}

static proto_item*
padd_time(ptvcursor_t *ptvc, const ptvc_record *rec)
{
	proto_item	*item;
	nw_time_t	nw_time;
	gint		offset;

	offset = ptvcursor_current_offset(ptvc);

	item = ptvcursor_add(ptvc, *rec->hf_ptr,
		rec->length, rec->endianness);

	uint_to_nwtime(get_item_value(item), &nw_time);
	
	proto_item_set_text(item, get_item_name(item)); 
	proto_item_append_text(item, ": %02u:%02u:%02u",
			nw_time.hour, nw_time.minute, nw_time.second);
	return item;
}



/* Add a value for a ptvc_record, and process the sub-ptvc_record
 * that it points to. */
static void
process_bitfield_sub_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
		gboolean really_decode)
{
	proto_item		*item;
	proto_tree		*sub_tree;
	const ptvc_record	*sub_rec;
	int			current_offset;
	gint			ett;
	ptvcursor_t		*sub_ptvc;

	if (really_decode) {
		/* Save the current offset */
		current_offset = ptvcursor_current_offset(ptvc);

		/* Add the item */
		item = ptvcursor_add(ptvc, *rec->hf_ptr, rec->length,
				rec->endianness);

		ett = *rec->sub_ptvc_rec->ett;

		/* Make a new protocol sub-tree */
		sub_tree = proto_item_add_subtree(item, ett);

		/* Make a new ptvcursor */
		sub_ptvc = ptvcursor_new(sub_tree, ptvcursor_tvbuff(ptvc),
				current_offset);

		/* Use it */
		sub_rec = rec->sub_ptvc_rec->ptvc_rec;
		while(sub_rec->hf_ptr != NULL) {
			g_assert(!sub_rec->sub_ptvc_rec);
			ptvcursor_add_no_advance(sub_ptvc, *sub_rec->hf_ptr,
					sub_rec->length, sub_rec->endianness);
			sub_rec++;
		}

		/* Free it. */
		ptvcursor_free(sub_ptvc);
	}
	else {
		ptvcursor_advance(ptvc, rec->length);
	}
}

/* Process a sub-ptvc_record that points to a "struct" ptvc_record. */
static void
process_struct_sub_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
		int *req_cond_results, gboolean really_decode,
		const ncp_record *ncp_rec)
{
	const ptvc_record	*sub_rec;
	gint			ett;
	proto_tree		*old_tree=NULL, *new_tree;
	proto_item		*item=NULL;
	gint			offset=0;

	/* Create a sub-proto_tree? */
	if (rec->sub_ptvc_rec->descr) {
		ett = *rec->sub_ptvc_rec->ett;
		old_tree = ptvcursor_tree(ptvc);
		offset = ptvcursor_current_offset(ptvc);
		item = proto_tree_add_text(old_tree, ptvcursor_tvbuff(ptvc),
				offset, PROTO_LENGTH_UNTIL_END,
				rec->sub_ptvc_rec->descr);
		new_tree = proto_item_add_subtree(item, ett);
		ptvcursor_set_tree(ptvc, new_tree);
	}

	/* Get the ptvc_record for the struct and call our caller
	 * to process it. */
	sub_rec = rec->sub_ptvc_rec->ptvc_rec;
	process_ptvc_record(ptvc, sub_rec, req_cond_results, really_decode, ncp_rec);

	/* Re-set the tree */
	if (rec->sub_ptvc_rec->descr) {
		proto_item_set_len(item, ptvcursor_current_offset(ptvc) - offset);
		ptvcursor_set_tree(ptvc, old_tree);
	}
}

/* Run through the table of ptvc_record's and add info to the tree. This
 * is the work-horse of process_ptvc_record(). */
static void
_process_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
		int *req_cond_results, gboolean really_decode,
		const ncp_record *ncp_rec)
{
	proto_item	*item;
	guint		i, repeat_count;
	padd_func_t	func = NULL;

	if (rec->sub_ptvc_rec) {
		/* Repeat this? */
		if (rec->repeat_index == NO_REPEAT) {
			if (rec->hf_ptr == PTVC_STRUCT) {
				process_struct_sub_ptvc_record(ptvc, rec,
						req_cond_results, really_decode,
						ncp_rec);
			}
			else {
				process_bitfield_sub_ptvc_record(ptvc, rec,
						really_decode);
			}
		}
		else {
			repeat_count = repeat_vars[rec->repeat_index];
			for (i = 0; i < repeat_count; i++ ) {
				if (rec->hf_ptr == PTVC_STRUCT) {
					process_struct_sub_ptvc_record(ptvc, rec,
						req_cond_results, really_decode,
						ncp_rec);
				}
				else {
					process_bitfield_sub_ptvc_record(ptvc, rec,
							really_decode);
				}
			}
		}
	}
	else {
		/* If we can't repeat this field, we might use it
		 * to set a 'var'. */
		if (rec->repeat_index == NO_REPEAT) {
			if (really_decode) {
				/* Handle any special formatting. */
				switch(rec->special_fmt) {
					case NCP_FMT_NONE:
						func = padd_normal;
						break;
					case NCP_FMT_NW_DATE:
						func = padd_date;
						break;
					case NCP_FMT_NW_TIME:
						func = padd_time;
						break;
					default:
						g_assert_not_reached();
				}
				item = func(ptvc, rec);

				/* Set the value as a 'var' ? */
				if (rec->var_index != NO_VAR) {
					repeat_vars[rec->var_index] = get_item_value(item);
				}
			}
			else {
				/* If we don't decode the field, we
				 * better not use the value to set a var.
				 * Actually, we could, as long as we don't
				 * *use* that var; for now keep this assert in
				 * place. */
				g_assert(rec->var_index == NO_VAR);
				ptvcursor_advance(ptvc, rec->length);
			}
		}
		else {
			/* We do repeat this field. */
			repeat_count = repeat_vars[rec->repeat_index];
			if (really_decode) {
				/* Handle any special formatting. */
				switch(rec->special_fmt) {
					case NCP_FMT_NONE:
						func = padd_normal;
						break;
					case NCP_FMT_NW_DATE:
						func = padd_date;
						break;
					case NCP_FMT_NW_TIME:
						func = padd_time;
						break;
					default:
						g_assert_not_reached();
				}
				for (i = 0; i < repeat_count; i++ ) {
					func(ptvc, rec);
				}
			}
			else {
				for (i = 0; i < repeat_count; i++ ) {
					ptvcursor_advance(ptvc, rec->length);
				}
			}
		}
	}
}

/* Run through the table of ptvc_record's and add info to the tree.
 * Honor a request condition result. */
static void
process_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
		int *req_cond_results, gboolean really_decode,
		const ncp_record *ncp_rec)
{
	gboolean decode;

	while(rec->hf_ptr != NULL) {
		decode = really_decode;
		/* If we're supposed to decode, check the request condition
		 * results to see if we should override this and *not* decode. */
		if (decode && req_cond_results) {
			if (rec->req_cond_index != NO_REQ_COND) {
				if (req_cond_results[rec->req_cond_index] == FALSE) {
					decode = FALSE;
				}
			}
		}
		if (decode || ncp_rec->req_cond_size_type == REQ_COND_SIZE_CONSTANT) {
			_process_ptvc_record(ptvc, rec, req_cond_results, decode, ncp_rec);
		}
		rec++;
	}
}



/* Clear the repeat_vars array. */
static void
clear_repeat_vars(void)
{
	guint i;

	for (i = 0 ; i < NUM_REPEAT_VARS; i++ ) {
		repeat_vars[i] = 0;
	}
}

/* Given an error_equivalency table and a completion code, return
 * the string representing the error. */
static const char*
ncp_error_string(const error_equivalency *errors, guint8 completion_code)
{
	while (errors->ncp_error_index != -1) {
		if (errors->error_in_packet == completion_code) {
			return ncp_errors[errors->ncp_error_index];
		}
		errors++;
	}

	return "Unknown";
}

static const ncp_record ncp1111_request =
	{ 0x01, 0x00, NO_SUBFUNC, "Create Connection Service", NCP_GROUP_CONNECTION,
		NULL, NULL, ncp_0x2_errors, NULL, NO_REQ_COND_SIZE, NULL };

/* Wrapper around proto_tree_free() */
void free_proto_tree(void *tree)
{
	if (tree) {
		proto_tree_free((proto_tree*) tree);
	}
}

void
dissect_ncp_request(tvbuff_t *tvb, packet_info *pinfo,
		guint16 nw_connection, guint8 sequence,
		guint16 type, proto_tree *ncp_tree)
{
	guint8			func, subfunc = 0;
	gboolean		requires_subfunc;
	gboolean		has_length = TRUE;
	ncp_req_hash_value	*request_value = NULL;
	const ncp_record	*ncp_rec = NULL;
	conversation_t		*conversation;
	ptvcursor_t		*ptvc = NULL;
	proto_tree		*temp_tree = NULL;
	gboolean		run_req_cond = FALSE;
	gboolean		run_info_str = FALSE;

	func = tvb_get_guint8(tvb, 6);

	requires_subfunc = ncp_requires_subfunc(func);
	has_length = ncp_has_length_parameter(func);
	if (requires_subfunc) {
		if (has_length) {
			subfunc = tvb_get_guint8(tvb, 9);
		}
		else {
			subfunc = tvb_get_guint8(tvb, 7);
		}
	}

	/* Determine which ncp_record to use. */
	switch (type) {
		case 0x1111:
			ncp_rec = &ncp1111_request;
			break;
		case 0x2222:
			ncp_rec = ncp_record_find(func, subfunc);
			break;
		default:
			ncp_rec = NULL;
	}

	/* Fill in the INFO column. */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (ncp_rec) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "C %s", ncp_rec->name);
		}
		else {
			if (requires_subfunc) {
				col_add_fstr(pinfo->cinfo, COL_INFO,
					"C Unknown Function %d %d (0x%02X/0x%02x)",
					func, subfunc, func, subfunc);
			}
			else {
				col_add_fstr(pinfo->cinfo, COL_INFO,
					"C Unknown Function %d (0x%02x)",
					func, func);
			}
		}
	}

	if (!pinfo->fd->flags.visited) {
		/* This is the first time we've looked at this packet.
		   Keep track of the address and connection whence the request
		   came, and the address and connection to which the request
		   is being sent, so that we can match up calls with replies.
		   (We don't include the sequence number, as we may want
		   to have all packets over the same connection treated
		   as being part of a single conversation so that we can
		   let the user select that conversation to be displayed.) */
		conversation = find_conversation(&pinfo->src, &pinfo->dst,
		    PT_NCP, nw_connection, nw_connection, 0);

		if (conversation == NULL) {
			/* It's not part of any conversation - create a new one. */
			conversation = conversation_new(&pinfo->src, &pinfo->dst,
			    PT_NCP, nw_connection, nw_connection, 0);
		}
		request_value = ncp_hash_insert(conversation, sequence, ncp_rec);

		/* If this is the first time we're examining the packet,
		 * check to see if this NCP type uses a "request condition".
		 * If so, we have to build a proto_tree because request conditions
		 * use display filters to work, and without a proto_tree,
		 * display filters can't possibly work. If we already have
		 * a proto_tree, then wonderful. If we don't, we need to build
		 * one. */
		if (ncp_rec) {
			if (ncp_rec->req_cond_indexes) {
				run_req_cond = TRUE;
			}
			/* Only create info string if COL_INFO is available. */
			if (ncp_rec->req_info_str && check_col(pinfo->cinfo, COL_INFO)) {
				run_info_str = TRUE;
			}
			/* We also have to use a tree if we have to construct an info_str */
			if ((run_info_str || run_req_cond) && !ncp_tree) {
				proto_item *ti;

				temp_tree = proto_tree_create_root();
				proto_tree_set_visible(temp_tree, FALSE);
				ti = proto_tree_add_item(temp_tree, proto_ncp, tvb, 0, -1, FALSE);
				ncp_tree = proto_item_add_subtree(ti, ett_ncp);
			}
		}
	}

	if (ncp_tree) {
		/* If the dissection throws an exception, be sure to free
		 * the temporary proto_tree that was created. Because of the
		 * way the CLEANUP_PUSH macro works, we can't put it in an 'if'
		 * block; it has to be in the same scope as the terminating
		 * CLEANUP_POP or CLEANUP_POP_AND_ALLOC. So, we always
		 * call CLEANUP_POP and friends, but the value of temp_tree is
		 * NULL if no cleanup is needed, and non-null if cleanup is needed. */
		CLEANUP_PUSH(free_proto_tree, temp_tree);

		/* Before the dissection, if we're saving data for a request
		 * condition, we have to prime the proto tree using the
		 * dfilter information */
		if (run_req_cond) {
			const int	*needed;
			dfilter_t	*dfilter;

			needed = ncp_rec->req_cond_indexes;

			while (*needed != -1) {
				dfilter = req_conds[*needed].dfilter;
				/* Prime the proto_tree with "interesting fields". */
				dfilter_prime_proto_tree(dfilter, ncp_tree);
				needed++;
			}
		}

		/* Before the dissection, if we need a field for the info_str,
		 * prime the tree. */
		if (run_info_str) {
			proto_tree_prime_hfid(ncp_tree, *ncp_rec->req_info_str->hf_ptr);
		}

		conversation = find_conversation(&pinfo->src, &pinfo->dst,
		    PT_NCP, nw_connection, nw_connection, 0);

		switch (type) {
			case 0x1111:
				; /* nothing */
				break;

			case 0x2222:
				proto_tree_add_uint_format(ncp_tree, hf_ncp_func, tvb, 6, 1,
					func, "Function: %d (0x%02X), %s",
					func, func, ncp_rec ? ncp_rec->name : "Unknown");
				break;

			default:
				; /* nothing */
				break;
		}

		if (requires_subfunc) {
			if (has_length) {
				proto_tree_add_item(ncp_tree, hf_ncp_length, tvb, 7,
					2, FALSE);
				proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 9, 1,
					subfunc, "SubFunction: %d (0x%02x)",
					subfunc, subfunc);
				ptvc = ptvcursor_new(ncp_tree, tvb, 10);
			}
			else {
				proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 7, 1,
					subfunc, "SubFunction: %d (0x%02x)",
					subfunc, subfunc);
				ptvc = ptvcursor_new(ncp_tree, tvb, 8);
			}
		}
		else {
			ptvc = ptvcursor_new(ncp_tree, tvb, 7);
		}

		/* The group is not part of the packet, but it's useful
		 * information to display anyway. */
		if (ncp_rec) {
			proto_tree_add_text(ncp_tree, tvb, 6, 1, "Group: %s",
					ncp_groups[ncp_rec->group]);
		}

		if (ncp_rec && ncp_rec->request_ptvc) {
			clear_repeat_vars();
			process_ptvc_record(ptvc, ncp_rec->request_ptvc, NULL, TRUE, ncp_rec);
		}
		ptvcursor_free(ptvc);

		/* Now that the dissection is done, do we need to run
		 * some display filters on the resulting tree in order
		 * to save results for "request conditions" ? */
		if (run_req_cond) {
			const int	*needed;
			gboolean	*results;
			dfilter_t	*dfilter;

			results = g_new0(gboolean, NUM_REQ_CONDS);
			needed = ncp_rec->req_cond_indexes;

			while (*needed != -1) {
				/* ncp_tree is not a root proto_tree, but
				 * dfilters will still work on it. */
				dfilter = req_conds[*needed].dfilter;
				results[*needed] = dfilter_apply(dfilter, ncp_tree);
				needed++;
			}

			/* Save the results so the reply packet dissection
			 * get to them. */
			request_value->req_cond_results = results;
		}

		/* Construct the info string if necessary */
		if (run_info_str) {
			GPtrArray *parray;
			int i, len;
			field_info *finfo;

			parray = proto_get_finfo_ptr_array(ncp_tree,
				*ncp_rec->req_info_str->hf_ptr);
			len = g_ptr_array_len(parray);
			if (len > 0) {
				col_set_str(pinfo->cinfo, COL_INFO, "C ");

				finfo = g_ptr_array_index(parray, 0);
				col_append_fstr(pinfo->cinfo, COL_INFO,
					(gchar*) ncp_rec->req_info_str->first_string,
					/* XXX - this only works for certain ftypes */
					fvalue_get(finfo->value));
			}
			if (len > 1) {
				for (i = 1; i < len; i++) {
					finfo = g_ptr_array_index(parray, i);
					col_append_fstr(pinfo->cinfo, COL_INFO,
						(gchar*) ncp_rec->req_info_str->repeat_string,
						/* XXX - this only works for certain ftypes */
						fvalue_get(finfo->value));
				}
			}
		}


		/* Free the temporary proto_tree */
		CLEANUP_CALL_AND_POP;
	}
}


void
dissect_ncp_reply(tvbuff_t *tvb, packet_info *pinfo,
	guint16 nw_connection, guint8 sequence, proto_tree *ncp_tree)
{
	conversation_t			*conversation;
	ncp_req_hash_value		*request_value = NULL;
	const ncp_record		*ncp_rec = NULL;
	int				*req_cond_results;
	guint8				completion_code;
	guint				length;
	ptvcursor_t			*ptvc = NULL;
	const char			*error_string;

	if (!pinfo->fd->flags.visited) {
		/* Find the conversation whence the request would have come. */
		conversation = find_conversation(&pinfo->src, &pinfo->dst,
			    PT_NCP, nw_connection, nw_connection, 0);
		if (conversation != NULL) {
			/* find the record telling us the request made that caused
			   this reply */
			request_value = ncp_hash_lookup(conversation, sequence);
			if (request_value) {
				ncp_rec = request_value->ncp_rec;
			}
			p_add_proto_data(pinfo->fd, proto_ncp, (void*) request_value);
		}
		/* else... we haven't seen an NCP Request for that conversation and sequence. */
	}
	else {
		request_value = p_get_proto_data(pinfo->fd, proto_ncp);
		if (request_value) {
			ncp_rec = request_value->ncp_rec;
		}
	}

	/* A completion code of 0 always means OK. Non-zero means failure,
	 * but each non-zero value has a different meaning. And the same value
	 * can have different meanings, depending on the ncp.func (and ncp.subfunc)
	 * value. */
	completion_code = tvb_get_guint8(tvb, 6);
	if (ncp_rec && ncp_rec->errors) {
		error_string = ncp_error_string(ncp_rec->errors, completion_code);
	}
	else if (completion_code == 0) {
		error_string = "OK";
	}
	else {
		error_string = "Not OK";
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "R %s", error_string);
	}

	if (ncp_tree) {

		/* Put the func (and maybe subfunc) from the request packet
		 * in the proto tree, but hidden. That way filters on ncp.func
		 * or ncp.subfunc will find both the requests and the replies.
		 */
		if (ncp_rec) {
			proto_tree_add_uint_format(ncp_tree, hf_ncp_func, tvb, 6, 0,
				ncp_rec->func, "Function: %d (0x%02X), %s",
				ncp_rec->func, ncp_rec->func, ncp_rec->name);
			if (ncp_requires_subfunc(ncp_rec->func)) {
				proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 6, 0,
					ncp_rec->subfunc, "SubFunction: %d (0x%02x)",
					ncp_rec->subfunc, ncp_rec->subfunc);
			}
		}

		proto_tree_add_uint_format(ncp_tree, hf_ncp_completion_code, tvb, 6, 1,
			completion_code, "Completion Code: %d (0x%02x), %s",
			completion_code, completion_code, error_string);

		proto_tree_add_item(ncp_tree, hf_ncp_connection_status, tvb, 7, 1, FALSE);

		length = tvb_length(tvb);
		if (!ncp_rec && length > 8) {
			proto_tree_add_text(ncp_tree, tvb, 8, length - 8,
					"No request record found. Parsing is impossible.");
		}
		else if (ncp_rec && ncp_rec->reply_ptvc) {
			/* If a non-zero completion code was found, it is
			 * legal to not have any fields, even if the packet
			 * type is defined as having fields. */
			if (completion_code != 0 && tvb_length(tvb) == 8) {
				return;
			}
			/*printf("func=0x%x subfunc=0x%x\n", ncp_rec->func, ncp_rec->subfunc);*/

			/* Any request condition results? */
			if (request_value) {
				req_cond_results = request_value->req_cond_results;
			}
			else {
				req_cond_results = NULL;
			}

			clear_repeat_vars();
			ptvc = ptvcursor_new(ncp_tree, tvb, 8);
			process_ptvc_record(ptvc, ncp_rec->reply_ptvc, req_cond_results,
					TRUE, ncp_rec);
			ptvcursor_free(ptvc);
		}
	}
}
