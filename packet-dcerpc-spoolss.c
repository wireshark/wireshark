/* packet-dcerpc-spoolss.c
 * Routines for SMB \PIPE\spoolss packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-spoolss.c,v 1.6 2002/03/20 09:09:07 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <string.h>

#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-spoolss.h"
#include "packet-dcerpc-reg.h"
#include "smb.h"

/*
 * Hash table for matching responses to replies
 */

#define REQUEST_HASH_INIT_COUNT 100

static GHashTable *request_hash;
static GMemChunk *request_hash_key_chunk;
static GMemChunk *request_hash_value_chunk;

typedef struct {
	dcerpc_info di;
	guint16 opnum;
} request_hash_key;

typedef struct {
	guint16 opnum;		/* Tag for union */

	guint32 request_num;	/* Request frame number */
	guint32 response_num;	/* Response frame number */

	/* Per-request information */

	union {
		struct {
			char *printer_name;
		} OpenPrinterEx;
		struct {
			int level;
		} GetPrinter;
	} data;

} request_hash_value;

/* Hash a request */

static guint hash_request(gconstpointer k)
{
	request_hash_key *r = (request_hash_key *)k;

	return r->di.smb_fid + r->di.call_id + r->di.smb_fid;
}

/* Compare two requests */

static gint compare_request(gconstpointer k1, gconstpointer k2)
{
	request_hash_key *r1 = (request_hash_key *)k1;
	request_hash_key *r2 = (request_hash_key *)k2;

	return r1->opnum == r2->opnum && r1->di.call_id == r2->di.call_id &&
		r1->di.smb_fid == r2->di.smb_fid && 
		r1->di.conv->index == r2->di.conv->index;
}

/* Store private information for a SPOOLSS request */

static void store_request_info(request_hash_key *key, 
			       request_hash_value *value)
{
	request_hash_key *chunk_key;
	request_hash_value *chunk_value;

	chunk_key = g_mem_chunk_alloc(request_hash_key_chunk);
	chunk_value = g_mem_chunk_alloc(request_hash_value_chunk);

	memcpy(chunk_key, key, sizeof(*key));
	memcpy(chunk_value, value, sizeof(*value));

	g_hash_table_insert(request_hash, chunk_key, chunk_value);
}

/* Store private information for a SPOOLSS call with no private
   information.  This is basically for updating the request/response frame
   numbers. */

#define SPOOLSS_DUMMY (guint16)-1 /* Dummy opnum */

static void store_request_info_none(packet_info *pinfo, dcerpc_info *di)
{
	request_hash_key key;
	request_hash_value value;

	memcpy(&key.di, di, sizeof(*di));
	key.opnum = SPOOLSS_DUMMY;

	value.opnum = SPOOLSS_DUMMY;
	value.request_num = pinfo->fd->num;
	value.response_num = 0;

	store_request_info(&key, &value);
}

/* Store private information for a OpenPrinterEx request */

static void store_request_info_OpenPrinterEx(packet_info *pinfo,
					     dcerpc_info *di,
					     char *printer_name)
{
	request_hash_key key;
	request_hash_value value;

	memcpy(&key.di, di, sizeof(*di));
	key.opnum = SPOOLSS_OPENPRINTEREX;

	value.opnum = SPOOLSS_OPENPRINTEREX;
	value.data.OpenPrinterEx.printer_name = strdup(printer_name);
	value.request_num = pinfo->fd->num;
	value.response_num = 0;

	store_request_info(&key, &value);
}

/* Store private information for a GetPrinter request */

static void store_request_info_GetPrinter(packet_info *pinfo,
					  dcerpc_info *di,
					  int level)
{
	request_hash_key key;
	request_hash_value value;

	memcpy(&key.di, di, sizeof(*di));
	key.opnum = SPOOLSS_GETPRINTER;

	value.opnum = SPOOLSS_GETPRINTER;
	value.data.GetPrinter.level = level;
	value.request_num = pinfo->fd->num;
	value.response_num = 0;

	store_request_info(&key, &value);
}

/* Fetch private information for a SPOOLSS request */

static request_hash_value *fetch_request_info(packet_info *pinfo, 
					      dcerpc_info *di,
					      guint16 opnum)
{
	request_hash_key key;
	request_hash_value *result;

	key.di = *di;
	key.opnum = opnum;

	result = g_hash_table_lookup(request_hash, &key);

	if (result && result->opnum != opnum)
		g_warning("Tag for response packet at frame %d is %d, not %d",
			  pinfo->fd->num, result->opnum, opnum);
	
	return result;
}

/* Add a text item like "Response in frame %d" using some request_info */

static void add_request_text(proto_tree *tree, tvbuff_t *tvb, int offset,
			     request_hash_value *request_info)
{
	if (request_info && request_info->response_num)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Response in frame %d",
				    request_info->response_num);
}

/* Add a text item like "Request in frame %d" using some request_info */

static void add_response_text(proto_tree *tree, tvbuff_t *tvb, int offset,
			     request_hash_value *request_info)
{
	if (request_info && request_info->request_num)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %d",
				    request_info->request_num);
}

/*
 * Hash table for matching policy handles to printer names 
 */

static int printer_ndx;		/* Hack for printer names */

#define POLICY_HND_HASH_INIT_COUNT 100

static GHashTable *policy_hnd_hash;
static GMemChunk *policy_hnd_hash_key_chunk;
static GMemChunk *policy_hnd_hash_value_chunk;

typedef struct {
	guint8 policy_hnd[20];
} policy_hnd_hash_key;

typedef struct {
	char *printer_name;
} policy_hnd_hash_value;

static void dump_policy_hnd(const guint8 *policy_hnd)
{
	int i, csum = 0;

	for(i = 0; i < 20; i++) {
		fprintf(stderr, "%02x ", policy_hnd[i]);
		csum += policy_hnd[i];
	}

	fprintf(stderr, "- %d\n", csum);
}

static guint hash_policy_hnd(gconstpointer k)
{
        policy_hnd_hash_key *p = (policy_hnd_hash_key *)k;
	guint hash;

	/* Bytes 4-7 of the policy handle are a timestamp so should make a
	   reasonable hash value */

	hash = p->policy_hnd[4] + (p->policy_hnd[5] << 8) +
		(p->policy_hnd[6] << 16) + (p->policy_hnd[7] << 24);

	return hash;
}

static gint compare_policy_hnd(gconstpointer k1, gconstpointer k2)
{
	policy_hnd_hash_key *p1 = (policy_hnd_hash_key *)k1;
	policy_hnd_hash_key *p2 = (policy_hnd_hash_key *)k2;

	return memcmp(p1->policy_hnd, p2->policy_hnd, 20) == 0;
}

static gboolean is_null_policy_hnd(const guint8 *policy_hnd)
{
	static guint8 null_policy_hnd[20];

	return memcmp(policy_hnd, null_policy_hnd, 20) == 0;
}

/* Associate a policy handle with a printer name */

static void store_printer_name(const guint8 *policy_hnd, char *printer_name)
{
	policy_hnd_hash_key *key;
	policy_hnd_hash_value *value;

	if (is_null_policy_hnd(policy_hnd))
		return;
	
	key = g_mem_chunk_alloc(policy_hnd_hash_key_chunk);
	value = g_mem_chunk_alloc(policy_hnd_hash_value_chunk);

	memcpy(key->policy_hnd, policy_hnd, 20);
	value->printer_name = strdup(printer_name);

	g_hash_table_insert(policy_hnd_hash, key, value);
}

/* Retrieve a printer name from a policy handle */

static char *fetch_printer_name(const guint8 *policy_hnd)
{
	policy_hnd_hash_key key;
	policy_hnd_hash_value *value;
	
	if (is_null_policy_hnd(policy_hnd))
		return NULL;

	memcpy(&key.policy_hnd, policy_hnd, 20);

	value = g_hash_table_lookup(policy_hnd_hash, &key);

	if (value)
		return value->printer_name;

	return NULL;
}

/* Delete the association between a policy handle and printer name */

static void delete_printer_name(guint8 *policy_hnd)
{
}

/* Read a policy handle and append the printer name associated with it to
   the packet info column */

static void append_printer_name(packet_info *pinfo, tvbuff_t *tvb,
				int offset, const guint8 *policy_hnd)
{
	if (check_col(pinfo->cinfo, COL_INFO)) {
		char *printer_name;
		
		printer_name = fetch_printer_name(policy_hnd);

		if (printer_name)
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
					printer_name);
	}
}

/* 
 * New system for handling pointers and buffers.  We act more like the NDR
 * specification and have a list of deferred pointers which are processed
 * after a structure has been parsed.  
 *
 * Each structure has a parse function which takes as an argument a GList.
 * As pointers are processed, they are appended onto this list.  When the
 * structure is complete, the pointers (referents) are processed by calling
 * prs_referents().  In the case of function arguments, the
 * prs_struct_and_referents() function is called as pointers are always
 * processed immediately after the argument.
 */

typedef int prs_fn(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, GList **dp_list, void **data);

/* Deferred referent */

struct deferred_ptr {
	prs_fn *fn;		/* Parse function to call */
	proto_tree *tree;	/* Tree context */
};

/* A structure to hold needed ethereal state to pass to GList foreach
   iterator. */

struct deferred_ptr_state {
	tvbuff_t *tvb;
	int *poffset;
	packet_info *pinfo;
	GList **dp_list;
	void **ptr_data;
};

void defer_ptr(GList **list, prs_fn *fn, proto_tree *tree)
{
	struct deferred_ptr *dr;

	dr = g_malloc(sizeof(struct deferred_ptr));

	dr->fn = fn;
	dr->tree = tree;
	
	*list = g_list_append(*list, dr);
}

/* Parse a pointer */

static int prs_ptr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, guint32 *data, char *name)
{
	guint32 ptr;

	offset = prs_uint32(tvb, offset, pinfo, tree, &ptr, NULL);

	if (tree && name)
		proto_tree_add_text(tree, tvb, offset - 4, 4, 
				    "%s pointer: 0x%08x", name, ptr);

	if (data)
		*data = ptr;

	return offset;
}

/* Iterator function for prs_referents */

static void dr_iterator(gpointer data, gpointer user_data)
{
	struct deferred_ptr *dp = (struct deferred_ptr *)data;
	struct deferred_ptr_state *s = (struct deferred_ptr_state *)user_data;

	/* Parse pointer */

	*s->poffset = dp->fn(s->tvb, *s->poffset, s->pinfo, dp->tree, 
			     s->dp_list, s->ptr_data);

	if (s->ptr_data)
		s->ptr_data++;		/* Ready for next parse fn */
}

/* Call the parse function for each element in the deferred pointers list.
   If there are any additional pointers in these structures they are pushed
   onto parent_dp_list. */ 

int prs_referents(tvbuff_t *tvb, int offset, packet_info *pinfo,
		  proto_tree *tree, GList **dp_list, GList **list,
		  void ***ptr_data)
{
	struct deferred_ptr_state s;
	int new_offset = offset;

	/* Create a list of void pointers to store return data */

	if (ptr_data) {
		int len = g_list_length(*dp_list) * sizeof(void *);

		if (len > 0) {
			*ptr_data = malloc(len);
			memset(*ptr_data, 0, len);
		} else
			*ptr_data = NULL;
	}

	/* Set up iterator data */

	s.tvb = tvb;
	s.poffset = &new_offset;
	s.pinfo = pinfo;
	s.dp_list = dp_list;
	s.ptr_data = ptr_data ? *ptr_data : NULL;

	g_list_foreach(*list, dr_iterator, &s);	

	*list = NULL;		/* XXX: free list */

	return new_offset;
}

/* Parse a structure then clean up any deferred referants it creates. */

static int prs_struct_and_referents(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    prs_fn *fn, void **data, void ***ptr_data)
{
	GList *dp_list = NULL;

	offset = fn(tvb, offset, pinfo, tree, &dp_list, data);

	offset = prs_referents(tvb, offset, pinfo, tree, &dp_list,
			       &dp_list, ptr_data);

	return offset;
}

/* Parse a Win32 error, basically a DOS error.  The spoolss API doesn't
   use NT status codes. */

static int prs_werror(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, guint32 *data)
{
	guint32 status;

	offset = prs_uint32(tvb, offset, pinfo, tree, &status, NULL);

	if (tree)
		proto_tree_add_text(tree, tvb, offset - 4, 4, "Status: %s",
				    val_to_str(status, DOS_errors, 
					       "Unknown error"));

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				val_to_str(status, DOS_errors, 
					   "Unknown error"));

	if (data)
		*data = status;

	return offset;
}

/*
 * SpoolssClosePrinter
 */

static int SpoolssClosePrinter_q(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree, 
				 char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	const guint8 *policy_hnd;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "ClosePrinter request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, &policy_hnd);

	append_printer_name(pinfo, tvb, offset, policy_hnd);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

static int SpoolssClosePrinter_r(tvbuff_t *tvb, int offset, 
				 packet_info *pinfo, proto_tree *tree, 
				 char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "ClosePrinter response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

/* Parse a UNISTR2 structure */

static gint ett_UNISTR2 = -1;

static int prs_UNISTR2_dp(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 length, the_offset, max_len;
	int old_offset = offset;
	int data16_offset;
	char *text;
	
	offset = prs_uint32(tvb, offset, pinfo, tree, &length, NULL);
	offset = prs_uint32(tvb, offset, pinfo, tree, &the_offset, NULL);
	offset = prs_uint32(tvb, offset, pinfo, tree, &max_len, NULL);

	offset = prs_uint16s(tvb, offset, pinfo, tree, max_len, &data16_offset,
			     NULL);
	
	text = fake_unicode(tvb, data16_offset, max_len);

	item = proto_tree_add_text(tree, tvb, old_offset, offset - old_offset,
				   "UNISTR2: %s", text);

	subtree = proto_item_add_subtree(item, ett_UNISTR2);	

	if (data)
		*data = text;
	else
		g_free(text);

	proto_tree_add_text(subtree, tvb, old_offset, 4, "Length: %u", length);

	old_offset += 4;

	proto_tree_add_text(subtree, tvb, old_offset, 4, "Offset: %u", 
			    the_offset);

	old_offset += 4;

	proto_tree_add_text(subtree, tvb, old_offset, 4, "Max length: %u",
			    max_len);

	old_offset += 4;

	proto_tree_add_text(subtree, tvb, old_offset, max_len * 2, "Data");

	return offset;
}

/*
 * SpoolssGetPrinterData
 */

static int SpoolssGetPrinterData_q(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	char *value_name;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "GetPrinterData request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&value_name,
					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", value_name);

	g_free(value_name);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Size");

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

static int SpoolssGetPrinterData_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;
	guint32 size, type;

	/* Update information fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "GetPrinterData response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_uint32(tvb, offset, pinfo, tree, &type, NULL);
  
	proto_tree_add_text(tree, tvb, offset - 4, 4, "Type: %s",
			    val_to_str(type, reg_datatypes, "Unknown type"));

	offset = prs_uint32(tvb, offset, pinfo, tree, &size, "Size");
  
	offset = prs_uint8s(tvb, offset, pinfo, tree, size, NULL, "Data");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

/*
 * SpoolssGetPrinterDataEx
 */

static int SpoolssGetPrinterDataEx_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	char *key_name, *value_name;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "GetPrinterDataEx request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&key_name,
					  NULL);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&value_name,
					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s/%s", 
				key_name, value_name);

	g_free(key_name);
	g_free(value_name);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Size");

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

static int SpoolssGetPrinterDataEx_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	guint32 size, type;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "GetPrinterDataEx response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_uint32(tvb, offset, pinfo, tree, &type, NULL);
  
	proto_tree_add_text(tree, tvb, offset - 4, 4, "Type: %s",
			    val_to_str(type, reg_datatypes, "Unknown type"));

	offset = prs_uint32(tvb, offset, pinfo, tree, &size, "Size");
  
	offset = prs_uint8s(tvb, offset, pinfo, tree, size, NULL, "Data");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

/*
 * SpoolssSetPrinterData
 */

static int SpoolssSetPrinterData_q(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	char *value_name;
	guint32 type, max_len;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "SetPrinterData request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&value_name,
					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", value_name);

	g_free(value_name);

	offset = prs_uint32(tvb, offset, pinfo, tree, &type, NULL);

	proto_tree_add_text(tree, tvb, offset - 4, 4, "Type: %s",
			    val_to_str(type, reg_datatypes, "Unknown type"));

	offset = prs_uint32(tvb, offset, pinfo, tree, &max_len, "Max length");

	offset = prs_uint8s(tvb, offset, pinfo, tree, max_len, NULL,
			    "Data");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Real length");

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

static int SpoolssSetPrinterData_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "SetPrinterData response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

/*
 * SpoolssSetPrinterDataEx
 */

static int SpoolssSetPrinterDataEx_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;
	char *key_name, *value_name;
	guint32 type, max_len;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "SetPrinterDataEx request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&key_name,
					  NULL);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&value_name,
					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s/%s",
				key_name, value_name);

	g_free(key_name);
	g_free(value_name);

	offset = prs_uint32(tvb, offset, pinfo, tree, &type, NULL);

	proto_tree_add_text(tree, tvb, offset - 4, 4, "Type: %s",
			    val_to_str(type, reg_datatypes, "Unknown type"));

	offset = prs_uint32(tvb, offset, pinfo, tree, &max_len, "Max length");

	offset = prs_uint8s(tvb, offset, pinfo, tree, max_len, NULL,
			    "Data");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Real length");

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

static int SpoolssSetPrinterDataEx_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "SetPrinterDataEx response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

/* Yet another way to represent a unicode string - sheesh. */

static int prs_uint16uni(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void **data, char *name)
{
	gint len = 0, remaining, i;
	char *text;

	offset = prs_align(offset, 2);

	/* Get remaining data in buffer as a string */

	remaining = tvb_length_remaining(tvb, offset)/2;
	text = fake_unicode(tvb, offset, remaining);
	len = strlen(text);

	if (name) 
		proto_tree_add_text(tree, tvb, offset, (len + 1) * 2, 
				    "%s: %s", name ? name : "UINT16UNI", 
				    text);

	if (data)
		*data = text;
	else
		g_free(text);

	return offset + (len + 1) * 2;
}

/*
 * DEVMODE
 */

static gint ett_DEVMODE = -1;

static int prs_DEVMODE(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;
	guint16 extra;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DEVMODE");

	subtree = proto_item_add_subtree(item, ett_DEVMODE);

	offset = prs_uint16uni(tvb, offset, pinfo, subtree, NULL, "Devicename");

	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Spec version");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Driver version");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Size");
	offset = prs_uint16(tvb, offset, pinfo, subtree, &extra, "Driver extra");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Fields");

	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Orientation");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Paper size");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Paper length");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Paper width");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Scale");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Copies");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Default source");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Print quality");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Color");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Duplex");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Y resolution");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "TT option");
	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Collate");

	offset = prs_uint16s(tvb, offset, pinfo, subtree, 32, NULL, "Buffer");

	offset = prs_uint16uni(tvb, offset, pinfo, subtree, NULL, "Form name");

	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Log pixels");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Bits per pel");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Pels width");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Pels height");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Display flags");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Display frequency");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "ICM method");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "ICM intent");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Media type");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Dither type");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Reserved");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Reserved");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Panning width");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Panning height");
	
	if (extra != 0)
		offset = prs_uint8s(tvb, offset, pinfo, subtree, extra, NULL,
				    "Private");

	return offset;
}

/*
 * Relative string given by offset into the current buffer.  Note that
 * the offset for subsequent relstrs are against the structure start, not
 * the point where the offset is parsed from.
 */

static gint ett_RELSTR = -1;

static int prs_relstr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, GList **dp_list, int struct_start,
		      void **data, char *name)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 relstr_offset, relstr_start, relstr_end;
	guint16 *ptr;
	char *text = strdup("NULL");
	gint len = 0, remaining, i;

	offset = prs_uint32(tvb, offset, pinfo, tree, &relstr_offset, NULL);

	/* A relative offset of zero is a NULL string */

	relstr_start = relstr_offset + struct_start;
               
	if (relstr_offset)
		relstr_end = prs_uint16uni(tvb, relstr_start, pinfo, tree, 
					   (void **)&text, NULL);
	else
		relstr_end = offset;
	
	item = proto_tree_add_text(tree, tvb, relstr_start, 
				   relstr_end - relstr_start, "%s: %s", 
				   name ? name : "RELSTR", text);

	subtree = proto_item_add_subtree(item, ett_RELSTR);

	if (data)
		*data = text;
	else
		g_free(text);

	proto_tree_add_text(subtree, tvb, offset - 4, 4, 
			    "Relative offset: %d", relstr_offset);

	proto_tree_add_text(subtree, tvb, relstr_start, 
			    relstr_end - relstr_start, "Data");

	return offset;
}

/*
 * PRINTER_INFO_0
 */

static gint ett_PRINTER_INFO_0 = -1;

static int prs_PRINTER_INFO_0(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, GList **dp_list, void **data)
{
	int struct_start = offset;

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Printer name");
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Server name");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "CJobs");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Total jobs");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Total bytes");

	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Year");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Month");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Day of week");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Day");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Hour");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Minute");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Second");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Milliseconds");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Global counter");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Total pages");

	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Major version");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Build version");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Session counter");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Printer errors");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Change id");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Status");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "C_setprinter");

	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Unknown");

	return offset;
}

/*
 * PRINTER_INFO_1
 */

static gint ett_PRINTER_INFO_1 = -1;

static int prs_PRINTER_INFO_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, GList **dp_list, void **data)
{
	return offset;
}

/*
 * PRINTER_INFO_2
 */

static gint ett_PRINTER_INFO_2 = -1;

static int prs_PRINTER_INFO_2(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, GList **dp_list, void **data)
{
	int struct_start = offset;
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Server name");
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Printer name");
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Share name");
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
                           NULL, "Port name");
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Driver name");
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Comment");
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Location");
	
	return offset;
}

/*
 * PRINTER_INFO_3
 */

static gint ett_PRINTER_INFO_3 = -1;

static int prs_PRINTER_INFO_3(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, GList **dp_list, void **data)
{
	return offset;
}

/*
 * DEVMODE_CTR
 */

static gint ett_DEVMODE_CTR = -1;

static int prs_DEVMODE_CTR(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DEVMODE_CTR");

	subtree = proto_item_add_subtree(item, ett_DEVMODE_CTR);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Size");
		
	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Devicemode");

	if (ptr)
		defer_ptr(dp_list, prs_DEVMODE, subtree);

	return offset;
}

/*
 * PRINTER_DEFAULT structure
 */

static gint ett_PRINTER_DEFAULT = -1;

static int prs_PRINTER_DEFAULT(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			       proto_tree *tree, GList **dp_list, void **data)
{
	GList *child_dp_list = NULL;
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0, access;

	item = proto_tree_add_text(tree, tvb, offset, 0, "PRINTER_DEFAULT");

	subtree = proto_item_add_subtree(item, ett_PRINTER_DEFAULT);

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Datatype");

	/* Not sure why this isn't a deferred pointer.  I think this may be
	   two structures stuck together. */

	if (ptr)
		offset = prs_UNISTR2_dp(tvb, offset, pinfo, subtree, dp_list, 
					NULL);

	offset = prs_DEVMODE_CTR(tvb, offset, pinfo, subtree,
				 &child_dp_list, NULL);
		
	offset = prs_uint32(tvb, offset, pinfo, subtree, &access, NULL);

	proto_tree_add_text(subtree, tvb, offset - 4, 4, 
			    "Access required: 0x%08x", access);

	offset = prs_referents(tvb, offset, pinfo, subtree, dp_list,
			       &child_dp_list, NULL);

	return offset;
}

/*
 * USER_LEVEL_1 structure
 */

static gint ett_USER_LEVEL_1 = -1;

static int prs_USER_LEVEL_1(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			    proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;

	item = proto_tree_add_text(tree, tvb, offset, 0, "USER_LEVEL_1");

	subtree = proto_item_add_subtree(item, ett_USER_LEVEL_1);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Size");

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Client name");

	if (ptr)
		defer_ptr(dp_list, prs_UNISTR2_dp, subtree);

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "User name");

	if (ptr)
		defer_ptr(dp_list, prs_UNISTR2_dp, subtree);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Build");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Major");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Minor");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Processor");
	
	return offset;
}

/*
 * USER_LEVEL structure
 */

static gint ett_USER_LEVEL = -1;

static int prs_USER_LEVEL(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			  proto_tree *tree, GList **parent_dp_list,
			  void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;
	guint32 level;

	item = proto_tree_add_text(tree, tvb, offset, 0, "USER_LEVEL");

	subtree = proto_item_add_subtree(item, ett_USER_LEVEL);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &level, "Info level");

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "User level");

	if (ptr) {
		switch (level) {
		case 1:
			defer_ptr(parent_dp_list, prs_USER_LEVEL_1, subtree);
			break;
		default:
			proto_tree_add_text(
				tree, tvb, offset, 0, 
				"[GetPrinter level %d not decoded]", level);
			break;
		}
	}

	return offset;
}

/*
 * SpoolssOpenPrinterEx
 */

static int SpoolssOpenPrinterEx_q(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree, 
				  char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	char *printer_name;
	guint32 ptr = 0;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "OpenPrinterEx request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_OPENPRINTEREX);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);

	/* Parse packet */

	offset = prs_ptr(tvb, offset, pinfo, tree, &ptr, "Printer name");

	if (ptr) {
		char *printer_name;

		offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
						  prs_UNISTR2_dp, 
						  (void **)&printer_name,
						  NULL); 

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
					printer_name);
		
		if (!request_info) {

			/* Store printer name to match with response packet */

			store_request_info_OpenPrinterEx(pinfo, di, 
							 printer_name);
		}

		g_free(printer_name);
	}

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_PRINTER_DEFAULT, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "User switch");

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_USER_LEVEL, NULL, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

static int SpoolssOpenPrinterEx_r(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree, 
				  char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;
	int start_offset = offset;
	guint32 status;

	/* Display informational data */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "OpenPrinterEx response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_OPENPRINTEREX);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_werror(tvb, offset, pinfo, tree, &status);

	if (status == 0) {
		const guint8 *policy_hnd;

		/* Associate the returned printer handle with a name */

		policy_hnd = tvb_get_ptr(tvb, start_offset, 20);

		if (request_info) {
			char *printer_name;

			printer_name = 
				request_info->data.OpenPrinterEx.printer_name;

			if (printer_name)
				store_printer_name(policy_hnd, printer_name);
		}
	}

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

/*
 * NOTIFY_OPTION_DATA structure
 */

static gint ett_NOTIFY_OPTION_DATA = -1;

static int prs_NOTIFY_OPTION_DATA(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  GList **parent_dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 count, i;

	item = proto_tree_add_text(tree, tvb, offset, 0, "NOTIFY_OPTION_DATA");

	subtree = proto_item_add_subtree(item, ett_NOTIFY_OPTION_DATA);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &count, "Count");

	for (i = 0; i < count; i++)
		offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, 
				    "Field");

	return offset;
}

/*
 * NOTIFY_OPTION structure
 */

static gint ett_NOTIFY_OPTION = -1;

static int prs_NOTIFY_OPTION(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			     proto_tree *tree, GList **parent_dp_list,
			     void **data) 
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;

	item = proto_tree_add_text(tree, tvb, offset, 0, "NOTIFY_OPTION");

	subtree = proto_item_add_subtree(item, ett_NOTIFY_OPTION);

	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Type");

	offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Reserved");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Reserved");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Reserved");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Count");

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Fields");

	if (ptr)
		defer_ptr(parent_dp_list, prs_NOTIFY_OPTION_DATA, subtree);

	return offset;
}

/*
 * NOTIFY_OPTION_CTR structure
 */

static gint ett_NOTIFY_OPTION_CTR = -1;

static int prs_NOTIFY_OPTION_CTR(tvbuff_t *tvb, int offset, 
				 packet_info *pinfo, proto_tree *tree,
				 GList **dp_list, void **data)
{
	GList *child_dp_list = NULL;
	proto_item *item;
	proto_tree *subtree;
	guint32 count, i, ptr;

	item = proto_tree_add_text(tree, tvb, offset, 0, 
				   "NOTIFY_OPTION_CTR");

	subtree = proto_item_add_subtree(item, ett_NOTIFY_OPTION_CTR);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &count, "Count");

	for (i = 0; i < count; i++)
		offset = prs_NOTIFY_OPTION(tvb, offset, pinfo, subtree, 
					   &child_dp_list, NULL);

	offset = prs_referents(tvb, offset, pinfo, subtree, dp_list,
			       &child_dp_list, NULL);

	return offset;
}

/*
 * NOTIFY_OPTION structure
 */

gint ett_NOTIFY_OPTION_ARRAY = -1;

static int prs_NOTIFY_OPTION_ARRAY(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;

	item = proto_tree_add_text(tree, tvb, offset, 0, 
				   "NOTIFY_OPTION_ARRAY");

	subtree = proto_item_add_subtree(item, ett_NOTIFY_OPTION_ARRAY);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Version");
	
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Flags");
	
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Count");
	
	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Option type");

	if (ptr)
		defer_ptr(dp_list, prs_NOTIFY_OPTION_CTR, subtree);

	return offset;
}

/*
 * SpoolssRFFPCNEX
 */

static int SpoolssRFFPCNEX_q(tvbuff_t *tvb, int offset, 
			     packet_info *pinfo, proto_tree *tree, 
			     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	char *printer_name;
	guint32 ptr = 0;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "RFFPCNEX request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Flags");
	
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Options");
	
	offset = prs_ptr(tvb, offset, pinfo, tree, &ptr, "Local machine");

	if (ptr) {
		offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
						  prs_UNISTR2_dp,
						  (void *)&printer_name, NULL);

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
					printer_name);
		g_free(printer_name);
	}

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Printer local");
	
	offset = prs_ptr(tvb, offset, pinfo, tree, &ptr, "Option");
	
	if (ptr) {
		offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
						  prs_NOTIFY_OPTION_ARRAY,
						  NULL, NULL);
	}
	
	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

static int SpoolssRFFPCNEX_r(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree, 
			     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "RFFPCNEX response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}

/*
 * SpoolssReplyOpenPrinter
 */

static int SpoolssReplyOpenPrinter_q(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	guint32 ptr = 0, type;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "ReplyOpenPrinter request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Printer");

	offset = prs_uint32(tvb, offset, pinfo, tree, &type, NULL);

	proto_tree_add_text(tree, tvb, offset - 4, 4, "Type: %s",
			    val_to_str(type, reg_datatypes, "Unknown type"));

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");	

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

static int SpoolssReplyOpenPrinter_r(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "ReplyOpenPrinter response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

/*
 * BUFFER_DATA
 */

static gint ett_BUFFER_DATA = -1;
static gint ett_BUFFER_DATA_BUFFER = -1;

struct BUFFER_DATA {
	proto_item *item;	/* proto_item holding proto_tree */
	proto_tree *tree;	/* proto_tree holding buffer data */
	tvbuff_t *tvb;		
	int offset;		/* Offset where data starts in tvb*/
};

static int prs_BUFFER_DATA(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item, *subitem;
	proto_tree *subtree, *subsubtree;
	guint32 ptr = 0, size;
	int data8_offset;

	item = proto_tree_add_text(tree, tvb, offset, 0, "BUFFER_DATA");

	subtree = proto_item_add_subtree(item, ett_BUFFER_DATA);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &size, "Size");

	subitem = proto_tree_add_text(subtree, tvb, offset, size, "Data");

	subsubtree = proto_item_add_subtree(subitem, ett_BUFFER_DATA_BUFFER);

	offset = prs_uint8s(tvb, offset, pinfo, subsubtree, size,
			    &data8_offset, NULL);

	/* Return some info which will help the caller "cast" the buffer
	   data and dissect it further. */

	if (data) {
		struct BUFFER_DATA *bd;

		bd = (struct BUFFER_DATA *)malloc(sizeof(struct BUFFER_DATA));

		bd->item = subitem;
		bd->tree = subsubtree;
		bd->tvb = tvb;
		bd->offset = data8_offset;

		*data = bd;
	}

	return offset;
}

/*
 * BUFFER
 */

static gint ett_BUFFER = -1;

static int prs_BUFFER(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0;

	item = proto_tree_add_text(tree, tvb, offset, 0, "BUFFER");

	subtree = proto_item_add_subtree(item, ett_BUFFER);

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Data");

	if (ptr)
		defer_ptr(dp_list, prs_BUFFER_DATA, subtree);

	return offset;
}

/*
 * SpoolssGetPrinter
 */

static int SpoolssGetPrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;
	guint32 level;
	const guint8 *policy_hnd;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "GetPrinter request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_GETPRINTER);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, &policy_hnd);

	append_printer_name(pinfo, tvb, offset, policy_hnd);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, NULL, NULL);

	if (!request_info) {
		
		/* Store info level to match with response packet */

		store_request_info_GetPrinter(pinfo, di, level);
	}

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Offered");

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

static int SpoolssGetPrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;
	void **data_list;
	struct BUFFER_DATA *bd = NULL;
	guint8 *data8;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "GetPrinter response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_GETPRINTER);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, (void **)&data8, 
					  &data_list);

	if (data_list)
		bd = (struct BUFFER_DATA *)data_list[0];

	if (bd && bd->tree && request_info) {
		gint16 level = request_info->data.GetPrinter.level;

		proto_item_append_text(bd->item, ", PRINTER_INFO_%d", level);

		switch (level) {
		case 0:
			prs_PRINTER_INFO_0(bd->tvb, bd->offset, pinfo, 
					   bd->tree, &dp_list, NULL);
			break;
			
		case 2:
			prs_PRINTER_INFO_2(bd->tvb, bd->offset, pinfo,
					   bd->tree, &dp_list, NULL);
			break;

		default:
			proto_tree_add_text(tree, tvb, offset, 0,
					    "[Unimplemented info level %d]",
					    level);
			break;
		}
	}

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

/*
 * SPOOL_PRINTER_INFO_LEVEL
 */

static gint ett_SPOOL_PRINTER_INFO_LEVEL = -1;

static int prs_SPOOL_PRINTER_INFO_LEVEL(tvbuff_t *tvb, int offset, 
					packet_info *pinfo, proto_tree *tree, 
					GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0, level;

	item = proto_tree_add_text(tree, tvb, offset, 0, 
				   "SPOOL_PRINTER_INFO_LEVEL");

	subtree = proto_item_add_subtree(item, ett_SPOOL_PRINTER_INFO_LEVEL);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &level, "Level");

	/* ptr */

	switch(level) {
	}

	return offset;
}

/*
 * SpoolssSetPrinter
 */

static int SpoolssSetPrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;
	guint32 level;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "SetPrinter request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	/* printer_info_level */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_SPOOL_PRINTER_INFO_LEVEL,
					  NULL, NULL);

	/* devmode_ctr */


	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Command");

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

static int SpoolssSetPrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "SetPrinter response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

/*
 * SpoolssEnumForms
 */

static int SpoolssEnumForms_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;
	guint32 level;
	const guint8 *policy_hnd;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "EnumForms request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, &policy_hnd);
	
	append_printer_name(pinfo, tvb, offset, policy_hnd);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Offered");

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

static int SpoolssEnumForms_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	GList *dp_list = NULL;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "EnumForms response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					   prs_BUFFER, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Num entries");

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);	

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

/*
 * SpoolssDeletePrinter
 */

static int SpoolssDeletePrinter_q(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree, 
				  char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	const guint8 *policy_hnd;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "DeletePrinter request");
	
	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, &policy_hnd);

	append_printer_name(pinfo, tvb, offset, policy_hnd);
	
	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

static int SpoolssDeletePrinter_r(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree, 
				  char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "DeletePrinter response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

/*
 * AddPrinterEx
 */

static int SpoolssAddPrinterEx_q(tvbuff_t *tvb, int offset, 
                                 packet_info *pinfo, proto_tree *tree, 
                                 char *drep)
{
       dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
       request_hash_value *request_info;
       guint32 ptr;
       char *printer_name;

       /* Update informational fields */

       if (check_col(pinfo->cinfo, COL_INFO))
               col_set_str(pinfo->cinfo, COL_INFO, "AddPrinterEx request");

       request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

       if (request_info)
               add_request_text(tree, tvb, offset, request_info);
       else 
               store_request_info_none(pinfo, di);

       /* Parse packet */

       offset = prs_ptr(tvb, offset, pinfo, tree, &ptr, "Server name");

       if (ptr) {
               offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
                                                 prs_UNISTR2_dp,
                                                 (void *)&printer_name, NULL);
               g_free(printer_name);
       }

       offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Level");
       
       /* PRINTER INFO LEVEL */

       offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
       offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
       offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
       offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");

       offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "User switch");

       /* USER LEVEL */

       if (tvb_length_remaining(tvb, offset) != 0)
               proto_tree_add_text(tree, tvb, offset, 0, 
                                   "[Long frame (%d bytes): SPOOLSS]",
                                   tvb_length_remaining(tvb, offset));

       return offset;
}      

static int SpoolssAddPrinterEx_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	int start_offset = offset;
	guint32 status;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "AddPrinterEx response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, NULL);

	offset = prs_werror(tvb, offset, pinfo, tree, &status);	

	if (status == 0) {
		const guint8 *policy_hnd;
		char *printer_name;

		/* Associate the returned printer handle with a name */

		policy_hnd = tvb_get_ptr(tvb, start_offset, 20);

		printer_name = g_strdup("<printer name here>");

		store_printer_name(policy_hnd, printer_name);

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", 
					printer_name);

		g_free(printer_name);
	}

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

/*
 * SpoolssEnumPrinterData
 */

static int SpoolssEnumPrinterData_q(tvbuff_t *tvb, int offset, 
				    packet_info *pinfo, proto_tree *tree, 
				    char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	const guint8 *policy_hnd;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "EnumPrinterData request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, tree, &policy_hnd);

	append_printer_name(pinfo, tvb, offset, policy_hnd);
	
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Index");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Value size");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Data size");

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

static int SpoolssEnumPrinterData_r(tvbuff_t *tvb, int offset, 
				    packet_info *pinfo, proto_tree *tree, 
				    char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	guint32 data_size, type, value_size;
	int uint16s_offset;
	char *text;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "EnumPrinterData response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_uint32(tvb, offset, pinfo, tree, &value_size, 
			    "Value size");
	
	offset = prs_uint16s(tvb, offset, pinfo, tree, value_size,
			     &uint16s_offset, NULL);
	
	text = fake_unicode(tvb, uint16s_offset, value_size);
	
	proto_tree_add_text(tree, tvb, uint16s_offset,
			    value_size * 2, "Value: %s", text);
       
	if (text[0] && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", text);
	
	g_free(text);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Real value size");

	offset = prs_uint32(tvb, offset, pinfo, tree, &type, NULL);

	proto_tree_add_text(tree, tvb, offset - 4, 4, "Type: %s",
			    val_to_str(type, reg_datatypes, "Unknown type"));

	offset = prs_uint32(tvb, offset, pinfo, tree, &data_size, "Data size");

	offset = prs_uint8s(tvb, offset, pinfo, tree, data_size, NULL,
			    "Data");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Real data size");

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);	
	
	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

/*
 * SpoolssEnumPrinters
 */

static int SpoolssEnumPrinters_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;
	guint32 ptr, level;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "EnumPrinters request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Flags");

	offset = prs_ptr(tvb, offset, pinfo, tree, &ptr, "Devicemode");

	if (ptr)
		offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
						  prs_UNISTR2_dp, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");
	
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level, %d", level);
	
	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					  prs_BUFFER, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Offered");

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

static int SpoolssEnumPrinters_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "EnumPrinters response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					  prs_BUFFER, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Returned");

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);	

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

/*
 * AddPrinterDriver
 */

static int SpoolssAddPrinterDriver_q(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "AddPrinterDriver request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}      

static int SpoolssAddPrinterDriver_r(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "AddPrinterDriver response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);    

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}      

/*
 * AddForm
 */

static int SpoolssAddForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "AddForm response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;
	
	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}      

#if 0

/* Templates for new subdissectors */

/*
 * FOO
 */

static int SpoolssFoo_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Foo request");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);

	if (request_info)
		add_request_text(tree, tvb, offset, request_info);
	else 
		store_request_info_none(pinfo, di);

	/* Parse packet */

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

static int SpoolssFoo_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	request_hash_value *request_info;

	/* Update informational fields */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Foo response");

	request_info = fetch_request_info(pinfo, di, SPOOLSS_DUMMY);
	add_response_text(tree, tvb, offset, request_info);

	if (request_info)
		request_info->response_num = pinfo->fd->num;

	/* Parse packet */

	if (tvb_length_remaining(tvb, offset) != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "[Long frame (%d bytes): SPOOLSS]",
				    tvb_length_remaining(tvb, offset));

	return offset;
}	

#endif

/*
 * List of subdissectors for this pipe.
 */

static dcerpc_sub_dissector dcerpc_spoolss_dissectors[] = {
        { SPOOLSS_ENUMPRINTERS, "SPOOLSS_ENUMPRINTERS", 
	  SpoolssEnumPrinters_q, SpoolssEnumPrinters_r },
        { SPOOLSS_SETJOB, "SPOOLSS_SETJOB", NULL, NULL },
        { SPOOLSS_GETJOB, "SPOOLSS_GETJOB", NULL, NULL },
        { SPOOLSS_ENUMJOBS, "SPOOLSS_ENUMJOBS", NULL, NULL },
        { SPOOLSS_ADDPRINTER, "SPOOLSS_ADDPRINTER", NULL, NULL },
        { SPOOLSS_DELETEPRINTER, "SPOOLSS_DELETEPRINTER", 
	  SpoolssDeletePrinter_q, SpoolssDeletePrinter_r },
        { SPOOLSS_SETPRINTER, "SPOOLSS_SETPRINTER", 
	  SpoolssSetPrinter_q, SpoolssSetPrinter_r },
        { SPOOLSS_GETPRINTER, "SPOOLSS_GETPRINTER", 
	  SpoolssGetPrinter_q, SpoolssGetPrinter_r },
        { SPOOLSS_ADDPRINTERDRIVER, "SPOOLSS_ADDPRINTERDRIVER", 
	  NULL, SpoolssAddPrinterDriver_r },
        { SPOOLSS_ENUMPRINTERDRIVERS, "SPOOLSS_ENUMPRINTERDRIVERS", NULL, NULL },
        { SPOOLSS_GETPRINTERDRIVERDIRECTORY, "SPOOLSS_GETPRINTERDRIVERDIRECTORY", NULL, NULL },
        { SPOOLSS_DELETEPRINTERDRIVER, "SPOOLSS_DELETEPRINTERDRIVER", NULL, NULL },
        { SPOOLSS_ADDPRINTPROCESSOR, "SPOOLSS_ADDPRINTPROCESSOR", NULL, NULL },
        { SPOOLSS_ENUMPRINTPROCESSORS, "SPOOLSS_ENUMPRINTPROCESSORS", NULL, NULL },
        { SPOOLSS_STARTDOCPRINTER, "SPOOLSS_STARTDOCPRINTER", NULL, NULL },
        { SPOOLSS_STARTPAGEPRINTER, "SPOOLSS_STARTPAGEPRINTER", NULL, NULL },
        { SPOOLSS_WRITEPRINTER, "SPOOLSS_WRITEPRINTER", NULL, NULL },
        { SPOOLSS_ENDPAGEPRINTER, "SPOOLSS_ENDPAGEPRINTER", NULL, NULL },
        { SPOOLSS_ABORTPRINTER, "SPOOLSS_ABORTPRINTER", NULL, NULL },
        { SPOOLSS_ENDDOCPRINTER, "SPOOLSS_ENDDOCPRINTER", NULL, NULL },
        { SPOOLSS_ADDJOB, "SPOOLSS_ADDJOB", NULL, NULL },
        { SPOOLSS_SCHEDULEJOB, "SPOOLSS_SCHEDULEJOB", NULL, NULL },
        { SPOOLSS_GETPRINTERDATA, "SPOOLSS_GETPRINTERDATA", 
	  SpoolssGetPrinterData_q, SpoolssGetPrinterData_r },	
        { SPOOLSS_SETPRINTERDATA, "SPOOLSS_SETPRINTERDATA", 
	  SpoolssSetPrinterData_q, SpoolssSetPrinterData_r },
        { SPOOLSS_CLOSEPRINTER, "SPOOLSS_CLOSEPRINTER", 
	  SpoolssClosePrinter_q, SpoolssClosePrinter_r },
        { SPOOLSS_ADDFORM, "SPOOLSS_ADDFORM", 
	  NULL, SpoolssAddForm_r },
        { SPOOLSS_DELETEFORM, "SPOOLSS_DELETEFORM", NULL, NULL },
        { SPOOLSS_GETFORM, "SPOOLSS_GETFORM", NULL, NULL },
        { SPOOLSS_SETFORM, "SPOOLSS_SETFORM", NULL, NULL },
        { SPOOLSS_ENUMFORMS, "SPOOLSS_ENUMFORMS", 
	  SpoolssEnumForms_q, SpoolssEnumForms_r },
        { SPOOLSS_ENUMPORTS, "SPOOLSS_ENUMPORTS", NULL, NULL },
        { SPOOLSS_ENUMMONITORS, "SPOOLSS_ENUMMONITORS", NULL, NULL },
        { SPOOLSS_ENUMPRINTPROCDATATYPES, "SPOOLSS_ENUMPRINTPROCDATATYPES", NULL, NULL },
        { SPOOLSS_GETPRINTERDRIVER2, "SPOOLSS_GETPRINTERDRIVER2", NULL, NULL },
        { SPOOLSS_FCPN, "SPOOLSS_FCPN", NULL, NULL },
        { SPOOLSS_REPLYOPENPRINTER, "SPOOLSS_REPLYOPENPRINTER", 
	  SpoolssReplyOpenPrinter_q, SpoolssReplyOpenPrinter_r },
        { SPOOLSS_REPLYCLOSEPRINTER, "SPOOLSS_REPLYCLOSEPRINTER", NULL, NULL },
        { SPOOLSS_RFFPCNEX, "SPOOLSS_RFFPCNEX",
	  SpoolssRFFPCNEX_q, SpoolssRFFPCNEX_r },
        { SPOOLSS_RRPCN, "SPOOLSS_RRPCN", NULL, NULL },
        { SPOOLSS_RFNPCNEX, "SPOOLSS_RFNPCNEX", NULL, NULL },
        { SPOOLSS_OPENPRINTEREX, "SPOOLSS_OPENPRINTEREX", 
	  SpoolssOpenPrinterEx_q, SpoolssOpenPrinterEx_r },
        { SPOOLSS_ADDPRINTEREX, "SPOOLSS_ADDPRINTEREX", 
	  NULL, SpoolssAddPrinterEx_r },
        { SPOOLSS_ENUMPRINTERDATA, "SPOOLSS_ENUMPRINTERDATA", 
	  SpoolssEnumPrinterData_q, SpoolssEnumPrinterData_r },
        { SPOOLSS_DELETEPRINTERDATA, "SPOOLSS_DELETEPRINTERDATA", NULL, NULL },
        { SPOOLSS_GETPRINTERDATAEX, "SPOOLSS_GETPRINTERDATAEX", 
	  SpoolssGetPrinterDataEx_q, SpoolssGetPrinterDataEx_r },
        { SPOOLSS_SETPRINTERDATAEX, "SPOOLSS_SETPRINTERDATAEX", 
	  SpoolssSetPrinterDataEx_q, SpoolssSetPrinterDataEx_r },

        {0, NULL, NULL,  NULL },
};

/*
 * Dissector initialisation function
 */

static void spoolss_init(void)
{
	/* Initialise policy handle to printer name hash table */

	if (policy_hnd_hash_key_chunk)
		g_mem_chunk_destroy(policy_hnd_hash_key_chunk);

	if (policy_hnd_hash_value_chunk)
		g_mem_chunk_destroy(policy_hnd_hash_value_chunk);

	policy_hnd_hash_key_chunk = g_mem_chunk_new(
		"policy_hnd_hash_key_chunk", sizeof(policy_hnd_hash_key),
		POLICY_HND_HASH_INIT_COUNT * sizeof(policy_hnd_hash_key),
		G_ALLOC_ONLY);

	policy_hnd_hash_value_chunk = g_mem_chunk_new(
		"policy_hnd_hash_value_chunk", sizeof(policy_hnd_hash_value),
		POLICY_HND_HASH_INIT_COUNT * sizeof(policy_hnd_hash_value),
		G_ALLOC_ONLY);

	policy_hnd_hash = g_hash_table_new(hash_policy_hnd,
					   compare_policy_hnd);

	/* Initialise request/response matching hash table */

	if (request_hash_key_chunk)
		g_mem_chunk_destroy(request_hash_key_chunk);

	request_hash_key_chunk = g_mem_chunk_new(
		"request_hash_key_chunk", sizeof(request_hash_key),
		REQUEST_HASH_INIT_COUNT * sizeof(request_hash_key),
		G_ALLOC_ONLY);

	request_hash_value_chunk = g_mem_chunk_new(
		"request_hash_value_chunk", sizeof(request_hash_value),
		REQUEST_HASH_INIT_COUNT * sizeof(request_hash_value),
		G_ALLOC_ONLY);

	request_hash = g_hash_table_new(hash_request, compare_request);
}

/* Protocol registration */

static int proto_dcerpc_spoolss = -1;
static gint ett_dcerpc_spoolss = -1;

void 
proto_register_dcerpc_spoolss(void)
{
        static gint *ett[] = {
                &ett_dcerpc_spoolss,
		&ett_NOTIFY_OPTION_ARRAY,
		&ett_NOTIFY_OPTION_CTR,
		&ett_NOTIFY_OPTION,
		&ett_NOTIFY_OPTION_DATA,
		&ett_PRINTER_DEFAULT,
		&ett_DEVMODE_CTR,
		&ett_DEVMODE,
		&ett_USER_LEVEL,
		&ett_USER_LEVEL_1,
		&ett_BUFFER,
		&ett_BUFFER_DATA,
		&ett_BUFFER_DATA_BUFFER,
		&ett_UNISTR2,
		&ett_SPOOL_PRINTER_INFO_LEVEL,
		&ett_PRINTER_INFO_0,
		&ett_PRINTER_INFO_1,
		&ett_PRINTER_INFO_2,
		&ett_PRINTER_INFO_3,
		&ett_RELSTR,
        };

        proto_dcerpc_spoolss = proto_register_protocol(
                "Microsoft Spool Subsystem", "SPOOLSS", "spoolss");

        proto_register_subtree_array(ett, array_length(ett));

	register_init_routine(spoolss_init);
}

/* Protocol handoff */

static e_uuid_t uuid_dcerpc_spoolss = {
        0x12345678, 0x1234, 0xabcd,
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab }
};

static guint16 ver_dcerpc_spoolss = 1;

void
proto_reg_handoff_dcerpc_spoolss(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_spoolss, ett_dcerpc_spoolss, 
                         &uuid_dcerpc_spoolss, ver_dcerpc_spoolss, 
                         dcerpc_spoolss_dissectors);
}
