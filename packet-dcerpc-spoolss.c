/* packet-dcerpc-spoolss.c
 * Routines for SMB \PIPE\spoolss packet disassembly
 * Copyright 2001-2002, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-spoolss.c,v 1.29 2002/05/13 01:27:07 tpot Exp $
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
#include "packet-smb-common.h"

/* Global objects */

static int hf_spoolss_hnd = -1;
static int hf_spoolss_rc = -1;
static int hf_spoolss_offered = -1;
static int hf_spoolss_needed = -1;
static int hf_spoolss_returned = -1;
static int hf_spoolss_buffer_size = -1;
static int hf_spoolss_buffer_data = -1;
static int hf_spoolss_relstr_offset = -1;
static int hf_spoolss_printername = -1;
static int hf_spoolss_servername = -1;
static int hf_spoolss_username = -1;
static int hf_spoolss_documentname = -1;
static int hf_spoolss_outputfile = -1;
static int hf_spoolss_datatype = -1;
static int hf_spoolss_textstatus = -1;
static int hf_spoolss_level = -1;

/* Print job */

static int hf_spoolss_jobid = -1;
static int hf_spoolss_jobstatus = -1;
static int hf_spoolss_jobpriority = -1;
static int hf_spoolss_jobposition = -1;
static int hf_spoolss_jobtotalpages = -1;
static int hf_spoolss_jobpagesprinted = -1;
static int hf_spoolss_enumjobs_firstjob = -1;
static int hf_spoolss_enumjobs_numjobs = -1;

/* SYSTEM_TIME */

static int hf_spoolss_time_year = -1;
static int hf_spoolss_time_month = -1;
static int hf_spoolss_time_dow = -1;
static int hf_spoolss_time_day = -1;
static int hf_spoolss_time_hour = -1;
static int hf_spoolss_time_minute = -1;
static int hf_spoolss_time_second = -1;
static int hf_spoolss_time_msec = -1;

/* Printer data */

static int hf_spoolss_printerdata_name = -1;
static int hf_spoolss_printerdata_size = -1;

/* SetJob */

static int hf_spoolss_setjob_cmd = -1;

/* 
 * Routines to dissect a spoolss BUFFER 
 */

typedef struct {
	guint32 size;		/* Size of buffer */
	guint8 *data;		/* Contents of buffer */
	int offset;		/* Offset to start of buffer */
	proto_item *tree;	/* Proto tree buffer located in */
} BUFFER;

static int
dissect_spoolss_buffer_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep)
{
	dcerpc_info *di = pinfo->private_data;
	BUFFER *b = (BUFFER *)di->private_data;
	guint32 size;
	guint8 *data;

	/* Dissect size and data */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_buffer_size, &size);

	offset = dissect_ndr_uint8s(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_buffer_data, size, &data);

	/* Return buffer info */

	if (b) {
		b->size = size;
		b->data = data;
		b->offset = offset - size;
		b->tree = tree;
	}

	return offset;
}

static int
dissect_spoolss_buffer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		       proto_tree *tree, char *drep, BUFFER *b)
{
	dcerpc_info *di = pinfo->private_data;

	if (b)
		memset(b, 0, sizeof(BUFFER));

	di->private_data = b;

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
				     dissect_spoolss_buffer_data,
				     NDR_POINTER_UNIQUE, "Buffer",
				     -1, 0);

	return offset;
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

static void defer_ptr(GList **list, prs_fn *fn, proto_tree *tree)
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

static int prs_referents(tvbuff_t *tvb, int offset, packet_info *pinfo,
		  proto_tree *tree _U_, GList **dp_list, GList **list,
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

/* Display a policy handle in the protocol tree */

static gint ett_POLICY_HND = -1;

static void display_pol(proto_tree *tree, tvbuff_t *tvb, int offset, 
			const guint8 *policy_hnd)
{
	proto_item *item;
	char *pol_name = NULL;
	int pol_open_frame = 0, pol_close_frame = 0;
	proto_tree *subtree;

	dcerpc_smb_fetch_pol(policy_hnd, &pol_name, &pol_open_frame,
			     &pol_close_frame);

	item = proto_tree_add_text(tree, tvb, offset, 20, 
				   "Policy handle%s%s", 
				   pol_name ? ": " : "", 
				   pol_name ? pol_name : "");

	subtree = proto_item_add_subtree(item, ett_POLICY_HND);

	if (pol_open_frame)
		proto_tree_add_text(subtree, tvb, offset, 0,
				    "Opened in frame %u", pol_open_frame);

	if (pol_close_frame)
		proto_tree_add_text(subtree, tvb, offset, 0,
				    "Closed in frame %u", pol_close_frame);

	proto_tree_add_text(subtree, tvb, offset, 20, "Policy Handle: %s",
			    tvb_bytes_to_str(tvb, offset, 20));
}

/*
 * SpoolssClosePrinter
 */

static int SpoolssClosePrinter_q(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree, 
				 char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);
	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, TRUE);

	dcerpc_smb_fetch_pol((const guint8 *)&policy_hnd, &pol_name, 0, 0);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	dcerpc_smb_store_pol((const guint8 *)&policy_hnd, NULL, 0, pinfo->fd->num);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssClosePrinter_r(tvbuff_t *tvb, int offset, 
				 packet_info *pinfo, proto_tree *tree, 
				 char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);
	

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

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
				   char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *value_name = NULL;
	e_ctx_hnd policy_hnd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_spoolss_hnd, &policy_hnd,
		FALSE, FALSE);

 	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
 					  prs_UNISTR2_dp, (void **)&value_name,
 					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", value_name);

	g_free(value_name);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_printerdata_size, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssGetPrinterData_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 size, type;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_uint32(tvb, offset, pinfo, tree, &type, NULL);
  
	proto_tree_add_text(tree, tvb, offset - 4, 4, "Type: %s",
			    val_to_str(type, reg_datatypes, "Unknown type"));

	offset = prs_uint32(tvb, offset, pinfo, tree, &size, "Size");
  
	offset = prs_uint8s(tvb, offset, pinfo, tree, size, NULL, "Data");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssGetPrinterDataEx
 */

static int SpoolssGetPrinterDataEx_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *key_name, *value_name;
	const guint8 *policy_hnd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&key_name,
					  NULL);

	/*
	 * Register a cleanup function in case on of our tvbuff accesses
	 * throws an exception. We need to clean up key_name.
	 */
	CLEANUP_PUSH(g_free, key_name);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, (void **)&value_name,
					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s/%s", 
				key_name, value_name);

	/*
	 * We're done with key_name, so we can call the cleanup handler to
	 * free it, and then pop the cleanup handler.
	 */
	CLEANUP_CALL_AND_POP;

	/*
	 * We're also done with value_name.
	 */
	g_free(value_name);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Size");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssGetPrinterDataEx_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 size, type;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_uint32(tvb, offset, pinfo, tree, &type, NULL);
  
	proto_tree_add_text(tree, tvb, offset - 4, 4, "Type: %s",
			    val_to_str(type, reg_datatypes, "Unknown type"));

	offset = prs_uint32(tvb, offset, pinfo, tree, &size, "Size");
  
	offset = prs_uint8s(tvb, offset, pinfo, tree, size, NULL, "Data");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssSetPrinterData
 */

static int SpoolssSetPrinterData_q(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *value_name = NULL;
	guint32 type, max_len;
	const guint8 *policy_hnd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

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

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssSetPrinterData_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssSetPrinterDataEx
 */

static int SpoolssSetPrinterDataEx_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *key_name, *value_name;
	guint32 type, max_len;
	const guint8 *policy_hnd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

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

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssSetPrinterDataEx_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/* Yet another way to represent a unicode string - sheesh. This function
   dissects a NULL terminate unicode string at the current offset and
   returns the (char *) equivalent.  This really should return UTF8 or
   something but we use fake_unicode() instead. */

static int
dissect_spoolss_uint16uni(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, char *drep, char **data)
{
	gint len, remaining;
	char *text;

	if (offset % 2)
		offset += 2 - (offset % 2);

	/* Get remaining data in buffer as a string */

	remaining = tvb_length_remaining(tvb, offset) / 2;
	text = fake_unicode(tvb, offset, remaining);
	len = strlen(text);

	proto_tree_add_text(tree, tvb, offset, len * 2, "%s: %s",
			    "UINT16UNI", tvb_bytes_to_str(tvb, offset, len * 2));

	if (data)
		*data = text;
	else
		g_free(text);

	return offset + (len + 1) * 2;
}

static int prs_uint16uni(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			 proto_tree *tree, void **data, char *name)
{
	gint len = 0, remaining;
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
	guint16 extra;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DEVMODE");

	subtree = proto_item_add_subtree(item, ett_DEVMODE);

 	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Size");

	/* The device name is stored in a 32-wchar buffer */

	prs_uint16uni(tvb, offset, pinfo, subtree, NULL, "Devicename");
	offset += 64;

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

	prs_uint16uni(tvb, offset, pinfo, subtree, NULL, "Form name");
	offset += 64;

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

static int
dissect_spoolss_relstr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, char *drep, int hf_index,
		       int struct_start, char **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 relstr_offset, relstr_start, relstr_end, relstr_len;
	char *text;

	item = proto_tree_add_string(tree, hf_index, tvb, offset, 4, "");

	subtree = proto_item_add_subtree(item, ett_RELSTR);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_relstr_offset,
				    &relstr_offset);
	
	/* A relative offset of zero is a NULL string */

	relstr_start = relstr_offset + struct_start;
               
	if (relstr_offset)
		relstr_end = dissect_spoolss_uint16uni(
			tvb, relstr_start, pinfo, subtree, drep, &text);
	else {
		text = g_strdup("NULL");
		relstr_end = offset;
	}

	relstr_len = relstr_end - relstr_start;

	proto_item_append_text(item, text);

	if (data)
		*data = text;
	else
		g_free(text);
					       
	return offset;
}

static int prs_relstr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, GList **dp_list, int struct_start,
		      void **data, char *name)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 relstr_offset, relstr_start, relstr_end;
	char *text = strdup("NULL");

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
	int struct_start = offset;

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Flags");
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Description");
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Name");
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Comment");
	
	return offset;
}

/*
 * PRINTER_INFO_2
 */

static gint ett_PRINTER_INFO_2 = -1;

static int prs_PRINTER_INFO_2(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, int len, GList **dp_list, 
			      void **data)
{
	int struct_start = offset;
	guint32 rel_offset;
	
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

	/* This is a relative devicemode */

	offset = prs_uint32(tvb, offset, pinfo, tree, &rel_offset, NULL);

	prs_DEVMODE(tvb, struct_start + rel_offset - 4, pinfo, tree, 
		    dp_list, NULL);
	
	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Separator file");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Print processor");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Datatype");

	offset = prs_relstr(tvb, offset, pinfo, tree, dp_list, struct_start,
			    NULL, "Parameters");

	/* This is a relative security descriptor */

	offset = prs_uint32(tvb, offset, pinfo, tree, &rel_offset, NULL);

	/*
	 * XXX - what *is* the length of this security descriptor?
	 * "prs_PRINTER_INFO_2()" is passed to "defer_ptr()", but
	 * "defer_ptr" takes, as an argument, a function with a
	 * different calling sequence from "prs_PRINTER_INFO_2()",
	 * lacking the "len" argument, so that won't work.
	 */
	dissect_nt_sec_desc(tvb, struct_start + rel_offset, tree, len);
	
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Attributes");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Priority");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, 
			    "Default priority");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Start time");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "End time");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Status");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Jobs");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Average PPM");

	return offset;
}

/*
 * PRINTER_INFO_3
 */

static gint ett_PRINTER_INFO_3 = -1;

static int prs_PRINTER_INFO_3(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, int len, GList **dp_list, 
			      void **data)
{
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Flags");

	offset = dissect_nt_sec_desc(tvb, offset, tree, len);

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
		offset = prs_DEVMODE(tvb, offset, pinfo, subtree, dp_list, 
				     data);

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
				  char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 ptr = 0;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

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
		
		/* Store printer name to match with reply packet */

		dcv->private_data = printer_name;
	}

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_PRINTER_DEFAULT, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "User switch");

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_USER_LEVEL, NULL, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssOpenPrinterEx_r(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree, 
				  char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 status;
	const guint8 *policy_hnd;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_werror(tvb, offset, pinfo, tree, &status);

	if (status == 0) {

		/* Associate the returned printer handle with a name */

		if (dcv->private_data) {
			dcerpc_smb_store_pol(policy_hnd, dcv->private_data,
					     pinfo->fd->num, 0);

			g_free(dcv->private_data);
			dcv->private_data = NULL;
		}
	}

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

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
	guint32 count, i;

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
			     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *printer_name;
	guint32 ptr = 0;
	const guint8 *policy_hnd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

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
	
	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int SpoolssRFFPCNEX_r(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree, 
			     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * SpoolssReplyOpenPrinter
 */

static int SpoolssReplyOpenPrinter_q(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 type;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_UNISTR2_dp, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Printer");

	offset = prs_uint32(tvb, offset, pinfo, tree, &type, NULL);

	proto_tree_add_text(tree, tvb, offset - 4, 4, "Type: %s",
			    val_to_str(type, reg_datatypes, "Unknown type"));

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");	

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssReplyOpenPrinter_r(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	const guint8 *policy_hnd;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

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
	int size;		/* Size of buffer data */
};

static int prs_BUFFER_DATA(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item, *subitem;
	proto_tree *subtree, *subsubtree;
	guint32 size;
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
		bd->size = size;

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
			       proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;
	const guint8 *policy_hnd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, NULL, NULL);

	dcv->private_data = (void *)level;

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Offered");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssGetPrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	GList *dp_list = NULL;
	void **data_list;
	struct BUFFER_DATA *bd = NULL;
	gint16 level = (guint32)dcv->private_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, NULL, &data_list);

	if (data_list)
		bd = (struct BUFFER_DATA *)data_list[0];

	if (bd && bd->tree) {
		proto_item_append_text(bd->item, ", PRINTER_INFO_%d", level);

		switch (level) {
		case 0:
			prs_PRINTER_INFO_0(bd->tvb, bd->offset, pinfo, 
					   bd->tree, &dp_list, NULL);
			break;
			
		case 1:
			prs_PRINTER_INFO_1(bd->tvb, bd->offset, pinfo, 
					   bd->tree, &dp_list, NULL);
			break;
			
		case 2:
			prs_PRINTER_INFO_2(bd->tvb, bd->offset, pinfo,
					   bd->tree, bd->size, &dp_list, NULL);
			break;

		case 3:
			prs_PRINTER_INFO_3(bd->tvb, bd->offset, pinfo,
					   bd->tree, bd->size, &dp_list, NULL);
			break;

		default:
			proto_tree_add_text(bd->tree, tvb, offset, 0,
					    "[Unknown info level %d]", level);
			break;
		}
	}

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * SEC_DESC_BUF
 */

static gint ett_SEC_DESC_BUF = -1;

static int prs_SEC_DESC_BUF(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, GList **dp_list, void **Data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 len;

	item = proto_tree_add_text(tree, tvb, offset, 0, "SEC_DESC_BUF");

	subtree = proto_item_add_subtree(item, ett_SEC_DESC_BUF);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &len, "Max length");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Undocumented");
	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Length");
	
	dissect_nt_sec_desc(tvb, offset, subtree, len);

	offset += len;

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
	guint32 level;

	item = proto_tree_add_text(tree, tvb, offset, 0, 
				   "SPOOL_PRINTER_INFO_LEVEL");

	subtree = proto_item_add_subtree(item, ett_SPOOL_PRINTER_INFO_LEVEL);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &level, "Level");

	switch(level) {
	case 3: {
		guint32 ptr;

		offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr,
				 "Devicemode container");

		if (ptr)
			defer_ptr(dp_list, prs_DEVMODE_CTR, subtree);

		offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr,
				 "Security descriptor");

		if (ptr)
			defer_ptr(dp_list, prs_SEC_DESC_BUF, subtree);
	
		break;
	}
	case 2: {
		guint32 ptr;

		offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Info");

		if (ptr)
			defer_ptr(dp_list, prs_PRINTER_INFO_2, subtree);

		break;
	}
	default:
		proto_tree_add_text(subtree, tvb, offset, 0,
				    "[Unknown info level %d]", level);
		break;		
	}

done:
	return offset;
}

/*
 * SpoolssSetPrinter
 */

static int SpoolssSetPrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;
	const guint8 *policy_hnd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_SPOOL_PRINTER_INFO_LEVEL,
					  NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Command");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssSetPrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * FORM_REL
 */

static const value_string form_type_vals[] =
{
	{ FORM_USER, "FORM_USER" },
	{ FORM_BUILTIN, "FORM_BUILTIN" },
	{ FORM_PRINTER, "FORM_PRINTER" },
	{ 0, NULL }
};

static gint ett_FORM_REL = -1;

static int prs_FORM_REL(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, int struct_start, GList **dp_list, 
			void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 flags;

	item = proto_tree_add_text(tree, tvb, offset, 0, "FORM_REL");

	subtree = proto_item_add_subtree(item, ett_FORM_REL);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &flags, NULL);

	proto_tree_add_text(subtree, tvb, offset - 4, 4, "Flags: %s",
			    val_to_str(flags, form_type_vals, "Unknown type"));

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list,
			    struct_start, NULL, "Name");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Width");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Height");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
			    "Left margin");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
			    "Top margin");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
			    "Horizontal imageable length");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
			    "Vertical imageable length");

	return offset;
}

/*
 * SpoolssEnumForms
 */

static int SpoolssEnumForms_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;
	const guint8 *policy_hnd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);
	
	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	dcv->private_data = (void *)level;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
					  prs_BUFFER, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Offered");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssEnumForms_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 count;
	struct BUFFER_DATA *bd = NULL;
	void **data_list;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					   prs_BUFFER, NULL, &data_list);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_uint32(tvb, offset, pinfo, tree, &count, "Num entries");

	if (data_list)
		bd = (struct BUFFER_DATA *)data_list[0];

	CLEANUP_PUSH(g_free, bd);

	if (bd && bd->tree) {
		guint32 level = (guint32)dcv->private_data, i;
		GList *child_dp_list = NULL;

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

		proto_item_append_text(bd->item, ", FORM_%d", level);

		/* Unfortunately this array isn't in NDR format so we can't
		   use prs_array().  The other weird thing is the
		   struct_start being inside the loop rather than outside.
		   Very strange. */

		for (i = 0; i < count; i++) {
			int struct_start = bd->offset;

			bd->offset = prs_FORM_REL(
				bd->tvb, bd->offset, pinfo, bd->tree, 
				struct_start, &child_dp_list, NULL);
		}

	}

	CLEANUP_CALL_AND_POP;

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);	

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * SpoolssDeletePrinter
 */

static int SpoolssDeletePrinter_q(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree, 
				  char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	const guint8 *policy_hnd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);
	
	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssDeletePrinter_r(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree, 
				  char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	const guint8 *policy_hnd;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * AddPrinterEx
 */
#if 0
static int SpoolssAddPrinterEx_q(tvbuff_t *tvb, int offset, 
                                 packet_info *pinfo, proto_tree *tree, 
                                 char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 ptr;
	
	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */
	
	offset = prs_ptr(tvb, offset, pinfo, tree, &ptr, "Server name");
	
	if (ptr) {
		char *printer_name;

		offset = prs_struct_and_referents(tvb, offset, pinfo, tree,
						  prs_UNISTR2_dp,
						  (void *)&printer_name, NULL);

		if (printer_name)
			dcv->private_data = printer_name;
	}
	
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Level");
	
	/* TODO: PRINTER INFO LEVEL */
	
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Unknown");
	
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "User switch");
	
	/* TODO: USER LEVEL */
	
	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);
	
	return offset;
}      
#endif
static int SpoolssAddPrinterEx_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 status;
	const guint8 *policy_hnd;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_werror(tvb, offset, pinfo, tree, &status);	

	if (status == 0) {

		/* Associate the returned printer handle with a name */

		if (dcv->private_data) {

			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(
					pinfo->cinfo, COL_INFO, ", %s", 
					(char *)dcv->private_data);

			dcerpc_smb_store_pol(
				policy_hnd, dcv->private_data, pinfo->fd->num, 0);

			g_free(dcv->private_data);
			dcv->private_data = NULL;
		}
	}

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * SpoolssEnumPrinterData
 */

static int SpoolssEnumPrinterData_q(tvbuff_t *tvb, int offset, 
				    packet_info *pinfo, proto_tree *tree, 
				    char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	const guint8 *policy_hnd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);
	
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Index");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Value size");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Data size");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssEnumPrinterData_r(tvbuff_t *tvb, int offset, 
				    packet_info *pinfo, proto_tree *tree, 
				    char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 data_size, type, value_size;
	int uint16s_offset;
	char *text;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

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
	
	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * SpoolssEnumPrinters
 */

static int SpoolssEnumPrinters_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 ptr, level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

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

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssEnumPrinters_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					  prs_BUFFER, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Returned");

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);	

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * AddPrinterDriver
 */
#if 0
static int SpoolssAddPrinterDriver_q(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}      
#endif
static int SpoolssAddPrinterDriver_r(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);    

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}      

/*
 * FORM_1
 */

static gint ett_FORM_1 = -1;

static int prs_FORM_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 ptr = 0, flags;

	item = proto_tree_add_text(tree, tvb, offset, 0, "FORM_1");

	subtree = proto_item_add_subtree(item, ett_FORM_1);

	offset = prs_ptr(tvb, offset, pinfo, subtree, &ptr, "Name");

	if (ptr)
		defer_ptr(dp_list, prs_UNISTR2_dp, subtree);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &flags, NULL);

	proto_tree_add_text(subtree, tvb, offset - 4, 4, "Flags: %s",
			    val_to_str(flags, form_type_vals, "Unknown type"));

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Unknown");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Width");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Height");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
			    "Left margin");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
			    "Top margin");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
			    "Horizontal imageable length");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
			    "Vertical imageable length");

	return offset;
}

/*
 * FORM_CTR
 */

static gint ett_FORM_CTR = -1;

static int prs_FORM_CTR(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 level;

	item = proto_tree_add_text(tree, tvb, offset, 0, "FORM_CTR");

	subtree = proto_item_add_subtree(item, ett_FORM_CTR);

	offset = prs_uint32(tvb, offset, pinfo, subtree, &level, "Level");

	switch(level) {
	case 1:
		offset = prs_struct_and_referents(tvb, offset, pinfo, subtree,
						  prs_FORM_1, NULL, NULL);
		break;
	default:
		proto_tree_add_text(subtree, tvb, offset, 0,
				    "[Unknown info level %d]", level);
		break;
	}

	return offset;
}

/*
 * AddForm
 */

static int SpoolssAddForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	const guint8 *policy_hnd;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");	

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	/* Store info level to match with reply packet */

	dcv->private_data = (void *)level;

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					  prs_FORM_CTR, NULL, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssAddForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}      

/*
 * DeleteForm
 */

static int SpoolssDeleteForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	const guint8 *policy_hnd;
	char *form_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					  prs_UNISTR2_dp, (void **)&form_name,
					  NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", form_name);

	g_free(form_name);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssDeleteForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * SetForm
 */

static int SpoolssSetForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	const guint8 *policy_hnd;
	guint32 level;
	char *form_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					  prs_UNISTR2_dp, (void **)&form_name,
					  NULL);	

	CLEANUP_PUSH(g_free, form_name);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");	

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, level %d", 
				form_name, level);

	CLEANUP_CALL_AND_POP;

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					  prs_FORM_CTR, NULL, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssSetForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}      

/*
 * GetForm
 */

static int SpoolssGetForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;
	const guint8 *policy_hnd;
	char *form_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = prs_policy_hnd(tvb, offset, pinfo, NULL, &policy_hnd);

	display_pol(tree, tvb, offset - 20, policy_hnd);

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					  prs_UNISTR2_dp, (void **)&form_name,
					  NULL);	

	CLEANUP_PUSH(g_free, form_name);

	offset = prs_uint32(tvb, offset, pinfo, tree, &level, "Level");

	dcv->private_data = (void *)level;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, level %d",
				form_name, level);

	CLEANUP_CALL_AND_POP;

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					  prs_BUFFER, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Offered");

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssGetForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	void **data_list;
	struct BUFFER_DATA *bd = NULL;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = prs_struct_and_referents(tvb, offset, pinfo, tree, 
					  prs_BUFFER, NULL, &data_list);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Needed");

	if (data_list)
		bd = (struct BUFFER_DATA *)data_list[0];

	CLEANUP_PUSH(g_free, bd);

	if (bd && bd->tree) {
		guint32 level = (guint32)dcv->private_data;

		switch(level) {
		case 1: {
			int struct_start = bd->offset;
			GList *dp_list = NULL;

			bd->offset = prs_FORM_REL(
				bd->tvb, bd->offset, pinfo, bd->tree, 
				struct_start, &dp_list, NULL);
			break;
		}
		default:
			proto_tree_add_text(
				bd->tree, bd->tvb, bd->offset, 0, 
				"[Unknown info level %d]", level);
			break;
		}

	}

	CLEANUP_CALL_AND_POP;

	offset = prs_werror(tvb, offset, pinfo, tree, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/* A generic reply function that just parses the status code.  Useful for
   unimplemented dissectors so the status code can be inserted into the
   INFO column. */

static int SpoolssGeneric_r(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			    proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	int len = tvb_length(tvb);

	proto_tree_add_text(tree, tvb, offset, 0, 
			    "[Unimplemented dissector: SPOOLSS]");

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	prs_werror(tvb, len - 4, pinfo, tree, NULL);

	return offset;
}

/*
 * SYSTEM_TIME
 */

static gint ett_SYSTEM_TIME;

static int
dissect_spoolss_SYSTEM_TIME(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			    proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint16 year, month, day, hour, minute, second;

	item = proto_tree_add_text(tree, tvb, offset, 16, "SYSTEM_TIME: ");

	subtree = proto_item_add_subtree(item, ett_SYSTEM_TIME);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_year, &year);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_month, &month);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_dow, NULL);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_day, &day);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_hour, &hour);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_minute, &minute);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_second, &second);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, subtree, drep,
				     hf_spoolss_time_msec, NULL);

	proto_item_append_text(item, "%d/%02d/%02d %02d:%02d:%02d", year,
			       month, day, hour, minute, second);

	return offset;
}

/*
 * JOB_INFO_1
 */

static gint ett_JOB_INFO_1;

static int
dissect_spoolss_JOB_INFO_1(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			   proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	int struct_start = offset;
	char *document_name;

	item = proto_tree_add_text(tree, tvb, offset, 0, "JOB_INFO_1");

	subtree = proto_item_add_subtree(item, ett_JOB_INFO_1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobid, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_printername,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_servername,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_username,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_documentname,
		struct_start, &document_name);

	proto_item_append_text(item, ": %s", document_name);
	g_free(document_name);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_datatype,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, drep, hf_spoolss_textstatus,
		struct_start, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobstatus, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobpriority, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobposition, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobtotalpages, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_jobpagesprinted, NULL);

	offset = dissect_spoolss_SYSTEM_TIME(tvb, offset, pinfo, subtree, 
					     drep); 

	proto_item_set_len(item, offset - struct_start);

	return offset;
}

/*
 * JOB_INFO_2
 */

static gint ett_JOB_INFO_2;

#if 0

static int prs_JOB_INFO_2(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, GList **dp_list, void **data)
{
	proto_item *item;
	proto_tree *subtree;
	int struct_start = offset;
	guint32 rel_offset;

	item = proto_tree_add_text(tree, tvb, offset, 0, "JOB_INFO_2");

	subtree = proto_item_add_subtree(item, ett_FORM_CTR);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Job ID");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Printer name");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Machine name");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "User name");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Document");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Notify name");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Data type");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Print processor");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Parameters");

	offset = prs_relstr(tvb, offset, pinfo, subtree, dp_list, struct_start,
			    NULL, "Driver name");

	offset = prs_uint32(tvb, offset, pinfo, tree, &rel_offset, NULL);

	prs_DEVMODE(tvb, struct_start + rel_offset - 4, pinfo, tree, 
		    dp_list, NULL);	

	/* XXX security descriptor */

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Security descriptor");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Status");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Priority");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Position");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Start time");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Until time");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Total pages");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Size");

	offset = prs_struct_and_referents(tvb, offset, pinfo, subtree,
					  prs_SYSTEM_TIME, NULL, NULL);

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Time elapsed");

	offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "Pages printed");

	return offset;
}

#endif

/*
 * EnumJobs
 */

static int SpoolssEnumJobs_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %d", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumjobs_firstjob, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumjobs_numjobs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_level, &level);

	dcv->private_data = (void *)level;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_offered, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssEnumJobs_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	gint16 level = (guint32)dcv->private_data;
	BUFFER buffer;
	guint32 num_jobs, i;
	int buffer_offset;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %d", dcv->req_frame);

	/* Parse packet */

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep,
					&buffer); 

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_needed, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_enumjobs_numjobs, &num_jobs);

	buffer_offset = buffer.offset;

	for (i = 0; i < num_jobs; i++) {
		switch(level) {
		case 1:
			buffer_offset = dissect_spoolss_JOB_INFO_1(
				tvb, buffer_offset, pinfo, buffer.tree, drep);
			break;
		case 2:
		default:
			proto_tree_add_text(
				buffer.tree, tvb, buffer_offset, buffer.size, 
				"[Unknown info level %d]", level);
			goto done;
		}

	}

done:
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * SetJob
 */

/* Set job command values */

#define JOB_CONTROL_PAUSE              1
#define JOB_CONTROL_RESUME             2
#define JOB_CONTROL_CANCEL             3
#define JOB_CONTROL_RESTART            4
#define JOB_CONTROL_DELETE             5

static const value_string setjob_commands[] = {
	{ JOB_CONTROL_PAUSE, "Pause" },
	{ JOB_CONTROL_RESUME, "Resume" },
	{ JOB_CONTROL_CANCEL, "Cancel" },
	{ JOB_CONTROL_RESTART, "Restart" },
	{ JOB_CONTROL_DELETE, "Delete" },
	{ 0, NULL }
};

static int SpoolssSetJob_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 jobid, cmd;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_jobid, &jobid);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_level, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_setjob_cmd, &cmd);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(
			pinfo->cinfo, COL_INFO, ", %s jobid %d",
			val_to_str(cmd, setjob_commands, "Unknown command"),
			jobid);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssSetJob_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * GetJob
 */

static int SpoolssGetJob_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level, jobid;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, NULL,
				       FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_jobid, &jobid);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_level, &level);

	dcv->private_data = (void *)level;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d, jobid %d",
				level, jobid);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_offered, NULL);	

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssGetJob_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	gint32 level = (guint32)dcv->private_data;
	BUFFER buffer;
	int buffer_offset;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, drep, 
					&buffer);

	if (!buffer.size)
		goto done;

	buffer_offset = buffer.offset;

	switch(level) {
	case 1:
		buffer_offset = dissect_spoolss_JOB_INFO_1(
			tvb, buffer_offset, pinfo, buffer.tree, drep);
		break;
	case 2:
	default:
		proto_tree_add_text(
			buffer.tree, tvb, buffer_offset, buffer.size, 
			"[Unknown info level %d]", level);
		goto done;
	}

done:
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_needed, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * StartPagePrinter
 */

static int SpoolssStartPagePrinter_q(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, FALSE);

	dcerpc_smb_fetch_pol((const guint8 *)&policy_hnd, &pol_name, 0, 0);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssStartPagePrinter_r(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * EndPagePrinter
 */

static int SpoolssEndPagePrinter_q(tvbuff_t *tvb, int offset, 
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, FALSE);

	dcerpc_smb_fetch_pol((const guint8 *)&policy_hnd, &pol_name, 0, 0);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssEndPagePrinter_r(tvbuff_t *tvb, int offset, 
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * DOC_INFO_1
 */

static gint ett_DOC_INFO_1 = -1;

static int
dissect_spoolss_doc_info_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DOC_INFO_1");

	subtree = proto_item_add_subtree(item, ett_DOC_INFO_1);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Document name", hf_spoolss_documentname, 0);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Output file", hf_spoolss_outputfile, 0);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Data type", hf_spoolss_datatype, 0);

	return offset;
}

static int
dissect_spoolss_doc_info_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, char *drep)
{
	dcerpc_info *di = pinfo->private_data;
	
	switch(di->levels) {
	case 1:
		offset = dissect_spoolss_doc_info_1(
			tvb, offset, pinfo, tree, drep);
		break;
	default:
		proto_tree_add_text(tree, tvb, offset, 0,
				    "[Unknown info level %d]", di->levels);
		break;
	}

	return offset;
}

/*
 * DOC_INFO
 */

static gint ett_DOC_INFO = -1;

static int
dissect_spoolss_doc_info(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 level;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DOC_INFO");

	subtree = proto_item_add_subtree(item, ett_DOC_INFO);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_level, &level);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, subtree, drep,
				     dissect_spoolss_doc_info_data,
				     NDR_POINTER_UNIQUE, "Document info",
				     -1, level);
	return offset;
}

/*
 * DOC_INFO_CTR
 */

static gint ett_DOC_INFO_CTR = -1;

static int
dissect_spoolss_doc_info_ctr(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, char *drep)
{
	proto_item *item;
	proto_tree *subtree;

	item = proto_tree_add_text(tree, tvb, offset, 0, "DOC_INFO_CTR");

	subtree = proto_item_add_subtree(item, ett_DOC_INFO_CTR);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
				    hf_spoolss_level, NULL);

	offset = dissect_spoolss_doc_info( 
		tvb, offset, pinfo, subtree, drep); 

	return offset;
}

/*
 * StartDocPrinter
 */

static int SpoolssStartDocPrinter_q(tvbuff_t *tvb, int offset, 
				    packet_info *pinfo, proto_tree *tree, 
				    char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, FALSE);

	dcerpc_smb_fetch_pol((const guint8 *)&policy_hnd, &pol_name, 0, 0);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	offset = dissect_spoolss_doc_info_ctr(tvb, offset, pinfo, tree, drep);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssStartDocPrinter_r(tvbuff_t *tvb, int offset, 
				    packet_info *pinfo, proto_tree *tree, 
				    char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_spoolss_jobid, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

/*
 * EndDocPrinter
 */

static int SpoolssEndDocPrinter_q(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree, 
				  char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_spoolss_hnd, &policy_hnd,
				       FALSE, FALSE);

	dcerpc_smb_fetch_pol((const guint8 *)&policy_hnd, &pol_name, 0, 0);

	if (check_col(pinfo->cinfo, COL_INFO) && pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssEndDocPrinter_r(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree, 
				  char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
				  hf_spoolss_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

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
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

static int SpoolssFoo_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0, 
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}	

#endif

/*
 * List of subdissectors for this pipe.
 */

static dcerpc_sub_dissector dcerpc_spoolss_dissectors[] = {
        { SPOOLSS_ENUMPRINTERS, "EnumPrinters", 
	  SpoolssEnumPrinters_q, SpoolssEnumPrinters_r },
	{ SPOOLSS_OPENPRINTER, "OpenPrinter", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_SETJOB, "SetJob", 
	  SpoolssSetJob_q, SpoolssSetJob_r },
        { SPOOLSS_GETJOB, "GetJob", 
	  SpoolssGetJob_q, SpoolssGetJob_r },
        { SPOOLSS_ENUMJOBS, "EnumJobs", 
	  SpoolssEnumJobs_q, SpoolssEnumJobs_r },
        { SPOOLSS_ADDPRINTER, "AddPrinter", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_DELETEPRINTER, "DeletePrinter", 
	  SpoolssDeletePrinter_q, SpoolssDeletePrinter_r },
        { SPOOLSS_SETPRINTER, "SetPrinter", 
	  SpoolssSetPrinter_q, SpoolssSetPrinter_r },
        { SPOOLSS_GETPRINTER, "GetPrinter", 
	  SpoolssGetPrinter_q, SpoolssGetPrinter_r },
        { SPOOLSS_ADDPRINTERDRIVER, "AddPrinterDriver", 
	  NULL, SpoolssAddPrinterDriver_r },
        { SPOOLSS_ENUMPRINTERDRIVERS, "EnumPrinterDrivers", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_GETPRINTERDRIVER, "GetPrinterDriver", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_GETPRINTERDRIVERDIRECTORY, "GetPrinterDriverDirectory", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_DELETEPRINTERDRIVER, "DeletePrinterDriver", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ADDPRINTPROCESSOR, "AddPrintProcessor", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ENUMPRINTPROCESSORS, "EnumPrintProcessor", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_GETPRINTPROCESSORDIRECTORY, "GetPrintProcessorDirectory", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_STARTDOCPRINTER, "StartDocPrinter", 
	  SpoolssStartDocPrinter_q, SpoolssStartDocPrinter_r },
        { SPOOLSS_STARTPAGEPRINTER, "StartPagePrinter", 
	  SpoolssStartPagePrinter_q, SpoolssStartPagePrinter_r },
        { SPOOLSS_WRITEPRINTER, "WritePrinter", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ENDPAGEPRINTER, "EndPagePrinter", 
	  SpoolssEndPagePrinter_q, SpoolssEndPagePrinter_r },
        { SPOOLSS_ABORTPRINTER, "AbortPrinter", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_READPRINTER, "ReadPrinter", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ENDDOCPRINTER, "EndDocPrinter", 
	  SpoolssEndDocPrinter_q, SpoolssEndDocPrinter_r },
        { SPOOLSS_ADDJOB, "AddJob", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_SCHEDULEJOB, "ScheduleJob", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_GETPRINTERDATA, "GetPrinterData", 
	  SpoolssGetPrinterData_q, SpoolssGetPrinterData_r },	
        { SPOOLSS_SETPRINTERDATA, "SetPrinterData", 
	  SpoolssSetPrinterData_q, SpoolssSetPrinterData_r },
	{ SPOOLSS_WAITFORPRINTERCHANGE, "WaitForPrinterChange", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_CLOSEPRINTER, "ClosePrinter", 
	  SpoolssClosePrinter_q, SpoolssClosePrinter_r },
        { SPOOLSS_ADDFORM, "AddForm", 
	  SpoolssAddForm_q, SpoolssAddForm_r },
        { SPOOLSS_DELETEFORM, "DeleteForm", 
	  SpoolssDeleteForm_q, SpoolssDeleteForm_r },
        { SPOOLSS_GETFORM, "GetForm", 
	  SpoolssGetForm_q, SpoolssGetForm_r },
        { SPOOLSS_SETFORM, "SetForm", 
	  SpoolssSetForm_q, SpoolssSetForm_r },
        { SPOOLSS_ENUMFORMS, "EnumForms", 
	  SpoolssEnumForms_q, SpoolssEnumForms_r },
        { SPOOLSS_ENUMPORTS, "EnumPorts", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ENUMMONITORS, "EnumMonitors", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPORT, "AddPort", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_CONFIGUREPORT, "ConfigurePort", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPORT, "DeletePort", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_CREATEPRINTERIC, "CreatePrinterIC", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_PLAYGDISCRIPTONPRINTERIC, "PlayDiscriptOnPrinterIC", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTERIC, "DeletePrinterIC", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPRINTERCONNECTION, "AddPrinterConnection", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTERCONNECTION, "DeletePrinterConnection", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_PRINTERMESSAGEBOX, "PrinterMessageBox", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDMONITOR, "AddMonitor", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEMONITOR, "DeleteMonitor", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTPROCESSOR, "DeletePrintProcessor", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPRINTPROVIDER, "AddPrintProvider", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTPROVIDER, "DeletePrintProvider", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_ENUMPRINTPROCDATATYPES, "EnumPrintProcDataTypes", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_RESETPRINTER, "ResetPrinter", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_GETPRINTERDRIVER2, "GetPrinterDriver2", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_FINDFIRSTPRINTERCHANGENOTIFICATION, 
	  "FindFirstPrinterChangeNotification", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_FINDNEXTPRINTERCHANGENOTIFICATION, 
	  "FindNextPrinterChangeNotification", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_FCPN, "FCPN", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ROUTERFINDFIRSTPRINTERNOTIFICATIONOLD, 
	  "RouterFindFirstPrinterNotificationOld", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_REPLYOPENPRINTER, "ReplyOpenPrinter", 
	  SpoolssReplyOpenPrinter_q, SpoolssReplyOpenPrinter_r },
	{ SPOOLSS_ROUTERREPLYPRINTER, "RouterREplyPrinter", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_REPLYCLOSEPRINTER, "ReplyClosePrinter", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPORTEX, "AddPortEx", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_REMOTEFINDFIRSTPRINTERCHANGENOTIFICATION, 
	  "RemoteFindFirstPrinterChangeNotification", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_SPOOLERINIT, "SpoolerInit", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_RESETPRINTEREX, "ResetPrinterEx", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_RFFPCNEX, "RFFPCNEX", 
	  SpoolssRFFPCNEX_q, SpoolssRFFPCNEX_r },
        { SPOOLSS_RRPCN, "RRPCN", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_RFNPCNEX, "RFNPCNEX", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_OPENPRINTEREX, "OpenPrinterEx", 
	  SpoolssOpenPrinterEx_q, SpoolssOpenPrinterEx_r },
        { SPOOLSS_ADDPRINTEREX, "AddPrinterEx", 
	  NULL, SpoolssAddPrinterEx_r },
        { SPOOLSS_ENUMPRINTERDATA, "EnumPrinterData", 
	  SpoolssEnumPrinterData_q, SpoolssEnumPrinterData_r },
        { SPOOLSS_DELETEPRINTERDATA, "DeletePrinterData", 
	  NULL, SpoolssGeneric_r },
        { SPOOLSS_GETPRINTERDATAEX, "GetPrinterDataEx", 
	  SpoolssGetPrinterDataEx_q, SpoolssGetPrinterDataEx_r },
        { SPOOLSS_SETPRINTERDATAEX, "SetPrinterDataEx", 
	  SpoolssSetPrinterDataEx_q, SpoolssSetPrinterDataEx_r },
	{ SPOOLSS_ENUMPRINTERDATAEX, "EnumPrinterDataEx", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ENUMPRINTERKEY, "EnumPrinterKey", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTERDATAEX, "DeletePrinterDataEx", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTERDRIVEREX, "DeletePrinterDriverEx", 
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPRINTERDRIVEREX, "AddPrinterDriverEx", 
	  NULL, SpoolssGeneric_r },

        { 0, NULL, NULL, NULL },
};

/*
 * Dissector initialisation function
 */

/* Protocol registration */

static int proto_dcerpc_spoolss = -1;
static gint ett_dcerpc_spoolss = -1;

void 
proto_register_dcerpc_spoolss(void)
{
        static hf_register_info hf[] = {
		{ &hf_spoolss_hnd,
		  { "Context handle", "spoolss.hnd", FT_BYTES, BASE_NONE, 
		    NULL, 0x0, "SPOOLSS policy handle", HFILL }},
		{ &hf_spoolss_rc,
		  { "Return code", "spoolss.rc", FT_UINT32, BASE_HEX, 
		    VALS(DOS_errors), 0x0, "SPOOLSS return code", HFILL }},
		{ &hf_spoolss_offered,
		  { "Offered", "spoolss.offered", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Size of buffer offered in this request", HFILL }},
		{ &hf_spoolss_needed,
		  { "Needed", "spoolss.needed", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Size of buffer required for request", HFILL }},
		{ &hf_spoolss_relstr_offset,
		  { "Relative string offset", "spoolss.relstr.offset", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Offset of relative string data", HFILL }},
		{ &hf_spoolss_printername,
		  { "Printer name", "spoolss.printername", FT_STRING, BASE_NONE,
		    NULL, 0, "Printer name", HFILL }},
		{ &hf_spoolss_servername,
		  { "Server name", "spoolss.servername", FT_STRING, BASE_NONE,
		    NULL, 0, "Server name", HFILL }},
		{ &hf_spoolss_username,
		  { "User name", "spoolss.username", FT_STRING, BASE_NONE,
		    NULL, 0, "User name", HFILL }},
		{ &hf_spoolss_documentname,
		  { "Document name", "spoolss.document", FT_STRING, BASE_NONE,
		    NULL, 0, "Document name", HFILL }},
		{ &hf_spoolss_outputfile,
		  { "Output file", "spoolss.outputfile", FT_STRING, BASE_NONE,
		    NULL, 0, "Output File", HFILL }},
		{ &hf_spoolss_datatype,
		  { "Datatype", "spoolss.Datatype", FT_STRING, BASE_NONE,
		    NULL, 0, "Datatype", HFILL }},
		{ &hf_spoolss_textstatus,
		  { "Text status", "spoolss.textstatus", FT_STRING, BASE_NONE,
		    NULL, 0, "Text status", HFILL }},
		{ &hf_spoolss_buffer_size,
		  { "Buffer size", "spoolss.buffer.size", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Size of buffer", HFILL }},
		{ &hf_spoolss_buffer_data,
		  { "Buffer data", "spoolss.buffer.data", FT_BYTES, BASE_HEX, 
		    NULL, 0x0, "Contents of buffer", HFILL }},
		{ &hf_spoolss_enumjobs_firstjob,
		  { "First job", "spoolss.enumjobs.firstjob", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Index of first job to return", HFILL }},
		{ &hf_spoolss_enumjobs_numjobs,
		  { "Num jobs", "spoolss.enumjobs.numjobs", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Number of jobs to return", HFILL }},
		{ &hf_spoolss_level,
		  { "Info level", "spoolss.enumjobs.level", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Info level", HFILL }},


		/* Print jobs */

		{ &hf_spoolss_jobid,
		  { "Job ID", "spoolss.job.id", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Job identification number", HFILL }},
		{ &hf_spoolss_jobstatus,
		  { "Job status", "spoolss.job.status", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Job status", HFILL }},
		{ &hf_spoolss_jobpriority,
		  { "Job priority", "spoolss.job.priority", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Job priority", HFILL }},
		{ &hf_spoolss_jobposition,
		  { "Job position", "spoolss.job.position", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Job position", HFILL }},
		{ &hf_spoolss_jobtotalpages,
		  { "Job total pages", "spoolss.job.totalpages", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Job total pages", HFILL }},
		{ &hf_spoolss_jobpagesprinted,
		  { "Job pages printed", "spoolss.job.pagesprinted", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Job identification number", HFILL }},

		/* SYSTEM_TIME */

		{ &hf_spoolss_time_year,
		  { "Year", "spoolss.time.year", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Year", HFILL }},
		{ &hf_spoolss_time_month,
		  { "Month", "spoolss.time.month", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Month", HFILL }},
		{ &hf_spoolss_time_dow,
		  { "Day of week", "spoolss.time.dow", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Day of week", HFILL }},
		{ &hf_spoolss_time_day,
		  { "Day", "spoolss.time.day", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Day", HFILL }},
		{ &hf_spoolss_time_hour,
		  { "Hour", "spoolss.time.hour", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Hour", HFILL }},
		{ &hf_spoolss_time_minute,
		  { "Minute", "spoolss.time.minute", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Minute", HFILL }},
		{ &hf_spoolss_time_second,
		  { "Second", "spoolss.time.second", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Second", HFILL }},
		{ &hf_spoolss_time_msec,
		  { "Millisecond", "spoolss.time.msec", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Millisecond", HFILL }},

		/* Printer data */

		{ &hf_spoolss_printerdata_size,
		  { "Printer data size", "spoolss.printerdata.size", FT_UINT32, BASE_DEC, 
		    NULL, 0x0, "Printer data name", HFILL }},
		{ &hf_spoolss_printerdata_name,
		  { "Printer data name", "spoolss.printerdata.name", FT_STRING, BASE_NONE,
		    NULL, 0, "Printer data name", HFILL }},

		/* SetJob RPC */

		{ &hf_spoolss_setjob_cmd,
		  { "Set job command", "spoolss.setjob.cmd", FT_UINT32, BASE_DEC, 
		    VALS(&setjob_commands), 0x0, "Printer data name", HFILL }},
	};

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
		&ett_POLICY_HND,
		&ett_FORM_REL,
		&ett_FORM_CTR,
		&ett_FORM_1,
		&ett_JOB_INFO_1,
		&ett_JOB_INFO_2,
		&ett_SEC_DESC_BUF,
		&ett_SYSTEM_TIME,
		&ett_DOC_INFO_1,
		&ett_DOC_INFO,
		&ett_DOC_INFO_CTR,
        };

        proto_dcerpc_spoolss = proto_register_protocol(
                "Microsoft Spool Subsystem", "SPOOLSS", "spoolss");

	proto_register_field_array(proto_dcerpc_spoolss, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));
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
