/* packet-dcerpc-nt.h
 * Routines for DCERPC over SMB packet disassembly
 * Copyright 2001-2003 Tim Potter <tpot@samba.org>
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

#ifndef __PACKET_DCERPC_NT_H
#define __PACKET_DCERPC_NT_H

#include "ws_symbol_export.h"

/*
 * Platform ID values, used by several dissectors.
 */
extern const value_string platform_id_vals[];

/* Routines for handling deferral of referants in NDR */

#define ALIGN_TO_8_BYTES \
	{ \
	  if(!di->conformant_run) { \
		if(offset&0x07) { \
			offset=(offset&0xfffffff8)+8; \
		} \
	  } \
	}
#define ALIGN_TO_4_BYTES \
	{ \
	  if(!di->conformant_run) { \
		if(offset&0x03) { \
			offset=(offset&0xfffffffc)+4; \
		} \
	  } \
	}
#define ALIGN_TO_2_BYTES \
	{ \
	  if(!di->conformant_run) { \
		if(offset&0x01) { \
			offset=(offset&0xfffffffe)+2; \
		} \
	  } \
	}

#define ALIGN_TO_5_BYTES ALIGN_TO_4_OR_8_BYTES

#define ALIGN_TO_4_OR_8_BYTES \
	{ \
	  if (di->call_data->flags & DCERPC_IS_NDR64) { \
	    ALIGN_TO_8_BYTES; \
	  } else { \
	    ALIGN_TO_4_BYTES; \
	  } \
	}

#define ALIGN_TO_3_BYTES ALIGN_TO_2_OR_4_BYTES

#define ALIGN_TO_2_OR_4_BYTES \
	{ \
	  if (di->call_data->flags & DCERPC_IS_NDR64) { \
	    ALIGN_TO_4_BYTES; \
	  } else { \
	    ALIGN_TO_2_BYTES; \
	  } \
	}
int
dissect_ndr_datablob(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index,
			int use_remaining_space);

int
dissect_null_term_string(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, guint8 *drep, int hf_index,
							int levels);

int
dissect_null_term_wstring(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, guint8 *drep, int hf_index,
							int levels);

int
dissect_ndr_counted_ascii_string_cb(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep, int hf_index,
				  dcerpc_callback_fnct_t *callback,
				    void *callback_args);
int
dissect_ndr_counted_ascii_string(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
				   dcerpc_info *di, guint8 *drep, int hf_index, int levels);

int
dissect_ndr_counted_string_cb(tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      dcerpc_info *di, guint8 *drep, int hf_index,
			      dcerpc_callback_fnct_t *callback,
			      void *callback_args);

int
dissect_ndr_counted_string_ptr(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *parent_tree,
			       dcerpc_info *di, guint8 *drep);

int
dissect_ndr_counted_string(tvbuff_t *tvb, int offset,
			   packet_info *pinfo, proto_tree *parent_tree,
			   dcerpc_info *di, guint8 *drep, int hf_index, int levels);

int
dissect_ndr_counted_byte_array(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *parent_tree,
			       dcerpc_info *di, guint8 *drep, int hf_index, int levels);

int
dissect_ndr_counted_byte_array_cb(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep, int hf_index,
				  dcerpc_callback_fnct_t *callback,
				  void *callback_args);

int
dissect_ndr_nt_acct_ctrl(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *parent_tree, dcerpc_info *di, guint8 *drep);

int
dissect_nt_GUID(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			dcerpc_info *di, guint8 *drep);

int
dissect_ndr_lsa_String(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *parent_tree, dcerpc_info *di, guint8 *drep,
		       guint32 param, int hfindex);

int
dissect_ndr_nt_NTTIME (tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			dcerpc_info *di, guint8 *drep, int hf_index);
int
dissect_ndr_nt_LOGON_HOURS(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			dcerpc_info *di, guint8 *drep);
int
dissect_ndr_nt_SID(tvbuff_t *tvb, int offset,
		   packet_info *pinfo, proto_tree *tree,
		   dcerpc_info *di, guint8 *drep);
int
dissect_ndr_nt_SID_with_options(tvbuff_t *tvb, int offset,
		   packet_info *pinfo, proto_tree *tree,
			dcerpc_info *di, guint8 *drep, guint32 options);
int
dissect_ndr_nt_PSID(tvbuff_t *tvb, int offset,
		    packet_info *pinfo, proto_tree *parent_tree,
		    dcerpc_info *di, guint8 *drep);
int
dissect_ndr_nt_PSID_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			dcerpc_info *di, guint8 *drep);

int
dissect_ndr_nt_SID_AND_ATTRIBUTES_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			dcerpc_info *di, guint8 *drep);
int
dissect_ndr_nt_SID_AND_ATTRIBUTES(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			dcerpc_info *di, guint8 *drep);

int
dissect_ndr_nt_SID28(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, guint8 *drep);
/*
 * Policy handle hashing
 */

/* Store open and close packet numbers for a policy handle */

void
dcerpc_smb_store_pol_pkts(e_ctx_hnd *policy_hnd, packet_info *pinfo,
			  gboolean is_open, gboolean is_close);

/* Store a name with a policy handle */

void
dcerpc_store_polhnd_name(e_ctx_hnd *policy_hnd, packet_info *pinfo,
			  const char *name);

/* Fetch details stored with a policy handle */

gboolean
dcerpc_fetch_polhnd_data(e_ctx_hnd *policy_hnd, char **name, guint32 *type,
		     guint32 *open_frame, guint32 *close_frame,
		     guint32 cur_frame);

/* Dissect NT specific things */

int
dissect_ntstatus(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		 proto_tree *tree, dcerpc_info *di, guint8 *drep,
		 int hfindex, guint32 *pdata);

int
dissect_doserror(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		 proto_tree *tree, dcerpc_info *di, guint8 *drep,
		 int hfindex, guint32 *pdata);

int
dissect_nt_policy_hnd(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		      proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      gboolean is_open, gboolean is_close);

int
PIDL_dissect_policy_hnd(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		      proto_tree *tree, dcerpc_info* di, guint8 *drep, int hfindex,
		      guint32 param);

int
dissect_nt_guid_hnd(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		      proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      gboolean is_open, gboolean is_close);

int
dissect_nt_LUID(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep);

/* Stored here instead of packet-dcerpc{,-ndr}.c as they are probably not
   official NDR representations. */

int dissect_dcerpc_uint8s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                          proto_tree *tree, dcerpc_info *di, guint8 *drep,
                          int hfindex, int length, const guint8 **pdata);

int dissect_ndr_uint8s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep,
                       int hfindex, int length, const guint8 **pdata);

int dissect_dcerpc_uint16s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
			   proto_tree *tree, guint8 *drep,
			   int hfindex, int length);

int dissect_ndr_uint16s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, guint8 *drep,
			int hfindex, int length);

int dissect_ndr_str_pointer_item(tvbuff_t *tvb, gint offset,
				 packet_info *pinfo, proto_tree *tree,
				 dcerpc_info *di, guint8 *drep, int type, const char *text,
				 int hf_index, int levels);

/*
 * Helper routines for dissecting NDR strings
 */

/* Number of levels to go up appending string to pointer item */
#define CB_STR_ITEM_LEVELS(x)	((x) & 0xFFFF)
#define CB_STR_SAVE     0x20000000	/* Save string to dcv->private_data */
#define CB_STR_COL_INFO 0x10000000	/* Append string to COL_INFO */

void cb_wstr_postprocess(packet_info *pinfo, proto_tree *tree _U_,
			proto_item *item, dcerpc_info *di, tvbuff_t *tvb,
			int start_offset, int end_offset,
			void *callback_args);
void cb_str_postprocess(packet_info *pinfo, proto_tree *tree _U_,
			proto_item *item, dcerpc_info *di, tvbuff_t *tvb,
			int start_offset, int end_offset,
			void *callback_args);

/* Initialise DCERPC over SMB */

void dcerpc_smb_init(int proto_dcerpc);

/* Used into packet-dcerpc-netlogon.c*/
extern int hf_nt_cs_len;
extern int hf_nt_cs_size;

#endif /* packet-dcerpc-nt.h */
