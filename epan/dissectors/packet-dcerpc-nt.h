/* packet-dcerpc-nt.h
 * Routines for DCERPC over SMB packet disassembly
 * Copyright 2001-2003 Tim Potter <tpot@samba.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_DCERPC_NT_H
#define __PACKET_DCERPC_NT_H

/*
 * ett_ value for Unicode strings.
 */
extern gint ett_nt_unicode_string;

/*
 * Platform ID values, used by several dissectors.
 */
extern const value_string platform_id_vals[];

/* Routines for handling deferral of referants in NDR */

#define ALIGN_TO_8_BYTES \
	{ dcerpc_info *xzdi; \
	  xzdi=pinfo->private_data; \
	  if(!xzdi->conformant_run) { \
		if(offset&0x07) { \
			offset=(offset&0xfffffff8)+8; \
		} \
	  } \
	}
#define ALIGN_TO_4_BYTES \
	{ dcerpc_info *xzdi; \
	  xzdi=pinfo->private_data; \
	  if(!xzdi->conformant_run) { \
		if(offset&0x03) { \
			offset=(offset&0xfffffffc)+4; \
		} \
	  } \
	}
#define ALIGN_TO_2_BYTES \
	{ dcerpc_info *xzdi; \
	  xzdi=pinfo->private_data; \
	  if(!xzdi->conformant_run) { \
		if(offset&0x01) { \
			offset=(offset&0xfffffffe)+2; \
		} \
	  } \
	}

int
dissect_ndr_counted_ascii_string_cb(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  guint8 *drep, int hf_index,
				  dcerpc_callback_fnct_t *callback,
				    void *callback_args);
int
dissect_ndr_counted_ascii_string(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
				 guint8 *drep, int hf_index, int levels);

int
dissect_ndr_counted_string_cb(tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      guint8 *drep, int hf_index, 
			      dcerpc_callback_fnct_t *callback,
			      void *callback_args);

int
dissect_ndr_counted_string_ptr(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *parent_tree,
			       guint8 *drep);

int
dissect_ndr_counted_string(tvbuff_t *tvb, int offset,
			   packet_info *pinfo, proto_tree *parent_tree,
			   guint8 *drep, int hf_index, int levels);

int
dissect_ndr_counted_byte_array(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *parent_tree,
			       guint8 *drep, int hf_index, int levels);

int
dissect_ndr_counted_byte_array_cb(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  guint8 *drep, int hf_index,
				  dcerpc_callback_fnct_t *callback,
				  void *callback_args);

int
dissect_ndr_nt_acct_ctrl(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *parent_tree, guint8 *drep);

int
dissect_nt_GUID(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep);

int
dissect_ndr_nt_NTTIME (tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep, int hf_index);
int
dissect_ndr_nt_LOGON_HOURS(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep);
int
dissect_ndr_nt_SID(tvbuff_t *tvb, int offset,
		   packet_info *pinfo, proto_tree *tree,
		   guint8 *drep);
int
dissect_ndr_nt_SID_with_options(tvbuff_t *tvb, int offset, 
		   packet_info *pinfo, proto_tree *tree, 
				guint8 *drep, guint32 options);
int
dissect_ndr_nt_PSID(tvbuff_t *tvb, int offset,
		    packet_info *pinfo, proto_tree *parent_tree,
		    guint8 *drep);
int
dissect_ndr_nt_PSID_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep);

int
dissect_ndr_nt_SID_AND_ATTRIBUTES_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep);
int
dissect_ndr_nt_SID_AND_ATTRIBUTES(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep);

/*
 * Policy handle hashing
 */

/* Store open and close packet numbers for a policy handle */

void
dcerpc_smb_store_pol_pkts(e_ctx_hnd *policy_hnd, packet_info *pinfo,
			  gboolean is_open, gboolean is_close);

/* Store a name with a policy handle */

void
dcerpc_smb_store_pol_name(e_ctx_hnd *policy_hnd, packet_info *pinfo,
			  const char *name);

/* Fetch details stored with a policy handle */

gboolean
dcerpc_smb_fetch_pol(e_ctx_hnd *policy_hnd, char **name,
		     guint32 *open_frame, guint32 *close_frame,
		     guint32 cur_frame);

/* Dissect NT specific things */

int
dissect_ntstatus(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		 proto_tree *tree, guint8 *drep,
		 int hfindex, guint32 *pdata);

int
dissect_doserror(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		 proto_tree *tree, guint8 *drep,
		 int hfindex, guint32 *pdata);

int
dissect_nt_policy_hnd(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		      proto_tree *tree, guint8 *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      gboolean is_open, gboolean is_close);

int
dissect_nt_guid_hnd(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		      proto_tree *tree, guint8 *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      gboolean is_open, gboolean is_close);

int
dissect_nt_LUID(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep);

/* Stored here instead of packet-dcerpc{,-ndr}.c as they are probably not
   official NDR representations. */

int dissect_dcerpc_uint8s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                          proto_tree *tree, guint8 *drep,
                          int hfindex, int length, const guint8 **pdata);

int dissect_ndr_uint8s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, guint8 *drep,
                       int hfindex, int length, const guint8 **pdata);

int dissect_dcerpc_uint16s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
			   proto_tree *tree, guint8 *drep,
			   int hfindex, int length);

int dissect_ndr_uint16s(tvbuff_t *tvb, gint offset, packet_info *pinfo,
			proto_tree *tree, guint8 *drep,
			int hfindex, int length);

int dissect_ndr_str_pointer_item(tvbuff_t *tvb, gint offset, 
				 packet_info *pinfo, proto_tree *tree, 
				 guint8 *drep, int type, const char *text, 
				 int hf_index, int levels);

/*
 * Helper routines for dissecting NDR strings
 */

/* Number of levels to go up appending string to pointer item */
#define CB_STR_ITEM_LEVELS(x)	((x) & 0xFFFF)
#define CB_STR_COL_INFO 0x10000	/* Append string to COL_INFO */
#define CB_STR_SAVE     0x20000	/* Save string to dcv->private_data */

void cb_wstr_postprocess(packet_info *pinfo, proto_tree *tree _U_,
			proto_item *item, tvbuff_t *tvb, 
			int start_offset, int end_offset,
			void *callback_args);
void cb_str_postprocess(packet_info *pinfo, proto_tree *tree _U_,
			proto_item *item, tvbuff_t *tvb, 
			int start_offset, int end_offset,
			void *callback_args);

/* Initialise DCERPC over SMB */

void dcerpc_smb_init(int proto_dcerpc);

#endif /* packet-dcerpc-nt.h */
