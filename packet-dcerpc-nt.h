/* packet-dcerpc-nt.h
 * Routines for DCERPC over SMB packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-nt.h,v 1.13 2002/03/15 08:59:52 sahlberg Exp $
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

#ifndef __PACKET_DCERPC_NT_H
#define __PACKET_DCEPRC_NT_H

/* Routines for parsing simple types */

int prs_align(int offset, int n);

int prs_uint8(tvbuff_t *tvb, int offset, packet_info *pinfo,
	      proto_tree *tree, guint8 *data, char *name);

int prs_uint8s(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, int count, guint8 **data, char *name);

int prs_uint16(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, guint16 *data, char *name);

int prs_uint16s(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, int count, guint16 **data, char *name);

int prs_uint32(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, guint32 *data, char *name);

int prs_uint32s(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, int count, guint32 **data, char *name);

/* Parse NT status code */

int prs_ntstatus(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree);

/* Parse some common RPC structures */

char *fake_unicode(guint16 *data, int len);

int prs_UNISTR2(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, int flags, char **data, char *name);

int prs_policy_hnd(tvbuff_t *tvb, int offset, packet_info *pinfo, 
		   proto_tree *tree, const guint8 **data);

/* Routines for handling deferral of referants in NDR */

#define PARSE_SCALARS 1
#define PARSE_BUFFERS 2

int prs_push_ptr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree, GList **ptr_list, char *name);

guint32 prs_pop_ptr(GList **ptr_list, char *name);



#define ALIGN_TO_4_BYTES	{if(offset&0x03)offset=(offset&0xfffffffc)+4;}

int
dissect_ndr_nt_UNICODE_STRING_str(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep);
int
dissect_ndr_nt_UNICODE_STRING(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree, 
			char *drep, int hf_index, int levels);
int
dissect_ndr_nt_STRING_string (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep);
int
dissect_ndr_nt_STRING (tvbuff_t *tvb, int offset, 
                        packet_info *pinfo, proto_tree *parent_tree, 
			char *drep, int hf_index, int levels);
int 
dissect_ndr_nt_acct_ctrl(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			proto_tree *parent_tree, char *drep);
int
dissect_ndr_nt_NTTIME (tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep, int hf_index);
int
dissect_ndr_nt_LOGON_HOURS(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep);
int
dissect_ndr_nt_SID(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree, 
			char *drep);
int
dissect_ndr_nt_PSID(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep);
int
dissect_ndr_nt_PSID_ARRAY(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep);

int
dissect_ndr_nt_SID_AND_ATTRIBUTES_ARRAY(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep);
int
dissect_ndr_nt_SID_AND_ATTRIBUTES(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep);



#endif /* packet-dcerpc-nt.h */
