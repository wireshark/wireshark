/* packet-dcerpc-lsa.c
 * Routines for SMB \PIPE\lsarpc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-lsa.c,v 1.4 2001/12/17 08:27:00 guy Exp $
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

#include "packet.h"
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-lsa.h"
#include "smb.h"

/*
 * Parse a unicode string.
 *
 *  typedef struct {
 *    short length;
 *    short size;
 *    [size_is(size/2)] [length_is(length/2)] [unique] wchar_t *string;
 *  } UNICODE_STRING;
 *
 */

/* Convert a (little endian) unicode string to ASCII.  We fake it by just
   taking every odd byte. */

static char *fake_unicode(guint16 *data, int len)
{
	char *buffer;
	int i;

	buffer = malloc(len + 1);

	for (i = 0; i < len; i++)
		buffer[i] = data[i] & 0xff;

	buffer[len] = 0;

	return buffer;
}

static int ett_UNISTR = -1;
static int ett_UNISTR_hdr = -1;

static int prs_UNISTR(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, int flags, GList **ptr_list, 
		      char *name)
{
	proto_tree *scalars, *buffers;
	guint16 length, size;

	if (flags & PARSE_SCALARS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "String header");
		subtree = proto_item_add_subtree(item, ett_UNISTR_hdr);
		
		offset = prs_uint16(tvb, offset, pinfo, subtree, &length, 
				    "Length");

		offset = prs_uint16(tvb, offset, pinfo, subtree, &size, 
				    "Size");

		offset = prs_push_ptr(tvb, offset, pinfo, subtree,
				      ptr_list, "Data");
	}

	if (flags & PARSE_BUFFERS) {
		proto_item *item;
		proto_tree *subtree;
		guint32 max_len, stroffset, actual_count, i;
		int old_offset;
		guint16 *string;
		char *astring;

		/* Parse data */

		old_offset = offset;

		offset = prs_uint32(tvb, offset, pinfo, NULL, &max_len, 
				    "Max length");

		offset = prs_uint32(tvb, offset, pinfo, NULL, &stroffset, 
				    "Offset");

		offset = prs_uint32(tvb, offset, pinfo, NULL, 
				    &actual_count, "Actual length");

		offset = prs_uint16s(tvb, offset, pinfo, NULL,
				     actual_count, &string, "Data");

		/* Insert into display */

		astring = fake_unicode(string, actual_count);

		if (!astring || !astring[0])
			astring = strdup("(NULL)");

		item = proto_tree_add_text(tree, tvb, old_offset, 
					   offset - old_offset, "String: %s", 
					   astring);

		free(astring);

		subtree = proto_item_add_subtree(item, ett_UNISTR);

		proto_tree_add_text(subtree, tvb, old_offset, 4, 
				    "Max length: %d", max_len);
		old_offset += 4;

		proto_tree_add_text(subtree, tvb, old_offset, 4, 
				    "Offset: %d", stroffset);
		old_offset += 4;

		proto_tree_add_text(subtree, tvb, old_offset, 4,
				    "Actual length: %d", actual_count);
		old_offset += 4;

		if (prs_pop_ptr(ptr_list, "Data"))
			proto_tree_add_text(subtree, tvb, old_offset, 
					    actual_count * 2, "Data");
	}

	return offset;
}

/*
 *  typedef struct {
 *    char revision;
 *    char subauth_count;
 *    char authority[6];
 *    [size_is(subauth_count)] long subauth[*];
 *  } SID;
 *
 */

static int ett_SID = -1;

/* For some reason the SID structure is treated as a scalar type.  For
   instance in an array of SIDs, I would have thought that this entire
   structure should be in the scalars part of the RPC but instead is in
   the buffers section.  I am probably misunderstanding NDR arrays
   though. - tpot */

static int prs_SID(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree)
{
	guint8 subauth_count, id_auth[6];
	int old_offset, i;
	proto_item *item;
	proto_tree *subtree;
	guint32 ia, *subauths, subauth_max;
	guint8 revision;
	char sid_str[128];

	old_offset = offset;

	offset = prs_uint32(tvb, offset, pinfo, NULL, &subauth_max, 
			    "Array max count");

	offset = prs_uint8(tvb, offset, pinfo, NULL, &revision, "Revision");

	offset = prs_uint8(tvb, offset, pinfo, NULL, &subauth_count, 
			   "Subauth count");

	for (i = 0; i < 6; i++)
		offset = prs_uint8(tvb, offset, pinfo, NULL, &id_auth[i], 
				   "Authority");
	
	ia = id_auth[5] + (id_auth[4] << 8 ) + (id_auth[3] << 16) + 
		(id_auth[2] << 24);

	sprintf(sid_str, "S-%u-%u", revision, ia);

	offset = prs_uint32s(tvb, offset, pinfo, NULL, subauth_count,
			     &subauths, "Subauth count");

	for (i = 0; i < subauth_count; i++) {
		char sa[16];

		sprintf(sa, "-%u", subauths[i]);
 		strcat(sid_str, sa);
	}

	/* Insert into display */

	item = proto_tree_add_text(tree, tvb, offset, 0, "SID: %s", sid_str);
	subtree = proto_item_add_subtree(item, ett_SID);

	proto_tree_add_text(subtree, tvb, old_offset, 4, 
			    "Subauth array max count: %d", subauth_max);

	old_offset += 4;

	proto_tree_add_text(subtree, tvb, old_offset, 1, "Revision: %d", 
			    revision);

	old_offset++;

	proto_tree_add_text(subtree, tvb, old_offset, 1, "Subauth count: %d",
			    subauth_count); 

	old_offset++;

	proto_tree_add_text(subtree, tvb, old_offset, 6, "Authority");

	old_offset += 6;

	proto_tree_add_text(subtree, tvb, old_offset, subauth_count * 4,
			    "Subauthorities");

	old_offset += subauth_count * 4;

	return offset;
}

/*
 * Close a policy handle.
 *
 *  long LsarClose(
 *      [in,out] [context_handle] void **hnd
 * );
 *
 */

static int LsaClose_q(tvbuff_t *tvb, int offset, packet_info *pinfo, 
		      proto_tree *tree, char *drep)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "ClosePolicy request");

	offset = prs_policy_hnd(tvb, offset, pinfo, tree);

	return offset;
}

static int LsaClose_r(tvbuff_t *tvb, int offset, packet_info *pinfo, 
		      proto_tree *tree, char *drep)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "ClosePolicy reply");

	offset = prs_policy_hnd(tvb, offset, pinfo, tree);
	offset = prs_ntstatus(tvb, offset, pinfo, tree);

	return offset;
}

/* 
 * Dissect a SECURITY_DESCRIPTOR structure 
 *
 * typedef struct {
 *   char revision;
 *   char reserved;
 *   short control;
 *   [unique] SID *owner;
 *   [unique] SID *group;
 *   [unique] SEC_ACL *sacl;
 *   [unique] SEC_ACL *dacl;
 * } SECURITY_DESCRIPTOR;
 *
 */

static int prs_SECURITY_DESCRIPTOR(tvbuff_t *tvb, int offset, 
				   packet_info *pinfo, proto_tree *tree, 
				   int flags)
{
	/* Not implemented */

	return offset;
}

/* Dissect a SECURITY_QOS structure
 *
 *  typedef struct {
 *   uint32 struct_len;
 *   uint16 imp_level;
 *   char track_context;
 *   char effective_only;
 * } SECURITY_QOS;
 *
 */

static int ett_SECURITY_QOS = -1;
static int ett_SECURITY_QOS_hdr = -1;

static int prs_SECURITY_QOS(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			    proto_tree *tree, int flags)
{
	if (flags & PARSE_SCALARS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "SECURITY_QOS header");
		subtree = proto_item_add_subtree(item, ett_SECURITY_QOS_hdr);

		offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
				    "Struct length");

		offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, 
				    "Implementation level");

		offset = prs_uint8(tvb, offset, pinfo, subtree, NULL, 
				   "Track context");

		offset = prs_uint8(tvb, offset, pinfo, subtree, NULL, 
				   "Effective only");
	}

	if (flags & PARSE_BUFFERS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "SECURITY_QOS");
		subtree = proto_item_add_subtree(item, ett_SECURITY_QOS);
	}

	return offset;
}

/*
 * Dissect an OBJECT_ATTRIBUTES structure.
 *
 * typedef struct {
 *   uint32 struct_len;
 *   [unique] char *root_dir;
 *   [unique] unistr2 *name;
 *   uint32 attributes;
 *   [unique] SECURITY_DESCRIPTOR *sec_desc;
 *   [unique] SECURITY_QOS *sec_qos;
 * } OBJECT_ATTRIBUTES;
 *
 */

static int prs_OBJECT_ATTRIBUTES(tvbuff_t *tvb, int offset, 
				 packet_info *pinfo, proto_tree *tree, 
				 int flags, GList **ptr_list)
{
	if (flags & PARSE_SCALARS) {
		offset = prs_uint32(tvb, offset, pinfo, tree, NULL, 
				    "Structure length");

		offset = prs_push_ptr(tvb, offset, pinfo, tree, ptr_list,
				      "Root directory");

		offset = prs_push_ptr(tvb, offset, pinfo, tree, ptr_list, 
				      "Name");

		offset = prs_uint32(tvb, offset, pinfo, tree, NULL, 
				    "Attributes");

		offset = prs_push_ptr(tvb, offset, pinfo, tree, ptr_list,
				      "SECURITY_DESCRIPTOR");

		offset = prs_push_ptr(tvb, offset, pinfo, tree, ptr_list,
				      "SEC_QOS");
	}

	if (flags & PARSE_BUFFERS) {
		if (prs_pop_ptr(ptr_list, "Root directory"))
		    offset = prs_uint8(tvb, offset, pinfo, tree, NULL, 
				       "Root directory");
		    
		if (prs_pop_ptr(ptr_list, "Name"))
			offset = prs_UNISTR2(tvb, offset, pinfo, tree,
					     flags, NULL, "Name");

		if (prs_pop_ptr(ptr_list, "SECURITY_DESCRIPTOR"))
			offset = prs_SECURITY_DESCRIPTOR(
				tvb, offset, pinfo, tree, flags);

		if (prs_pop_ptr(ptr_list, "SEC_QOS"))
			offset = prs_SECURITY_QOS(
				tvb, offset, pinfo, tree, flags);

	}

	return offset;
}

/*
 * Open a LSA policy handle.  Note that due to a bug in Microsoft's
 * original IDL, only the first character of the server name is ever sent
 * across the wire.  Since the server name is in UNC format this will be a
 * single '\'.
 * 
 *  uint32 LsarOpenPolicy(
 *       [in] [unique] wchar_t *server,
 *       [in] [ref] OBJECT_ATTRIBUTES *attribs,
 *       [in] uint32 access,
 *      [out] [context_handle] void **hnd
 * );
 *
 */ 

static int LsaOpenPolicy_q(tvbuff_t * tvb, int offset,
			   packet_info * pinfo, proto_tree * tree,
			   char *drep)
{
	GList *ptr_list = NULL;
	int flags = PARSE_SCALARS|PARSE_BUFFERS;
	guint32 access;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "OpenPolicy request");

        offset = prs_push_ptr(tvb, offset, pinfo, tree, &ptr_list, "Server");

        if (prs_pop_ptr(&ptr_list, "Server"))
                offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Server");

	offset = prs_OBJECT_ATTRIBUTES(tvb, offset, pinfo, tree, flags,
				       &ptr_list);

        offset = prs_uint32(tvb, offset, pinfo, tree, &access, NULL);

	proto_tree_add_text(tree, tvb, offset, 4, "Access: 0x%08x", access);

        return offset;
}

static int LsaOpenPolicy_r(tvbuff_t * tvb, int offset,
                            packet_info * pinfo, proto_tree * tree,
                            char *drep)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "OpenPolicy reply");

        offset = prs_policy_hnd(tvb, offset, pinfo, tree);
        offset = prs_ntstatus(tvb, offset, pinfo, tree);

        return offset;
}

/*
 * Parse a NAME_AND_SID structure.
 *
 * typedef struct {
 *   UNICODE_STRING name;
 *   [unique] SID *sid;
 * } NAME_AND_SID;
 *
 */

int ett_NAME_AND_SID = -1;
int ett_NAME_AND_SID_hdr = -1;

static int prs_NAME_AND_SID(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			    proto_tree *tree, int flags, GList **ptr_list)
{
	if (flags & PARSE_SCALARS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "NAME_AND_SID header");
		subtree = proto_item_add_subtree(item, ett_NAME_AND_SID_hdr);

		offset = prs_UNISTR(tvb, offset, pinfo, subtree, 
				    PARSE_SCALARS, ptr_list, "Name");
		offset = prs_push_ptr(tvb, offset, pinfo, subtree,
				      ptr_list, "SID");
	}

	if (flags & PARSE_BUFFERS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "NAME_AND_SID");
		subtree = proto_item_add_subtree(item, ett_NAME_AND_SID);

		offset = prs_UNISTR(tvb, offset, pinfo, subtree, 
				    PARSE_BUFFERS, ptr_list, "Name");

		if (prs_pop_ptr(ptr_list, "SID"))
			offset = prs_SID(tvb, offset, pinfo, subtree);
	}

	return offset;
}

/*
 * Parse a POLICY_INFORMATION structure. 
 *
 * typedef union {
 *   [case(1)] AUDIT_LOG_INFO audit_log;
 *   [case(2)] AUDIT_SETTINGS audit_settings;
 *   [case(3)] NAME_AND_SID primary_domain;
 *   [case(5)] NAME_AND_SID account_domain;
 *   [case(4)] UNICODE_STRING account;
 *   [case(6)] SERVER_ROLE server_role;
 *   [case(7)] REPLICA_SOURCE replica_source;
 *   [case(8)] QUOTA_INFO default_quota;
 *   [case(9)] HISTORY history;
 *   [case(10)] AUDIT_SET_INFO audit_set;
 *   [case(11)] AUDIT_QUERY_INFO audit_query;
 * } POLICY_INFORMATION;
 *
 */

static int ett_POLICY_INFORMATION = -1;

static int prs_POLICY_INFORMATION(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree, 
				  int flags)
{
	guint16 level;
	proto_item *item;
	proto_tree *subtree;
	GList *ptr_list = NULL;

	item = proto_tree_add_text(tree, tvb, offset, 0, "POLICY_INFORMATION");
	subtree = proto_item_add_subtree(item, ett_POLICY_INFORMATION);

	offset = prs_uint16(tvb, offset, pinfo, subtree, &level, "Info level");

	switch (level) {
	case 1: 
/*		offset = prs_AUDIT_LOG_INFO(tvb, offset, pinfo, subtree); */
		break;
	case 2:
/*		offset = prs_AUDIT_SETTINGS(tvb, offset, pinfo, subtree); */
		break;
	case 3:
		offset = prs_NAME_AND_SID(tvb, offset, pinfo, subtree,
					  flags, &ptr_list);
		break;
	case 4:
/*		offset = prs_UNISTR2(tvb, offset, pinfo, subtree); */
		break;
	case 5:
		offset = prs_NAME_AND_SID(tvb, offset, pinfo, subtree, 
					  flags, &ptr_list);
		break;
	case 6:
/*		offset = prs_SERVER_ROLE(tvb, offset, pinfo, subtree); */
		break;
	case 7:
/*		offset = prs_REPLICA_SOURCE(tvb, offset, pinfo, subtree); */
		break;
	case 8:
/*		offset = prs_QUOTA_INFO(tvb, offset, pinfo, subtree); */
		break;
	case 9:
/*		offset = prs_HISTORY(tvb, offset, pinfo, subtree); */
		break;
	case 10:
/*		offset = prs_AUDIT_SET_INFO(tvb, offset, pinfo, subtree); */
		break;
	case 11:
/*		offset = prs_AUDIT_QUERY_INFO(tvb, offset, pinfo, subtree); */
		break;
	}

	return offset;
}

/*
 * uint32 LsarQueryInformationPolicy(
 *       [in] [context_handle] void *hnd,
 *       [in] uint16 level,
 *      [out] [switch_is(level)] [ref] POLICY_INFORMATION **info
 * );
 *
 */

static int LsaQueryInfoPolicy_q(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "QueryInfo request");

	offset = prs_policy_hnd(tvb, offset, pinfo, tree);
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Info level");

	return offset;
}

static int LsaQueryInfoPolicy_r(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	GList *ptr_list = NULL;
	int flags = PARSE_SCALARS|PARSE_BUFFERS;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "QueryInfo reply");

	offset = prs_push_ptr(tvb, offset, pinfo, tree, &ptr_list, 
			      "POLICY_INFORMATION");

	if (prs_pop_ptr(&ptr_list, "POLICY_INFORMATION"))
		offset = prs_POLICY_INFORMATION(tvb, offset, pinfo, tree,
						flags);

	offset = prs_ntstatus(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * Parse a DOM_RID structure.
 *
 * typedef struct {
 *    short type;
 *    long rid;
 *    long dom_idx;
 * } DOM_RID;
 *
 */

static int ett_DOM_RID = -1;

static int prs_DOM_RID(tvbuff_t *tvb, int offset, packet_info *pinfo, 
		       proto_tree *tree, int flags, GList **ptr_list)
{
	if (flags & PARSE_SCALARS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, "DOM_RID");
		subtree = proto_item_add_subtree(item, ett_DOM_RID);

		offset = prs_uint16(tvb, offset, pinfo, subtree, NULL, "Type");
	
		offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, "RID");

		offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
				    "Domain index");
	}

	if (flags & PARSE_BUFFERS) {
	}

	return offset;
}

/*
 * Parse a DOM_RID_ARRAY structure.
 *
 * typedef struct {
 *   long count;
 *   [size_is(count)] [unique] DOM_RID *rids;
 * } DOM_RID_ARRAY;
 *
 */

static int ett_DOM_RID_ARRAY = -1;
static int ett_DOM_RID_ARRAY_hdr = -1;

static int prs_DOM_RID_ARRAY(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			     proto_tree *tree, int flags, GList **ptr_list)
{
	if (flags & PARSE_SCALARS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "DOM_RID_ARRAY header");
		subtree = proto_item_add_subtree(item, ett_DOM_RID_ARRAY_hdr);

		
		offset = prs_uint32(tvb, offset, pinfo, subtree, NULL,
				    "Count");

		offset = prs_push_ptr(tvb, offset, pinfo, subtree, ptr_list, 
				      "RIDs");
	}

	if (flags & PARSE_BUFFERS) {
		proto_item *item;
		proto_tree *subtree;
		guint32 count, i;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "DOM_RID_ARRAY");
		subtree = proto_item_add_subtree(item, ett_DOM_RID_ARRAY);

		if (prs_pop_ptr(ptr_list, "RIDs")) {
			offset = prs_uint32(tvb, offset, pinfo, subtree, &count,
					    "Count");

			for (i = 0; i < count; i++) {
				offset = prs_DOM_RID(tvb, offset, pinfo,
						     subtree, PARSE_SCALARS,
						     ptr_list);
			}

			for (i = 0; i < count; i++) {
				offset = prs_DOM_RID(tvb, offset, pinfo,
						     subtree, PARSE_BUFFERS,
						     ptr_list);
			}
		}
	}

	return offset;
}

/*
 * Parse a NAME_AND_SID_ARRAY structure.
 *
 * typedef struct {
 *   long count;
 *   [size_is(count)] [unique] NAME_AND_SID *objects;
 * } NAME_AND_SID_ARRAY;
 *
 */

static int ett_NAME_AND_SID_ARRAY = -1;
static int ett_NAME_AND_SID_ARRAY_hdr = -1;

static int prs_NAME_AND_SID_ARRAY(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree, 
				  int flags, GList **ptr_list)
{
	if (flags & PARSE_SCALARS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "NAME_AND_SID_ARRAY header");
		subtree = proto_item_add_subtree(
			item, ett_NAME_AND_SID_ARRAY_hdr);

		offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
				    "Count");

		offset = prs_push_ptr(tvb, offset, pinfo, subtree, ptr_list,
				      "NAME_AND_SIDs");

		offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
				    "Max count");

	}

	if (flags & PARSE_BUFFERS) {
		proto_item *item;
		proto_tree *subtree;
		guint32 count, i;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "NAME_AND_SID_ARRAY");
		subtree = proto_item_add_subtree(
			item, ett_NAME_AND_SID_ARRAY);

		offset = prs_uint32(tvb, offset, pinfo, subtree, &count, 
				    "Count");

		if (!prs_pop_ptr(ptr_list, "NAME_AND_SIDs"))
			goto done;

		for (i = 0; i < count; i++) {
			offset = prs_NAME_AND_SID(tvb, offset, pinfo, subtree,
						  PARSE_SCALARS, ptr_list);
		}

		for (i = 0; i < count; i++) {
			offset = prs_NAME_AND_SID(tvb, offset, pinfo, subtree,
						  PARSE_BUFFERS, ptr_list);
		}
	done:
	}

	return offset;
}

/*
 * Parse a DOM_REF_INFO structure.
 *
 * typedef struct {
 *   NAME_AND_SID_ARRAY domains;
 *   long count;
 * } DOM_REF_INFO;
 *
 */

static int ett_DOM_REF_INFO = -1;
static int ett_DOM_REF_INFO_hdr = -1;

static int prs_DOM_REF_INFO(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			    proto_tree *tree, int flags, GList **ptr_list)
{
	if (flags & PARSE_SCALARS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "DOM_REF_INFO header");
		subtree = proto_item_add_subtree(item, ett_DOM_REF_INFO_hdr);
	}

	if (flags & PARSE_BUFFERS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "DOM_REF_INFO");
		subtree = proto_item_add_subtree(item, ett_DOM_REF_INFO);

		offset = prs_NAME_AND_SID_ARRAY(tvb, offset, pinfo, subtree, 
						PARSE_SCALARS, ptr_list);

		offset = prs_NAME_AND_SID_ARRAY(tvb, offset, pinfo, subtree, 
						PARSE_BUFFERS, ptr_list);
	}

	return offset;
}

/*
 * Convert a list of names to a list of SIDs.
 *
 *   uint32 LsarLookupNames(
 *       [in] [context_handle] void *hnd,
 *       [in] uint32 num_names,
 *       [in] [size_is(num_names)] [ref] UNISTR2 *names,
 *      [out] [ref] DOM_REF_INFO **domains,
 *   [in,out] [ref] DOM_RID_ARRAY *rids,
 *       [in] uint16 level,
 *   [in,out] [ref] uint32 *num_mapped
 * );
 *
 */

static int LsaLookupNames_q(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	GList *ptr_list = NULL;
	guint32 count, i;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "LookupNames request");

	offset = prs_policy_hnd(tvb, offset, pinfo, tree);

	offset = prs_uint32(tvb, offset, pinfo, tree, &count, "Num names");

	offset = prs_uint32(tvb, offset, pinfo, tree, &count, 
			    "Name array max count");

	for (i = 0; i < count; i++)
		offset = prs_UNISTR(tvb, offset, pinfo, tree, PARSE_SCALARS, 
				    &ptr_list, "Name");

	for (i = 0; i < count; i++)
		offset = prs_UNISTR(tvb, offset, pinfo, tree, PARSE_BUFFERS,
				    &ptr_list, "Name");

	offset = prs_DOM_RID_ARRAY(tvb, offset, pinfo, tree, 
				   PARSE_SCALARS|PARSE_BUFFERS, &ptr_list);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Info level");

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Num mapped");
		
	return offset;
}

static int LsaLookupNames_r(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	GList *ptr_list = NULL;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "LookupNames reply");

	offset = prs_push_ptr(tvb, offset, pinfo, tree, &ptr_list, "Domains");

	if (prs_pop_ptr(&ptr_list, "Domains"))
		offset = prs_DOM_REF_INFO(tvb, offset, pinfo, tree,
					  PARSE_SCALARS|PARSE_BUFFERS, 
					  &ptr_list);

	offset = prs_DOM_RID_ARRAY(tvb, offset, pinfo, tree, 
				   PARSE_SCALARS|PARSE_BUFFERS, &ptr_list);

	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Num mapped");

	offset = prs_ntstatus(tvb, offset, pinfo, tree);

	g_assert(g_list_length(ptr_list) == 0);

	return offset;
}

/*
 * Parse a SID_ARRAY structure.
 *
 * typedef struct {
 *   long count;
 *   [size_is(count)] [unique] PSID *sids;
 * } SID_ARRAY;
 *
 */

static int ett_SID_ARRAY = -1;
static int ett_SID_ARRAY_hdr = -1;

static int prs_SID_ARRAY(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			 proto_tree *tree, int flags, GList **ptr_list)
{
	if (flags & PARSE_SCALARS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "SID_ARRAY header");
		subtree = proto_item_add_subtree(item, ett_SID_ARRAY_hdr);

		
		offset = prs_uint32(tvb, offset, pinfo, subtree, NULL,
				    "Count");
		
		offset = prs_push_ptr(tvb, offset, pinfo, subtree, ptr_list, 
				      "SIDs");
	}

	if (flags & PARSE_BUFFERS) {
		proto_item *item;
		proto_tree *subtree;
		guint32 count, i;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "SID_ARRAY");
		subtree = proto_item_add_subtree(item, ett_SID_ARRAY);

		if (!prs_pop_ptr(ptr_list, "SIDs"))
			goto done;
		
		offset = prs_uint32(tvb, offset, pinfo, subtree, &count, 
				    "Count");

		for (i = 0; i < count; i++)
			offset = prs_push_ptr(tvb, offset, pinfo, 
					      subtree, ptr_list, "SID"); 

		for (i = 0; i < count; i++) {
			if (prs_pop_ptr(ptr_list, "SID"))
				offset = prs_SID(tvb, offset, pinfo, subtree);
		}
	done:
	}

	return offset;
}

/*
 * Parse an ACCOUNT_NAME structure.
 *
 * typedef struct {
 *   unsigned short type;
 *   UNICODE_STRING name;
 *   long dom_idx;
 * } ACCOUNT_NAME;
 *
 */

static int prs_ACCOUNT_NAME(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			    proto_tree *tree, int flags, GList **ptr_list)
{
	if (flags & PARSE_SCALARS) {
		offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Type");

		offset = prs_uint32(tvb, offset, pinfo, tree, NULL, 
				    "Domain index");
		
		offset = prs_UNISTR(tvb, offset, pinfo, tree,
				    PARSE_SCALARS, ptr_list, "Name");
	}

	if (flags & PARSE_BUFFERS) {
		offset = prs_UNISTR(tvb, offset, pinfo, tree,
				    PARSE_BUFFERS, ptr_list, "Name");
	}

	return offset;
}

/*
 * Parse an ACCOUNT_NAME_ARRAY structure.
 *
 * typedef struct {
 *   long count;
 *   [size_is(count)] [unique] ACCOUNT_NAME *domains;
 * } ACCOUNT_NAME_ARRAY;
 *
 */

static int prs_ACCOUNT_NAME_ARRAY(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree, 
				  int flags, GList **ptr_list)
{
	if (flags & PARSE_SCALARS) {
		proto_item *item;
		proto_tree *subtree;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "ACCOUNT_NAME_ARRAY header");
		subtree = proto_item_add_subtree(item, ett_SID_ARRAY_hdr);

		offset = prs_uint32(tvb, offset, pinfo, subtree, NULL, 
				    "Count");
		
		offset = prs_push_ptr(tvb, offset, pinfo, subtree, ptr_list,
				      "ACCOUNT_NAMEs");
	}

	if (flags & PARSE_BUFFERS) {
		proto_item *item;
		proto_tree *subtree;
		guint32 count, i;

		item = proto_tree_add_text(tree, tvb, offset, 0, 
					   "ACCOUNT_NAME_ARRAY");
		subtree = proto_item_add_subtree(item, ett_SID_ARRAY);

		if (!prs_pop_ptr(ptr_list, "ACCOUNT_NAMEs"))
			goto done;
		
		offset = prs_uint32(tvb, offset, pinfo, subtree, &count, 
				    "Count");

		for (i = 0; i < count; i++) {
			offset = prs_ACCOUNT_NAME(tvb, offset, pinfo, subtree, 
						  PARSE_SCALARS, ptr_list);
		}

		for (i = 0; i < count; i++) {
			offset = prs_ACCOUNT_NAME(tvb, offset, pinfo, subtree, 
						  PARSE_BUFFERS, ptr_list);
		}
	done:
	}

	return offset;
}

/*
 * Convert a list of SIDs to a list of names.
 *
 * long LsarLookupSids(
 *       [in] [context_handle] void *hnd,
 *       [in] [ref] SID_ARRAY *sids,
 *      [out] [ref] DOM_REF_INFO **domains,
 *   [in,out] [ref] ACCOUNT_NAME_ARRAY *names,
 *       [in] unsigned short level,
 *   [in,out] [ref] long *num_mapped
 * );
 *
 */

static int LsaLookupSids_q(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			   proto_tree *tree, char *drep)
{
	GList *ptr_list = NULL;
	int flags = PARSE_SCALARS|PARSE_BUFFERS;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "LookupSids request");

	offset = prs_policy_hnd(tvb, offset, pinfo, tree);

	offset = prs_SID_ARRAY(tvb, offset, pinfo, tree, flags, &ptr_list);

	offset = prs_ACCOUNT_NAME_ARRAY(tvb, offset, pinfo, tree, flags, 
					&ptr_list);
	
	offset = prs_uint16(tvb, offset, pinfo, tree, NULL, "Info level");
	
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Num mapped");

	return offset;
}

static int LsaLookupSids_r(tvbuff_t *tvb, int offset, packet_info *pinfo, 
			   proto_tree *tree, char *drep)
{
	GList *ptr_list = NULL;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "LookupSids reply");

	offset = prs_push_ptr(tvb, offset, pinfo, tree, &ptr_list,
			 "DOM_REF_INFO");

	if (prs_pop_ptr(&ptr_list, "DOM_REF_INFO"))
		offset = prs_DOM_REF_INFO(tvb, offset, pinfo, tree,
					  PARSE_SCALARS|PARSE_BUFFERS,
					  &ptr_list);

	offset = prs_ACCOUNT_NAME_ARRAY(tvb, offset, pinfo, tree, 
					PARSE_SCALARS|PARSE_BUFFERS,
					&ptr_list);
	
	offset = prs_uint32(tvb, offset, pinfo, tree, NULL, "Num mapped");
	
	offset = prs_ntstatus(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * List of subdissectors for this pipe.
 */

static dcerpc_sub_dissector dcerpc_lsa_dissectors[] = {
        { LSA_CLOSE, "LSA_CLOSE", LsaClose_q, LsaClose_r },
        { LSA_DELETE, "LSA_DELETE", NULL, NULL },
        { LSA_ENUM_PRIVS, "LSA_ENUM_PRIVS", NULL, NULL },
        { LSA_QUERYSECOBJ, "LSA_QUERYSECOBJ", NULL, NULL },
        { LSA_SETSECOBJ, "LSA_SETSECOBJ", NULL, NULL },
        { LSA_CHANGEPASSWORD, "LSA_CHANGEPASSWORD", NULL, NULL },
        { LSA_OPENPOLICY, "LSA_OPENPOLICY", 
	  LsaOpenPolicy_q, LsaOpenPolicy_r },
        { LSA_QUERYINFOPOLICY, "LSA_QUERYINFOPOLICY", 
	  LsaQueryInfoPolicy_q, LsaQueryInfoPolicy_r },
        { LSA_SETINFOPOLICY, "LSA_SETINFOPOLICY", NULL, NULL },
        { LSA_CLEARAUDITLOG, "LSA_CLEARAUDITLOG", NULL, NULL },
        { LSA_CREATEACCOUNT, "LSA_CREATEACCOUNT", NULL, NULL },
        { LSA_ENUM_ACCOUNTS, "LSA_ENUM_ACCOUNTS", NULL, NULL },
        { LSA_CREATETRUSTDOM, "LSA_CREATETRUSTDOM", NULL, NULL },
        { LSA_ENUMTRUSTDOM, "LSA_ENUMTRUSTDOM", NULL, NULL },
        { LSA_LOOKUPNAMES, "LSA_LOOKUPNAMES",
	  LsaLookupNames_q, LsaLookupNames_r },
        { LSA_LOOKUPSIDS, "LSA_LOOKUPSIDS", 
	  LsaLookupSids_q, LsaLookupSids_r },
        { LSA_CREATESECRET, "LSA_CREATESECRET", NULL, NULL },
        { LSA_OPENACCOUNT, "LSA_OPENACCOUNT", NULL, NULL },
        { LSA_ENUMPRIVSACCOUNT, "LSA_ENUMPRIVSACCOUNT", NULL, NULL },
        { LSA_ADDPRIVS, "LSA_ADDPRIVS", NULL, NULL },
        { LSA_REMOVEPRIVS, "LSA_REMOVEPRIVS", NULL, NULL },
        { LSA_GETQUOTAS, "LSA_GETQUOTAS", NULL, NULL },
        { LSA_SETQUOTAS, "LSA_SETQUOTAS", NULL, NULL },
        { LSA_GETSYSTEMACCOUNT, "LSA_GETSYSTEMACCOUNT", NULL, NULL },
        { LSA_SETSYSTEMACCOUNT, "LSA_SETSYSTEMACCOUNT", NULL, NULL },
        { LSA_OPENTRUSTDOM, "LSA_OPENTRUSTDOM", NULL, NULL },
        { LSA_QUERYTRUSTDOM, "LSA_QUERYTRUSTDOM", NULL, NULL },
        { LSA_SETINFOTRUSTDOM, "LSA_SETINFOTRUSTDOM", NULL, NULL },
        { LSA_OPENSECRET, "LSA_OPENSECRET", NULL, NULL },
        { LSA_SETSECRET, "LSA_SETSECRET", NULL, NULL },
        { LSA_QUERYSECRET, "LSA_QUERYSECRET", NULL, NULL },
        { LSA_LOOKUPPRIVVALUE, "LSA_LOOKUPPRIVVALUE", NULL, NULL },
        { LSA_LOOKUPPRIVNAME, "LSA_LOOKUPPRIVNAME", NULL, NULL },
        { LSA_PRIV_GET_DISPNAME, "LSA_PRIV_GET_DISPNAME", NULL, NULL },
        { LSA_DELETEOBJECT, "LSA_DELETEOBJECT", NULL, NULL },
        { LSA_ENUMACCTWITHRIGHT, "LSA_ENUMACCTWITHRIGHT", NULL, NULL },
        { LSA_ENUMACCTRIGHTS, "LSA_ENUMACCTRIGHTS", NULL, NULL },
        { LSA_ADDACCTRIGHTS, "LSA_ADDACCTRIGHTS", NULL, NULL },
        { LSA_REMOVEACCTRIGHTS, "LSA_REMOVEACCTRIGHTS", NULL, NULL },
        { LSA_QUERYTRUSTDOMINFO, "LSA_QUERYTRUSTDOMINFO", NULL, NULL },
        { LSA_SETTRUSTDOMINFO, "LSA_SETTRUSTDOMINFO", NULL, NULL },
        { LSA_DELETETRUSTDOM, "LSA_DELETETRUSTDOM", NULL, NULL },
        { LSA_STOREPRIVDATA, "LSA_STOREPRIVDATA", NULL, NULL },
        { LSA_RETRPRIVDATA, "LSA_RETRPRIVDATA", NULL, NULL },
        { LSA_OPENPOLICY2, "LSA_OPENPOLICY2", NULL, NULL },
        { LSA_UNK_GET_CONNUSER, "LSA_UNK_GET_CONNUSER", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

/* Protocol registration */

static int proto_dcerpc_lsa = -1;
static gint ett_dcerpc_lsa = -1;

void 
proto_register_dcerpc_lsa(void)
{
        static gint *ett[] = {
                &ett_dcerpc_lsa,
		&ett_UNISTR,
		&ett_UNISTR_hdr,
		&ett_NAME_AND_SID,
		&ett_NAME_AND_SID_hdr,
		&ett_SID,
		&ett_POLICY_INFORMATION,
		&ett_DOM_REF_INFO,
		&ett_DOM_REF_INFO_hdr,
		&ett_DOM_RID_ARRAY,
		&ett_DOM_RID_ARRAY_hdr,
		&ett_DOM_RID,
		&ett_SID_ARRAY,
		&ett_SID_ARRAY_hdr,
		&ett_NAME_AND_SID_ARRAY,
		&ett_NAME_AND_SID_ARRAY_hdr,
		&ett_SECURITY_QOS,
		&ett_SECURITY_QOS_hdr,
        };

        proto_dcerpc_lsa = proto_register_protocol(
                "Microsoft Local Security Architecture", "LSA", "lsa");

        proto_register_subtree_array(ett, array_length(ett));
}

/* Protocol handoff */

static e_uuid_t uuid_dcerpc_lsa = {
        0x12345778, 0x1234, 0xabcd, 
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
};

static guint16 ver_dcerpc_lsa = 0;

void
proto_reg_handoff_dcerpc_lsa(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_lsa, ett_dcerpc_lsa, &uuid_dcerpc_lsa,
                         ver_dcerpc_lsa, dcerpc_lsa_dissectors);
}
