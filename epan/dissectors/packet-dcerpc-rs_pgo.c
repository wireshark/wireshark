/* packet-dcerpc-rs_pgo.c
 *
 * Routines for dcerpc Afs4Int dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz  security/idl/rs_pgo.idl
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-dce122.h"
/*
delete
dissect_rgy_acct_user_flags_t
*/

static int proto_rs_pgo = -1;
static int hf_rs_pgo_opnum = -1;
static int hf_rs_var1 = -1;
static int hf_rs_pgo_query_result_t = -1;
static int hf_rs_pgo_query_t = -1;
static int hf_rs_pgo_query_key_t = -1;
static int hf_error_status_t = -1;
static int hf_sec_rgy_pgo_flags_t = -1;
static int hf_rs_sec_rgy_pgo_item_t_quota = -1;
static int hf_rs_sec_rgy_pgo_item_t_unix_num = -1;
static int hf_rs_timeval = -1;
static int hf_rs_uuid1 = -1;
static int hf_sec_rgy_domain_t = -1;
static int hf_sec_rgy_name_t_principalName_string = -1;
static int hf_sec_rgy_name_t_size = -1;
static int hf_sec_rgy_pname_t_principalName_string = -1;
static int hf_sec_rgy_pname_t_size = -1;
static int hf_rs_pgo_unix_num_key_t = -1;

static gint ett_rs_cache_data_t = -1;
static gint ett_sec_rgy_domain_t = -1;
static gint ett_rgy_acct_user_flags_t = -1;
static gint ett_sec_attr_component_name_t = -1;
static gint ett_sec_passwd_type_t = -1;
static gint ett_sec_rgy_acct_admin_flags_t = -1;
static gint ett_sec_rgy_acct_admin_t = -1;
static gint ett_sec_rgy_acct_auth_flags_t = -1;
static gint ett_sec_rgy_acct_key_t = -1;
static gint ett_sec_rgy_acct_user_t = -1;
static gint ett_sec_rgy_cursor_t = -1;
static gint ett_sec_rgy_foreign_id_t = -1;
static gint ett_sec_rgy_login_name_t = -1;
static gint ett_sec_rgy_name_t = -1;
static gint ett_sec_rgy_pgo_item_t = -1;
static gint ett_sec_rgy_pname_t = -1;
static gint ett_sec_rgy_sid_t = -1;
static gint ett_sec_rgy_unix_passwd_buf_t = -1;
static gint ett_sec_rgy_unix_sid_t = -1;
static gint ett_sec_timeval_sec_t = -1;
static gint ett_sec_rgy_pgo_flags_t = -1;
static gint ett_error_status_t = -1;
static gint ett_rs_pgo_query_t = -1;
static gint ett_rs_pgo_query_key_t = -1;
static gint ett_rs_pgo_id_key_t = -1;
static gint ett_rs_pgo_unix_num_key_t = -1;
static gint ett_rs_pgo_query_result_t = -1;
static gint ett_rs_pgo_result_t = -1;


#define sec_rgy_acct_admin_valid  0x1
#define sec_rgy_acct_admin_audit   0x2
#define sec_rgy_acct_admin_server  0x4
#define sec_rgy_acct_admin_client  0x8
#define sec_rgy_acct_admin_flags_none  0
#define sec_rgy_acct_auth_post_dated        0x1
#define sec_rgy_acct_auth_forwardable       0x2
#define sec_rgy_acct_auth_tgt               0x4
#define sec_rgy_acct_auth_renewable         0x8
#define sec_rgy_acct_auth_proxiable        0x10
#define sec_rgy_acct_auth_dup_skey   0x20
#define sec_rgy_acct_auth_user_to_user  0x40
#define sec_rgy_acct_auth_flags_none  0
#define sec_rgy_acct_user_passwd_valid   0x1
#define sec_rgy_acct_user_flags_none  0
#define rs_acct_part_user        0x1
#define rs_acct_part_admin      0x2
#define rs_acct_part_passwd    0x4
#define rs_acct_part_unused     0x8
#define rs_acct_part_login_name  0x10
#define sec_rgy_pgo_is_an_alias   0x1
#define sec_rgy_pgo_is_required   0x2
#define sec_rgy_pgo_projlist_ok  0x4
#define sec_rgy_pgo_flags_none  0
#define sec_rgy_acct_user_passwd_valid  0x1
#define sec_rgy_acct_user_flags_none  0

static gint ett_rs_pgo = -1;

static e_uuid_t uuid_rs_pgo =
  { 0x4c878280, 0x3000, 0x0000, {0x0d, 0x00, 0x02, 0x87, 0x14, 0x00, 0x00,
				 0x00}
};
static guint16 ver_rs_pgo = 1;


static int
dissect_error_status_t (tvbuff_t * tvb, int offset,
			packet_info * pinfo, proto_tree * parent_tree,
			guint8 * drep)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 st;
  dcerpc_info *di;
  const char *st_str;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1,
				  "error_status_t");
      tree = proto_item_add_subtree (item, ett_error_status_t);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_error_status_t,
			&st);
  st_str = val_to_str_ext (st, &dce_error_vals_ext, "%u");

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " st:%s ", st_str);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_sec_rgy_pname_t (tvbuff_t * tvb, int offset,
			 packet_info * pinfo, proto_tree * parent_tree,
			 guint8 * drep)
{


  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
#define    sec_rgy_pname_t_size 257
/*
dissect    sec_rgy_pname const signed32        sec_rgy_pname_t_size  = 257; * Include final '\0' *
          typedef [string] char sec_rgy_pname_t[sec_rgy_pname_t_size];
*/
  guint32 string_size;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1, "sec_rgy_pname_t");
      tree = proto_item_add_subtree (item, ett_sec_rgy_pname_t);
    }

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			       hf_sec_rgy_pname_t_size, &string_size);
  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " String_size:%u", string_size);
  if (string_size < sec_rgy_pname_t_size)
    {
/* proto_tree_add_string(tree, id, tvb, start, length, value_ptr); */

      proto_tree_add_item (tree, hf_sec_rgy_pname_t_principalName_string,
			   tvb, offset, string_size, ENC_ASCII|ENC_NA);
      if (string_size > 1)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_fstr (pinfo->cinfo, COL_INFO, " Principal:%s",
			     tvb_get_ephemeral_string(tvb, offset, string_size));
	}
      offset += string_size;
    }
  else
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO,
			 " :FIXME!: Invalid string length of  %u",
			 string_size);
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_sec_rgy_pgo_flags_t (tvbuff_t * tvb, int offset,
			     packet_info * pinfo, proto_tree * parent_tree,
			     guint8 * drep)
{

/*

*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  dcerpc_info *di;
  guint32 flags;

/*
    typedef bitset  sec_rgy_pgo_flags_t;
*/

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1,
			     "sec_rgy_pgo_flags_t ");
      tree = proto_item_add_subtree (item, ett_sec_rgy_pgo_flags_t);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_sec_rgy_pgo_flags_t, &flags);

/*
     *
     * s e c _ r g y _ p g o _ f l a g s _ t
     *

        * pgo item is an alias *
        const unsigned32 sec_rgy_pgo_is_an_alias  = 0x1;

        * pgo item is required - cannot be deleted *
        const unsigned32 sec_rgy_pgo_is_required  = 0x2;

        *
         * projlist_ok: on person items indicates person can have a concurrent
         * group set on group items indicates this group can appear on a
         * concurrent group set.  On org items this flag is undefined.
         *
        const unsigned32 sec_rgy_pgo_projlist_ok = 0x4;

        *
        * bits 4-32 unused
        *
        const unsigned32 sec_rgy_pgo_flags_none = 0;
*/
#define sec_rgy_pgo_is_an_alias   0x1
#define sec_rgy_pgo_is_required   0x2
#define sec_rgy_pgo_projlist_ok   0x4
#define sec_rgy_pgo_flags_none      0


  col_append_str (pinfo->cinfo, COL_INFO, " PgoFlags=");
  if ((flags & sec_rgy_pgo_is_an_alias) == sec_rgy_pgo_is_an_alias)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":IS_AN_ALIAS");
    }
  if ((flags & sec_rgy_pgo_is_required) == sec_rgy_pgo_is_required)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":IS_REQUIRED");
    }
  if ((flags & sec_rgy_pgo_projlist_ok) == sec_rgy_pgo_projlist_ok)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":PROJLIST_OK");
    }
  if ((flags & sec_rgy_acct_admin_client) == sec_rgy_acct_admin_client)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":NONE");
    }
  if ((flags & sec_rgy_pgo_flags_none) == sec_rgy_pgo_flags_none)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":NONE");
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}




static int
dissect_rs_cache_data_t (tvbuff_t * tvb, int offset,
			 packet_info * pinfo, proto_tree * parent_tree,
			 guint8 * drep)
{

/*
    typedef struct {
        uuid_t              site_id;
        sec_timeval_sec_t   person_dtm;
        sec_timeval_sec_t   group_dtm;
        sec_timeval_sec_t   org_dtm;
    } rs_cache_data_t;
*/


  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  dcerpc_info *di;
  guint32 person_dtm, group_dtm, org_dtm;
  e_uuid_t uuid1;


  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1, "rs_cache_data_t");
      tree = proto_item_add_subtree (item, ett_rs_cache_data_t);
    }


  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep, hf_rs_uuid1, &uuid1);
  offset =
    dissect_dcerpc_time_t (tvb, offset, pinfo, tree, drep, hf_rs_timeval,
			   &person_dtm);
  offset =
    dissect_dcerpc_time_t (tvb, offset, pinfo, tree, drep, hf_rs_timeval,
			   &group_dtm);
  offset =
    dissect_dcerpc_time_t (tvb, offset, pinfo, tree, drep, hf_rs_timeval,
			   &org_dtm);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     " siteid %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x person_dtm:%u group_dtm:%u org_dtm:%u",
		     uuid1.Data1, uuid1.Data2, uuid1.Data3, uuid1.Data4[0],
		     uuid1.Data4[1], uuid1.Data4[2], uuid1.Data4[3],
		     uuid1.Data4[4], uuid1.Data4[5], uuid1.Data4[6],
		     uuid1.Data4[7], person_dtm, group_dtm, org_dtm);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}



static int
dissect_sec_rgy_name_t (tvbuff_t * tvb, int offset,
			packet_info * pinfo, proto_tree * parent_tree,
			guint8 * drep)
{


  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
#define    sec_rgy_name_t_size  1025
/*    typedef [string] char sec_rgy_name_t[sec_rgy_name_t_size]; */
  guint32 string_size;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1, "sec_rgy_name_t");
      tree = proto_item_add_subtree (item, ett_sec_rgy_name_t);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_sec_rgy_name_t_size, &string_size);
  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " String_size:%u", string_size);
  if (string_size < sec_rgy_name_t_size)
    {
/* proto_tree_add_string(tree, id, tvb, start, length, value_ptr); */

      proto_tree_add_item (tree, hf_sec_rgy_name_t_principalName_string,
			   tvb, offset, string_size, ENC_ASCII|ENC_NA);
      if (string_size > 1)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_fstr (pinfo->cinfo, COL_INFO, " Principal:%s",
			     tvb_get_ephemeral_string (tvb, offset, string_size));
	}
      offset += string_size;
    }
  else
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO,
			 " :FIXME!: Invalid string length of  %u",
			 string_size);
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_sec_rgy_domain_t (tvbuff_t * tvb, int offset,
			  packet_info * pinfo, proto_tree * parent_tree,
			  guint8 * drep)
{

/*
    typedef signed32    sec_rgy_domain_t;
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  dcerpc_info *di;
  guint32 domain_t;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1, "sec_rgy_domain_t");
      tree = proto_item_add_subtree (item, ett_sec_rgy_domain_t);
    }


  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_sec_rgy_domain_t,
			&domain_t);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " sec_rgy_domain_t:%u",
		     domain_t);


  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_sec_rgy_pgo_item_t (tvbuff_t * tvb, int offset,
			    packet_info * pinfo, proto_tree * parent_tree,
			    guint8 * drep)
{

/*
    typedef struct {
        uuid_t              id;
        signed32            unix_num;
        signed32            quota;
        sec_rgy_pgo_flags_t flags;
        sec_rgy_pname_t     fullname;
    }               sec_rgy_pgo_item_t;

*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  dcerpc_info *di;
  e_uuid_t id;
  guint32 unix_num, quota;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1,
			     " sec_rgy_pgo_item_t ");
      tree = proto_item_add_subtree (item, ett_sec_rgy_pgo_item_t);
    }

  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep, hf_rs_uuid1, &id);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_rs_sec_rgy_pgo_item_t_unix_num, &unix_num);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_rs_sec_rgy_pgo_item_t_quota, &quota);
  offset = dissect_sec_rgy_pgo_flags_t (tvb, offset, pinfo, tree, drep);
  offset += 4;			/* XXX */
  offset = dissect_sec_rgy_pname_t (tvb, offset, pinfo, tree, drep);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     " sec_rgy_pgo_item_t - id %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x unix_num:%u quota:%u",
		     id.Data1, id.Data2, id.Data3, id.Data4[0],
		     id.Data4[1], id.Data4[2], id.Data4[3],
		     id.Data4[4], id.Data4[5], id.Data4[6],
		     id.Data4[7], unix_num, quota);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_sec_rgy_cursor_t (tvbuff_t * tvb, int offset,
			  packet_info * pinfo, proto_tree * parent_tree,
			  guint8 * drep)
{

/*
     * Database cursor for iterative operations
     *
    typedef struct {
        uuid_t          source;
        signed32        handle;
        boolean32       valid;
    }               sec_rgy_cursor_t;


*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  dcerpc_info *di;
  e_uuid_t source;
  guint32 handle, valid;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1,
			     " sec_rgy_cursor_t ");
      tree = proto_item_add_subtree (item, ett_sec_rgy_cursor_t);
    }

  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep, hf_rs_uuid1, &source);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_rs_sec_rgy_pgo_item_t_unix_num, &handle);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_rs_sec_rgy_pgo_item_t_quota, &valid);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     " sec_rgy_cursor_t - source %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x handle:%u valid:%u",
		     source.Data1, source.Data2, source.Data3,
		     source.Data4[0], source.Data4[1], source.Data4[2],
		     source.Data4[3], source.Data4[4], source.Data4[5],
		     source.Data4[6], source.Data4[7], handle, valid);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_rs_pgo_query_t (tvbuff_t * tvb, int offset,
			packet_info * pinfo, proto_tree * parent_tree,
			guint8 * drep)
{

  typedef enum
  {
    rs_pgo_query_name,
    rs_pgo_query_id,
    rs_pgo_query_unix_num,
    rs_pgo_query_next,
    rs_pgo_query_none
  } rs_pgo_query_t;


  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  dcerpc_info *di;
  guint8 query_t;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1, "rs_pgo_query_t ");
      tree = proto_item_add_subtree (item, ett_rs_pgo_query_t);
    }
  offset =
    dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep, hf_rs_pgo_query_t,
		       &query_t);
  col_append_str (pinfo->cinfo, COL_INFO, " rs_pgo_query_t:");

  switch (query_t)
    {
    case rs_pgo_query_name:
      col_append_str (pinfo->cinfo, COL_INFO, "NAME");
      break;
    case rs_pgo_query_id:
      col_append_str (pinfo->cinfo, COL_INFO, "ID");
      break;
    case rs_pgo_query_unix_num:
      col_append_str (pinfo->cinfo, COL_INFO, "UNIX_NUM");
      break;
    case rs_pgo_query_next:
      col_append_str (pinfo->cinfo, COL_INFO, "NEXT");
      break;
    case rs_pgo_query_none:
      col_append_str (pinfo->cinfo, COL_INFO, "NONE");
      break;
    default:
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, " unknown:%u", query_t);
      break;
      ;
    }


  proto_item_set_len (item, offset - old_offset);
  return offset;
}
static int
dissect_rs_pgo_id_key_t (tvbuff_t * tvb, int offset,
			 packet_info * pinfo, proto_tree * parent_tree,
			 guint8 * drep)
{

/*
    typedef struct {
        uuid_t          id;
        sec_rgy_name_t  scope;
    } rs_pgo_id_key_t;

*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  dcerpc_info *di;
  e_uuid_t id;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1,
			     "rs_pgo_id_key_t ");
      tree = proto_item_add_subtree (item, ett_rs_pgo_id_key_t);
    }

  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep, hf_rs_uuid1, &id);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     " rs_pgo_id_key_t - id %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		     id.Data1, id.Data2, id.Data3, id.Data4[0],
		     id.Data4[1], id.Data4[2], id.Data4[3],
		     id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_rs_pgo_result_t (tvbuff_t * tvb, int offset,
			 packet_info * pinfo, proto_tree * parent_tree,
			 guint8 * drep)
{

/*
    typedef struct {
        sec_rgy_name_t      name;
        sec_rgy_pgo_item_t  item;
    } rs_pgo_result_t;


*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1,
			     "rs_pgo_result_t ");
      tree = proto_item_add_subtree (item, ett_rs_pgo_result_t);
    }

  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_sec_rgy_pgo_item_t (tvb, offset, pinfo, tree, drep);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}



static int
dissect_rs_pgo_unix_num_key_t (tvbuff_t * tvb, int offset,
			       packet_info * pinfo, proto_tree * parent_tree,
			       guint8 * drep)
{

/*
    typedef struct {
        signed32        unix_num;
        sec_rgy_name_t  scope;
    } rs_pgo_unix_num_key_t;


r

*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  dcerpc_info *di;
  guint32 rs_pgo_unix_num_key_t;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1,
			     " rs_pgo_unix_num_key_t ");
      tree = proto_item_add_subtree (item, ett_rs_pgo_unix_num_key_t);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_rs_pgo_unix_num_key_t, &rs_pgo_unix_num_key_t);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     " rs_pgo_unix_num_key_t:%u", rs_pgo_unix_num_key_t);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_rs_pgo_query_key_t (tvbuff_t * tvb, int offset,
			    packet_info * pinfo, proto_tree * parent_tree,
			    guint8 * drep)
{

  typedef enum
  {
    rs_pgo_query_name,
    rs_pgo_query_id,
    rs_pgo_query_unix_num,
    rs_pgo_query_next,
    rs_pgo_query_none
  } rs_pgo_query_t;
/*
    typedef union switch (rs_pgo_query_t query) tagged_union {
        case rs_pgo_query_name:
            sec_rgy_name_t              name;

        case rs_pgo_query_id:
            rs_pgo_id_key_t             id_key;

        case rs_pgo_query_unix_num:
            rs_pgo_unix_num_key_t       unix_num_key;

        case rs_pgo_query_next:
            sec_rgy_name_t              scope;

        default:
            ;                       * empty branch of union *

    } rs_pgo_query_key_t;
*/


  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  dcerpc_info *di;
  guint16 query_t;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1,
			     "rs_pgo_query_key_t ");
      tree = proto_item_add_subtree (item, ett_rs_pgo_query_key_t);
    }
  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep, hf_rs_pgo_query_key_t,
			&query_t);
  col_append_str (pinfo->cinfo, COL_INFO, " rs_pgo_query_key_t:");
  offset += 4;
  switch (query_t)
    {
    case rs_pgo_query_name:
      col_append_str (pinfo->cinfo, COL_INFO, "NAME");
      offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);
      break;
    case rs_pgo_query_id:
      col_append_str (pinfo->cinfo, COL_INFO, "ID");
      offset = dissect_rs_pgo_id_key_t (tvb, offset, pinfo, tree, drep);
      break;
    case rs_pgo_query_unix_num:
      col_append_str (pinfo->cinfo, COL_INFO, "UNIX_NUM");
      offset = dissect_rs_pgo_unix_num_key_t (tvb, offset, pinfo, tree, drep);
      break;
    case rs_pgo_query_next:
      col_append_str (pinfo->cinfo, COL_INFO, "NEXT");
      offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);
      break;
    case rs_pgo_query_none:
      col_append_str (pinfo->cinfo, COL_INFO, "NONE");
      break;

    default:
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, " unknown:%u", query_t);
      ;
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_rs_pgo_query_result_t (tvbuff_t * tvb, int offset,
			       packet_info * pinfo, proto_tree * parent_tree,
			       guint8 * drep)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 st;
  dcerpc_info *di;
  const char *status;
#define error_status_ok 0

  /*
     typedef union switch (signed32 status) tagged_union {
     case error_status_ok:
     rs_pgo_result_t     result;

     default:
     ;                      * empty branch of union *

     } rs_pgo_query_result_t;
   */

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1,
				  "rs_pgo_query_result_t");
      tree = proto_item_add_subtree (item, ett_rs_pgo_query_result_t);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_rs_pgo_query_result_t, &st);
  status = val_to_str_ext (st, &dce_error_vals_ext, "%u");

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " status:%s ", status);

  offset += 4;			/* XXX */

  switch (st)
    {
    case error_status_ok:
      offset = dissect_rs_pgo_result_t (tvb, offset, pinfo, tree, drep);
      break;
    default:
      ;

    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}



static int
rs_pgo_dissect_add_rqst (tvbuff_t * tvb, int offset,
			 packet_info * pinfo, proto_tree * tree,
			 guint8 * drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]        sec_rgy_domain_t    name_domain,
        [in]        sec_rgy_name_t      pgo_name,
        [in]        sec_rgy_pgo_item_t  *pgo_item,
*/

  offset = dissect_sec_rgy_domain_t (tvb, offset, pinfo, tree, drep);
  offset += 4;
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_sec_rgy_pgo_item_t, NDR_POINTER_REF,
			 "sec_rgy_pgo_item_t: ", -1);

  return offset;
}
static int
rs_pgo_dissect_add_resp (tvbuff_t * tvb, int offset,
			 packet_info * pinfo, proto_tree * tree,
			 guint8 * drep)
{
  dcerpc_info *di;
  guint32 buff_remain;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]       rs_cache_data_t     *cache_info,
        [out]       error_status_t      *status
*/

 buff_remain = tvb_length_remaining(tvb, offset);

/* found several add_member responses that had 8 bytes of data. first was 4 0's and last was 3 zeros and a 1 */
if (buff_remain > 8) {
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_cache_data_t, NDR_POINTER_REF,
			 "cache_info: ", -1);
}
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_error_status_t, NDR_POINTER_REF, "status: ",
			 -1);
  return offset;
}

static int
rs_pgo_dissect_delete_rqst (tvbuff_t * tvb, int offset,
			    packet_info * pinfo, proto_tree * tree,
			    guint8 * drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]        sec_rgy_domain_t    name_domain,
        [in]        sec_rgy_name_t      pgo_name,
*/
  offset = dissect_sec_rgy_domain_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);

  return offset;
}

static int
rs_pgo_dissect_delete_resp (tvbuff_t * tvb, int offset,
			    packet_info * pinfo, proto_tree * tree,
			    guint8 * drep)
{
  dcerpc_info *di;
  guint32 buff_remain;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]       rs_cache_data_t     *cache_info,
        [out]       error_status_t      *status
*/
 buff_remain = tvb_length_remaining(tvb, offset);

/* found several add_member responses that had 8 bytes of data. first was 4 0's and last was 3 zeros and a 1 */

  if (buff_remain > 8) {
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_cache_data_t, NDR_POINTER_REF,
			 "cache_info:", -1);
  }

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_error_status_t, NDR_POINTER_REF, "status:",
			 -1);

  return offset;
}

static int
rs_pgo_dissect_replace_rqst (tvbuff_t * tvb, int offset,
			     packet_info * pinfo, proto_tree * tree,
			     guint8 * drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]        sec_rgy_domain_t    name_domain,
        [in]        sec_rgy_name_t      pgo_name,
        [in]        sec_rgy_pgo_item_t  *pgo_item,
*/
  offset = dissect_sec_rgy_domain_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_sec_rgy_pgo_item_t, NDR_POINTER_REF,
			 "pgo_item:", -1);

  return offset;
}

static int
rs_pgo_dissect_replace_resp (tvbuff_t * tvb, int offset,
			     packet_info * pinfo, proto_tree * tree,
			     guint8 * drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]       rs_cache_data_t     *cache_info,
        [out]       error_status_t      *status

*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_cache_data_t, NDR_POINTER_REF,
			 "cache_info:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_error_status_t, NDR_POINTER_REF, "status:",
			 -1);

  return offset;
}


static int
rs_pgo_dissect_add_member_rqst (tvbuff_t * tvb, int offset,
				packet_info * pinfo, proto_tree * tree,
				guint8 * drep)
{

  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }



/*
        [in]        sec_rgy_domain_t    name_domain,
        [in]        sec_rgy_name_t      go_name,
        [in]        sec_rgy_name_t      person_name,
*/

  offset = dissect_sec_rgy_domain_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);


  return offset;

}
static int
rs_pgo_dissect_rename_rqst (tvbuff_t * tvb, int offset,
			    packet_info * pinfo, proto_tree * tree,
			    guint8 * drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]        sec_rgy_domain_t    name_domain,
        [in]        sec_rgy_name_t      old_name,
        [in]        sec_rgy_name_t      new_name,
*/
  offset = dissect_sec_rgy_domain_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);


  return offset;
}

static int
rs_pgo_dissect_rename_resp (tvbuff_t * tvb, int offset,
			    packet_info * pinfo, proto_tree * tree,
			    guint8 * drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]       rs_cache_data_t     *cache_info,
        [out]       error_status_t      *status
*/
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_cache_data_t, NDR_POINTER_REF,
			 "cache_info:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_error_status_t, NDR_POINTER_REF, "status:",
			 -1);

  return offset;
}


static int
rs_pgo_dissect_add_member_resp (tvbuff_t * tvb, int offset,
				packet_info * pinfo, proto_tree * tree,
				guint8 * drep)
{
  dcerpc_info *di;
  guint32 buff_remain;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]       rs_cache_data_t     *cache_info,
        [out]       error_status_t      *status
*/

 buff_remain = tvb_length_remaining(tvb, offset);

/* found several add responses that had 8 bytes of data. first was 4 0's and last was 3 zeros and a 1 */
if (buff_remain > 8) {

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_cache_data_t, NDR_POINTER_REF,
			 "cache_info:", -1);
}
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_error_status_t, NDR_POINTER_REF, "status:",
			 -1);


  return offset;
}

static int
rs_pgo_dissect_delete_member_rqst (tvbuff_t * tvb, int offset,
				   packet_info * pinfo, proto_tree * tree,
				   guint8 * drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
    void rs_pgo_delete_member (
        [in]        sec_rgy_domain_t    name_domain,
        [in]        sec_rgy_name_t      go_name,
        [in]        sec_rgy_name_t      person_name,
    );
*/

  offset = dissect_sec_rgy_domain_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);

  return offset;

}


static int
rs_pgo_dissect_get_members_rqst (tvbuff_t * tvb, int offset,
				 packet_info * pinfo, proto_tree * tree,
				 guint8 * drep)
{

  guint32 max_members;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]        sec_rgy_domain_t        name_domain,
        [in]        sec_rgy_name_t          go_name,
        [in, out]   sec_rgy_cursor_t        *member_cursor,
        [in]        signed32                max_members,
*/

  offset = dissect_sec_rgy_domain_t (tvb, offset, pinfo, tree, drep);
  offset += 4;
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_sec_rgy_cursor_t, NDR_POINTER_REF,
			 "member_cursor:", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rs_var1,
			&max_members);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " :max_members:%u", max_members);

  return offset;
}

static int
rs_pgo_dissect_key_transfer_rqst (tvbuff_t * tvb, int offset,
				  packet_info * pinfo, proto_tree * tree,
				  guint8 * drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]        sec_rgy_domain_t    name_domain,
        [in]        rs_pgo_query_t      requested_result_type,
        [in, out]   rs_pgo_query_key_t  *key,
*/

  offset += 4;
  offset = dissect_sec_rgy_domain_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_rs_pgo_query_t (tvb, offset, pinfo, tree, drep);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_pgo_query_key_t, NDR_POINTER_REF, "key:",
			 -1);

  return offset;
}

static int
rs_pgo_dissect_key_transfer_resp (tvbuff_t * tvb, int offset,
				  packet_info * pinfo, proto_tree * tree,
				  guint8 * drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in, out]   rs_pgo_query_key_t  *key,
        [out]       rs_cache_data_t     *cache_info,
        [out]       error_status_t      *status
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_pgo_query_key_t, NDR_POINTER_REF, "key:",
			 -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_cache_data_t, NDR_POINTER_REF,
			 "cache_info:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_error_status_t, NDR_POINTER_REF, "status:",
			 -1);

  return offset;
}


static int
rs_pgo_dissect_is_member_resp (tvbuff_t * tvb, int offset,
			       packet_info * pinfo, proto_tree * tree,
			       guint8 * drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]       rs_cache_data_t     *cache_info,
        [out]       error_status_t      *status
*/
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_cache_data_t, NDR_POINTER_REF,
			 "cache_info:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_error_status_t, NDR_POINTER_REF, "status:",
			 -1);

  return offset;
}

static int
rs_pgo_dissect_is_member_rqst (tvbuff_t * tvb, int offset,
			       packet_info * pinfo, proto_tree * tree,
			       guint8 * drep)
{
  dcerpc_info *di;
/*
        [in]        sec_rgy_domain_t    name_domain,
        [in]        sec_rgy_name_t      go_name,
        [in]        sec_rgy_name_t      person_name,
*/


  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  offset += 4;
  offset = dissect_sec_rgy_domain_t (tvb, offset, pinfo, tree, drep);
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);
  offset += 4;
  offset = dissect_sec_rgy_name_t (tvb, offset, pinfo, tree, drep);


  return offset;

}


static int
rs_pgo_dissect_get_rqst (tvbuff_t * tvb, int offset,
			 packet_info * pinfo, proto_tree * tree,
			 guint8 * drep)
{
  dcerpc_info *di;
  guint32 allow_aliases;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]        sec_rgy_domain_t        name_domain,
        [in]        rs_pgo_query_key_t      *key,
        [in]        boolean32               allow_aliases,
        [in, out]   sec_rgy_cursor_t        *item_cursor,
*/

  offset = dissect_sec_rgy_domain_t (tvb, offset, pinfo, tree, drep);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_pgo_query_key_t, NDR_POINTER_REF, "key:",
			 -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rs_var1,
			&allow_aliases);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " :allow_aliases:%u",
		     allow_aliases);


  offset += 4;			/* XXX */

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_sec_rgy_cursor_t, NDR_POINTER_REF,
			 "item_cursor:", -1);
  return offset;

}

static int
rs_pgo_dissect_get_resp (tvbuff_t * tvb, int offset,
			 packet_info * pinfo, proto_tree * tree,
			 guint8 * drep)
{

  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in, out]   sec_rgy_cursor_t        *item_cursor,
        [out]       rs_cache_data_t         *cache_info,
        [out]       rs_pgo_query_result_t   *result
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_sec_rgy_cursor_t, NDR_POINTER_REF,
			 "item_cursor:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_cache_data_t, NDR_POINTER_REF,
			 "cache_info:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_pgo_query_result_t, NDR_POINTER_REF,
			 "result:", -1);

  return offset;

}

static int
rs_pgo_dissect_delete_member_resp (tvbuff_t * tvb, int offset,
				   packet_info * pinfo, proto_tree * tree,
				   guint8 * drep)
{

  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]       rs_cache_data_t     *cache_info,
        [out]       error_status_t      *status

*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_rs_cache_data_t, NDR_POINTER_REF,
			 "cache_info:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_error_status_t, NDR_POINTER_REF, "status:",
			 -1);

  return offset;

}


static dcerpc_sub_dissector rs_pgo_dissectors[] = {
  {0, "add", rs_pgo_dissect_add_rqst, rs_pgo_dissect_add_resp},
  {1, "delete", rs_pgo_dissect_delete_rqst, rs_pgo_dissect_delete_resp},
  {2, "replace", rs_pgo_dissect_replace_rqst, rs_pgo_dissect_replace_resp},
  {3, "rename", rs_pgo_dissect_rename_rqst, rs_pgo_dissect_rename_resp},
  {4, "get", rs_pgo_dissect_get_rqst, rs_pgo_dissect_get_resp},
  {5, "key_transfer", rs_pgo_dissect_key_transfer_rqst,
   rs_pgo_dissect_key_transfer_resp},
  {6, "add_member", rs_pgo_dissect_add_member_rqst,
   rs_pgo_dissect_add_member_resp},
  {7, "delete_member", rs_pgo_dissect_delete_member_rqst,
   rs_pgo_dissect_delete_member_resp},
  {8, "is_member", rs_pgo_dissect_is_member_rqst,
   rs_pgo_dissect_is_member_resp},
  {9, "get_members", rs_pgo_dissect_get_members_rqst, NULL},
  {0, NULL, NULL, NULL},
};


void
proto_register_rs_pgo (void)
{
  static hf_register_info hf[] = {
    {&hf_rs_pgo_opnum,
     {"Operation", "rs_pgo.opnum", FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}},
    {&hf_error_status_t,
     {"Error status", "rs_pgo.error_status", FT_UINT32, BASE_DEC, NULL,
      0x0, NULL, HFILL}},
    {&hf_rs_pgo_query_key_t,
     {"Query key", "rs_pgo.query_key", FT_UINT32, BASE_DEC,
      NULL, 0x0, NULL, HFILL}},
    {&hf_rs_pgo_query_result_t,
     {"Query result", "rs_pgo.query_result", FT_UINT32,
      BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_rs_pgo_query_t,
     {"Query", "rs_pgo.query", FT_UINT32, BASE_DEC, NULL,
      0x0, NULL, HFILL}},
    {&hf_rs_sec_rgy_pgo_item_t_quota,
     {"Quota", "rs_pgo.quota",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_rs_sec_rgy_pgo_item_t_unix_num,
     {"Unix num",
      "rs_pgo.unix_num", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
      HFILL}},
    {&hf_rs_timeval,
     {"Timeval", "rs_pgo.timeval", FT_RELATIVE_TIME, BASE_NONE, NULL,
      0x0, NULL, HFILL}},
    {&hf_rs_uuid1,
     {"Uuid1", "rs_pgo.uuid1", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_rs_var1,
     {"Var1", "rs_pgo.var1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
      HFILL}},
    {&hf_sec_rgy_domain_t,
     {"Domain", "rs_pgo.domain", FT_UINT32, BASE_DEC,
      NULL, 0x0, NULL, HFILL}},
    {&hf_sec_rgy_name_t_principalName_string,
     {"Name principalName", "rs_pgo.name_principalName", FT_STRING, BASE_NONE, NULL,
      0x0, NULL, HFILL}},
    {&hf_sec_rgy_name_t_size,
     {"Name_t size", "rs_pgo.name_t_size", FT_UINT32,
      BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_sec_rgy_pgo_flags_t,
     {"Flags", "rs_pgo.flags", FT_UINT32,
      BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_sec_rgy_pname_t_size,
     {"Pname_t size", "rs_pgo.pname_t_size", FT_UINT32, BASE_DEC, NULL,
      0x0, NULL, HFILL}},
    {&hf_sec_rgy_pname_t_principalName_string,
     {"Pname principalName", "rs_pgo.pname_principalName", FT_STRING,
      BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_rs_pgo_unix_num_key_t,
     {"Unix num key", "rs_pgo.unix_num_key_t", FT_UINT32,
      BASE_DEC,
      NULL, 0x0, NULL, HFILL}}
  };

  static gint *ett[] = {
    &ett_error_status_t,
    &ett_rgy_acct_user_flags_t,
    &ett_rs_pgo,
    &ett_rs_pgo_id_key_t,
    &ett_rs_pgo_query_key_t,
    &ett_rs_pgo_query_result_t,
    &ett_rs_pgo_query_t,
    &ett_rs_pgo_result_t,
    &ett_rs_pgo_unix_num_key_t,
    &ett_sec_attr_component_name_t,
    &ett_sec_passwd_type_t,
    &ett_sec_rgy_acct_admin_flags_t,
    &ett_sec_rgy_acct_admin_t,
    &ett_sec_rgy_acct_auth_flags_t,
    &ett_sec_rgy_acct_key_t,
    &ett_sec_rgy_acct_user_t,
    &ett_sec_rgy_cursor_t,
    &ett_sec_rgy_foreign_id_t,
    &ett_sec_rgy_login_name_t,
    &ett_sec_rgy_name_t,
    &ett_sec_rgy_domain_t,
    &ett_sec_rgy_pgo_flags_t,
    &ett_sec_rgy_pgo_item_t,
    &ett_sec_rgy_pname_t,
    &ett_sec_rgy_sid_t,
    &ett_sec_rgy_unix_passwd_buf_t,
    &ett_sec_rgy_unix_sid_t,
    &ett_sec_timeval_sec_t,
    &ett_rs_cache_data_t,
  };
  proto_rs_pgo =
    proto_register_protocol ("DCE Name Service", "RS_PGO", "rs_pgo");
  proto_register_field_array (proto_rs_pgo, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_pgo (void)
{
  /* Register the protocol as dcerpc */
  dcerpc_init_uuid (proto_rs_pgo, ett_rs_pgo, &uuid_rs_pgo, ver_rs_pgo,
		    rs_pgo_dissectors, hf_rs_pgo_opnum);
}
