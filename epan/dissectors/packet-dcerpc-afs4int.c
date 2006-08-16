/* packet-dcerpc-afs4int.c
 *
 * Routines for dcerpc Afs4Int dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com> 
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/fsint/afs4int.idl
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
 * test
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-dce122.h"

#define AFS_SETMODTIME  1
#define AFS_SETOWNER  2
#define AFS_SETGROUP  4
#define AFS_SETMODE  8
#define AFS_SETACCESSTIME  0x10
#define AFS_SETCHANGETIME  0x20
#define AFS_SETLENGTH  0x40
#define AFS_SETTYPEUUID  0x80
#define AFS_SETDEVNUM  0x100
#define AFS_SETMODEXACT  0x200
#define AFS_SETTRUNCLENGTH  0x400
#define AFS_SETCLIENTSPARE  0x800

#define TKN_LOCK_READ                   0x001
#define TKN_LOCK_WRITE                  0x002
#define TKN_DATA_READ                   0x004
#define TKN_DATA_WRITE                  0x008
#define TKN_OPEN_READ                   0x010
#define TKN_OPEN_WRITE                  0x020
#define TKN_OPEN_SHARED                 0x040
#define TKN_OPEN_EXCLUSIVE              0x080
#define TKN_OPEN_DELETE                 0x100
#define TKN_OPEN_PRESERVE               0x200
#define TKN_STATUS_READ                 0x400
#define TKN_STATUS_WRITE                0x800
#define TKN_OPEN_UNLINK                 0x1000
#define TKN_SPOT_HERE                   0x2000
#define TKN_SPOT_THERE                  0x4000
#define TKN_OPEN_NO_READ                0x8000
#define TKN_OPEN_NO_WRITE               0x10000
#define TKN_OPEN_NO_UNLINK              0x20000

#define AFS_CONN_PARAM_HOSTLIFE  0
#define AFS_CONN_PARAM_HOSTRPC  1
#define AFS_CONN_PARAM_DEADSERVER  2
#define AFS_CONN_PARAM_EPOCH 3
#define AFS_CONN_PARAM_MAXFILE_CLIENT  4
#define AFS_CONN_PARAM_MAXFILE_SERVER  5
#define AFS_CONN_PARAM_HOST_TYPE_CLIENT 6
#define AFS_CONN_PARAM_HOST_TYPE_SERVER 7
#define AFS_CONN_PARAM_FT_MASK_CLIENT 8
#define AFS_CONN_PARAM_FT_MASK_SERVER 9
#define AFS_CONN_PARAM_SUPPORTS_64BITS 0x10000
#define AFS_CONN_PARAM_512BYTE_BLOCKS 0x20000

#define AFS_FLAG_SEC_SERVICE             0x1
#define AFS_FLAG_CONTEXT_NEW_IF          0x2
#define AFS_FLAG_CONTEXT_DO_RESET        0x4
#define AFS_FLAG_CONTEXT_NEW_ACL_IF      0x8
#define AFS_FLAG_CONTEXT_NEW_TKN_TYPES  0x10

#define AFS_FLAG_RETURNTOKEN           1
#define AFS_FLAG_TOKENJUMPQUEUE        2
#define AFS_FLAG_SKIPTOKEN             4
#define AFS_FLAG_NOOPTIMISM           0x8
#define AFS_FLAG_TOKENID              0x10
#define AFS_FLAG_RETURNBLOCKER        0x20
#define AFS_FLAG_ASYNCGRANT           0x40
#define AFS_FLAG_NOREVOKE             0x80
#define AFS_FLAG_MOVE_REESTABLISH     0x100
#define AFS_FLAG_SERVER_REESTABLISH   0x200
#define AFS_FLAG_NO_NEW_EPOCH         0x400
#define AFS_FLAG_MOVE_SOURCE_OK       0x800
#define AFS_FLAG_SYNC                 0x1000
#define AFS_FLAG_ZERO                 0x2000
#define AFS_FLAG_SKIPSTATUS           0x4000
#define AFS_FLAG_FORCEREVOCATIONS     0x8000
#define AFS_FLAG_FORCEVOLQUIESCE      0x10000
#define AFS_FLAG_FORCEREVOCATIONDOWN  0x20000

static int hf_afs4int_opnum = -1;


static int hf_afs4int_afsFid_cell_high = -1;
static int hf_afs4int_afsuuid_uuid = -1;
static int hf_afs4int_fetchdata_pipe_t_size = -1;
static int hf_afs4int_afsNameString_t_principalName_string = -1;
static int hf_afs4int_afsFid_cell_low = -1;
static int hf_afs4int_afsFid_volume_high = -1;
static int hf_afs4int_afsFid_volume_low = -1;
static int hf_afs4int_afsFid_Vnode = -1;
static int hf_afs4int_afsFid_Unique = -1;
static int hf_afs4int_volume_high = -1;
static int hf_afs4int_volume_low = -1;
static int hf_afs4int_vnode = -1;
static int hf_afs4int_unique = -1;
static int hf_afs4int_interfaceversion = -1;
static int hf_afs4int_filetype = -1;
static int hf_afs4int_linkcount = -1;
static int hf_afs4int_length_high = -1;
static int hf_afs4int_length_low = -1;
static int hf_afs4int_dataversion_high = -1;
static int hf_afs4int_dataversion_low = -1;
static int hf_afs4int_author = -1;
static int hf_afs4int_owner = -1;
static int hf_afs4int_group = -1;
static int hf_afs4int_calleraccess = -1;
static int hf_afs4int_anonymousaccess = -1;
static int hf_afs4int_aclexpirationtime = -1;
static int hf_afs4int_mode = -1;
static int hf_afs4int_parentvnode = -1;
static int hf_afs4int_parentunique = -1;
static int hf_afs4int_modtime_sec = -1;
static int hf_afs4int_modtime_msec = -1;
static int hf_afs4int_changetime_sec = -1;
static int hf_afs4int_changetime_msec = -1;
static int hf_afs4int_accesstime_sec = -1;
static int hf_afs4int_accesstime_msec = -1;
static int hf_afs4int_servermodtime_sec = -1;
static int hf_afs4int_servermodtime_msec = -1;
static int hf_afs4int_typeuuid = -1;
static int hf_afs4int_objectuuid = -1;
static int hf_afs4int_devicenumber = -1;
static int hf_afs4int_blocksused = -1;
static int hf_afs4int_clientspare1 = -1;
static int hf_afs4int_devicenumberhighbits = -1;
static int hf_afs4int_agtypeunique = -1;
static int hf_afs4int_himaxspare = -1;
static int hf_afs4int_lomaxspare = -1;
static int hf_afs4int_pathconfspare = -1;
static int hf_afs4int_spare4 = -1;
static int hf_afs4int_spare5 = -1;
static int hf_afs4int_spare6 = -1;
static int hf_afs4int_volid_hi = -1;
static int hf_afs4int_volid_low = -1;
static int hf_afs4int_vvage = -1;
static int hf_afs4int_vv_hi = -1;
static int hf_afs4int_vv_low = -1;
static int hf_afs4int_vvpingage = -1;
static int hf_afs4int_vvspare1 = -1;
static int hf_afs4int_vvspare2 = -1;
static int hf_afs4int_beginrange = -1;
static int hf_afs4int_beginrangeext = -1;
static int hf_afs4int_endrange = -1;
static int hf_afs4int_endrangeext = -1;
static int hf_afs4int_expirationtime = -1;
static int hf_afs4int_tokenid_hi = -1;
static int hf_afs4int_tokenid_low = -1;
static int hf_afs4int_type_hi = -1;
static int hf_afs4int_type_low = -1;
static int hf_afs4int_tn_length = -1;
static int hf_afs4int_storestatus_accesstime_sec = -1;
static int hf_afs4int_storestatus_accesstime_usec = -1;
static int hf_afs4int_storestatus_changetime_sec = -1;
static int hf_afs4int_storestatus_changetime_usec = -1;
static int hf_afs4int_storestatus_clientspare1 = -1;
static int hf_afs4int_storestatus_cmask = -1;
static int hf_afs4int_storestatus_devicenumber = -1;
static int hf_afs4int_storestatus_devicenumberhighbits = -1;
static int hf_afs4int_storestatus_devicetype = -1;
static int hf_afs4int_storestatus_group = -1;
static int hf_afs4int_storestatus_length_high = -1;
static int hf_afs4int_storestatus_length_low = -1;
static int hf_afs4int_storestatus_mask = -1;
static int hf_afs4int_storestatus_mode = -1;
static int hf_afs4int_storestatus_modtime_sec = -1;
static int hf_afs4int_storestatus_modtime_usec = -1;
static int hf_afs4int_storestatus_owner = -1;
static int hf_afs4int_storestatus_spare1 = -1;
static int hf_afs4int_storestatus_spare2 = -1;
static int hf_afs4int_storestatus_spare3 = -1;
static int hf_afs4int_storestatus_spare4 = -1;
static int hf_afs4int_storestatus_spare5 = -1;
static int hf_afs4int_storestatus_spare6 = -1;
static int hf_afs4int_storestatus_trunc_high = -1;
static int hf_afsconnparams_mask = -1;
static int hf_afs4int_storestatus_trunc_low = -1;
static int hf_afs4int_storestatus_typeuuid = -1;
static int hf_afs4int_l_end_pos = -1;
static int hf_afs4int_l_end_pos_ext = -1;
static int hf_afs4int_l_fstype = -1;
static int hf_afs4int_l_pid = -1;
static int hf_afs4int_l_start_pos = -1;
static int hf_afs4int_l_start_pos_ext = -1;
static int hf_afs4int_l_sysid = -1;
static int hf_afs4int_l_type = -1;
static int hf_afs4int_l_whence = -1;
static int hf_afs4int_acl_len = -1;
static int hf_afs4int_st = -1;
static int hf_afs4int_uint = -1;
static int hf_afs4int_setcontext_rqst_epochtime = -1;
static int hf_afs4int_setcontext_rqst_secobjectid = -1;
static int hf_afs4int_setcontext_rqst_clientsizesattrs = -1;
static int hf_afs4int_setcontext_rqst_parm7 = -1;
static int hf_afs4int_afsNetAddr_type = -1;
static int hf_afs4int_afsNetAddr_data = -1;
static int hf_afs4int_returntokenidp_high = -1;
static int hf_afs4int_minvvp_low = -1;
static int hf_afs4int_position_high = -1;
static int hf_afs4int_position_low = -1;
static int hf_afs4int_offsetp_high = -1;
static int hf_afs4int_nextoffsetp_low = -1;
static int hf_afs4int_cellidp_high = -1;
static int hf_afserrorstatus_st = -1;
static int hf_afs4int_length = -1;
static int hf_afsconnparams_values = -1;
static int hf_afs4int_acltype = -1;
static int hf_afs4int_afsTaggedPath_tp_chars = -1;
static int hf_afs4int_afsTaggedPath_tp_tag = -1;
static int hf_afs4int_afsacl_uuid1 = -1;
static int hf_afs4int_bulkfetchstatus_size = -1;
static int hf_afs4int_flags = -1;
static int hf_afs4int_afsreturndesc_tokenid_high = -1;
static int hf_afs4int_afsreturndesc_tokenid_low = -1;
static int hf_afs4int_afsreturndesc_type_high = -1;
static int hf_afs4int_afsreturndesc_type_low = -1;
static int hf_afs4int_returntokenidp_low = -1;
static int hf_afs4int_minvvp_high = -1;
static int hf_afs4int_offsetp_low = -1;
static int hf_afs4int_nextoffsetp_high = -1;
static int hf_afs4int_cellidp_low = -1;
static int hf_afs4int_tn_tag = -1;
static int hf_afs4int_tn_size = -1;
static int hf_afs4int_tn_string = -1;
static int hf_afs4int_bulkfetchvv_numvols = -1;
static int hf_afs4int_bulkfetchvv_spare1 = -1;
static int hf_afs4int_bulkfetchvv_spare2 = -1;
static int hf_afs4int_bulkkeepalive_numexecfids = -1;
static int hf_afs4int_bulkkeepalive_spare4 = -1;
static int hf_afs4int_bulkkeepalive_spare2 = -1;
static int hf_afs4int_bulkkeepalive_spare1 = -1;
static int hf_afs4int_afsacl_defaultcell_uuid = -1;
static int hf_afs4int_gettime_syncdispersion = -1;
static int hf_afs4int_gettime_syncdistance = -1;
static int hf_afs4int_gettime_usecondsp = -1;
static int hf_afs4int_readdir_size = -1;
static int hf_afs4int_afsNameString_t_principalName_size = -1;
static int hf_afs4int_afsNameString_t_principalName_size2 = -1;
static int hf_afs4int_afsTaggedPath_tp_length = -1;
static int hf_afs4int_fstype = -1;
static int hf_afs4int_gettime_secondsp = -1;

static int proto_afs4int = -1;

static gint ett_afs4int = -1;
static gint ett_afs4int_afsFid = -1;
static gint ett_afs4int_afsReturnDesc = -1;
static gint ett_afs4int_afsNetAddr = -1;
static gint ett_afs4int_fetchstatus = -1;
static gint ett_afs4int_afsflags = -1;
static gint ett_afs4int_volsync = -1;
static gint ett_afs4int_minvvp = -1;
static gint ett_afs4int_afsfidtaggedname = -1;
static gint ett_afs4int_afstaggedname = -1;
static gint ett_afs4int_afstoken = -1;
static gint ett_afs4int_afsstorestatus = -1;
static gint ett_afs4int_afsRecordLock = -1;
static gint ett_afs4int_afsAcl = -1;
static gint ett_afs4int_afsNameString_t = -1;
static gint ett_afs4int_afsConnParams = -1;
static gint ett_afs4int_afsErrorStatus = -1;
static gint ett_afs4int_afsNetData = -1;
static gint ett_afs4int_afsTaggedPath = -1;
static gint ett_afs4int_afsBulkStat = -1;
static gint ett_afs4int_afsuuid = -1;
static gint ett_afs4int_offsetp = -1;
static gint ett_afs4int_returntokenidp = -1;
static gint ett_afs4int_afsbundled_stat = -1;


/* vars for our macro(s) */
static int hf_error_st = -1;

static e_uuid_t uuid_afs4int =
  { 0x4d37f2dd, 0xed93, 0x0000, {0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00,
				 0x00}
};
static guint16 ver_afs4int = 4;

/* XXX the only macro that I could not find the right way to convert easily.
The reason is because we reset col_info if st is non zero for many rpcs.
This is because on error, many structures are filled with garbage.
We end up not knowing if data is valid until we get the st var at the very end of the stubdata..
We can not just jump to the end, because more often than not an extra buffer exists in payload
after st. Thus we have to advance on each item until we read in ST, then we clear col_info. on error 
A good example is FetchStatus() on a file that returns ENOEXIST.
inode, volume, etc all will be garbage.
*/

#define MACRO_ST_CLEAR(name) \
  { \
    guint32 st; \
    const char *st_str; \
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_error_st, &st); \
    st_str = val_to_str (st, dce_error_vals, "%u"); \
    if (st){ \
      if (check_col (pinfo->cinfo, COL_INFO)) \
        col_add_fstr (pinfo->cinfo, COL_INFO, "%s st:%s ", name, st_str); \
    }else{ \
      if (check_col (pinfo->cinfo, COL_INFO)) \
        col_append_fstr (pinfo->cinfo, COL_INFO, " st:%s ", st_str); \
    } \
  }

static int
dissect_afsFid (tvbuff_t * tvb, int offset,
		packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{

/*
        afsHyper Cell;
        afsHyper Volume;
        unsigned32 Vnode;
        unsigned32 Unique;
*/


  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 volume_low, unique, vnode, inode;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }



  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1, "afsFid:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsFid);
    }


  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			       hf_afs4int_afsFid_cell_high, NULL);

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			       hf_afs4int_afsFid_cell_low, NULL);

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			       hf_afs4int_afsFid_volume_high, NULL);

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			       hf_afs4int_afsFid_volume_low, &volume_low);

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			       hf_afs4int_afsFid_Vnode, &vnode);

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			       hf_afs4int_afsFid_Unique, &unique);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " :FSID:%u ", volume_low);

  if ((vnode == 1) || (vnode == 2))
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, " InFS ");
    }
  else
    {
      inode = ((volume_low << 16) + vnode) & 0x7fffffff;
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, " inode:%u ", inode);
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsConnParams (tvbuff_t * tvb, int offset,
		       packet_info * pinfo, proto_tree * parent_tree,
		       guint8 *drep)
{

/*
        unsigned32 Mask;
        unsigned32 Values[20];
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 mask, Values[20];
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
			     "afsConnParams_t:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsConnParams);
    }
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_mask, &mask);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[0]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[1]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[2]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[3]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[4]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[5]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[6]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[7]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[9]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[9]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[10]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[11]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[12]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[13]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[14]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[15]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[16]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[17]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[18]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afsconnparams_values, &Values[19]);
  if ((mask & AFS_CONN_PARAM_HOSTLIFE) == AFS_CONN_PARAM_HOSTLIFE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":HOSTLIFE");
    }
  if ((mask & AFS_CONN_PARAM_HOSTRPC) == AFS_CONN_PARAM_HOSTRPC)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":HOSTRPC");
    }
  if ((mask & AFS_CONN_PARAM_DEADSERVER) == AFS_CONN_PARAM_DEADSERVER)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":DEADSERVER");
    }
  if ((mask & AFS_CONN_PARAM_EPOCH) == AFS_CONN_PARAM_EPOCH)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":EPOCH");
    }
  if ((mask & AFS_CONN_PARAM_MAXFILE_CLIENT) == AFS_CONN_PARAM_MAXFILE_CLIENT)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":MAXFILE_CLIENT");
    }
  if ((mask & AFS_CONN_PARAM_MAXFILE_SERVER) == AFS_CONN_PARAM_MAXFILE_SERVER)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":MAXFILE_SERVER");
    }
  if ((mask & AFS_CONN_PARAM_HOST_TYPE_CLIENT) ==
      AFS_CONN_PARAM_HOST_TYPE_CLIENT)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":HOST_TYPE_CLIENT");
    }
  if ((mask & AFS_CONN_PARAM_HOST_TYPE_SERVER) ==
      AFS_CONN_PARAM_HOST_TYPE_SERVER)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":HOST_TYPE_SERVER");
    }
  if ((mask & AFS_CONN_PARAM_FT_MASK_CLIENT) == AFS_CONN_PARAM_FT_MASK_CLIENT)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":FT_MASK_CLIENT");
    }
  if ((mask & AFS_CONN_PARAM_FT_MASK_SERVER) == AFS_CONN_PARAM_FT_MASK_SERVER)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":FT_MASK_SERVER");
    }
  if ((mask & AFS_CONN_PARAM_SUPPORTS_64BITS) ==
      AFS_CONN_PARAM_SUPPORTS_64BITS)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":SUPPORTS_64BITS");
    }
  if ((mask & AFS_CONN_PARAM_512BYTE_BLOCKS) == AFS_CONN_PARAM_512BYTE_BLOCKS)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":512BYTE_BLOCKS");
    }
  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     " Values:%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u",
		     Values[0], Values[1], Values[2], Values[3],
		     Values[4], Values[5], Values[6], Values[7], Values[8],
		     Values[9], Values[10], Values[11], Values[12],
		     Values[13], Values[14], Values[15], Values[16],
		     Values[17], Values[18], Values[19]);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsNameString_t (tvbuff_t * tvb, int offset,
			 packet_info * pinfo, proto_tree * parent_tree,
			 guint8 *drep)
{

/*
typedef [string] byte   NameString_t[AFS_NAMEMAX];
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
#define AFS_NAMEMAX    256
  guint32 string_size;
  const guint8 *namestring;
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
			     "afsNameString_t:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsNameString_t);
    }

 offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_afsNameString_t_principalName_size,
			&string_size);
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, " String_size:%u", string_size);
  if (string_size < AFS_NAMEMAX)
    {
/* proto_tree_add_string(tree, id, tvb, start, length, value_ptr); */

      proto_tree_add_string (tree, hf_afs4int_afsNameString_t_principalName_string, tvb, offset, string_size, tvb_get_ptr (tvb, offset, string_size));
      namestring = tvb_get_ptr (tvb, offset, string_size);
      offset += string_size;
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, " Principal:%s", namestring);
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
dissect_afsNetAddr (tvbuff_t * tvb, int offset,
		    packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{

/*                 unsigned16 type;
                   unsigned8 data[14];
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint16 type;
  guint8 data;
  int i;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1,
				  "afsNetAddr:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsNetAddr);
    }


  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_afsNetAddr_type, &type);

  if (type)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, " Type:%u ", type);


      for (i = 0; i < 14; i++)
	{

	  offset =
	    dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			       hf_afs4int_afsNetAddr_data, &data);


	  switch (i)
	    {
	    case 1:
	      if (data)
		{
		  if (check_col (pinfo->cinfo, COL_INFO))
		    col_append_fstr (pinfo->cinfo, COL_INFO, " Port:%u",
				     data);
		}
	      break;
	    case 2:
	      if (check_col (pinfo->cinfo, COL_INFO))
		col_append_fstr (pinfo->cinfo, COL_INFO, " IP:%u.", data);
	      break;
	    case 3:
	      if (check_col (pinfo->cinfo, COL_INFO))
		col_append_fstr (pinfo->cinfo, COL_INFO, "%u.", data);
	      break;
	    case 4:
	      if (check_col (pinfo->cinfo, COL_INFO))
		col_append_fstr (pinfo->cinfo, COL_INFO, "%u.", data);
	      break;
	    case 5:
	      if (check_col (pinfo->cinfo, COL_INFO))
		col_append_fstr (pinfo->cinfo, COL_INFO, "%u", data);
	      break;
	    }

	}

    }
  else
    {

      offset += 14;		/* space left after reading in type for the array. */
    }


  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_afsNetData (tvbuff_t * tvb, int offset,
		    packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{
/*  
	afsNetAddr sockAddr;
        NameString_t principalName;
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
	proto_tree_add_text (parent_tree, tvb, offset, -1, "afsNetData:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsNetData);
    }


  offset = dissect_afsNetAddr ( tvb, offset, pinfo, tree, drep);
  offset += 4; /* buffer */
  offset = dissect_afsNameString_t ( tvb, offset, pinfo, tree, drep);

   proto_item_set_len (item, offset - old_offset); 
  return offset;

}

static int
dissect_afsTaggedPath (tvbuff_t * tvb, int offset,
		       packet_info * pinfo, proto_tree * parent_tree,
		       guint8 *drep)
{

/*
        codesetTag      tp_tag;
        unsigned16      tp_length;
        byte            tp_chars[AFS_PATHMAX+1]; 1024+1
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 tp_tag;
  guint16 tp_length;
  const guint8 *tp_chars;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item =
	proto_tree_add_text (parent_tree, tvb, offset, -1, "afsTaggedPath");
      tree = proto_item_add_subtree (item, ett_afs4int_afsTaggedPath);
    }


  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_afsTaggedPath_tp_tag, &tp_tag);
  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_afsTaggedPath_tp_length, &tp_length);
  proto_tree_add_string (tree, hf_afs4int_afsTaggedPath_tp_chars, tvb, offset,
			 hf_afs4int_afsTaggedPath_tp_length, tvb_get_ptr (tvb,
									  offset,
									  tp_length));
  tp_chars = tvb_get_ptr (tvb, offset, 1025);
  offset += 1025;
  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " :tp_chars %s", tp_chars);


  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsAcl (tvbuff_t * tvb, int offset,
		packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{
/* 
        unsigned32 afsACL_len;
        [length_is(afsACL_len)] byte afsACL_val[AFS_ACLMAX];
*/



  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 acl_len;
  e_uuid_t uuid1, defaultcell;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }



  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1, "afsAcl");
      tree = proto_item_add_subtree (item, ett_afs4int_afsAcl);
    }


  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_acl_len,
			&acl_len);
  offset += 8;			/* bypass spare and duplicate acl_len */
  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep,
			hf_afs4int_afsacl_uuid1, &uuid1);
  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     " - %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		     uuid1.Data1, uuid1.Data2, uuid1.Data3, uuid1.Data4[0],
		     uuid1.Data4[1], uuid1.Data4[2], uuid1.Data4[3],
		     uuid1.Data4[4], uuid1.Data4[5], uuid1.Data4[6],
		     uuid1.Data4[7]);

  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep,
			hf_afs4int_afsacl_defaultcell_uuid, &defaultcell);
  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     "  %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		     defaultcell.Data1, defaultcell.Data2, defaultcell.Data3,
		     defaultcell.Data4[0], defaultcell.Data4[1],
		     defaultcell.Data4[2], defaultcell.Data4[3],
		     defaultcell.Data4[4], defaultcell.Data4[5],
		     defaultcell.Data4[6], defaultcell.Data4[7]);

  offset += (acl_len - 38);

  if (offset <= old_offset)
    THROW(ReportedBoundsError);

  proto_item_set_len(item, offset-old_offset); 
  return offset;
}


static int
dissect_afsErrorStatus (tvbuff_t * tvb, int offset,
			packet_info * pinfo, proto_tree * parent_tree,
			guint8 *drep)
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
				  "afsErrorStatus");
      tree = proto_item_add_subtree (item, ett_afs4int_afsErrorStatus);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afserrorstatus_st,
			&st);
  st_str = val_to_str (st, dce_error_vals, "%u");

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " st:%s ", st_str);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsRecordLock (tvbuff_t * tvb, int offset,
		       packet_info * pinfo, proto_tree * parent_tree,
		       guint8 *drep)
{
/*
        signed16     l_type;
        signed16     l_whence;
        unsigned32   l_start_pos;
        unsigned32   l_end_pos;
        unsigned32   l_pid;
        unsigned32   l_sysid;
        unsigned32   l_fstype;
        unsigned32   l_start_pos_ext; was l_spare0: high 32b of l_start_pos
        unsigned32   l_end_pos_ext; was l_spare1: high 32b of l_end_pos
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint16 l_type, l_whence;
  guint32 l_start_pos, l_end_pos, l_pid, l_sysid, l_fstype, l_start_pos_ext,
    l_end_pos_ext;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1,
				  "afsRecordLock:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsRecordLock);
    }

  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep, hf_afs4int_l_type,
			&l_type);
  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep, hf_afs4int_l_whence,
			&l_whence);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_l_start_pos, &l_start_pos);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_l_end_pos,
			&l_end_pos);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_l_pid,
			&l_pid);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_l_sysid,
			&l_sysid);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_l_fstype,
			&l_fstype);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_l_start_pos_ext, &l_start_pos_ext);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_l_end_pos_ext, &l_end_pos_ext);


  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsstorestatus (tvbuff_t * tvb, int offset,
			packet_info * pinfo, proto_tree * parent_tree,
			guint8 *drep)
{
/*
        unsigned32              mask;
        afsTimeval              modTime;
        afsTimeval              accessTime;
        afsTimeval              changeTime;
        unsigned32              owner;
        unsigned32              group;
        unsigned32              mode;
        afsHyper                truncLength;     applied first 
        afsHyper                length;
        afsUUID                 typeUUID;
        unsigned32              deviceType;      character or block 
        unsigned32              deviceNumber;
        unsigned32              cmask;
        unsigned32              clientSpare1;    client-only attrs 
        unsigned32              deviceNumberHighBits;
        unsigned32              spare1;
        unsigned32              spare2;
        unsigned32              spare3;
        unsigned32              spare4;
        unsigned32              spare5;
        unsigned32              spare6;
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 mask, modtime_sec, changetime_sec, accesstime_sec, devicenumber,
    clientspare1, devicenumberhighbits, spare1, spare2, spare3, spare4,
    spare5, spare6, accesstime_usec, changetime_usec, owner, group, mode,
    trunc_high, trunc_low, length_high, length_low, devicetype,
    cmask, modtime_usec;
  e_uuid_t typeuuid;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1,
				  "afsStoreStatus:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsstorestatus);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_mask, &mask);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_modtime_sec, &modtime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_modtime_usec, &modtime_usec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_accesstime_sec,
			&accesstime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_accesstime_usec,
			&accesstime_usec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_changetime_sec,
			&changetime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_changetime_usec,
			&changetime_usec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_owner, &owner);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_group, &group);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_mode, &mode);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_trunc_high, &trunc_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_trunc_low, &trunc_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_length_high, &length_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_length_low, &length_low);
  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_typeuuid, &typeuuid);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_devicetype, &devicetype);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_devicenumber, &devicenumber);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_cmask, &cmask);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_clientspare1, &clientspare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_devicenumberhighbits,
			&devicenumberhighbits);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_spare1, &spare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_spare2, &spare2);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_spare3, &spare3);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_spare4, &spare4);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_spare5, &spare5);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_storestatus_spare6, &spare6);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " Mask=");
  if ((mask & AFS_SETMODTIME) == AFS_SETMODTIME)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, ":SETMODTIME-%u.%u",
			 modtime_sec, modtime_usec);
    }
  if ((mask & AFS_SETOWNER) == AFS_SETOWNER)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, ":SETOWNER-%u", owner);
    }
  if ((mask & AFS_SETGROUP) == AFS_SETGROUP)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, ":SETGROUP-%u", group);
    }
  if ((mask & AFS_SETMODE) == AFS_SETMODE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, ":SETMODE-%o", mode);
    }
  if ((mask & AFS_SETACCESSTIME) == AFS_SETACCESSTIME)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, ":SETACCESSTIME-%u.%u",
			 accesstime_sec, accesstime_usec);
    }
  if ((mask & AFS_SETCHANGETIME) == AFS_SETCHANGETIME)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, ":SETCHANGETIME-%u.%u",
			 changetime_sec, changetime_usec);
    }
  if ((mask & AFS_SETLENGTH) == AFS_SETLENGTH)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":SETLENGTH");
    }
  if ((mask & AFS_SETTYPEUUID) == AFS_SETTYPEUUID)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":SETTYPEUUID");
    }
  if ((mask & AFS_SETDEVNUM) == AFS_SETDEVNUM)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":SETDEVNUM");
    }
  if ((mask & AFS_SETMODEXACT) == AFS_SETMODEXACT)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":SETMODEXACT");
    }
  if ((mask & AFS_SETTRUNCLENGTH) == AFS_SETTRUNCLENGTH)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":SETTRUNCLENGTH");
    }
  if ((mask & AFS_SETCLIENTSPARE) == AFS_SETCLIENTSPARE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":SETCLIENTSPARE");
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afstoken (tvbuff_t * tvb, int offset,
		  packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{
/*
        afsHyper tokenID;
        unsigned32 expirationTime;
        afsHyper type;
        unsigned32 beginRange;
        unsigned32 endRange;
        unsigned32 beginRangeExt;
        unsigned32 endRangeExt;
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 tokenid_hi, tokenid_low, expirationtime, type_hi, type_low,
    beginrange, endrange, beginrangeext, endrangeext, type;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1, "afsToken:");
      tree = proto_item_add_subtree (item, ett_afs4int_afstoken);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_tokenid_hi,
			&tokenid_hi);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_tokenid_low, &tokenid_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_expirationtime, &expirationtime);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_type_hi,
			&type_hi);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_type_low,
			&type_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_beginrange,
			&beginrange);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_endrange,
			&endrange);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_beginrangeext, &beginrangeext);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_endrangeext, &endrangeext);
  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     "  :Tokenid:%u/%u ExpirationTime:%u beginrange:%u endrange:%u beginrangeext:%u endrangeext:%u",
		     tokenid_hi, tokenid_low, expirationtime, beginrange,
		     endrange, beginrangeext, endrangeext);
  type = type_low;

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_str (pinfo->cinfo, COL_INFO, " Type=");

  if ((type & TKN_LOCK_READ) == TKN_LOCK_READ)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":LOCK_READ");
    }
  if ((type & TKN_LOCK_WRITE) == TKN_LOCK_WRITE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":LOCK_WRITE");
    }
  if ((type & TKN_DATA_READ) == TKN_DATA_READ)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":DATA_READ");
    }
  if ((type & TKN_DATA_WRITE) == TKN_DATA_WRITE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":DATA_WRITE");
    }
  if ((type & TKN_OPEN_READ) == TKN_OPEN_READ)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_READ");
    }
  if ((type & TKN_OPEN_WRITE) == TKN_OPEN_WRITE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_WRITE");
    }
  if ((type & TKN_OPEN_SHARED) == TKN_OPEN_SHARED)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_SHARED");
    }
  if ((type & TKN_OPEN_EXCLUSIVE) == TKN_OPEN_EXCLUSIVE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_EXCLUSIVE");
    }
  if ((type & TKN_OPEN_DELETE) == TKN_OPEN_DELETE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_DELETE");
    }
  if ((type & TKN_OPEN_PRESERVE) == TKN_OPEN_PRESERVE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_PRESERVE");
    }
  if ((type & TKN_STATUS_READ) == TKN_STATUS_READ)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":STATUS_READ");
    }
  if ((type & TKN_STATUS_WRITE) == TKN_STATUS_WRITE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":STATUS_WRITE");
    }
  if ((type & TKN_OPEN_UNLINK) == TKN_OPEN_UNLINK)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_UNLINK");
    }
  if ((type & TKN_SPOT_HERE) == TKN_SPOT_HERE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":SPOT_HERE");
    }
  if ((type & TKN_SPOT_THERE) == TKN_SPOT_THERE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":SPOT_THERE");
    }
  if ((type & TKN_OPEN_NO_READ) == TKN_OPEN_NO_READ)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_NO_READ");
    }
  if ((type & TKN_OPEN_NO_WRITE) == TKN_OPEN_NO_WRITE)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_NO_WRITE");
    }
  if ((type & TKN_OPEN_NO_UNLINK) == TKN_OPEN_NO_UNLINK)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_NO_UNLINK");
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afstaggedname (tvbuff_t * tvb, int offset,
		       packet_info * pinfo, proto_tree * parent_tree,
		       guint8 *drep)
{

/*
        codesetTag      tn_tag;
        unsigned16      tn_length;
        byte            tn_chars[AFS_NAMEMAX+1];
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 tn_tag;
  guint16 tn_length;
  const guint8 *tn_string;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1,
				  "afsTaggedName:");
      tree = proto_item_add_subtree (item, ett_afs4int_afstaggedname);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_tn_tag,
			&tn_tag);
  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep, hf_afs4int_tn_length,
			&tn_length);
  if (tn_length < 254)
    {
      proto_tree_add_string (tree, hf_afs4int_tn_string, tvb, offset,
			     hf_afs4int_tn_size, tvb_get_ptr (tvb, offset,
							      tn_length));
      tn_string = tvb_get_ptr (tvb, offset, 257);
      offset += 257;
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO, " :tn_tag: %s", tn_string);
    }
  else
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_fstr (pinfo->cinfo, COL_INFO,
			 " :FIXME!: Invalid string length of  %u", tn_length);
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsfidtaggedname (tvbuff_t * tvb, int offset,
			  packet_info * pinfo, proto_tree * parent_tree,
			  guint8 *drep)
{
/*
        afsFid fid;
        afsTaggedName name;
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
      item = proto_tree_add_text (parent_tree, tvb, offset, -1,
				  "FidTaggedName:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsfidtaggedname);
    }
  offset = dissect_afsFid (tvb, offset, pinfo, tree, drep);
  offset = dissect_afstaggedname (tvb, offset, pinfo, tree, drep);

  proto_item_set_len (item, offset - old_offset);
  return offset;

}

static int
dissect_minvvp (tvbuff_t * tvb, int offset,
		packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{

/* unsigned32 minvvp_high
   unsigned32 minvvp_low
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 minvvp_high, minvvp_low;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1, "minVVp:");
      tree = proto_item_add_subtree (item, ett_afs4int_minvvp);
    }
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_minvvp_high, &minvvp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_minvvp_low,
			&minvvp_low);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " minVVp:%u/%u", minvvp_high,
		     minvvp_low);


  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_afsuuid (tvbuff_t * tvb, int offset,
                packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{

/* uuid  UUID
*/
/*HEREN*/

  e_uuid_t uuid1;

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
      item = proto_tree_add_text (parent_tree, tvb, offset, -1, "afsUUID:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsuuid);
    }

  offset = dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep, hf_afs4int_afsuuid_uuid, &uuid1);


if (check_col (pinfo->cinfo, COL_INFO)) col_append_fstr (pinfo->cinfo, COL_INFO, ":%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", uuid1.Data1, uuid1.Data2, uuid1.Data3, uuid1.Data4[0], uuid1.Data4[1], uuid1.Data4[2], uuid1.Data4[3], uuid1.Data4[4], uuid1.Data4[5], uuid1.Data4[6], uuid1.Data4[7]);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_offsetp (tvbuff_t * tvb, int offset,
                packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{

/* unsigned32 offsetp_high
   unsigned32 offsetp_low
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 offsetp_high, offsetp_low;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1, "minVVp:");
      tree = proto_item_add_subtree (item, ett_afs4int_offsetp);
    }
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                        hf_afs4int_offsetp_high, &offsetp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_offsetp_low,
                        &offsetp_low);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " offsetp:%u/%u", offsetp_high,
                     offsetp_low);


  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_returntokenidp (tvbuff_t * tvb, int offset,
                packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{

/* unsigned32 returntokenidp_high
   unsigned32 returntokenidp_low
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 returntokenidp_high, returntokenidp_low;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1, "returnTokenIDp:");
      tree = proto_item_add_subtree (item, ett_afs4int_returntokenidp);
    }
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                        hf_afs4int_returntokenidp_high, &returntokenidp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_returntokenidp_low,
                        &returntokenidp_low);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " returnTokenIDp:%u/%u", returntokenidp_high,
                     returntokenidp_low);


  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_volsync (tvbuff_t * tvb, int offset,
		 packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{
/*
        afsHyper VolID;
        afsHyper VV;             volume's version 
        unsigned32 VVAge;        age, in seconds, of the knowledge that the
                                        given VolVers is current 
        unsigned32 VVPingAge; age, in seconds, of the last probe from
                                   the callee (the secondary) to the primary 
        unsigned32 vv_spare1;
        unsigned32 vv_spare2;
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 volid_hi, volid_low, vv_hi, vv_low, vvage, vvpingage, vvspare1,
    vvspare2;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1,
				  "AfsVolSync:");
      tree = proto_item_add_subtree (item, ett_afs4int_volsync);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_volid_hi,
			&volid_hi);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_volid_low,
			&volid_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_vv_hi,
			&vv_hi);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_vv_low,
			&vv_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_vvage,
			&vvage);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_vvpingage,
			&vvpingage);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_vvspare1,
			&vvspare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_vvspare2,
			&vvspare2);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     " volid_hi:%u volid_low:%u vv_hi:%u vv_low:%u vvage:%u vvpingage:%u vvpspare1:%u vvspare2:%u",
		     volid_hi, volid_low, vv_hi, vv_low, vvage, vvpingage,
		     vvspare1, vvspare2);


  proto_item_set_len (item, offset - old_offset);
  return offset;

}

static int
dissect_afsFlags (tvbuff_t * tvb, int offset,
		  packet_info * pinfo, proto_tree * parent_tree, guint8 *drep)
{


/*
  unsigned32 flags 
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 flags;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1, "AfsFlags:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsflags);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_flags,
			&flags);

  if (flags)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO, " Flags=");
      if ((flags & AFS_FLAG_RETURNTOKEN) == AFS_FLAG_RETURNTOKEN)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":RETURNTOKEN");
	}
      if ((flags & AFS_FLAG_TOKENJUMPQUEUE) == AFS_FLAG_TOKENJUMPQUEUE)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":TOKENJUMPQUEUE");
	}
      if ((flags & AFS_FLAG_SKIPTOKEN) == AFS_FLAG_SKIPTOKEN)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":SKIPTOKEN");
	}
      if ((flags & AFS_FLAG_NOOPTIMISM) == AFS_FLAG_NOOPTIMISM)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":NOOPTIMISM");
	}
      if ((flags & AFS_FLAG_TOKENID) == AFS_FLAG_TOKENID)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":TOKENID");
	}
      if ((flags & AFS_FLAG_RETURNBLOCKER) == AFS_FLAG_RETURNBLOCKER)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":RETURNBLOCKER");
	}
      if ((flags & AFS_FLAG_ASYNCGRANT) == AFS_FLAG_ASYNCGRANT)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":ASYNCGRANT");
	}
      if ((flags & AFS_FLAG_NOREVOKE) == AFS_FLAG_NOREVOKE)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":NOREVOKE");
	}
      if ((flags & AFS_FLAG_MOVE_REESTABLISH) == AFS_FLAG_MOVE_REESTABLISH)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":MOVE_REESTABLISH");
	}
      if ((flags & AFS_FLAG_SERVER_REESTABLISH) ==
	  AFS_FLAG_SERVER_REESTABLISH)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":SERVER_REESTABLISH");
	}
      if ((flags & AFS_FLAG_NO_NEW_EPOCH) == AFS_FLAG_NO_NEW_EPOCH)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":NO_NEW_EPOCH");
	}
      if ((flags & AFS_FLAG_MOVE_SOURCE_OK) == AFS_FLAG_MOVE_SOURCE_OK)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":MOVE_SOURCE_OK");
	}
      if ((flags & AFS_FLAG_SYNC) == AFS_FLAG_SYNC)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":SYNC");
	}
      if ((flags & AFS_FLAG_ZERO) == AFS_FLAG_ZERO)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":ZERO");
	}
      if ((flags & AFS_FLAG_SKIPSTATUS) == AFS_FLAG_SKIPSTATUS)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":SKIPSTATUS");
	}
      if ((flags & AFS_FLAG_FORCEREVOCATIONS) == AFS_FLAG_FORCEREVOCATIONS)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":FORCEREVOCATIONS");
	}
      if ((flags & AFS_FLAG_FORCEVOLQUIESCE) == AFS_FLAG_FORCEVOLQUIESCE)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":FORCEVOLQUIESCE");
	}
      if ((flags & AFS_FLAG_SEC_SERVICE) == AFS_FLAG_SEC_SERVICE)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":SEC_SERVICE");
	}
      if ((flags & AFS_FLAG_CONTEXT_NEW_ACL_IF) ==
	  AFS_FLAG_CONTEXT_NEW_ACL_IF)
	{
	  if (check_col (pinfo->cinfo, COL_INFO))
	    col_append_str (pinfo->cinfo, COL_INFO, ":CONTEXT_NEW_ACL_IF");
	}
    }


  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_fetchstatus (tvbuff_t * tvb, int offset,
		     packet_info * pinfo, proto_tree * parent_tree,
		     guint8 *drep)
{

/*
        unsigned32              interfaceVersion;
        unsigned32              fileType;
        unsigned32              linkCount;
        afsHyper                length;
        afsHyper                dataVersion;
        unsigned32              author;
        unsigned32              owner;
        unsigned32              group;
        unsigned32              callerAccess;
        unsigned32              anonymousAccess;
        unsigned32              aclExpirationTime;
        unsigned32              mode;
        unsigned32              parentVnode;
        unsigned32              parentUnique;
        afsTimeval              modTime;
        afsTimeval              changeTime;
        afsTimeval              accessTime;
        afsTimeval              serverModTime;
        afsUUID                 typeUUID;
        afsUUID                 objectUUID;
        unsigned32              deviceNumber;
        unsigned32              blocksUsed;
        unsigned32              clientSpare1;   * client-only attrs *
        unsigned32              deviceNumberHighBits;
        unsigned32              spare0;
        unsigned32              spare1;
        unsigned32              spare2;
        unsigned32              spare3;
        unsigned32              spare4;
        unsigned32              spare5;
        unsigned32              spare6;
*/
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 interfaceversion, filetype, linkcount, length_high, length_low,
    dataversion_high, dataversion_low, author, owner, group, calleraccess,
    anonymousaccess, aclexpirationtime, mode, parentvnode, parentunique,
    modtime_sec, modtime_msec, changetime_sec, changetime_msec,
    accesstime_sec, accesstime_msec, servermodtime_msec, servermodtime_sec,
    devicenumber, blocksused, clientspare1, devicenumberhighbits,
    agtypeunique, himaxspare, lomaxspare, pathconfspare, spare4, spare5,
    spare6;
  e_uuid_t typeuuid, objectuuid;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }



  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1,
				  "FetchStatus:");
      tree = proto_item_add_subtree (item, ett_afs4int_fetchstatus);
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_interfaceversion, &interfaceversion);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_filetype,
			&filetype);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_linkcount,
			&linkcount);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_length_high, &length_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_length_low,
			&length_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_dataversion_high, &dataversion_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_dataversion_low, &dataversion_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_author,
			&author);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_owner,
			&owner);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_group,
			&group);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_calleraccess, &calleraccess);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_anonymousaccess, &anonymousaccess);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_aclexpirationtime, &aclexpirationtime);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_mode,
			&mode);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_parentvnode, &parentvnode);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_parentunique, &parentunique);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_modtime_sec, &modtime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_modtime_msec, &modtime_msec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_changetime_sec, &changetime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_changetime_msec, &changetime_msec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_accesstime_sec, &accesstime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_accesstime_msec, &accesstime_msec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_servermodtime_sec, &servermodtime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_servermodtime_msec, &servermodtime_msec);
  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep, hf_afs4int_typeuuid,
			&typeuuid);
  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep, hf_afs4int_objectuuid,
			&objectuuid);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_devicenumber, &devicenumber);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_blocksused,
			&blocksused);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_clientspare1, &clientspare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_devicenumberhighbits,
			&devicenumberhighbits);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_agtypeunique, &agtypeunique);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_himaxspare,
			&himaxspare);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_lomaxspare,
			&lomaxspare);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_pathconfspare, &pathconfspare);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_spare4,
			&spare4);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_spare5,
			&spare5);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_spare6,
			&spare6);


  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO,
		     " :interfacever:%u filetype:%u linkcount:%u length:%u dataver:%u author:%u owner:%u group:%u calleraccess:%u anonaccess:%u aclexpire:%u mode:%u parentvnode:%u parentunique:%u modtimesec:%u changetime_sec:%u accesstime_sec:%u servermodtimesec:%u devicenumber:%u blocksused:%u clientspare:%u devicehighbits:%u agtypeunique:%u",
		     interfaceversion, filetype, linkcount, length_low,
		     dataversion_low, author, owner, group, calleraccess,
		     anonymousaccess, aclexpirationtime, mode, parentvnode,
		     parentunique, modtime_sec, changetime_sec,
		     accesstime_sec, servermodtime_sec, devicenumber,
		     blocksused, clientspare1, devicenumberhighbits,
		     agtypeunique);


  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsReturnDesc (tvbuff_t * tvb, int offset,
		       packet_info * pinfo, proto_tree * parent_tree,
		       guint8 *drep)
{
/*
        afsFid fid;             * useful hint *
        afsHyper tokenID;
        afsHyper type;          * mask *
        unsigned32 flags;       * just in case *
*/

  proto_item *item = NULL;
  proto_tree *tree = NULL;
  int old_offset = offset;
  guint32 tokenid_high, tokenid_low, type_high, type_low;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


  if (parent_tree)
    {
      item = proto_tree_add_text (parent_tree, tvb, offset, -1,
				  "afsReturnDesc:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsReturnDesc);
    }


  offset = dissect_afsFid ( tvb, offset, pinfo, tree, drep);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_afsreturndesc_tokenid_high, &tokenid_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_afsreturndesc_tokenid_low, &tokenid_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_afsreturndesc_type_high, &type_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_afsreturndesc_type_low, &type_low);
  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " TokenId:%u/%u Type:%u/%u",
		     tokenid_high, tokenid_low, type_high, type_low);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags: ", -1);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}



static int
dissect_afsReturns (tvbuff_t * tvb, int offset,
		    packet_info * pinfo, proto_tree * tree, guint8 *drep)
{

/*
        long afsReturns_len;
        [length_is(afsReturns_len)] afsReturnDesc afsReturns_val[AFS_BULKMAX];
*/

  /* this is not really a ucvarray, but with the initial len, we can
     cheat and pretend it is */
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  offset =
    dissect_ndr_ucvarray (tvb, offset, pinfo, tree, drep,
			  dissect_afsReturnDesc);

  return offset;
}

#if 0 /* not used */

static int
dissect_afsbundled_stat (tvbuff_t * tvb, int offset,
                packet_info * pinfo, proto_tree * parent_tree, guint8 *drep _U_)
{


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
      item = proto_tree_add_text (parent_tree, tvb, offset, -1, "afsbundled_stat:");
      tree = proto_item_add_subtree (item, ett_afs4int_afsbundled_stat);
    }

/*  bundled_stat

        afsFid fid;
        afsFetchStatus stat;
        afsToken token;
        error_status_t error;
*/

/*
        offset = dissect_afsFid(tvb, offset, pinfo, tree, drep);
*/
/* SKIPTOKEN/STAT?
        offset = dissect_fetchstatus(tvb, offset, pinfo, tree, drep);
        offset = dissect_afstoken(tvb, offset, pinfo, tree, drep); 
*/
/* This is currently under construction as I figure out the reverse layout of the packet. */
/*
        offset = dissect_afsErrorStatus (tvb, offset, pinfo, tree, drep);
*/




  proto_item_set_len (item, offset - old_offset);
return offset;

}

#endif /* not used */

static int
dissect_afsBulkStat (tvbuff_t * tvb _U_, int offset,
                                  packet_info * pinfo _U_, proto_tree * tree _U_,
                                  guint8 *drep _U_)
{
/*
        unsigned32 BulkStat_len;
        [length_is(BulkStat_len)] bundled_stat BulkStat_val[AFS_BULKMAX];
*/
        /* this is not really a ucvarray, but with the initial len, we can
           cheat and pretend it is */
	   /*
        offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
                dissect_afsbundled_stat);
		*/

        return offset;
}




static int
afs4int_dissect_removefile_rqst (tvbuff_t * tvb, int offset,
				 packet_info * pinfo, proto_tree * tree,
				 guint8 *drep)
{


  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [in]    afsFid          *DirFidp,
        [in]    afsFidTaggedName        *Namep,
        [in]    afsHyper        *returnTokenIDp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/


  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsfidtaggedname, NDR_POINTER_REF,
			 "afsFidTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_returntokenidp,
			 NDR_POINTER_REF, "afsReturnTokenIDp:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "afsMinVVp:", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}

static int
afs4int_dissect_storedata_rqst (tvbuff_t * tvb, int offset,
				packet_info * pinfo, proto_tree * tree,
				guint8 *drep)
{
  guint32 position_high, position_low, length;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsFid          *Fidp,
        [in]    afsStoreStatus  *InStatusp,
        [in]    afsHyper        *Position,
        [in]    signed32        Length,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
        [in]    pipe_t          *storeStream,
*/


  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsstorestatus, NDR_POINTER_REF,
			 "afsStoreStatus:", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_position_high, &position_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_position_low, &position_low);

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_length, &length);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " Position:%u/%u Length:%u",
		     position_high, position_low, length);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);

/* XXX need to decode pipe_t still here */

  return offset;
}

static int
afs4int_dissect_gettoken_rqst (tvbuff_t * tvb, int offset,
			       packet_info * pinfo, proto_tree * tree,
			       guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [in]    afsFid          *Fidp,
        [in]    afsToken        *MinTokenp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afstoken,
			 NDR_POINTER_REF, "afsToken: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}
static int
afs4int_dissect_gettoken_resp (tvbuff_t * tvb, int offset,
			       packet_info * pinfo, proto_tree * tree,
			       guint8 *drep)
{

  dcerpc_info *di;
  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsToken        *OutTokenp,
        [out]   afsRecordLock   *OutBlockerp,
        [out]   afsFetchStatus  *OutStatusp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afstoken,
			 NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsRecordLock, NDR_POINTER_REF,
			 "afsRecordLock: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "afsFetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsErrorStatus, NDR_POINTER_REF,
			 "afsErrorStatus: ", -1);

  return offset;
}

static int
afs4int_dissect_lookuproot_rqst (tvbuff_t * tvb, int offset,
				 packet_info * pinfo, proto_tree * tree,
				 guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
 *         [in]    afsFid          *InFidp,
 *         [in]    afsHyper        *minVVp,
 *         [in]    unsigned32   Flags,
 */

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}

static int
afs4int_dissect_fetchdata_rqst (tvbuff_t * tvb, int offset,
				packet_info * pinfo, proto_tree * tree,
				guint8 *drep)
{
  guint32 position_high, position_low, length;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsFid          *Fidp,
        [in]    afsHyper        *minVVp,
        [in]    afsHyper        *Position,
        [in]    signed32                Length,
        [in]    unsigned32      Flags,
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_position_high, &position_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_position_low, &position_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_length, &length);
  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " Position:%u/%u Length:%u",
		     position_high, position_low, length);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}

static int
afs4int_dissect_fetchacl_rqst (tvbuff_t * tvb, int offset,
			       packet_info * pinfo, proto_tree * tree,
			       guint8 *drep)
{

  guint32 acltype;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [in]    afsFid          *Fidp,
        [in]    unsigned32      aclType,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_acltype,
			&acltype);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);

  if (acltype)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	col_append_str (pinfo->cinfo, COL_INFO,
			" :copy the ACL from specified fid:");
    }


  return offset;
}
static int
afs4int_dissect_fetchstatus_rqst (tvbuff_t * tvb, int offset,
				  packet_info * pinfo, proto_tree * tree,
				  guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [in]    afsFid          *Fidp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}
static int
afs4int_dissect_storeacl_rqst (tvbuff_t * tvb, int offset,
			       packet_info * pinfo, proto_tree * tree,
			       guint8 *drep)
{
  guint32 acltype;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsFid          *Fidp,
        [in]    afsACL          *AccessListp,
        [in]    unsigned32      aclType,
        [in]    afsFid          *aclFidp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/


  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsAcl,
			 NDR_POINTER_REF, "afsAcl: ", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_afs4int_acltype,
			&acltype);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " aclType:%u",acltype);

  return offset;
}

static int
afs4int_dissect_storestatus_rqst (tvbuff_t * tvb, int offset,
				  packet_info * pinfo, proto_tree * tree,
				  guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [in]    afsFid          *Fidp,
        [in]    afsStoreStatus  *InStatusp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsstorestatus, NDR_POINTER_REF,
			 "afsStoreStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);


  return offset;
}

static int
afs4int_dissect_createfile_rqst (tvbuff_t * tvb, int offset,
				 packet_info * pinfo, proto_tree * tree,
				 guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [in]    afsFid          *DirFidp,
        [in]    afsTaggedName   *Namep,
        [in]    afsStoreStatus  *InStatusp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afstaggedname, NDR_POINTER_REF,
			 "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsstorestatus, NDR_POINTER_REF,
			 "afsStoreStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}

static int
afs4int_dissect_rename_rqst (tvbuff_t * tvb, int offset,
			     packet_info * pinfo, proto_tree * tree,
		     guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsFid          *OldDirFidp,
        [in]    afsFidTaggedName        *OldNamep,
        [in]    afsFid          *NewDirFidp,
        [in]    afsFidTaggedName        *NewNamep,
        [in]    afsHyper        *returnTokenIDp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsfidtaggedname, NDR_POINTER_REF,
			 "afsFidTaggedName: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afstaggedname, NDR_POINTER_REF,
			 "afsFidTaggedName: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_returntokenidp, NDR_POINTER_REF,
			 "afsReturnTokenIDp: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_minvvp, NDR_POINTER_REF,
			 "afsminVVp: ", -1);

  offset = dissect_afsFlags(tvb, offset, pinfo, tree, drep);

  return offset;
}

static int
afs4int_dissect_symlink_rqst (tvbuff_t * tvb, int offset,
			      packet_info * pinfo, proto_tree * tree,
			      guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsFid          *DirFidp,
        [in]    afsTaggedName   *Namep,
        [in]    afsTaggedPath   *LinkContentsp,
        [in]    afsStoreStatus  *InStatusp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/


  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afstaggedname, NDR_POINTER_REF,
			 "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsTaggedPath, NDR_POINTER_REF,
			 "afsTaggedPath: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsstorestatus, NDR_POINTER_REF,
			 "afsStoreStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
    offset = dissect_afsFlags (tvb, offset, pinfo, tree, drep);

  return offset;
}

static int
afs4int_dissect_readdir_rqst (tvbuff_t * tvb, int offset,
			      packet_info * pinfo, proto_tree * tree,
			      guint8 *drep)
{
  guint32 size;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsFid          *DirFidp,
        [in]    afsHyper        *Offsetp,
        [in]    unsigned32      Size,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_offsetp,
			 NDR_POINTER_REF, "Offsetp: ", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_readdir_size, &size);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " Size:%u", size);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
   offset = dissect_afsFlags ( tvb, offset, pinfo, tree, drep);

  return offset;
}

static int
afs4int_dissect_makedir_rqst (tvbuff_t * tvb, int offset,
			      packet_info * pinfo, proto_tree * tree,
			      guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsFid          *DirFidp,
        [in]    afsTaggedName   *Namep,
        [in]    afsStoreStatus  *InStatusp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afstaggedname, NDR_POINTER_REF,
			 "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsstorestatus, NDR_POINTER_REF,
			 "afsStoreStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
  offset = dissect_afsFlags ( tvb, offset, pinfo, tree, drep);

  return offset;
}

static int
afs4int_dissect_removedir_rqst (tvbuff_t * tvb, int offset,
				packet_info * pinfo, proto_tree * tree,
				guint8 *drep)
{
  guint32 returntokenidp_high, returntokenidp_low;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsFid          *DirFidp,
        [in]    afsFidTaggedName        *Namep,
        [in]    afsHyper        *returnTokenIDp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsfidtaggedname, NDR_POINTER_REF,
			 "afsFidTaggedName: ", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_returntokenidp_high, &returntokenidp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_returntokenidp_low, &returntokenidp_low);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " returnTokenIDp:%u/%u",
		     returntokenidp_high, returntokenidp_low);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
  offset = dissect_afsFlags ( tvb, offset, pinfo, tree, drep );

  return offset;
}

static int
afs4int_dissect_lookup_rqst (tvbuff_t * tvb, int offset,
			     packet_info * pinfo, proto_tree * tree,
			     guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsFid          *DirFidp,
        [in]    afsTaggedName   *Namep,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afstaggedname, NDR_POINTER_REF,
			 "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
   offset = dissect_afsFlags ( tvb, offset, pinfo, tree, drep);

  return offset;
}
static int
afs4int_dissect_lookup_resp (tvbuff_t * tvb, int offset,
			     packet_info * pinfo, proto_tree * tree,
			     guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFid          *OutFidp,
        [out]   afsFetchStatus  *OutFidStatusp,
        [out]   afsFetchStatus  *OutDirStatusp,
        [out]   afsToken        *OutTokenp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afstoken,
			 NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("Lookup reply");

  return offset;

}

static int
afs4int_dissect_makemountpoint_rqst (tvbuff_t * tvb, int offset,
				     packet_info * pinfo, proto_tree * tree,
				     guint8 *drep)
{
  dcerpc_info *di;
  guint16 type;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [in]    afsFid          *DirFidp,
        [in]    afsTaggedName   *Namep,
        [in]    afsTaggedName   *cellNamep,
        [in]    afsFStype       Type,
        [in]    afsTaggedName   *volumeNamep,
        [in]    afsStoreStatus  *InStatusp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afstaggedname, NDR_POINTER_REF,
			 "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afstaggedname, NDR_POINTER_REF,
			 "afsTaggedName: ", -1);
  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep, hf_afs4int_fstype,
			&type);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afstaggedname, NDR_POINTER_REF,
			 "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsstorestatus, NDR_POINTER_REF,
			 "afsStoreStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);

  offset = dissect_afsFlags (tvb, offset, pinfo, tree, drep);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " Type:%u", type);

  return offset;

}

static int
afs4int_dissect_setcontext_rqst (tvbuff_t * tvb, int offset,
				 packet_info * pinfo, proto_tree * tree,
				 guint8 *drep)
{
  dcerpc_info *di;

  guint32 epochtime, clientsizesattrs, parm7;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    unsigned32      epochTime,
        [in]    afsNetData      *callbackAddr,
        [in]    unsigned32      Flags,
        [in]    afsUUID         *secObjectID,
        [in]    unsigned32      clientSizesAttrs,
        [in]    unsigned32      parm7
*/


  offset =
    dissect_dcerpc_time_t (tvb, offset, pinfo, tree, drep,
			   hf_afs4int_setcontext_rqst_epochtime, &epochtime);

  offset =  dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsNetData,
			 NDR_POINTER_REF, "afsNetData:", -1);

  offset = dissect_afsFlags (tvb, offset, pinfo, tree, drep);

if (check_col (pinfo->cinfo, COL_INFO)) col_append_str (pinfo->cinfo, COL_INFO, " setObjectID");

  offset =  dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsuuid,
			 NDR_POINTER_REF, "afsUUID:", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_setcontext_rqst_clientsizesattrs,
			&clientsizesattrs);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_setcontext_rqst_parm7, &parm7);

if (check_col (pinfo->cinfo, COL_INFO)) col_append_fstr (pinfo->cinfo, COL_INFO, " epochTime:%u clientSizesAttrs:%u parm7:%u", epochtime, clientsizesattrs, parm7);

  return offset;
}

static int
afs4int_dissect_setcontext_resp (tvbuff_t * tvb, int offset,
				 packet_info * pinfo, proto_tree * tree,
				 guint8 *drep)
{
/* nothing but error code */

  dcerpc_info *di;


  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  MACRO_ST_CLEAR ("SetContext reply");
  return offset;
}

static int
  afs4int_dissect_lookuproot_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  /*
   *        [out]   afsFid          *OutFidp,
   *        [out]   afsFetchStatus  *OutFidStatusp,
   *        [out]   afsToken        *OutTokenp,
   *        [out]   afsVolSync      *Syncp
   */
  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afstoken,
			 NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("LookupRoot reply");
  return offset;
}

static int
  afs4int_dissect_fetchdata_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{

  dcerpc_info *di;
  guint32 pipe_t_size;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutStatusp,
        [out]   afsToken        *OutTokenp,
        [out]   afsVolSync      *Syncp,
        [out]   pipe_t          *fetchStream
*/
/* The SkipToken/SkipStatus flags are always used in every fetchdata request I have seen.
There is also not sign of the afsVolSync structure... Just size, and data string... aka pipe_t */

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_fetchdata_pipe_t_size, &pipe_t_size);

  return offset;
}

static int
  afs4int_dissect_fetchacl_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [out]   afsACL          *AccessListp,
        [out]   afsFetchStatus  *OutStatusp,
        [out]   afsVolSync      *Syncp
*/
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsAcl,
			 NDR_POINTER_REF, "afsAcl: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("FetchAcl reply");
  return offset;
}

static int
  afs4int_dissect_fetchstatus_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutStatusp,
        [out]   afsToken        *OutTokenp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afstoken,
			 NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("FetchStatus reply");
  return offset;
}

static int
  afs4int_dissect_storedata_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutStatusp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("StoreData reply");
  return offset;
}

static int
  afs4int_dissect_storeacl_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutStatusp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("StoreAcl reply");
  return offset;
}

static int
  afs4int_dissect_storestatus_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutStatusp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("StoreStatus reply");
  return offset;
}

static int
  afs4int_dissect_removefile_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutDirStatusp,
        [out]   afsFetchStatus  *OutFileStatusp,
        [out]   afsFid          *OutFileFidp,
        [out]   afsVolSync      *Syncp
*/
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("RemoveFile reply");
  return offset;
}

static int
  afs4int_dissect_createfile_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFid          *OutFidp,
        [out]   afsFetchStatus  *OutFidStatusp,
        [out]   afsFetchStatus  *OutDirStatusp,
        [out]   afsToken        *OutTokenp,
        [out]   afsVolSync      *Syncp
*/

  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afstoken,
			 NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("CreateFile reply");

  return offset;
}
static int
  afs4int_dissect_rename_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/* 
        [out]   afsFetchStatus  *OutOldDirStatusp,
        [out]   afsFetchStatus  *OutNewDirStatusp,
        [out]   afsFid          *OutOldFileFidp,
        [out]   afsFetchStatus  *OutOldFileStatusp,
        [out]   afsFid          *OutNewFileFidp,
        [out]   afsFetchStatus  *OutNewFileStatusp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR("Rename reply");
  return offset;
}

static int
  afs4int_dissect_symlink_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFid          *OutFidp,
        [out]   afsFetchStatus  *OutFidStatusp,
        [out]   afsFetchStatus  *OutDirStatusp,
        [out]   afsToken        *OutTokenp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afstoken,
			 NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("Symlink reply");

  return offset;
}

static int
  afs4int_dissect_hardlink_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutFidStatusp,
        [out]   afsFetchStatus  *OutDirStatusp,
        [out]   afsVolSync      *Syncp
*/


  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("Hardlink reply");

  return offset;
}
static int
  afs4int_dissect_hardlink_rqst
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsFid          *DirFidp,
        [in]    afsTaggedName   *Namep,
        [in]    afsFid          *ExistingFidp,
        [in]    afsHyper        *minVVp,
        [in]    unsigned32      Flags,
*/

  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afstaggedname, NDR_POINTER_REF,
			 "afsTaggedName: ", -1);
  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);

  offset = dissect_afsFlags ( tvb, offset, pinfo, tree, drep);

  return offset;
}

static int
  afs4int_dissect_makedir_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFid          *OutFidp,
        [out]   afsFetchStatus  *OutFidStatusp,
        [out]   afsFetchStatus  *OutDirStatusp,
        [out]   afsToken        *OutTokenp,
        [out]   afsVolSync      *Syncp
*/
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afstoken,
			 NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);

  MACRO_ST_CLEAR ("MakeDir reply");

  return offset;
}

static int
  afs4int_dissect_removedir_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutDirStatusp,
        [out]   afsFid          *OutFidp,
        [out]   afsFetchStatus  *OutDelStatusp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("RemoveDir reply");

  return offset;

}

static int
  afs4int_dissect_readdir_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{

  guint32 nextoffsetp_high, nextoffsetp_low;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [out]   afsHyper        *NextOffsetp,
        [out]   afsFetchStatus  *OutDirStatusp,
        [out]   afsToken        *OutTokenp,
        [out]   afsVolSync      *Syncp,
        [out]   pipe_t          *dirStream
*/

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_nextoffsetp_high, &nextoffsetp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_nextoffsetp_low, &nextoffsetp_low);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " NextOffsetp:%u/%u",
		     nextoffsetp_high, nextoffsetp_low);

  /* all packets seem to have SKIPTOKEN/SKIPSTATUS sent, and thus these structures are missing on calls holding tokens. */

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  /* XXX need to add pipe_t here, once figured out. */

  return offset;
}

static int
  afs4int_dissect_releasetokens_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  /* no out */
  MACRO_ST_CLEAR ("ReleaseTokens reply");
  return offset;
}

static int
  afs4int_dissect_releasetokens_rqst
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [in]    afsReturns      *Tokens_Arrayp,
        [in]    unsigned32      Flags
*/
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsReturns,
			 NDR_POINTER_REF, "afsReturns: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags: ", -1);
  return offset;
}

static int
  afs4int_dissect_gettime_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{

  guint32 secondsp, usecondsp, syncdistance, syncdispersion;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   unsigned32      *Secondsp,
        [out]   unsigned32      *USecondsp,
        [out]   unsigned32      *SyncDistance,
        [out]   unsigned32      *SyncDispersion
*/

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_gettime_secondsp, &secondsp);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_gettime_usecondsp, &usecondsp);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_gettime_syncdistance, &syncdistance);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_gettime_syncdispersion, &syncdispersion);

  if (check_col (pinfo->cinfo, COL_INFO)) col_append_fstr (pinfo->cinfo, COL_INFO, " Secondsp:%u  Usecondsp:%u SyncDistance:/%u SyncDispersion:%u", secondsp, usecondsp, syncdistance, syncdispersion);

  MACRO_ST_CLEAR ("GetTime reply");

  return offset;

}

static int
  afs4int_dissect_gettime_rqst
  (tvbuff_t *
   tvb _U_, int offset, packet_info * pinfo, proto_tree * tree _U_, guint8 *drep _U_)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  /* nothing */

  return offset;
}

static int
  afs4int_dissect_processquota_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in,out]        afsQuota        *quotaListp,
        [out]           afsFetchStatus  *OutStatusp,
        [out]           afsVolSync      *Syncp
*/

  /* XXX need afsQuota */
  offset += 92;
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("ProcessQuota reply");

  return offset;
}

static int
  afs4int_dissect_processquota_rqst
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]            afsFid          *Fidp,
        [in]            afsHyper        *minVVp,
        [in]            unsigned32      Flags,
        [in,out]        afsQuota        *quotaListp,
*/

  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
  offset = dissect_afsFlags ( tvb, offset, pinfo, tree, drep);

  /* XXX need to figure out afsQuota here */
  return offset;
}

static int
  afs4int_dissect_getserverinterfaces_rqst
  (tvbuff_t *
   tvb _U_, int offset, packet_info * pinfo, proto_tree * tree _U_, guint8 *drep _U_)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in, out]               dfs_interfaceList *serverInterfacesP
*/
  /* XXX figure out dfs_interfacelist */
  return offset;
}

static int
  afs4int_dissect_getserverinterfaces_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in, out]               dfs_interfaceList *serverInterfacesP
*/
  /* XXX figure out dfs_interfacelist */

  MACRO_ST_CLEAR ("GetServerInterfaces reply");
  return offset;
}

static int
  afs4int_dissect_setparams_rqst
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]            unsigned32      Flags,
        [in, out]       afsConnParams   *paramsP
*/
  offset = dissect_afsFlags( tvb, offset, pinfo, tree, drep);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsConnParams, NDR_POINTER_REF,
			 "afsConnParams:", -1);
  return offset;
}

static int
  afs4int_dissect_setparams_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in, out]       afsConnParams   *paramsP
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep,
			 dissect_afsConnParams, NDR_POINTER_REF,
			 "afsConnParams:", -1);
  MACRO_ST_CLEAR ("SetParams reply");
  return offset;
}

static int
  afs4int_dissect_makemountpoint_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFid          *OutFidp,
        [out]   afsFetchStatus  *OutFidStatusp,
        [out]   afsFetchStatus  *OutDirStatusp,
        [out]   afsVolSync      *Syncp
*/
  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("MakeMountPoint reply");
  return offset;
}

static int
  afs4int_dissect_getstatistics_rqst
  (tvbuff_t *
   tvb _U_, int offset, packet_info * pinfo, proto_tree * tree _U_, guint8 *drep _U_)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

  /* nothing for request */
  return offset;
}

static int
  afs4int_dissect_getstatistics_resp
  (tvbuff_t *
   tvb _U_, int offset, packet_info * pinfo, proto_tree * tree _U_, guint8 *drep _U_)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsStatistics   *Statisticsp
*/
  /* XXX figure out afsStatistics */
  return offset;
}

static int
  afs4int_dissect_bulkfetchvv_rqst
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{

  guint32 cellidp_high, cellidp_low, numvols, spare1, spare2;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsHyper        *cellIdp,
        [in]    afsBulkVolIDs   *VolIDsp,
        [in]    unsigned32      NumVols,
        [in]    unsigned32      Flags,
        [in]    unsigned32      spare1,
        [in]    unsigned32      spare2,
*/
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_cellidp_high, &cellidp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_cellidp_low, &cellidp_low);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " CellIDp:%u/%u", cellidp_high,
		     cellidp_low);

  /* XXX figure out the afsBulkVolIDS */
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_bulkfetchvv_numvols, &numvols);

  offset = dissect_afsFlags (tvb, offset, pinfo, tree, drep);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_bulkfetchvv_spare1, &spare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_bulkfetchvv_spare2, &spare2);
  return offset;
}

static int
  afs4int_dissect_bulkfetchvv_resp
  (tvbuff_t *
   tvb _U_, int offset, packet_info * pinfo, proto_tree * tree _U_, guint8 *drep _U_)
{
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsBulkVVs      *VolVVsp,
        [out]   unsigned32      *spare4
*/
  /* XXX need to figure out afsBulkVVs  ; */
  return offset;
}

static int
  afs4int_dissect_bulkkeepalive_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  guint32 spare4;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   unsigned32      *spare4
*/

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_bulkkeepalive_spare4, &spare4);
  MACRO_ST_CLEAR ("BulkKeepAlive reply");
  return offset;
}

static int
  afs4int_dissect_bulkkeepalive_rqst
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  guint32 numexecfids, spare1, spare2;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]    afsBulkFEX      *KAFEXp,
        [in]    unsigned32      numExecFids,
        [in]    unsigned32      Flags,
        [in]    unsigned32      spare1,
        [in]    unsigned32      spare2,
*/
  /* XXX figure out afsBulkFEX */
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_bulkkeepalive_numexecfids, &numexecfids);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFlags,
			 NDR_POINTER_REF, "afsFlags:", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_bulkkeepalive_spare1, &spare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_bulkkeepalive_spare2, &spare2);
  return offset;
}

static int
  afs4int_dissect_bulkfetchstatus_rqst
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{
  guint32 offsetp_high, offsetp_low, size;
  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [in]            afsFid          *DirFidp,
        [in]            afsHyper        *Offsetp,
        [in]            unsigned32      Size,
        [in]            afsHyper        *minVVp,
        [in]            unsigned32      Flags,
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsFid,
			 NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_offsetp_high, &offsetp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_offsetp_low, &offsetp_low);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " Offsetp:%u/%u", offsetp_high,
		     offsetp_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_bulkfetchstatus_size, &size);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_minvvp,
			 NDR_POINTER_REF, "MinVVp:", -1);
  offset = dissect_afsFlags(tvb, offset, pinfo, tree, drep);

  return offset;
}

static int
  afs4int_dissect_bulkfetchstatus_resp
  (tvbuff_t *
   tvb, int offset, packet_info * pinfo, proto_tree * tree, guint8 *drep)
{

  dcerpc_info *di;

  di = pinfo->private_data;
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]           BulkStat        *bulkstats,
        [out]           afsHyper        *NextOffsetp,
        [out]           afsFetchStatus  *OutDirStatusp,
        [out]           afsToken        *OutTokenp,
        [out]           afsVolSync      *Syncp,
        [out]           pipe_t          *dirStream
*/
  
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afsBulkStat,
			 NDR_POINTER_REF, "BulkStat: ", -1);
/* Under construction. The packet seems to have the pipe_t before the rest of the data listed in idl. */

/*
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_nextoffsetp_high, &nextoffsetp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_afs4int_nextoffsetp_low, &nextoffsetp_low);

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, " NextOffsetp:%u/%u",
		     nextoffsetp_high, nextoffsetp_low);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_fetchstatus,
			 NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_afstoken,
			 NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, drep, dissect_volsync,
			 NDR_POINTER_REF, "VolSync: ", -1);
*/
  /* XXX figure out pipe_t */

  return offset;
}

static dcerpc_sub_dissector afs4int_dissectors[] = {
  { 0, "SetContext", afs4int_dissect_setcontext_rqst, afs4int_dissect_setcontext_resp} ,
  { 1, "LookupRoot", afs4int_dissect_lookuproot_rqst, afs4int_dissect_lookuproot_resp} ,
  { 2, "FetchData", afs4int_dissect_fetchdata_rqst, afs4int_dissect_fetchdata_resp} ,
  { 3, "FetchAcl", afs4int_dissect_fetchacl_rqst, afs4int_dissect_fetchacl_resp} ,
  { 4, "FetchStatus", afs4int_dissect_fetchstatus_rqst, afs4int_dissect_fetchstatus_resp} ,
  { 5, "StoreData", afs4int_dissect_storedata_rqst, afs4int_dissect_storedata_resp} ,
  { 6, "StoreAcl", afs4int_dissect_storeacl_rqst, afs4int_dissect_storeacl_resp} ,
  { 7, "StoreStatus", afs4int_dissect_storestatus_rqst, afs4int_dissect_storestatus_resp} ,
  { 8, "RemoveFile", afs4int_dissect_removefile_rqst, afs4int_dissect_removefile_resp} ,
  { 9, "CreateFile", afs4int_dissect_createfile_rqst, afs4int_dissect_createfile_resp} ,
  { 10, "Rename", afs4int_dissect_rename_rqst, afs4int_dissect_rename_resp} ,
  { 11, "Symlink", afs4int_dissect_symlink_rqst, afs4int_dissect_symlink_resp} ,
  { 12, "HardLink", afs4int_dissect_hardlink_rqst, afs4int_dissect_hardlink_resp} ,
  { 13, "MakeDir", afs4int_dissect_makedir_rqst, afs4int_dissect_makedir_resp} ,
  { 14, "RemoveDir", afs4int_dissect_removedir_rqst, afs4int_dissect_removedir_resp} ,
  { 15, "Readdir", afs4int_dissect_readdir_rqst, afs4int_dissect_readdir_resp} ,
  { 16, "Lookup", afs4int_dissect_lookup_rqst, afs4int_dissect_lookup_resp} ,
  { 17, "GetToken", afs4int_dissect_gettoken_rqst, afs4int_dissect_gettoken_resp} ,
  { 18, "ReleaseTokens", afs4int_dissect_releasetokens_rqst, afs4int_dissect_releasetokens_resp} ,
  { 19, "GetTime", afs4int_dissect_gettime_rqst, afs4int_dissect_gettime_resp} ,
  { 20, "MakeMountPoint", afs4int_dissect_makemountpoint_rqst, afs4int_dissect_makemountpoint_resp} ,
  { 21, "GetStatistics", afs4int_dissect_getstatistics_rqst, afs4int_dissect_getstatistics_resp} ,
  { 22, "BulkFetchVV", afs4int_dissect_bulkfetchvv_rqst, afs4int_dissect_bulkfetchvv_resp} ,
  { 23, "BulkKeepAlive", afs4int_dissect_bulkkeepalive_rqst, afs4int_dissect_bulkkeepalive_resp} ,
  { 24, "ProcessQuota", afs4int_dissect_processquota_rqst, afs4int_dissect_processquota_resp} ,
  { 25, "GetServerInterfaces", afs4int_dissect_getserverinterfaces_rqst, afs4int_dissect_getserverinterfaces_resp} ,
  { 26, "SetParams", afs4int_dissect_setparams_rqst, afs4int_dissect_setparams_resp} ,
  { 27, "BulkFetchStatus", afs4int_dissect_bulkfetchstatus_rqst, afs4int_dissect_bulkfetchstatus_resp} ,
  { 0, NULL, NULL, NULL}
  ,
};
void
proto_register_afs4int (void)
{


  static hf_register_info hf[] = {
    { &hf_error_st, {"AFS4Int Error Status Code", "afs4int.st", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_afs4int_flags, {"DFS Flags", "afs4int.flags", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_afs4int_tn_string, {"String ", "afs4int.string", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL}},
    { &hf_afs4int_tn_size, {"String Size", "afs4int.tn_size", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_afs4int_opnum, {"Operation", "afs4int.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Operation", HFILL}},
    { &hf_afs4int_setcontext_rqst_epochtime, {"EpochTime:", "afs4int.setcontext_rqst_epochtime", FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0, "", HFILL}},
    { &hf_afs4int_setcontext_rqst_secobjectid, { "SetObjectid:", "afs4int.setcontext_secobjextid", FT_STRING, BASE_NONE, NULL, 0x0, "UUID", HFILL} } ,
    { &hf_afs4int_setcontext_rqst_clientsizesattrs, { "ClientSizeAttrs:", "afs4int.setcontext_clientsizesattrs", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_setcontext_rqst_parm7, { "Parm7:", "afs4int.setcontext.parm7", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_acl_len, {"Acl Length", "afs4int.acl_len", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_afs4int_acltype, {"afs4int.acltype", "afs4int.acltype", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_afs4int_minvvp_high, {"afs4int.minvvp_high", "afs4int.minvvp_high", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_afs4int_minvvp_low, {"afs4int.minvvp_low", "afs4int.minvvp_low", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_afs4int_volume_low, { "afs4int.volume_low", "afs4int.volume_low", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_volume_high, { "afs4int.volume_high", "afs4int.volume_high", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_vnode, { "afs4int.vnode", "afs4int.vnode", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_unique, { "afs4int.unique", "afs4int.unique", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_accesstime_msec, { "afs4int.accesstime_msec", "afs4int.accesstime_msec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_accesstime_sec, { "afs4int.accesstime_sec", "afs4int.accesstime_sec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_aclexpirationtime, { "afs4int.aclexpirationtime", "afs4int.aclexpirationtime", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_agtypeunique, { "afs4int.agtypeunique", "afs4int.agtypeunique", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_anonymousaccess, { "afs4int.anonymousaccess", "afs4int.anonymousaccess", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_author, { "afs4int.author", "afs4int.author", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_blocksused, { "afs4int.blocksused", "afs4int.blocksused", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} },
    { &hf_afs4int_calleraccess, { "afs4int.calleraccess", "afs4int.calleraccess", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_changetime_msec, { "afs4int.changetime_msec", "afs4int.changetime_msec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_changetime_sec, { "afs4int.changetime_sec", "afs4int.changetime_sec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_clientspare1, { "afs4int.clientspare1", "afs4int.clientspare1", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_dataversion_high, { "afs4int.dataversion_high", "afs4int.dataversion_high", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_dataversion_low, { "afs4int.dataversion_low", "afs4int.dataversion_low", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_devicenumber, { "afs4int.devicenumber", "afs4int.devicenumber", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_devicenumberhighbits, { "afs4int.devicenumberhighbits", "afs4int.devicenumberhighbits", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_filetype, { "afs4int.filetype", "afs4int.filetype", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_group, { "afs4int.group", "afs4int.group", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_himaxspare, { "afs4int.himaxspare", "afs4int.himaxspare", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_interfaceversion, { "afs4int.interfaceversion", "afs4int.interfaceversion", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_length_high, { "afs4int.length_high", "afs4int.length_high", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_length_low, { "afs4int.length_low", "afs4int.length_low", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } , 
    { &hf_afs4int_linkcount, { "afs4int.linkcount", "afs4int.linkcount", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_lomaxspare, { "afs4int.lomaxspare", "afs4int.lomaxspare", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_mode, { "afs4int.mode", "afs4int.mode", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_modtime_msec, { "afs4int.modtime_msec", "afs4int.modtime_msec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_modtime_sec, { "afs4int.modtime_sec", "afs4int.modtime_sec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_objectuuid, { "afs4int.objectuuid", "afs4int.objectuuid", FT_GUID, BASE_NONE, NULL, 0x0, "UUID", HFILL} } ,
    { &hf_afs4int_owner, { "afs4int.owner", "afs4int.owner", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_parentunique, { "afs4int.parentunique", "afs4int.parentunique", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_parentvnode, { "afs4int.parentvnode", "afs4int.parentvnode", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_pathconfspare, { "afs4int.pathconfspare", "afs4int.pathconfspare", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_servermodtime_msec, { "afs4int.servermodtime_msec", "afs4int.servermodtime_msec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_servermodtime_sec, { "afs4int.servermodtime_sec", "afs4int.servermodtime_sec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_spare4, { "afs4int.spare4", "afs4int.spare4", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_spare5, { "afs4int.spare5", "afs4int.spare5", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_spare6, { "afs4int.spare6", "afs4int.spare6", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_typeuuid, { "afs4int.typeuuid", "afs4int.typeuuid", FT_GUID, BASE_NONE, NULL, 0x0, "UUID", HFILL} } ,
    { &hf_afs4int_volid_hi, { "afs4int.volid_hi", "afs4int.volid_hi", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_volid_low, { "afs4int.volid_low", "afs4int.volid_low", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_vvage, { "afs4int.vvage", "afs4int.vvage", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_vv_hi, { "afs4int.vv_hi", "afs4int.vv_hi", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_vv_low, { "afs4int.vv_low", "afs4int.vv_low", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_vvpingage, { "afs4int.vvpingage", "afs4int.vvpingage", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_vvspare1, { "afs4int.vvspare1", "afs4int.vvspare1", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_vvspare2, { "afs4int.vvspare2", "afs4int.vvspare2", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_beginrange, { "afs4int.beginrange", "afs4int.beginrange", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_beginrangeext, { "afs4int.beginrangeext", "afs4int.beginrangeext", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_endrange, { "afs4int.endrange", "afs4int.endrange", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_endrangeext, { "afs4int.endrangeext", "afs4int.endrangeext", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_expirationtime, { "afs4int.expirationtime", "afs4int.expirationtime", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_tokenid_hi, { "afs4int.tokenid_hi", "afs4int.tokenid_hi", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_tokenid_low, { "afs4int.tokenid_low", "afs4int.tokenid_low", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_type_hi, { "afs4int.type_hi", "afs4int.type_hi", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_type_low, { "afs4int.type_low", "afs4int.type_low", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_tn_length, { "afs4int.tn_length", "afs4int.tn_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL} } , 
    { &hf_afs4int_tn_tag, { "afs4int.tn_tag", "afs4int.tn_tag", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_accesstime_sec, { "afs4int.storestatus_accesstime_sec", "afs4int.storestatus_accesstime_sec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_accesstime_usec, { "afs4int.storestatus_accesstime_usec", "afs4int.storestatus_accesstime_usec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_changetime_sec, { "afs4int.storestatus_changetime_sec", "afs4int.storestatus_changetime_sec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_changetime_usec, { "afs4int.storestatus_changetime_usec", "afs4int.storestatus_changetime_usec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_clientspare1, { "afs4int.storestatus_clientspare1", "afs4int.storestatus_clientspare1", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_cmask, { "afs4int.storestatus_cmask", "afs4int.storestatus_cmask", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_devicenumber, { "afs4int.storestatus_devicenumber", "afs4int.storestatus_devicenumber", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_devicenumberhighbits, { "afs4int.storestatus_devicenumberhighbits", "afs4int.storestatus_devicenumberhighbits", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_devicetype, { "afs4int.storestatus_devicetype", "afs4int.storestatus_devicetype", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_group, { "afs4int.storestatus_group", "afs4int.storestatus_group", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_length_high, { "afs4int.storestatus_length_high", "afs4int.storestatus_length_high", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_length_low, { "afs4int.storestatus_length_low", "afs4int.storestatus_length_low", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_mask, { "afs4int.storestatus_mask", "afs4int.storestatus_mask", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_mode, { "afs4int.storestatus_mode", "afs4int.storestatus_mode", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_modtime_sec, { "afs4int.storestatus_modtime_sec", "afs4int.storestatus_modtime_sec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_modtime_usec, { "afs4int.storestatus_modtime_usec", "afs4int.storestatus_modtime_usec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_owner, { "afs4int.storestatus_owner", "afs4int.storestatus_owner", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_spare1, { "afs4int.storestatus_spare1", "afs4int.storestatus_spare1", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_spare2, { "afs4int.storestatus_spare2", "afs4int.storestatus_spare2", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_spare3, { "afs4int.storestatus_spare3", "afs4int.storestatus_spare3", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_spare4, { "afs4int.storestatus_spare4", "afs4int.storestatus_spare4", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_spare5, { "afs4int.storestatus_spare5", "afs4int.storestatus_spare5", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_spare6, { "afs4int.storestatus_spare6", "afs4int.storestatus_spare6", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_trunc_high, { "afs4int.storestatus_trunc_high", "afs4int.storestatus_trunc_high", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_trunc_low, { "afs4int.storestatus_trunc_low", "afs4int.storestatus_trunc_low", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_storestatus_typeuuid, { "afs4int.storestatus_typeuuid", "afs4int.storestatus_typeuuid", FT_GUID, BASE_NONE, NULL, 0x0, "UUID", HFILL} } ,
    { &hf_afs4int_st, { "afs4int.st", "afs4int.st", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_uint, {"afs4int.uint", "afs4int.uint", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_afs4int_l_end_pos, { "afs4int.l_end_pos", "afs4int.l_end_pos", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_l_end_pos_ext, { "afs4int.l_end_pos_ext", "afs4int.l_end_pos_ext", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_l_fstype, { "afs4int.l_fstype", "afs4int.l_fstype", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_l_pid, { "afs4int.l_pid", "afs4int.l_pid", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_l_start_pos, { "afs4int.l_start_pos", "afs4int.l_start_pos", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_l_start_pos_ext, { "afs4int.l_start_pos_ext", "afs4int.l_start_pos_ext", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_l_sysid, { "afs4int.l_sysid", "afs4int.l_sysid", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_l_type, { "afs4int.l_type", "afs4int.l_type", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    { &hf_afs4int_l_whence, { "afs4int.l_whence", "afs4int.l_whence", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL} } ,
    {&hf_afsconnparams_mask,
     {"hf_afsconnparams_mask", "hf_afsconnparams_mask",
      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    {&hf_afsconnparams_values,
     {"hf_afsconnparams_values", "hf_afsconnparams_values",
      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsFid_cell_high,
     {"Cell High", "afs4int.afsFid.cell_high", FT_UINT32, BASE_HEX, NULL, 0x0,
      "afsFid Cell High", HFILL}},
    {&hf_afs4int_afsFid_cell_low,
     {"Cell Low", "afs4int.afsFid.cell_low", FT_UINT32, BASE_HEX, NULL, 0x0,
      "afsFid Cell Low", HFILL}},
    {&hf_afs4int_afsFid_volume_high,
     {"Volume High", "afs4int.afsFid.volume_high", FT_UINT32, BASE_HEX, NULL,
      0x0, "afsFid Volume High", HFILL}},
    {&hf_afs4int_afsFid_volume_low,
     {"Volume Low", "afs4int.afsFid.volume_low", FT_UINT32, BASE_HEX, NULL,
      0x0, "afsFid Volume Low", HFILL}},
    {&hf_afs4int_afsFid_Vnode,
     {"Vnode", "afs4int.afsFid.Vnode", FT_UINT32, BASE_HEX, NULL, 0x0,
      "afsFid Vnode", HFILL}},
    {&hf_afs4int_afsFid_Unique,
     {"Unique", "afs4int.afsFid.Unique", FT_UINT32, BASE_HEX, NULL, 0x0,
      "afsFid Unique", HFILL}},
    {&hf_afs4int_afsNetAddr_type,
     {"Type", "afsNetAddr.type", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsNetAddr_data,
     {"IP Data", "afsNetAddr.data", FT_UINT8, BASE_DEC, NULL, 0x0, "",
      HFILL}},
    {&hf_afs4int_position_high,
     {"Position High", "afs4int.position_high", FT_UINT32, BASE_HEX, NULL,
      0x0, "", HFILL}},
    {&hf_afs4int_position_low,
     {"Position Low", "afs4int.position_low", FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL}},
    {&hf_afs4int_afsreturndesc_tokenid_high,
     {"Tokenid High", "afs4int.afsreturndesc_tokenid_high", FT_UINT32,
      BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsreturndesc_tokenid_low,
     {"Tokenid low", "afs4int.afsreturndesc_tokenid_low", FT_UINT32, BASE_HEX,
      NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsreturndesc_type_high,
     {"Type high", "afs4int.type_high", FT_UINT32, BASE_HEX, NULL, 0x0, "",
      HFILL}},
    {&hf_afs4int_afsreturndesc_type_low,
     {"Type low", "afs4int.type_low", FT_UINT32, BASE_HEX, NULL, 0x0, "",
      HFILL}},
    {&hf_afs4int_offsetp_high,
     {"offset high", "afs4int.offset_high", FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL}},
    {&hf_afs4int_offsetp_low,
     {"offset high", "afs4int.offset_high", FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL}},
    {&hf_afs4int_nextoffsetp_high,
     {"next offset high", "afs4int.nextoffset_high", FT_UINT32, BASE_HEX,
      NULL, 0x0, "", HFILL}},
    {&hf_afs4int_nextoffsetp_low,
     {"next offset low", "afs4int.nextoffset_low", FT_UINT32, BASE_HEX, NULL,
      0x0, "", HFILL}},
    {&hf_afs4int_returntokenidp_high,
     {"return token idp high", "afs4int.returntokenidp_high", FT_UINT32,
      BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_returntokenidp_low,
     {"return token idp low", "afs4int.returntokenidp_low", FT_UINT32,
      BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_cellidp_high,
     {"cellidp high", "afs4int.cellidp_high", FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL}},
    {&hf_afs4int_cellidp_low,
     {"cellidp low", "afs4int.cellidp_low", FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL}},
    {&hf_afserrorstatus_st,
     {"AFS Error Code", "afs4int.afserrortstatus_st", FT_UINT32, BASE_HEX,
      NULL, 0x0, "", HFILL}},
    {&hf_afs4int_length,
     {"Length", "afs4int.length", FT_UINT32, BASE_HEX,
      NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsTaggedPath_tp_chars,
     {"AFS Tagged Path", "afs4int.TaggedPath_tp_chars", FT_STRING, BASE_NONE,
      NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsTaggedPath_tp_tag,
     {"AFS Tagged Path Name", "afs4int.TaggedPath_tp_tag", FT_UINT32,
      BASE_HEX,
      NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsacl_uuid1,
     {"AFS ACL UUID1", "afs4int.afsacl_uuid1", FT_GUID, BASE_NONE,
      NULL, 0x0, "UUID", HFILL}},
    {&hf_afs4int_bulkfetchstatus_size,
     {"BulkFetchStatus Size", "afs4int.bulkfetchstatus_size", FT_UINT32,
      BASE_HEX,
      NULL, 0x0, "", HFILL}},
    {&hf_afs4int_bulkfetchvv_numvols,
     {"afs4int.bulkfetchvv_numvols", "afs4int.bulkfetchvv_numvols",
      FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_bulkfetchvv_spare1,
     {"afs4int.bulkfetchvv_spare1", "afs4int.bulkfetchvv_spare1",
      FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_bulkfetchvv_spare2,
     {"afs4int.bulkfetchvv_spare2", "afs4int.bulkfetchvv_spare2",
      FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_bulkkeepalive_numexecfids, {"BulkKeepAlive numexecfids", "afs4int.bulkkeepalive_numexecfids", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_bulkkeepalive_spare4,
     {"BulkKeepAlive spare4", "afs4int.bulkfetchkeepalive_spare2",
      FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_bulkkeepalive_spare2,
     {"BulkKeepAlive spare2", "afs4int.bulkfetchkeepalive_spare2",
      FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_bulkkeepalive_spare1,
     {"BulkFetch KeepAlive spare1", "afs4int.bulkfetchkeepalive_spare1",
      FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsacl_defaultcell_uuid,
     {"Default Cell UUID",
      "afs4int.defaultcell_uuid", FT_GUID, BASE_NONE, NULL, 0x0,
      "UUID", HFILL}},
    {&hf_afs4int_afsuuid_uuid,
     {"AFS UUID",
      "afs4int.uuid", FT_GUID, BASE_NONE, NULL, 0x0,
      "UUID", HFILL}},
    {&hf_afs4int_gettime_syncdispersion,
     {"GetTime Syncdispersion",
      "afs4int.gettime_syncdispersion", FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL}},
    {&hf_afs4int_gettime_syncdistance,
     {"SyncDistance", "afs4int.gettime.syncdistance",
      FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_gettime_usecondsp,
     {"GetTime usecondsp", "afs4int.gettime_usecondsp",
      FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_readdir_size,
     {"Readdir Size", "afs4int.readdir.size", FT_UINT32,
      BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsNameString_t_principalName_size,
     {"Principal Name Size",
      "afs4int.principalName_size", FT_UINT32, BASE_HEX,
      NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsNameString_t_principalName_size2,
     {"Principal Name Size2",
      "afs4int.principalName_size2", FT_UINT32, BASE_HEX,
      NULL, 0x0, "", HFILL}},
    {&hf_afs4int_afsTaggedPath_tp_length,
     {"Tagged Path Length",
      "afs4int.afsTaggedPath_length", FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL}},
    {&hf_afs4int_fstype,
     {"Filetype", "afs4int.fstype", FT_UINT32, BASE_HEX, NULL,
      0x0, "", HFILL}},
    {&hf_afs4int_gettime_secondsp,
     {"GetTime secondsp", "afs4int.gettime_secondsp", FT_UINT32,
      BASE_HEX, NULL,
      0x0, "", HFILL}},
    {&hf_afs4int_afsNameString_t_principalName_string,
     {"Principal Name", "afs4int.NameString_principal", FT_STRING,
      BASE_NONE, NULL,
      0x0, "", HFILL}},
    {&hf_afs4int_fetchdata_pipe_t_size,
     {"FetchData Pipe_t size", "afs4int.fetchdata_pipe_t_size", FT_STRING,
      BASE_NONE, NULL,
      0x0, "", HFILL}},
  };
  static gint *ett[] = {
    &ett_afs4int,
    &ett_afs4int_afsReturnDesc,
    &ett_afs4int_afsFid,
    &ett_afs4int_afsNetAddr,
    &ett_afs4int_fetchstatus,
    &ett_afs4int_afsflags,
    &ett_afs4int_volsync,
    &ett_afs4int_minvvp,
    &ett_afs4int_afsfidtaggedname,
    &ett_afs4int_afstaggedname,
    &ett_afs4int_afstoken,
    &ett_afs4int_afsstorestatus,
    &ett_afs4int_afsRecordLock,
    &ett_afs4int_afsAcl,
    &ett_afs4int_afsNameString_t,
    &ett_afs4int_afsConnParams,
    &ett_afs4int_afsErrorStatus,
    &ett_afs4int_afsTaggedPath,
    &ett_afs4int_afsNetData,
    &ett_afs4int_afsBulkStat,
    &ett_afs4int_afsuuid,
    &ett_afs4int_offsetp,
    &ett_afs4int_returntokenidp,
    &ett_afs4int_afsbundled_stat,
  };
  proto_afs4int = proto_register_protocol ("DFS Calls", "DCE_DFS", "dce_dfs");
  proto_register_field_array (proto_afs4int, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_afs4int (void)
{
  /*
   * Register the protocol as dcerpc 
   */
  dcerpc_init_uuid (proto_afs4int, ett_afs4int, &uuid_afs4int, ver_afs4int,
		    afs4int_dissectors, hf_afs4int_opnum);
}
