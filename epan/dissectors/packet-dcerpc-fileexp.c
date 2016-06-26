/* packet-dcerpc-fileexp.c
 *
 * Routines for DCE DFS File Exporter dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/fsint/afs4int.idl
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

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>

#include "packet-dcerpc.h"
#include "packet-dcerpc-dce122.h"

void proto_register_fileexp (void);
void proto_reg_handoff_fileexp (void);

#define AFS_SETMODTIME     0x001
#define AFS_SETOWNER       0x002
#define AFS_SETGROUP       0x004
#define AFS_SETMODE        0x008
#define AFS_SETACCESSTIME  0x010
#define AFS_SETCHANGETIME  0x020
#define AFS_SETLENGTH      0x040
#define AFS_SETTYPEUUID    0x080
#define AFS_SETDEVNUM      0x100
#define AFS_SETMODEXACT    0x200
#define AFS_SETTRUNCLENGTH 0x400
#define AFS_SETCLIENTSPARE 0x800

#define TKN_LOCK_READ                   0x00001
#define TKN_LOCK_WRITE                  0x00002
#define TKN_DATA_READ                   0x00004
#define TKN_DATA_WRITE                  0x00008
#define TKN_OPEN_READ                   0x00010
#define TKN_OPEN_WRITE                  0x00020
#define TKN_OPEN_SHARED                 0x00040
#define TKN_OPEN_EXCLUSIVE              0x00080
#define TKN_OPEN_DELETE                 0x00100
#define TKN_OPEN_PRESERVE               0x00200
#define TKN_STATUS_READ                 0x00400
#define TKN_STATUS_WRITE                0x00800
#define TKN_OPEN_UNLINK                 0x01000
#define TKN_SPOT_HERE                   0x02000
#define TKN_SPOT_THERE                  0x04000
#define TKN_OPEN_NO_READ                0x08000
#define TKN_OPEN_NO_WRITE               0x10000
#define TKN_OPEN_NO_UNLINK              0x20000

#define AFS_CONN_PARAM_HOSTLIFE         0
#define AFS_CONN_PARAM_HOSTRPC          1
#define AFS_CONN_PARAM_DEADSERVER       2
#define AFS_CONN_PARAM_EPOCH            3
#define AFS_CONN_PARAM_MAXFILE_CLIENT   4
#define AFS_CONN_PARAM_MAXFILE_SERVER   5
#define AFS_CONN_PARAM_HOST_TYPE_CLIENT 6
#define AFS_CONN_PARAM_HOST_TYPE_SERVER 7
#define AFS_CONN_PARAM_FT_MASK_CLIENT   8
#define AFS_CONN_PARAM_FT_MASK_SERVER   9

#define AFS_CONN_PARAM_SUPPORTS_64BITS  0x10000
#define AFS_CONN_PARAM_512BYTE_BLOCKS   0x20000

#define AFS_FLAG_SEC_SERVICE            0x01
#define AFS_FLAG_CONTEXT_NEW_IF         0x02
#define AFS_FLAG_CONTEXT_DO_RESET       0x04
#define AFS_FLAG_CONTEXT_NEW_ACL_IF     0x08
#define AFS_FLAG_CONTEXT_NEW_TKN_TYPES  0x10

#define AFS_FLAG_RETURNTOKEN          0x00001
#define AFS_FLAG_TOKENJUMPQUEUE       0x00002
#define AFS_FLAG_SKIPTOKEN            0x00004
#define AFS_FLAG_NOOPTIMISM           0x00008
#define AFS_FLAG_TOKENID              0x00010
#define AFS_FLAG_RETURNBLOCKER        0x00020
#define AFS_FLAG_ASYNCGRANT           0x00040
#define AFS_FLAG_NOREVOKE             0x00080
#define AFS_FLAG_MOVE_REESTABLISH     0x00100
#define AFS_FLAG_SERVER_REESTABLISH   0x00200
#define AFS_FLAG_NO_NEW_EPOCH         0x00400
#define AFS_FLAG_MOVE_SOURCE_OK       0x00800
#define AFS_FLAG_SYNC                 0x01000
#define AFS_FLAG_ZERO                 0x02000
#define AFS_FLAG_SKIPSTATUS           0x04000
#define AFS_FLAG_FORCEREVOCATIONS     0x08000
#define AFS_FLAG_FORCEVOLQUIESCE      0x10000
#define AFS_FLAG_FORCEREVOCATIONDOWN  0x20000

static int hf_fileexp_opnum = -1;


static int hf_fileexp_afsFid_cell_high = -1;
static int hf_fileexp_afsuuid_uuid = -1;
static int hf_fileexp_fetchdata_pipe_t_size = -1;
static int hf_fileexp_afsNameString_t_principalName_string = -1;
static int hf_fileexp_afsFid_cell_low = -1;
static int hf_fileexp_afsFid_volume_high = -1;
static int hf_fileexp_afsFid_volume_low = -1;
static int hf_fileexp_afsFid_Vnode = -1;
static int hf_fileexp_afsFid_Unique = -1;
static int hf_fileexp_interfaceversion = -1;
static int hf_fileexp_filetype = -1;
static int hf_fileexp_linkcount = -1;
static int hf_fileexp_length_high = -1;
static int hf_fileexp_length_low = -1;
static int hf_fileexp_dataversion_high = -1;
static int hf_fileexp_dataversion_low = -1;
static int hf_fileexp_author = -1;
static int hf_fileexp_owner = -1;
static int hf_fileexp_group = -1;
static int hf_fileexp_calleraccess = -1;
static int hf_fileexp_anonymousaccess = -1;
static int hf_fileexp_aclexpirationtime = -1;
static int hf_fileexp_mode = -1;
static int hf_fileexp_parentvnode = -1;
static int hf_fileexp_parentunique = -1;
static int hf_fileexp_modtime_sec = -1;
static int hf_fileexp_modtime_msec = -1;
static int hf_fileexp_changetime_sec = -1;
static int hf_fileexp_changetime_msec = -1;
static int hf_fileexp_accesstime_sec = -1;
static int hf_fileexp_accesstime_msec = -1;
static int hf_fileexp_servermodtime_sec = -1;
static int hf_fileexp_servermodtime_msec = -1;
static int hf_fileexp_typeuuid = -1;
static int hf_fileexp_objectuuid = -1;
static int hf_fileexp_devicenumber = -1;
static int hf_fileexp_blocksused = -1;
static int hf_fileexp_clientspare1 = -1;
static int hf_fileexp_devicenumberhighbits = -1;
static int hf_fileexp_agtypeunique = -1;
static int hf_fileexp_himaxspare = -1;
static int hf_fileexp_lomaxspare = -1;
static int hf_fileexp_pathconfspare = -1;
static int hf_fileexp_spare4 = -1;
static int hf_fileexp_spare5 = -1;
static int hf_fileexp_spare6 = -1;
static int hf_fileexp_volid_hi = -1;
static int hf_fileexp_volid_low = -1;
static int hf_fileexp_vvage = -1;
static int hf_fileexp_vv_hi = -1;
static int hf_fileexp_vv_low = -1;
static int hf_fileexp_vvpingage = -1;
static int hf_fileexp_vvspare1 = -1;
static int hf_fileexp_vvspare2 = -1;
static int hf_fileexp_beginrange = -1;
static int hf_fileexp_beginrangeext = -1;
static int hf_fileexp_endrange = -1;
static int hf_fileexp_endrangeext = -1;
static int hf_fileexp_expirationtime = -1;
static int hf_fileexp_tokenid_hi = -1;
static int hf_fileexp_tokenid_low = -1;
static int hf_fileexp_type_hi = -1;
static int hf_fileexp_type_low = -1;
static int hf_fileexp_tn_length = -1;
static int hf_fileexp_storestatus_accesstime_sec = -1;
static int hf_fileexp_storestatus_accesstime_usec = -1;
static int hf_fileexp_storestatus_changetime_sec = -1;
static int hf_fileexp_storestatus_changetime_usec = -1;
static int hf_fileexp_storestatus_clientspare1 = -1;
static int hf_fileexp_storestatus_cmask = -1;
static int hf_fileexp_storestatus_devicenumber = -1;
static int hf_fileexp_storestatus_devicenumberhighbits = -1;
static int hf_fileexp_storestatus_devicetype = -1;
static int hf_fileexp_storestatus_group = -1;
static int hf_fileexp_storestatus_length_high = -1;
static int hf_fileexp_storestatus_length_low = -1;
static int hf_fileexp_storestatus_mask = -1;
static int hf_fileexp_storestatus_mode = -1;
static int hf_fileexp_storestatus_modtime_sec = -1;
static int hf_fileexp_storestatus_modtime_usec = -1;
static int hf_fileexp_storestatus_owner = -1;
static int hf_fileexp_storestatus_spare1 = -1;
static int hf_fileexp_storestatus_spare2 = -1;
static int hf_fileexp_storestatus_spare3 = -1;
static int hf_fileexp_storestatus_spare4 = -1;
static int hf_fileexp_storestatus_spare5 = -1;
static int hf_fileexp_storestatus_spare6 = -1;
static int hf_fileexp_storestatus_trunc_high = -1;
static int hf_afsconnparams_mask = -1;
static int hf_fileexp_storestatus_trunc_low = -1;
static int hf_fileexp_storestatus_typeuuid = -1;
static int hf_fileexp_l_end_pos = -1;
static int hf_fileexp_l_end_pos_ext = -1;
static int hf_fileexp_l_fstype = -1;
static int hf_fileexp_l_pid = -1;
static int hf_fileexp_l_start_pos = -1;
static int hf_fileexp_l_start_pos_ext = -1;
static int hf_fileexp_l_sysid = -1;
static int hf_fileexp_l_type = -1;
static int hf_fileexp_l_whence = -1;
static int hf_fileexp_acl_len = -1;
static int hf_fileexp_setcontext_rqst_epochtime = -1;
static int hf_fileexp_setcontext_rqst_clientsizesattrs = -1;
static int hf_fileexp_setcontext_rqst_parm7 = -1;
static int hf_fileexp_afsNetAddr_type = -1;
static int hf_fileexp_afsNetAddr_data = -1;
static int hf_fileexp_returntokenidp_high = -1;
static int hf_fileexp_minvvp_low = -1;
static int hf_fileexp_position_high = -1;
static int hf_fileexp_position_low = -1;
static int hf_fileexp_offsetp_high = -1;
static int hf_fileexp_nextoffsetp_low = -1;
static int hf_fileexp_cellidp_high = -1;
static int hf_afserrorstatus_st = -1;
static int hf_fileexp_length = -1;
static int hf_afsconnparams_values = -1;
static int hf_fileexp_acltype = -1;
static int hf_fileexp_afsTaggedPath_tp_chars = -1;
static int hf_fileexp_afsTaggedPath_tp_tag = -1;
static int hf_fileexp_afsacl_uuid1 = -1;
static int hf_fileexp_bulkfetchstatus_size = -1;
static int hf_fileexp_flags = -1;
static int hf_fileexp_afsreturndesc_tokenid_high = -1;
static int hf_fileexp_afsreturndesc_tokenid_low = -1;
static int hf_fileexp_afsreturndesc_type_high = -1;
static int hf_fileexp_afsreturndesc_type_low = -1;
static int hf_fileexp_returntokenidp_low = -1;
static int hf_fileexp_minvvp_high = -1;
static int hf_fileexp_offsetp_low = -1;
static int hf_fileexp_nextoffsetp_high = -1;
static int hf_fileexp_cellidp_low = -1;
static int hf_fileexp_tn_tag = -1;
static int hf_fileexp_tn_string = -1;
static int hf_fileexp_bulkfetchvv_numvols = -1;
static int hf_fileexp_bulkfetchvv_spare1 = -1;
static int hf_fileexp_bulkfetchvv_spare2 = -1;
static int hf_fileexp_bulkkeepalive_numexecfids = -1;
static int hf_fileexp_bulkkeepalive_spare4 = -1;
static int hf_fileexp_bulkkeepalive_spare2 = -1;
static int hf_fileexp_bulkkeepalive_spare1 = -1;
static int hf_fileexp_afsacl_defaultcell_uuid = -1;
static int hf_fileexp_gettime_syncdispersion = -1;
static int hf_fileexp_gettime_syncdistance = -1;
static int hf_fileexp_gettime_usecondsp = -1;
static int hf_fileexp_readdir_size = -1;
static int hf_fileexp_afsNameString_t_principalName_size = -1;
static int hf_fileexp_afsTaggedPath_tp_length = -1;
static int hf_fileexp_fstype = -1;
static int hf_fileexp_gettime_secondsp = -1;

static int proto_fileexp = -1;

static gint ett_fileexp = -1;
static gint ett_fileexp_afsFid = -1;
static gint ett_fileexp_afsReturnDesc = -1;
static gint ett_fileexp_afsNetAddr = -1;
static gint ett_fileexp_fetchstatus = -1;
static gint ett_fileexp_afsflags = -1;
static gint ett_fileexp_volsync = -1;
static gint ett_fileexp_minvvp = -1;
static gint ett_fileexp_afsfidtaggedname = -1;
static gint ett_fileexp_afstaggedname = -1;
static gint ett_fileexp_afstoken = -1;
static gint ett_fileexp_afsstorestatus = -1;
static gint ett_fileexp_afsRecordLock = -1;
static gint ett_fileexp_afsAcl = -1;
static gint ett_fileexp_afsNameString_t = -1;
static gint ett_fileexp_afsConnParams = -1;
static gint ett_fileexp_afsErrorStatus = -1;
static gint ett_fileexp_afsNetData = -1;
static gint ett_fileexp_afsTaggedPath = -1;
static gint ett_fileexp_afsBulkStat = -1;
static gint ett_fileexp_afsuuid = -1;
static gint ett_fileexp_offsetp = -1;
static gint ett_fileexp_returntokenidp = -1;
static gint ett_fileexp_afsbundled_stat = -1;


/* vars for our macro(s) */
static int hf_error_st = -1;

static e_guid_t uuid_fileexp =
  { 0x4d37f2dd, 0xed93, 0x0000, {0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00, 0x00}
};
static guint16 ver_fileexp = 4;

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
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_error_st, &st); \
    st_str = val_to_str_ext (st, &dce_error_vals_ext, "%u"); \
    if (st) { \
      col_add_fstr (pinfo->cinfo, COL_INFO, "%s st:%s ", name, st_str); \
    } else { \
      col_append_fstr (pinfo->cinfo, COL_INFO, " st:%s ", st_str); \
    } \
  }

static int
dissect_afsFid (tvbuff_t *tvb, int offset,
                packet_info *pinfo, proto_tree *parent_tree,
                dcerpc_info *di, guint8 *drep)
{
/*
        afsHyper Cell;
        afsHyper Volume;
        unsigned32 Vnode;
        unsigned32 Unique;
*/

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     volume_low, unique, vnode, inode;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_afsFid, &item, "afsFid:");
    }

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                               hf_fileexp_afsFid_cell_high, NULL);

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                               hf_fileexp_afsFid_cell_low, NULL);

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                               hf_fileexp_afsFid_volume_high, NULL);

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                               hf_fileexp_afsFid_volume_low, &volume_low);

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                               hf_fileexp_afsFid_Vnode, &vnode);

  offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                               hf_fileexp_afsFid_Unique, &unique);

  col_append_fstr (pinfo->cinfo, COL_INFO, " :FSID:%u ", volume_low);

  if ((vnode == 1) || (vnode == 2))
    {
      col_append_str (pinfo->cinfo, COL_INFO, " InFS ");
    }
  else
    {
      inode = ((volume_low << 16) + vnode) & 0x7fffffff;
      col_append_fstr (pinfo->cinfo, COL_INFO, " inode:%u ", inode);
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsConnParams (tvbuff_t *tvb, int offset,
                       packet_info *pinfo, proto_tree *parent_tree,
                       dcerpc_info *di, guint8 *drep)
{
/*
        unsigned32 Mask;
        unsigned32 Values[20];
*/

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     mask, Values[20];

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree =
        proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                ett_fileexp_afsConnParams, &item, "afsConnParams_t:");
    }
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_mask, &mask);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[0]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[1]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[2]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[3]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[4]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[5]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[6]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[7]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[8]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[9]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[10]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[11]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[12]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[13]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[14]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[15]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[16]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[17]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[18]);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_afsconnparams_values, &Values[19]);
  if ((mask & AFS_CONN_PARAM_HOSTLIFE) == AFS_CONN_PARAM_HOSTLIFE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":HOSTLIFE");
    }
  if ((mask & AFS_CONN_PARAM_HOSTRPC) == AFS_CONN_PARAM_HOSTRPC)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":HOSTRPC");
    }
  if ((mask & AFS_CONN_PARAM_DEADSERVER) == AFS_CONN_PARAM_DEADSERVER)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":DEADSERVER");
    }
  if ((mask & AFS_CONN_PARAM_EPOCH) == AFS_CONN_PARAM_EPOCH)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":EPOCH");
    }
  if ((mask & AFS_CONN_PARAM_MAXFILE_CLIENT) == AFS_CONN_PARAM_MAXFILE_CLIENT)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":MAXFILE_CLIENT");
    }
  if ((mask & AFS_CONN_PARAM_MAXFILE_SERVER) == AFS_CONN_PARAM_MAXFILE_SERVER)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":MAXFILE_SERVER");
    }
  if ((mask & AFS_CONN_PARAM_HOST_TYPE_CLIENT) ==
      AFS_CONN_PARAM_HOST_TYPE_CLIENT)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":HOST_TYPE_CLIENT");
    }
  if ((mask & AFS_CONN_PARAM_HOST_TYPE_SERVER) ==
      AFS_CONN_PARAM_HOST_TYPE_SERVER)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":HOST_TYPE_SERVER");
    }
  if ((mask & AFS_CONN_PARAM_FT_MASK_CLIENT) == AFS_CONN_PARAM_FT_MASK_CLIENT)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":FT_MASK_CLIENT");
    }
  if ((mask & AFS_CONN_PARAM_FT_MASK_SERVER) == AFS_CONN_PARAM_FT_MASK_SERVER)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":FT_MASK_SERVER");
    }
  if ((mask & AFS_CONN_PARAM_SUPPORTS_64BITS) ==
      AFS_CONN_PARAM_SUPPORTS_64BITS)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":SUPPORTS_64BITS");
    }
  if ((mask & AFS_CONN_PARAM_512BYTE_BLOCKS) == AFS_CONN_PARAM_512BYTE_BLOCKS)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":512BYTE_BLOCKS");
    }
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
dissect_afsNameString_t (tvbuff_t *tvb, int offset,
                         packet_info *pinfo, proto_tree *parent_tree,
                         dcerpc_info *di, guint8 *drep)
{
/*
typedef [string] byte   NameString_t[AFS_NAMEMAX];
*/

  proto_item   *item       = NULL;
  proto_tree   *tree       = NULL;
  int           old_offset = offset;
#define AFS_NAMEMAX 256
  guint32       string_size;
  const guint8 *namestring;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree =
        proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                ett_fileexp_afsNameString_t, &item, "afsNameString_t:");
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                       hf_fileexp_afsNameString_t_principalName_size,
                       &string_size);
  col_append_fstr (pinfo->cinfo, COL_INFO, " String_size:%u", string_size);
  if (string_size < AFS_NAMEMAX)
    {
      proto_tree_add_item_ret_string(tree, hf_fileexp_afsNameString_t_principalName_string, tvb, offset, string_size, ENC_ASCII|ENC_NA, wmem_packet_scope(), &namestring);
      offset += string_size;
      col_append_fstr (pinfo->cinfo, COL_INFO, " Principal:%s", namestring);
    }
  else
    {
      col_append_fstr (pinfo->cinfo, COL_INFO,
                       " :FIXME!: Invalid string length of  %u",
                       string_size);
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_afsNetAddr (tvbuff_t *tvb, int offset,
                    packet_info *pinfo, proto_tree *parent_tree,
                    dcerpc_info *di, guint8 *drep)
{
/*                 unsigned16 type;
                   unsigned8 data[14];
*/

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint16     type;
  guint8      data;
  int         i;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                     ett_fileexp_afsNetAddr, &item, "afsNetAddr:");
    }

  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_afsNetAddr_type, &type);

  if (type)
    {
      col_append_fstr (pinfo->cinfo, COL_INFO, " Type:%u ", type);


      for (i = 0; i < 14; i++)
        {

          offset =
            dissect_ndr_uint8 (tvb, offset, pinfo, tree, di, drep,
                               hf_fileexp_afsNetAddr_data, &data);


          switch (i)
            {
            case 1:
              if (data)
                {
                    col_append_fstr (pinfo->cinfo, COL_INFO, " Port:%u",
                                     data);
                }
              break;
            case 2:
                col_append_fstr (pinfo->cinfo, COL_INFO, " IP:%u.", data);
              break;
            case 3:
                col_append_fstr (pinfo->cinfo, COL_INFO, "%u.", data);
              break;
            case 4:
                col_append_fstr (pinfo->cinfo, COL_INFO, "%u.", data);
              break;
            case 5:
                col_append_fstr (pinfo->cinfo, COL_INFO, "%u", data);
              break;
            }

        }

    }
  else
    {

      offset += 14;             /* space left after reading in type for the array. */
    }


  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_afsNetData (tvbuff_t *tvb, int offset,
                    packet_info *pinfo, proto_tree *parent_tree,
                    dcerpc_info *di, guint8 *drep)
{
/*
        afsNetAddr sockAddr;
        NameString_t principalName;
*/
  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree =
        proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_afsNetData, &item, "afsNetData:");
    }

  offset = dissect_afsNetAddr ( tvb, offset, pinfo, tree, di, drep);
  offset += 4; /* buffer */
  offset = dissect_afsNameString_t ( tvb, offset, pinfo, tree, di, drep);

  proto_item_set_len (item, offset - old_offset);
  return offset;

}

static int
dissect_afsTaggedPath (tvbuff_t *tvb, int offset,
                       packet_info *pinfo, proto_tree *parent_tree,
                       dcerpc_info *di, guint8 *drep)
{
/*
        codesetTag      tp_tag;
        unsigned16      tp_length;
        byte            tp_chars[AFS_PATHMAX+1]; 1024+1
*/

  proto_item   *item       = NULL;
  proto_tree   *tree       = NULL;
  int           old_offset = offset;
  guint32       tp_tag;
  guint16       tp_length;
  const guint8 *tp_chars;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree =
        proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_afsTaggedPath, &item, "afsTaggedPath");
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_afsTaggedPath_tp_tag, &tp_tag);
  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_afsTaggedPath_tp_length, &tp_length);
  proto_tree_add_item (tree, hf_fileexp_afsTaggedPath_tp_chars, tvb, offset,
                       tp_length, ENC_ASCII|ENC_NA);
  tp_chars = tvb_get_string_enc (wmem_packet_scope(), tvb, offset, 1025, ENC_ASCII);
  offset += 1025;
  col_append_fstr (pinfo->cinfo, COL_INFO, " :tp_chars %s", tp_chars);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsAcl (tvbuff_t *tvb, int offset,
                packet_info *pinfo, proto_tree *parent_tree,
                dcerpc_info *di, guint8 *drep)
{
/*
        unsigned32 afsACL_len;
        [length_is(afsACL_len)] byte afsACL_val[AFS_ACLMAX];
*/

  proto_item *item       = NULL;
  proto_tree *tree;
  int         old_offset = offset;
  guint32     acl_len;
  e_guid_t    uuid1, defaultcell;

  if (di->conformant_run)
    {
      return offset;
    }

  tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_afsAcl, &item, "afsAcl");

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_acl_len,
                        &acl_len);
  offset += 8;                  /* bypass spare and duplicate acl_len */
  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_afsacl_uuid1, &uuid1);
  col_append_fstr (pinfo->cinfo, COL_INFO,
                   " - %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   uuid1.data1, uuid1.data2, uuid1.data3, uuid1.data4[0],
                   uuid1.data4[1], uuid1.data4[2], uuid1.data4[3],
                   uuid1.data4[4], uuid1.data4[5], uuid1.data4[6],
                   uuid1.data4[7]);

  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_afsacl_defaultcell_uuid, &defaultcell);
  col_append_fstr (pinfo->cinfo, COL_INFO,
                     "  %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                     defaultcell.data1, defaultcell.data2, defaultcell.data3,
                     defaultcell.data4[0], defaultcell.data4[1],
                     defaultcell.data4[2], defaultcell.data4[3],
                     defaultcell.data4[4], defaultcell.data4[5],
                     defaultcell.data4[6], defaultcell.data4[7]);

  if (acl_len < 38)
    {
      /* XXX - exception */
      return offset;
    }

  offset += (acl_len - 38);

  proto_item_set_len (item, offset-old_offset);
  return offset;
}


static int
dissect_afsErrorStatus (tvbuff_t *tvb, int offset,
                        packet_info *pinfo, proto_tree *parent_tree,
                        dcerpc_info *di, guint8 *drep)
{
  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     st;
  const char *st_str;

  if (di->conformant_run)
  {
    return offset;
  }

  if (parent_tree)
  {
    tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                   ett_fileexp_afsErrorStatus, &item, "afsErrorStatus");
  }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_afserrorstatus_st,
                       &st);
  st_str = val_to_str_ext (st, &dce_error_vals_ext, "%u");

  col_append_fstr (pinfo->cinfo, COL_INFO, " st:%s ", st_str);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsRecordLock (tvbuff_t *tvb, int offset,
                       packet_info *pinfo, proto_tree *parent_tree,
                       dcerpc_info *di, guint8 *drep)
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

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint16     l_type, l_whence;
  guint32     l_start_pos, l_end_pos, l_pid, l_sysid, l_fstype;
  guint32     l_start_pos_ext, l_end_pos_ext;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                     ett_fileexp_afsRecordLock, &item, "afsRecordLock:");
    }

  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_l_type,
                        &l_type);
  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_l_whence,
                        &l_whence);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_l_start_pos, &l_start_pos);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_l_end_pos,
                        &l_end_pos);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_l_pid,
                        &l_pid);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_l_sysid,
                        &l_sysid);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_l_fstype,
                        &l_fstype);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_l_start_pos_ext, &l_start_pos_ext);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_l_end_pos_ext, &l_end_pos_ext);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsstorestatus (tvbuff_t *tvb, int offset,
                        packet_info *pinfo, proto_tree *parent_tree,
                        dcerpc_info *di, guint8 *drep)
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

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     mask, modtime_sec, changetime_sec, accesstime_sec, devicenumber;
  guint32     clientspare1, devicenumberhighbits, spare1, spare2, spare3, spare4;
  guint32     spare5, spare6, accesstime_usec, changetime_usec, owner, group, mode;
  guint32     trunc_high, trunc_low, length_high, length_low, devicetype;
  guint32     cmask, modtime_usec;
  e_guid_t    typeuuid;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                     ett_fileexp_afsstorestatus, &item, "afsStoreStatus:");
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_mask, &mask);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_modtime_sec, &modtime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_modtime_usec, &modtime_usec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_accesstime_sec,
                        &accesstime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_accesstime_usec,
                        &accesstime_usec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_changetime_sec,
                        &changetime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_changetime_usec,
                        &changetime_usec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_owner, &owner);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_group, &group);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_mode, &mode);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_trunc_high, &trunc_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_trunc_low, &trunc_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_length_high, &length_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_length_low, &length_low);
  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_typeuuid, &typeuuid);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_devicetype, &devicetype);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_devicenumber, &devicenumber);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_cmask, &cmask);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_clientspare1, &clientspare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_devicenumberhighbits,
                        &devicenumberhighbits);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_spare1, &spare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_spare2, &spare2);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_spare3, &spare3);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_spare4, &spare4);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_spare5, &spare5);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_storestatus_spare6, &spare6);

  col_append_str (pinfo->cinfo, COL_INFO, " Mask=");
  if ((mask & AFS_SETMODTIME) == AFS_SETMODTIME)
    {
        col_append_fstr (pinfo->cinfo, COL_INFO, ":SETMODTIME-%u.%u",
                         modtime_sec, modtime_usec);
    }
  if ((mask & AFS_SETOWNER) == AFS_SETOWNER)
    {
        col_append_fstr (pinfo->cinfo, COL_INFO, ":SETOWNER-%u", owner);
    }
  if ((mask & AFS_SETGROUP) == AFS_SETGROUP)
    {
        col_append_fstr (pinfo->cinfo, COL_INFO, ":SETGROUP-%u", group);
    }
  if ((mask & AFS_SETMODE) == AFS_SETMODE)
    {
        col_append_fstr (pinfo->cinfo, COL_INFO, ":SETMODE-%o", mode);
    }
  if ((mask & AFS_SETACCESSTIME) == AFS_SETACCESSTIME)
    {
        col_append_fstr (pinfo->cinfo, COL_INFO, ":SETACCESSTIME-%u.%u",
                         accesstime_sec, accesstime_usec);
    }
  if ((mask & AFS_SETCHANGETIME) == AFS_SETCHANGETIME)
    {
        col_append_fstr (pinfo->cinfo, COL_INFO, ":SETCHANGETIME-%u.%u",
                         changetime_sec, changetime_usec);
    }
  if ((mask & AFS_SETLENGTH) == AFS_SETLENGTH)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":SETLENGTH");
    }
  if ((mask & AFS_SETTYPEUUID) == AFS_SETTYPEUUID)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":SETTYPEUUID");
    }
  if ((mask & AFS_SETDEVNUM) == AFS_SETDEVNUM)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":SETDEVNUM");
    }
  if ((mask & AFS_SETMODEXACT) == AFS_SETMODEXACT)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":SETMODEXACT");
    }
  if ((mask & AFS_SETTRUNCLENGTH) == AFS_SETTRUNCLENGTH)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":SETTRUNCLENGTH");
    }
  if ((mask & AFS_SETCLIENTSPARE) == AFS_SETCLIENTSPARE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":SETCLIENTSPARE");
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afstoken (tvbuff_t *tvb, int offset,
                  packet_info *pinfo, proto_tree *parent_tree,
                  dcerpc_info *di, guint8 *drep)
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

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     tokenid_hi, tokenid_low, expirationtime, type_hi, type_low;
  guint32     beginrange, endrange, beginrangeext, endrangeext, type;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_afstoken, &item, "afsToken:");
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_tokenid_hi,
                        &tokenid_hi);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_tokenid_low, &tokenid_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_expirationtime, &expirationtime);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_type_hi,
                        &type_hi);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_type_low,
                        &type_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_beginrange,
                        &beginrange);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_endrange,
                        &endrange);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_beginrangeext, &beginrangeext);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_endrangeext, &endrangeext);
    col_append_fstr (pinfo->cinfo, COL_INFO,
                     "  :Tokenid:%u/%u ExpirationTime:%u beginrange:%u endrange:%u beginrangeext:%u endrangeext:%u",
                     tokenid_hi, tokenid_low, expirationtime, beginrange,
                     endrange, beginrangeext, endrangeext);
  type = type_low;

  col_append_str (pinfo->cinfo, COL_INFO, " Type=");

  if ((type & TKN_LOCK_READ) == TKN_LOCK_READ)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":LOCK_READ");
    }
  if ((type & TKN_LOCK_WRITE) == TKN_LOCK_WRITE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":LOCK_WRITE");
    }
  if ((type & TKN_DATA_READ) == TKN_DATA_READ)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":DATA_READ");
    }
  if ((type & TKN_DATA_WRITE) == TKN_DATA_WRITE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":DATA_WRITE");
    }
  if ((type & TKN_OPEN_READ) == TKN_OPEN_READ)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_READ");
    }
  if ((type & TKN_OPEN_WRITE) == TKN_OPEN_WRITE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_WRITE");
    }
  if ((type & TKN_OPEN_SHARED) == TKN_OPEN_SHARED)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_SHARED");
    }
  if ((type & TKN_OPEN_EXCLUSIVE) == TKN_OPEN_EXCLUSIVE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_EXCLUSIVE");
    }
  if ((type & TKN_OPEN_DELETE) == TKN_OPEN_DELETE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_DELETE");
    }
  if ((type & TKN_OPEN_PRESERVE) == TKN_OPEN_PRESERVE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_PRESERVE");
    }
  if ((type & TKN_STATUS_READ) == TKN_STATUS_READ)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":STATUS_READ");
    }
  if ((type & TKN_STATUS_WRITE) == TKN_STATUS_WRITE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":STATUS_WRITE");
    }
  if ((type & TKN_OPEN_UNLINK) == TKN_OPEN_UNLINK)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_UNLINK");
    }
  if ((type & TKN_SPOT_HERE) == TKN_SPOT_HERE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":SPOT_HERE");
    }
  if ((type & TKN_SPOT_THERE) == TKN_SPOT_THERE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":SPOT_THERE");
    }
  if ((type & TKN_OPEN_NO_READ) == TKN_OPEN_NO_READ)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_NO_READ");
    }
  if ((type & TKN_OPEN_NO_WRITE) == TKN_OPEN_NO_WRITE)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_NO_WRITE");
    }
  if ((type & TKN_OPEN_NO_UNLINK) == TKN_OPEN_NO_UNLINK)
    {
      col_append_str (pinfo->cinfo, COL_INFO, ":OPEN_NO_UNLINK");
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afstaggedname (tvbuff_t *tvb, int offset,
                       packet_info *pinfo, proto_tree *parent_tree,
                       dcerpc_info *di, guint8 *drep)
{
/*
        codesetTag      tn_tag;
        unsigned16      tn_length;
        byte            tn_chars[AFS_NAMEMAX+1];
*/

  proto_item   *item       = NULL;
  proto_tree   *tree       = NULL;
  int           old_offset = offset;
  guint32       tn_tag;
  guint16       tn_length;
  const guint8 *tn_string;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                     ett_fileexp_afstaggedname, &item, "afsTaggedName:");
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_tn_tag,
                        &tn_tag);
  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_tn_length,
                        &tn_length);
  if (tn_length < 254)
    {
      proto_tree_add_item (tree, hf_fileexp_tn_string, tvb, offset,
                             tn_length, ENC_ASCII|ENC_NA);
      tn_string = tvb_get_string_enc (wmem_packet_scope(), tvb, offset, 257, ENC_ASCII);
      offset += 257;
        col_append_fstr (pinfo->cinfo, COL_INFO, " :tn_tag: %s", tn_string);
    }
  else
    {
        col_append_fstr (pinfo->cinfo, COL_INFO,
                         " :FIXME!: Invalid string length of  %u", tn_length);
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_afsfidtaggedname (tvbuff_t *tvb, int offset,
                          packet_info *pinfo, proto_tree *parent_tree,
                          dcerpc_info *di, guint8 *drep)
{
/*
        afsFid fid;
        afsTaggedName name;
*/

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                     ett_fileexp_afsfidtaggedname, &item, "FidTaggedName:");
    }
  offset = dissect_afsFid (tvb, offset, pinfo, tree, di, drep);
  offset = dissect_afstaggedname (tvb, offset, pinfo, tree, di, drep);

  proto_item_set_len (item, offset - old_offset);
  return offset;

}

static int
dissect_minvvp (tvbuff_t *tvb, int offset,
                packet_info *pinfo, proto_tree *parent_tree,
                dcerpc_info *di, guint8 *drep)
{
/* unsigned32 minvvp_high
   unsigned32 minvvp_low
*/

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     minvvp_high, minvvp_low;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_minvvp,  &item, "minVVp:");
    }
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_minvvp_high, &minvvp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_minvvp_low,
                        &minvvp_low);

    col_append_fstr (pinfo->cinfo, COL_INFO, " minVVp:%u/%u", minvvp_high,
                     minvvp_low);


  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_afsuuid (tvbuff_t *tvb, int offset,
                 packet_info *pinfo, proto_tree *parent_tree,
                 dcerpc_info *di, guint8 *drep)
{
/* uuid  UUID
*/
/*HEREN*/

  e_guid_t uuid1;

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_afsuuid, &item, "afsUUID:");
    }

  offset = dissect_ndr_uuid_t (tvb, offset, pinfo, tree, di, drep, hf_fileexp_afsuuid_uuid, &uuid1);

  col_append_fstr (pinfo->cinfo, COL_INFO, ":%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", uuid1.data1, uuid1.data2, uuid1.data3, uuid1.data4[0], uuid1.data4[1], uuid1.data4[2], uuid1.data4[3], uuid1.data4[4], uuid1.data4[5], uuid1.data4[6], uuid1.data4[7]);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_offsetp (tvbuff_t *tvb, int offset,
                 packet_info *pinfo, proto_tree *parent_tree,
                 dcerpc_info *di, guint8 *drep)
{
/* unsigned32 offsetp_high
   unsigned32 offsetp_low
*/

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     offsetp_high, offsetp_low;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_offsetp, &item, "minVVp:");
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_offsetp_high, &offsetp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_offsetp_low,
                        &offsetp_low);

    col_append_fstr (pinfo->cinfo, COL_INFO, " offsetp:%u/%u", offsetp_high,
                     offsetp_low);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_returntokenidp (tvbuff_t *tvb, int offset,
                        packet_info *pinfo, proto_tree *parent_tree,
                        dcerpc_info *di, guint8 *drep)
{
/* unsigned32 returntokenidp_high
   unsigned32 returntokenidp_low
*/

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     returntokenidp_high, returntokenidp_low;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_returntokenidp, &item, "returnTokenIDp:");
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_returntokenidp_high, &returntokenidp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_returntokenidp_low,
                        &returntokenidp_low);

  col_append_fstr (pinfo->cinfo, COL_INFO, " returnTokenIDp:%u/%u", returntokenidp_high,
                     returntokenidp_low);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}


static int
dissect_volsync (tvbuff_t *tvb, int offset,
                 packet_info *pinfo, proto_tree *parent_tree,
                 dcerpc_info *di, guint8 *drep)
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

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     volid_hi, volid_low, vv_hi, vv_low, vvage, vvpingage;
  guint32     vvspare1, vvspare2;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                     ett_fileexp_volsync, &item, "AfsVolSync:");
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_volid_hi,
                        &volid_hi);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_volid_low,
                        &volid_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_vv_hi,
                        &vv_hi);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_vv_low,
                        &vv_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_vvage,
                        &vvage);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_vvpingage,
                        &vvpingage);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_vvspare1,
                        &vvspare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_vvspare2,
                        &vvspare2);

  col_append_fstr (pinfo->cinfo, COL_INFO,
                     " volid_hi:%u volid_low:%u vv_hi:%u vv_low:%u vvage:%u vvpingage:%u vvpspare1:%u vvspare2:%u",
                     volid_hi, volid_low, vv_hi, vv_low, vvage, vvpingage,
                     vvspare1, vvspare2);

  proto_item_set_len (item, offset - old_offset);
  return offset;

}

static int
dissect_afsFlags (tvbuff_t *tvb, int offset,
                  packet_info *pinfo, proto_tree *parent_tree,
                  dcerpc_info *di, guint8 *drep)
{
/*
  unsigned32 flags
*/

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     flags;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_afsflags, &item, "AfsFlags:");
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_flags,
                        &flags);

  if (flags)
    {
      col_append_str (pinfo->cinfo, COL_INFO, " Flags=");
      if ((flags & AFS_FLAG_RETURNTOKEN) == AFS_FLAG_RETURNTOKEN)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":RETURNTOKEN");
        }
      if ((flags & AFS_FLAG_TOKENJUMPQUEUE) == AFS_FLAG_TOKENJUMPQUEUE)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":TOKENJUMPQUEUE");
        }
      if ((flags & AFS_FLAG_SKIPTOKEN) == AFS_FLAG_SKIPTOKEN)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":SKIPTOKEN");
        }
      if ((flags & AFS_FLAG_NOOPTIMISM) == AFS_FLAG_NOOPTIMISM)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":NOOPTIMISM");
        }
      if ((flags & AFS_FLAG_TOKENID) == AFS_FLAG_TOKENID)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":TOKENID");
        }
      if ((flags & AFS_FLAG_RETURNBLOCKER) == AFS_FLAG_RETURNBLOCKER)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":RETURNBLOCKER");
        }
      if ((flags & AFS_FLAG_ASYNCGRANT) == AFS_FLAG_ASYNCGRANT)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":ASYNCGRANT");
        }
      if ((flags & AFS_FLAG_NOREVOKE) == AFS_FLAG_NOREVOKE)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":NOREVOKE");
        }
      if ((flags & AFS_FLAG_MOVE_REESTABLISH) == AFS_FLAG_MOVE_REESTABLISH)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":MOVE_REESTABLISH");
        }
      if ((flags & AFS_FLAG_SERVER_REESTABLISH) ==
          AFS_FLAG_SERVER_REESTABLISH)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":SERVER_REESTABLISH");
        }
      if ((flags & AFS_FLAG_NO_NEW_EPOCH) == AFS_FLAG_NO_NEW_EPOCH)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":NO_NEW_EPOCH");
        }
      if ((flags & AFS_FLAG_MOVE_SOURCE_OK) == AFS_FLAG_MOVE_SOURCE_OK)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":MOVE_SOURCE_OK");
        }
      if ((flags & AFS_FLAG_SYNC) == AFS_FLAG_SYNC)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":SYNC");
        }
      if ((flags & AFS_FLAG_ZERO) == AFS_FLAG_ZERO)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":ZERO");
        }
      if ((flags & AFS_FLAG_SKIPSTATUS) == AFS_FLAG_SKIPSTATUS)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":SKIPSTATUS");
        }
      if ((flags & AFS_FLAG_FORCEREVOCATIONS) == AFS_FLAG_FORCEREVOCATIONS)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":FORCEREVOCATIONS");
        }
      if ((flags & AFS_FLAG_FORCEVOLQUIESCE) == AFS_FLAG_FORCEVOLQUIESCE)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":FORCEVOLQUIESCE");
        }
      if ((flags & AFS_FLAG_SEC_SERVICE) == AFS_FLAG_SEC_SERVICE)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":SEC_SERVICE");
        }
      if ((flags & AFS_FLAG_CONTEXT_NEW_ACL_IF) ==
          AFS_FLAG_CONTEXT_NEW_ACL_IF)
        {
          col_append_str (pinfo->cinfo, COL_INFO, ":CONTEXT_NEW_ACL_IF");
        }
    }

  proto_item_set_len (item, offset - old_offset);
  return offset;
}

static int
dissect_fetchstatus (tvbuff_t *tvb, int offset,
                     packet_info *pinfo, proto_tree *parent_tree,
                     dcerpc_info *di, guint8 *drep)
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
  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     interfaceversion, filetype, linkcount, length_high, length_low;
  guint32     dataversion_high, dataversion_low, author, owner, group, calleraccess;
  guint32     anonymousaccess, aclexpirationtime, mode, parentvnode, parentunique;
  guint32     modtime_sec, modtime_msec, changetime_sec, changetime_msec;
  guint32     accesstime_sec, accesstime_msec, servermodtime_msec, servermodtime_sec;
  guint32     devicenumber, blocksused, clientspare1, devicenumberhighbits;
  guint32     agtypeunique, himaxspare, lomaxspare, pathconfspare, spare4;
  guint32     spare5, spare6;
  e_guid_t    typeuuid, objectuuid;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                     ett_fileexp_fetchstatus, &item, "FetchStatus:");
    }

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_interfaceversion, &interfaceversion);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_filetype,
                        &filetype);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_linkcount,
                        &linkcount);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_length_high, &length_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_length_low,
                        &length_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_dataversion_high, &dataversion_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_dataversion_low, &dataversion_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_author,
                        &author);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_owner,
                        &owner);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_group,
                        &group);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_calleraccess, &calleraccess);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_anonymousaccess, &anonymousaccess);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_aclexpirationtime, &aclexpirationtime);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_mode,
                        &mode);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_parentvnode, &parentvnode);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_parentunique, &parentunique);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_modtime_sec, &modtime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_modtime_msec, &modtime_msec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_changetime_sec, &changetime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_changetime_msec, &changetime_msec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_accesstime_sec, &accesstime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_accesstime_msec, &accesstime_msec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_servermodtime_sec, &servermodtime_sec);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_servermodtime_msec, &servermodtime_msec);
  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, di, drep, hf_fileexp_typeuuid,
                        &typeuuid);
  offset =
    dissect_ndr_uuid_t (tvb, offset, pinfo, tree, di, drep, hf_fileexp_objectuuid,
                        &objectuuid);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_devicenumber, &devicenumber);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_blocksused,
                        &blocksused);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_clientspare1, &clientspare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_devicenumberhighbits,
                        &devicenumberhighbits);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_agtypeunique, &agtypeunique);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_himaxspare,
                        &himaxspare);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_lomaxspare,
                        &lomaxspare);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_pathconfspare, &pathconfspare);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_spare4,
                        &spare4);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_spare5,
                        &spare5);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_spare6,
                        &spare6);

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
dissect_afsReturnDesc (tvbuff_t *tvb, int offset,
                       packet_info *pinfo, proto_tree *parent_tree,
                       dcerpc_info *di, guint8 *drep)
{
/*
        afsFid fid;             * useful hint *
        afsHyper tokenID;
        afsHyper type;          * mask *
        unsigned32 flags;       * just in case *
*/

  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;
  guint32     tokenid_high, tokenid_low, type_high, type_low;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1,
                                     ett_fileexp_afsReturnDesc, &item, "afsReturnDesc:");
    }

  offset = dissect_afsFid ( tvb, offset, pinfo, tree, di, drep);

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_afsreturndesc_tokenid_high, &tokenid_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_afsreturndesc_tokenid_low, &tokenid_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_afsreturndesc_type_high, &type_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_afsreturndesc_type_low, &type_low);
  col_append_fstr (pinfo->cinfo, COL_INFO, " TokenId:%u/%u Type:%u/%u",
                     tokenid_high, tokenid_low, type_high, type_low);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags: ", -1);

  proto_item_set_len (item, offset - old_offset);
  return offset;
}



static int
dissect_afsReturns (tvbuff_t *tvb, int offset,
                    packet_info *pinfo, proto_tree *tree,
                    dcerpc_info *di, guint8 *drep)
{
/*
        long afsReturns_len;
        [length_is(afsReturns_len)] afsReturnDesc afsReturns_val[AFS_BULKMAX];
*/

  /* this is not really a ucvarray, but with the initial len, we can
     cheat and pretend it is */
  if (di->conformant_run)
    {
      return offset;
    }

  offset =
    dissect_ndr_ucvarray (tvb, offset, pinfo, tree, di, drep,
                          dissect_afsReturnDesc);

  return offset;
}

#if 0 /* not used */

static int
dissect_afsbundled_stat (tvbuff_t *tvb, int offset,
                         packet_info *pinfo, proto_tree *parent_tree,
                         dcerpc_info *di, guint8 *drep _U_)
{
  proto_item *item       = NULL;
  proto_tree *tree       = NULL;
  int         old_offset = offset;

  if (di->conformant_run)
    {
      return offset;
    }

  if (parent_tree)
    {
      tree = proto_tree_add_subtree (parent_tree, tvb, offset, -1, ett_fileexp_afsbundled_stat, &item, "afsbundled_stat:");
    }

/*  bundled_stat

        afsFid fid;
        afsFetchStatus stat;
        afsToken token;
        error_status_t error;
*/

/*
        offset = dissect_afsFid(tvb, offset, pinfo, tree, di, drep);
*/
/* SKIPTOKEN/STAT?
        offset = dissect_fetchstatus (tvb, offset, pinfo, tree, di, drep);
        offset = dissect_afstoken (tvb, offset, pinfo, tree, di, drep);
*/
/* This is currently under construction as I figure out the reverse layout of the packet. */
/*
        offset = dissect_afsErrorStatus (tvb, offset, pinfo, tree, di, drep);
*/

  proto_item_set_len (item, offset - old_offset);
  return offset;

}

#endif /* not used */

static int
dissect_afsBulkStat (tvbuff_t *tvb _U_, int offset,
                                  packet_info *pinfo _U_, proto_tree *tree _U_,
                                  dcerpc_info *di _U_, guint8 *drep _U_)
{
/*
        unsigned32 BulkStat_len;
        [length_is (BulkStat_len)] bundled_stat BulkStat_val[AFS_BULKMAX];
*/
        /* this is not really a ucvarray, but with the initial len, we can
           cheat and pretend it is */
           /*
        offset = dissect_ndr_ucvarray (tvb, offset, pinfo, tree, drep,
                dissect_afsbundled_stat);
                */

        return offset;
}




static int
fileexp_dissect_removefile_rqst (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsfidtaggedname, NDR_POINTER_REF,
                         "afsFidTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_returntokenidp,
                         NDR_POINTER_REF, "afsReturnTokenIDp:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "afsMinVVp:", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}

static int
fileexp_dissect_storedata_rqst (tvbuff_t *tvb, int offset,
                                packet_info *pinfo, proto_tree *tree,
                                dcerpc_info *di, guint8 *drep)
{
  guint32 position_high, position_low, length;

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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsstorestatus, NDR_POINTER_REF,
                         "afsStoreStatus:", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_position_high, &position_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_position_low, &position_low);

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_length, &length);

  col_append_fstr (pinfo->cinfo, COL_INFO, " Position:%u/%u Length:%u",
                     position_high, position_low, length);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);

/* XXX need to decode pipe_t still here */

  return offset;
}

static int
fileexp_dissect_gettoken_rqst (tvbuff_t *tvb, int offset,
                               packet_info *pinfo, proto_tree *tree,
                               dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afstoken,
                         NDR_POINTER_REF, "afsToken: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}
static int
fileexp_dissect_gettoken_resp (tvbuff_t *tvb, int offset,
                               packet_info *pinfo, proto_tree *tree,
                               dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afstoken,
                         NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsRecordLock, NDR_POINTER_REF,
                         "afsRecordLock: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "afsFetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsErrorStatus, NDR_POINTER_REF,
                         "afsErrorStatus: ", -1);

  return offset;
}

static int
fileexp_dissect_lookuproot_rqst (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}

static int
fileexp_dissect_fetchdata_rqst (tvbuff_t *tvb, int offset,
                                packet_info *pinfo, proto_tree *tree,
                                dcerpc_info *di, guint8 *drep)
{
  guint32 position_high, position_low, length;

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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_position_high, &position_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_position_low, &position_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_length, &length);
  col_append_fstr (pinfo->cinfo, COL_INFO, " Position:%u/%u Length:%u",
                     position_high, position_low, length);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}

static int
fileexp_dissect_fetchacl_rqst (tvbuff_t *tvb, int offset,
                               packet_info *pinfo, proto_tree *tree,
                               dcerpc_info *di, guint8 *drep)
{
  guint32 acltype;

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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_acltype,
                        &acltype);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);

  if (acltype)
    {
      col_append_str (pinfo->cinfo, COL_INFO,
                        " :copy the ACL from specified fid:");
    }

  return offset;
}
static int
fileexp_dissect_fetchstatus_rqst (tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *tree,
                                  dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}
static int
fileexp_dissect_storeacl_rqst (tvbuff_t *tvb, int offset,
                               packet_info *pinfo, proto_tree *tree,
                               dcerpc_info *di, guint8 *drep)
{
  guint32 acltype;

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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsAcl,
                         NDR_POINTER_REF, "afsAcl: ", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_acltype,
                        &acltype);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);

  col_append_fstr (pinfo->cinfo, COL_INFO, " aclType:%u",acltype);

  return offset;
}

static int
fileexp_dissect_storestatus_rqst (tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *tree,
                                  dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsstorestatus, NDR_POINTER_REF,
                         "afsStoreStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}

static int
fileexp_dissect_createfile_rqst (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afstaggedname, NDR_POINTER_REF,
                         "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsstorestatus, NDR_POINTER_REF,
                         "afsStoreStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);

  return offset;
}

static int
fileexp_dissect_rename_rqst (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsfidtaggedname, NDR_POINTER_REF,
                         "afsFidTaggedName: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afstaggedname, NDR_POINTER_REF,
                         "afsFidTaggedName: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_returntokenidp, NDR_POINTER_REF,
                         "afsReturnTokenIDp: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_minvvp, NDR_POINTER_REF,
                         "afsminVVp: ", -1);

  offset = dissect_afsFlags (tvb, offset, pinfo, tree, di, drep);

  return offset;
}

static int
fileexp_dissect_symlink_rqst (tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *tree,
                              dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afstaggedname, NDR_POINTER_REF,
                         "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsTaggedPath, NDR_POINTER_REF,
                         "afsTaggedPath: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsstorestatus, NDR_POINTER_REF,
                         "afsStoreStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
    offset = dissect_afsFlags (tvb, offset, pinfo, tree, di, drep);

  return offset;
}

static int
fileexp_dissect_readdir_rqst (tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *tree,
                              dcerpc_info *di, guint8 *drep)
{
  guint32 size;

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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_offsetp,
                         NDR_POINTER_REF, "Offsetp: ", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_readdir_size, &size);

  col_append_fstr (pinfo->cinfo, COL_INFO, " Size:%u", size);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
   offset = dissect_afsFlags ( tvb, offset, pinfo, tree, di, drep);

  return offset;
}

static int
fileexp_dissect_makedir_rqst (tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *tree,
                              dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afstaggedname, NDR_POINTER_REF,
                         "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsstorestatus, NDR_POINTER_REF,
                         "afsStoreStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
  offset = dissect_afsFlags ( tvb, offset, pinfo, tree, di, drep);

  return offset;
}

static int
fileexp_dissect_removedir_rqst (tvbuff_t *tvb, int offset,
                                packet_info *pinfo, proto_tree *tree,
                                dcerpc_info *di, guint8 *drep)
{
  guint32 returntokenidp_high, returntokenidp_low;

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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsfidtaggedname, NDR_POINTER_REF,
                         "afsFidTaggedName: ", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_returntokenidp_high, &returntokenidp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_returntokenidp_low, &returntokenidp_low);

  col_append_fstr (pinfo->cinfo, COL_INFO, " returnTokenIDp:%u/%u",
                     returntokenidp_high, returntokenidp_low);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
  offset = dissect_afsFlags ( tvb, offset, pinfo, tree, di, drep );

  return offset;
}

static int
fileexp_dissect_lookup_rqst (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afstaggedname, NDR_POINTER_REF,
                         "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
   offset = dissect_afsFlags ( tvb, offset, pinfo, tree, di, drep);

  return offset;
}
static int
fileexp_dissect_lookup_resp (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afstoken,
                         NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("Lookup reply");

  return offset;

}

static int
fileexp_dissect_makemountpoint_rqst (tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree,
                                     dcerpc_info *di, guint8 *drep)
{
  guint16 type;

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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afstaggedname, NDR_POINTER_REF,
                         "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afstaggedname, NDR_POINTER_REF,
                         "afsTaggedName: ", -1);
  offset =
    dissect_ndr_uint16 (tvb, offset, pinfo, tree, di, drep, hf_fileexp_fstype,
                        &type);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afstaggedname, NDR_POINTER_REF,
                         "afsTaggedName: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsstorestatus, NDR_POINTER_REF,
                         "afsStoreStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);

  offset = dissect_afsFlags (tvb, offset, pinfo, tree, di, drep);

  col_append_fstr (pinfo->cinfo, COL_INFO, " Type:%u", type);

  return offset;

}

static int
fileexp_dissect_setcontext_rqst (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 dcerpc_info *di, guint8 *drep)
{
  guint32 epochtime, clientsizesattrs, parm7;

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
                           hf_fileexp_setcontext_rqst_epochtime, &epochtime);

  offset =  dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsNetData,
                         NDR_POINTER_REF, "afsNetData:", -1);

  offset = dissect_afsFlags (tvb, offset, pinfo, tree, di, drep);

  col_append_str (pinfo->cinfo, COL_INFO, " setObjectID");

  offset =  dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsuuid,
                         NDR_POINTER_REF, "afsUUID:", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_setcontext_rqst_clientsizesattrs,
                        &clientsizesattrs);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_setcontext_rqst_parm7, &parm7);

  col_append_fstr (pinfo->cinfo, COL_INFO, " epochTime:%u clientSizesAttrs:%u parm7:%u", epochtime, clientsizesattrs, parm7);

  return offset;
}

static int
fileexp_dissect_setcontext_resp (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 dcerpc_info *di, guint8 *drep)
{
/* nothing but error code */

  if (di->conformant_run)
    {
      return offset;
    }

  MACRO_ST_CLEAR ("SetContext reply");
  return offset;
}

static int
  fileexp_dissect_lookuproot_resp (tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree,
                                   dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afstoken,
                         NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("LookupRoot reply");
  return offset;
}

static int
  fileexp_dissect_fetchdata_resp (tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *tree,
                                  dcerpc_info *di, guint8 *drep)
{
  guint32 pipe_t_size;

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
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_fetchdata_pipe_t_size, &pipe_t_size);

  return offset;
}

static int
  fileexp_dissect_fetchacl_resp (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsAcl,
                         NDR_POINTER_REF, "afsAcl: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("FetchAcl reply");
  return offset;
}

static int
  fileexp_dissect_fetchstatus_resp (tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *tree,
                                    dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afstoken,
                         NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("FetchStatus reply");
  return offset;
}

static int
  fileexp_dissect_storedata_resp (tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *tree,
                                  dcerpc_info *di, guint8 *drep)
{
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutStatusp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("StoreData reply");
  return offset;
}

static int
  fileexp_dissect_storeacl_resp (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 dcerpc_info *di, guint8 *drep)
{
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutStatusp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("StoreAcl reply");
  return offset;
}

static int
  fileexp_dissect_storestatus_resp (tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *tree,
                                    dcerpc_info *di, guint8 *drep)
{
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   afsFetchStatus  *OutStatusp,
        [out]   afsVolSync      *Syncp
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("StoreStatus reply");
  return offset;
}

static int
  fileexp_dissect_removefile_resp (tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree,
                                   dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("RemoveFile reply");
  return offset;
}

static int
  fileexp_dissect_createfile_resp (tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree,
                                   dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afstoken,
                         NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("CreateFile reply");

  return offset;
}
static int
  fileexp_dissect_rename_resp (tvbuff_t *tvb, int offset,
                               packet_info *pinfo, proto_tree *tree,
                               dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("Rename reply");
  return offset;
}

static int
  fileexp_dissect_symlink_resp (tvbuff_t *tvb, int offset,
                                packet_info *pinfo, proto_tree *tree,
                                dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afstoken,
                         NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("Symlink reply");

  return offset;
}

static int
  fileexp_dissect_hardlink_resp (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("Hardlink reply");

  return offset;
}
static int
  fileexp_dissect_hardlink_rqst (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afstaggedname, NDR_POINTER_REF,
                         "afsTaggedName: ", -1);
  /* afsFid */
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);

  offset = dissect_afsFlags ( tvb, offset, pinfo, tree, di, drep);

  return offset;
}

static int
  fileexp_dissect_makedir_resp (tvbuff_t *tvb, int offset,
                                packet_info *pinfo, proto_tree *tree,
                                dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afstoken,
                         NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);

  MACRO_ST_CLEAR ("MakeDir reply");

  return offset;
}

static int
  fileexp_dissect_removedir_resp (tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *tree,
                                  dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("RemoveDir reply");

  return offset;

}

static int
  fileexp_dissect_readdir_resp (tvbuff_t *tvb, int offset,
                                packet_info *pinfo, proto_tree *tree,
                                dcerpc_info *di, guint8 *drep)
{
  guint32 nextoffsetp_high, nextoffsetp_low;

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
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_nextoffsetp_high, &nextoffsetp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_nextoffsetp_low, &nextoffsetp_low);

  col_append_fstr (pinfo->cinfo, COL_INFO, " NextOffsetp:%u/%u",
                     nextoffsetp_high, nextoffsetp_low);

  /* all packets seem to have SKIPTOKEN/SKIPSTATUS sent, and thus these structures are missing on calls holding tokens. */

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  /* XXX need to add pipe_t here, once figured out. */

  return offset;
}

static int
  fileexp_dissect_releasetokens_resp (tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree,
                                      dcerpc_info *di, guint8 *drep)
{
  if (di->conformant_run)
    {
      return offset;
    }

  /* no out */
  MACRO_ST_CLEAR ("ReleaseTokens reply");
  return offset;
}

static int
  fileexp_dissect_releasetokens_rqst (tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree,
                                      dcerpc_info *di, guint8 *drep)
{
  if (di->conformant_run)
    {
      return offset;
    }


/*
        [in]    afsReturns      *Tokens_Arrayp,
        [in]    unsigned32      Flags
*/
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsReturns,
                         NDR_POINTER_REF, "afsReturns: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags: ", -1);
  return offset;
}

static int
  fileexp_dissect_gettime_resp (tvbuff_t *tvb, int offset,
                                packet_info *pinfo, proto_tree *tree,
                                dcerpc_info *di, guint8 *drep)
{
  guint32 secondsp, usecondsp, syncdistance, syncdispersion;

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
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_gettime_secondsp, &secondsp);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_gettime_usecondsp, &usecondsp);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_gettime_syncdistance, &syncdistance);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_gettime_syncdispersion, &syncdispersion);

  col_append_fstr (pinfo->cinfo, COL_INFO, " Secondsp:%u  Usecondsp:%u SyncDistance:/%u SyncDispersion:%u", secondsp, usecondsp, syncdistance, syncdispersion);

  MACRO_ST_CLEAR ("GetTime reply");

  return offset;

}

static int
  fileexp_dissect_gettime_rqst (tvbuff_t *tvb _U_, int offset,
                                packet_info *pinfo _U_, proto_tree *tree _U_,
                                dcerpc_info *di, guint8 *drep _U_)
{
  if (di->conformant_run)
    {
      return offset;
    }

  /* nothing */

  return offset;
}

static int
  fileexp_dissect_processquota_resp (tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree,
                                     dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("ProcessQuota reply");

  return offset;
}

static int
  fileexp_dissect_processquota_rqst (tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree,
                                     dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
  offset = dissect_afsFlags ( tvb, offset, pinfo, tree, di, drep);

  /* XXX need to figure out afsQuota here */
  return offset;
}

static int
  fileexp_dissect_getserverinterfaces_rqst (tvbuff_t *tvb _U_, int offset,
                                            packet_info *pinfo _U_, proto_tree *tree _U_,
                                            dcerpc_info *di, guint8 *drep _U_)
{
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
  fileexp_dissect_getserverinterfaces_resp (tvbuff_t *tvb, int offset,
                                            packet_info *pinfo, proto_tree *tree,
                                            dcerpc_info *di, guint8 *drep)
{
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
  fileexp_dissect_setparams_rqst (tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *tree,
                                  dcerpc_info *di, guint8 *drep)
{
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in]            unsigned32      Flags,
        [in, out]       afsConnParams   *paramsP
*/
  offset = dissect_afsFlags ( tvb, offset, pinfo, tree, di, drep);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsConnParams, NDR_POINTER_REF,
                         "afsConnParams:", -1);
  return offset;
}

static int
  fileexp_dissect_setparams_resp (tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *tree,
                                  dcerpc_info *di, guint8 *drep)
{
  if (di->conformant_run)
    {
      return offset;
    }

/*
        [in, out]       afsConnParams   *paramsP
*/

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep,
                         dissect_afsConnParams, NDR_POINTER_REF,
                         "afsConnParams:", -1);
  MACRO_ST_CLEAR ("SetParams reply");
  return offset;
}

static int
  fileexp_dissect_makemountpoint_resp (tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree,
                                       dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);

  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
  MACRO_ST_CLEAR ("MakeMountPoint reply");
  return offset;
}

static int
  fileexp_dissect_getstatistics_rqst (tvbuff_t *tvb _U_, int offset,
                                      packet_info *pinfo _U_, proto_tree *tree _U_,
                                      dcerpc_info *di, guint8 *drep _U_)
{
  if (di->conformant_run)
    {
      return offset;
    }

  /* nothing for request */
  return offset;
}

static int
  fileexp_dissect_getstatistics_resp (tvbuff_t *tvb _U_, int offset,
                                      packet_info *pinfo _U_, proto_tree *tree _U_,
                                      dcerpc_info *di, guint8 *drep _U_)
{
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
  fileexp_dissect_bulkfetchvv_rqst (tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *tree,
                                    dcerpc_info *di, guint8 *drep)
{
  guint32 cellidp_high, cellidp_low, numvols, spare1, spare2;

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
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_cellidp_high, &cellidp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_cellidp_low, &cellidp_low);

  col_append_fstr (pinfo->cinfo, COL_INFO, " CellIDp:%u/%u", cellidp_high,
                     cellidp_low);

  /* XXX figure out the afsBulkVolIDS */
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_bulkfetchvv_numvols, &numvols);

  offset = dissect_afsFlags (tvb, offset, pinfo, tree, di, drep);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_bulkfetchvv_spare1, &spare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_bulkfetchvv_spare2, &spare2);
  return offset;
}

static int
  fileexp_dissect_bulkfetchvv_resp (tvbuff_t *tvb _U_, int offset,
                                    packet_info *pinfo _U_, proto_tree *tree _U_,
                                    dcerpc_info *di, guint8 *drep _U_)
{
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
  fileexp_dissect_bulkkeepalive_resp (tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree,
                                      dcerpc_info *di, guint8 *drep)
{
  guint32 spare4;

  if (di->conformant_run)
    {
      return offset;
    }

/*
        [out]   unsigned32      *spare4
*/

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_bulkkeepalive_spare4, &spare4);
  MACRO_ST_CLEAR ("BulkKeepAlive reply");
  return offset;
}

static int
  fileexp_dissect_bulkkeepalive_rqst (tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree,
                                      dcerpc_info *di, guint8 *drep)
{
  guint32 numexecfids, spare1, spare2;

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
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_bulkkeepalive_numexecfids, &numexecfids);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFlags,
                         NDR_POINTER_REF, "afsFlags:", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_bulkkeepalive_spare1, &spare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_bulkkeepalive_spare2, &spare2);
  return offset;
}

static int
  fileexp_dissect_bulkfetchstatus_rqst (tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree,
                                        dcerpc_info *di, guint8 *drep)
{
  guint32 offsetp_high, offsetp_low, size;

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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsFid,
                         NDR_POINTER_REF, "afsFid: ", -1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_offsetp_high, &offsetp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_offsetp_low, &offsetp_low);

  col_append_fstr (pinfo->cinfo, COL_INFO, " Offsetp:%u/%u", offsetp_high,
                     offsetp_low);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_bulkfetchstatus_size, &size);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_minvvp,
                         NDR_POINTER_REF, "MinVVp:", -1);
  offset = dissect_afsFlags (tvb, offset, pinfo, tree, di, drep);

  return offset;
}

static int
  fileexp_dissect_bulkfetchstatus_resp (tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree,
                                        dcerpc_info *di, guint8 *drep)
{
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
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afsBulkStat,
                         NDR_POINTER_REF, "BulkStat: ", -1);
/* Under construction. The packet seems to have the pipe_t before the rest of the data listed in idl. */

#if 0
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_nextoffsetp_high, &nextoffsetp_high);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
                        hf_fileexp_nextoffsetp_low, &nextoffsetp_low);

  col_append_fstr (pinfo->cinfo, COL_INFO, " NextOffsetp:%u/%u",
                     nextoffsetp_high, nextoffsetp_low);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_fetchstatus,
                         NDR_POINTER_REF, "FetchStatus: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_afstoken,
                         NDR_POINTER_REF, "afsToken: ", -1);
  offset =
    dissect_ndr_pointer (tvb, offset, pinfo, tree, di, drep, dissect_volsync,
                         NDR_POINTER_REF, "VolSync: ", -1);
#endif
  /* XXX figure out pipe_t */

  return offset;
}

static dcerpc_sub_dissector fileexp_dissectors[] = {
  { 0,  "SetContext",          fileexp_dissect_setcontext_rqst,          fileexp_dissect_setcontext_resp} ,
  { 1,  "LookupRoot",          fileexp_dissect_lookuproot_rqst,          fileexp_dissect_lookuproot_resp} ,
  { 2,  "FetchData",           fileexp_dissect_fetchdata_rqst,           fileexp_dissect_fetchdata_resp} ,
  { 3,  "FetchAcl",            fileexp_dissect_fetchacl_rqst,            fileexp_dissect_fetchacl_resp} ,
  { 4,  "FetchStatus",         fileexp_dissect_fetchstatus_rqst,         fileexp_dissect_fetchstatus_resp} ,
  { 5,  "StoreData",           fileexp_dissect_storedata_rqst,           fileexp_dissect_storedata_resp} ,
  { 6,  "StoreAcl",            fileexp_dissect_storeacl_rqst,            fileexp_dissect_storeacl_resp} ,
  { 7,  "StoreStatus",         fileexp_dissect_storestatus_rqst,         fileexp_dissect_storestatus_resp} ,
  { 8,  "RemoveFile",          fileexp_dissect_removefile_rqst,          fileexp_dissect_removefile_resp} ,
  { 9,  "CreateFile",          fileexp_dissect_createfile_rqst,          fileexp_dissect_createfile_resp} ,
  { 10, "Rename",              fileexp_dissect_rename_rqst,              fileexp_dissect_rename_resp} ,
  { 11, "Symlink",             fileexp_dissect_symlink_rqst,             fileexp_dissect_symlink_resp} ,
  { 12, "HardLink",            fileexp_dissect_hardlink_rqst,            fileexp_dissect_hardlink_resp} ,
  { 13, "MakeDir",             fileexp_dissect_makedir_rqst,             fileexp_dissect_makedir_resp} ,
  { 14, "RemoveDir",           fileexp_dissect_removedir_rqst,           fileexp_dissect_removedir_resp} ,
  { 15, "Readdir",             fileexp_dissect_readdir_rqst,             fileexp_dissect_readdir_resp} ,
  { 16, "Lookup",              fileexp_dissect_lookup_rqst,              fileexp_dissect_lookup_resp} ,
  { 17, "GetToken",            fileexp_dissect_gettoken_rqst,            fileexp_dissect_gettoken_resp} ,
  { 18, "ReleaseTokens",       fileexp_dissect_releasetokens_rqst,       fileexp_dissect_releasetokens_resp} ,
  { 19, "GetTime",             fileexp_dissect_gettime_rqst,             fileexp_dissect_gettime_resp} ,
  { 20, "MakeMountPoint",      fileexp_dissect_makemountpoint_rqst,      fileexp_dissect_makemountpoint_resp} ,
  { 21, "GetStatistics",       fileexp_dissect_getstatistics_rqst,       fileexp_dissect_getstatistics_resp} ,
  { 22, "BulkFetchVV",         fileexp_dissect_bulkfetchvv_rqst,         fileexp_dissect_bulkfetchvv_resp} ,
  { 23, "BulkKeepAlive",       fileexp_dissect_bulkkeepalive_rqst,       fileexp_dissect_bulkkeepalive_resp} ,
  { 24, "ProcessQuota",        fileexp_dissect_processquota_rqst,        fileexp_dissect_processquota_resp} ,
  { 25, "GetServerInterfaces", fileexp_dissect_getserverinterfaces_rqst, fileexp_dissect_getserverinterfaces_resp} ,
  { 26, "SetParams",           fileexp_dissect_setparams_rqst,           fileexp_dissect_setparams_resp} ,
  { 27, "BulkFetchStatus",     fileexp_dissect_bulkfetchstatus_rqst,     fileexp_dissect_bulkfetchstatus_resp} ,
  { 0, NULL, NULL, NULL}
  ,
};

void
proto_register_fileexp (void)
{

  static hf_register_info hf[] = {
    { &hf_error_st,
      { "AFS4Int Error Status Code", "fileexp.st",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_flags,
      { "DFS Flags", "fileexp.flags",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_tn_string,
      { "String", "fileexp.string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_opnum,
      { "Operation", "fileexp.opnum",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_setcontext_rqst_epochtime,
      { "EpochTime:", "fileexp.setcontext_rqst_epochtime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_setcontext_rqst_clientsizesattrs,
      { "ClientSizeAttrs:", "fileexp.setcontext_clientsizesattrs",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_setcontext_rqst_parm7,
      { "Parm7:", "fileexp.setcontext.parm7",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_acl_len,
      { "Acl Length", "fileexp.acl_len",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_acltype,
      { "Acl type", "fileexp.acltype",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_minvvp_high,
      { "minVVp high", "fileexp.minvvp_high",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_minvvp_low,
      { "minVVp low", "fileexp.minvvp_low",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_accesstime_msec,
      { "Access time (msec)", "fileexp.accesstime_msec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_accesstime_sec,
      { "Access time (sec)", "fileexp.accesstime_sec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_aclexpirationtime,
      { "Acl expiration time", "fileexp.aclexpirationtime",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_agtypeunique,
      { "agtypeunique", "fileexp.agtypeunique",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_anonymousaccess,
      { "Anonymous Access", "fileexp.anonymousaccess",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_author,
      { "Author", "fileexp.author",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_blocksused,
      { "Blocks used", "fileexp.blocksused",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_calleraccess,
      { "Caller access", "fileexp.calleraccess",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_changetime_msec,
      { "Change time (msec)", "fileexp.changetime_msec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_changetime_sec,
      { "Change time (sec)", "fileexp.changetime_sec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_clientspare1,
      { "Client spare1", "fileexp.clientspare1",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_dataversion_high,
      { "Data version (high)", "fileexp.dataversion_high",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_dataversion_low,
      { "Data version (low)", "fileexp.dataversion_low",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_devicenumber,
      { "Device number", "fileexp.devicenumber",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_devicenumberhighbits,
      { "Device number high bits", "fileexp.devicenumberhighbits",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_filetype,
      { "File type", "fileexp.filetype",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_group,
      { "Group", "fileexp.group",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_himaxspare,
      { "Hi max spare", "fileexp.himaxspare",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_interfaceversion,
      { "Interface version", "fileexp.interfaceversion",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_length_high,
      { "Length high", "fileexp.length_high",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_length_low,
      { "Length low", "fileexp.length_low",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_linkcount,
      { "Link count", "fileexp.linkcount",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_lomaxspare,
      { "Lo max spare", "fileexp.lomaxspare",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_mode,
      { "Mode", "fileexp.mode",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_modtime_msec,
      { "Modify time (msec)", "fileexp.modtime_msec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_modtime_sec,
      { "Modify time (sec)", "fileexp.modtime_sec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_objectuuid,
      { "Object uuid", "fileexp.objectuuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        "UUID", HFILL}
    },
    { &hf_fileexp_owner,
      { "Owner", "fileexp.owner",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_parentunique,
      { "Parent unique", "fileexp.parentunique",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_parentvnode,
      { "Parent vnode", "fileexp.parentvnode",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_pathconfspare,
      { "Path conf spare", "fileexp.pathconfspare",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_servermodtime_msec,
      { "Server modify time (msec)", "fileexp.servermodtime_msec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_servermodtime_sec,
      { "Server modify time (sec)", "fileexp.servermodtime_sec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_spare4,
      { "Spare4", "fileexp.spare4",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_spare5,
      { "Spare5", "fileexp.spare5",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_spare6,
      { "Spare6", "fileexp.spare6",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_typeuuid,
      { "Type uuid", "fileexp.typeuuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        "UUID", HFILL}
    },
    { &hf_fileexp_volid_hi,
      { "Vol id hi", "fileexp.volid_hi",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_volid_low,
      { "Vol id low", "fileexp.volid_low",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_vvage,
      { "Vvage", "fileexp.vvage",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_vv_hi,
      { "Vv hi", "fileexp.vv_hi",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_vv_low,
      { "Vv low", "fileexp.vv_low",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_vvpingage,
      { "Vv pingage", "fileexp.vvpingage",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_vvspare1,
      { "Vv spare1", "fileexp.vvspare1",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_vvspare2,
      { "Vv spare2", "fileexp.vvspare2",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_beginrange,
      { "Begin range", "fileexp.beginrange",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_beginrangeext,
      { "Begin range ext", "fileexp.beginrangeext",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_endrange,
      { "End range", "fileexp.endrange",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_endrangeext,
      { "End range ext", "fileexp.endrangeext",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_expirationtime,
      { "Expiration time", "fileexp.expirationtime",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_tokenid_hi,
      { "Tokenid hi", "fileexp.tokenid_hi",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_tokenid_low,
      { "Tokenid low", "fileexp.tokenid_low",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_type_hi,
      { "Type hi", "fileexp.type_hi",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_type_low,
      { "Type low", "fileexp.type_low",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_tn_length,
      { "Tn length", "fileexp.tn_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_tn_tag,
      { "Tn tag", "fileexp.tn_tag",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_accesstime_sec,
      { "Store status access time (sec)", "fileexp.storestatus_accesstime_sec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_accesstime_usec,
      { "Store status access time (usec)", "fileexp.storestatus_accesstime_usec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_changetime_sec,
      { "Store status change time (sec)", "fileexp.storestatus_changetime_sec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_changetime_usec,
      { "Store status change time (usec)", "fileexp.storestatus_changetime_usec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_clientspare1,
      { "Store Status client spare1", "fileexp.storestatus_clientspare1",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_cmask,
      { "Store status cmask", "fileexp.storestatus_cmask",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_devicenumber,
      { "Store status device number", "fileexp.storestatus_devicenumber",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_devicenumberhighbits,
      { "Store status device number high bits", "fileexp.storestatus_devicenumberhighbits",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_devicetype,
      { "Store status device type", "fileexp.storestatus_devicetype",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_group,
      { "Store status group", "fileexp.storestatus_group",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_length_high,
      { "Store status length high", "fileexp.storestatus_length_high",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_length_low,
      { "Store status length low", "fileexp.storestatus_length_low",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_mask,
      { "Store status mask", "fileexp.storestatus_mask",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_mode,
      { "Store status mode", "fileexp.storestatus_mode",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_modtime_sec,
      { "Store status modify time (sec)", "fileexp.storestatus_modtime_sec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_modtime_usec,
      { "Store status modify time (usec)", "fileexp.storestatus_modtime_usec",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_owner,
      { "Store status owner", "fileexp.storestatus_owner",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_spare1,
      { "Store status spare1", "fileexp.storestatus_spare1",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_spare2,
      { "Store status spare2", "fileexp.storestatus_spare2",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_spare3,
      { "Store status spare3", "fileexp.storestatus_spare3",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_spare4,
      { "Store status spare4", "fileexp.storestatus_spare4",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_spare5,
      { "Store status spare5", "fileexp.storestatus_spare5",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_spare6,
      { "Store status spare6", "fileexp.storestatus_spare6",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_trunc_high,
      { "Store status trunc high", "fileexp.storestatus_trunc_high",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_trunc_low,
      { "Store status trunc low", "fileexp.storestatus_trunc_low",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_storestatus_typeuuid,
      { "Store status type uuid", "fileexp.storestatus_typeuuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        "UUID", HFILL}
    },
    { &hf_fileexp_l_end_pos,
      { "l_end_pos", "fileexp.l_end_pos",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_l_end_pos_ext,
      { "l_end_pos_ext", "fileexp.l_end_pos_ext",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_l_fstype,
      { "l_fstype", "fileexp.l_fstype",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_l_pid,
      { "l_pid", "fileexp.l_pid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_l_start_pos,
      { "l_start_pos", "fileexp.l_start_pos",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_l_start_pos_ext,
      { "l_start_pos_ext", "fileexp.l_start_pos_ext",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_l_sysid,
      { "l_sysid", "fileexp.l_sysid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_l_type,
      { "l_type", "fileexp.l_type",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_l_whence,
      { "l_whence", "fileexp.l_whence",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_afsconnparams_mask,
      { "afs conn params mask", "fileexp.afs_connparams_mask",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_afsconnparams_values,
      { "afs conn params values", "fileexp.afs_connparams_values",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsFid_cell_high,
      { "Cell High", "fileexp.afsFid.cell_high",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "afsFid Cell High", HFILL}
    },
    { &hf_fileexp_afsFid_cell_low,
      { "Cell Low", "fileexp.afsFid.cell_low",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "afsFid Cell Low", HFILL}
    },
    { &hf_fileexp_afsFid_volume_high,
      { "Volume High", "fileexp.afsFid.volume_high",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "afsFid Volume High", HFILL}
    },
    { &hf_fileexp_afsFid_volume_low,
      { "Volume Low", "fileexp.afsFid.volume_low",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "afsFid Volume Low", HFILL}
    },
    { &hf_fileexp_afsFid_Vnode,
      { "Vnode", "fileexp.afsFid.Vnode",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "afsFid Vnode", HFILL}
    },
    { &hf_fileexp_afsFid_Unique,
      { "Unique", "fileexp.afsFid.Unique",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "afsFid Unique", HFILL}
    },
    { &hf_fileexp_afsNetAddr_type,
      { "Type", "fileexp.afsNetAddr.type",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsNetAddr_data,
      { "IP Data", "fileexp.afsNetAddr.data",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_position_high,
      { "Position High", "fileexp.position_high",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_position_low,
      { "Position Low", "fileexp.position_low",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsreturndesc_tokenid_high,
      { "Token id High", "fileexp.afsreturndesc_tokenid_high",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsreturndesc_tokenid_low,
      { "Token id low", "fileexp.afsreturndesc_tokenid_low",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsreturndesc_type_high,
      { "Type high", "fileexp.type_high",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsreturndesc_type_low,
      { "Type low", "fileexp.type_low",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_offsetp_high,
      { "offset high", "fileexp.offset_high",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_offsetp_low,
      { "offset high", "fileexp.offset_high",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_nextoffsetp_high,
      { "next offset high", "fileexp.nextoffset_high",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_nextoffsetp_low,
      { "next offset low", "fileexp.nextoffset_low",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_returntokenidp_high,
      { "return token idp high", "fileexp.returntokenidp_high",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_returntokenidp_low,
      { "return token idp low", "fileexp.returntokenidp_low",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_cellidp_high,
      { "cellidp high", "fileexp.cellidp_high",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_cellidp_low,
      { "cellidp low", "fileexp.cellidp_low",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_afserrorstatus_st,
      { "AFS Error Code", "fileexp.afserrortstatus_st",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_length,
      { "Length", "fileexp.length",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsTaggedPath_tp_chars,
      { "AFS Tagged Path", "fileexp.TaggedPath_tp_chars",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsTaggedPath_tp_tag,
      { "AFS Tagged Path Name", "fileexp.TaggedPath_tp_tag",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsacl_uuid1,
      { "AFS ACL UUID1", "fileexp.afsacl_uuid1",
        FT_GUID, BASE_NONE, NULL, 0x0,
        "UUID", HFILL}
    },
    { &hf_fileexp_bulkfetchstatus_size,
      { "BulkFetchStatus Size", "fileexp.bulkfetchstatus_size",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_bulkfetchvv_numvols,
      { "BulkFetchVv num vols", "fileexp.bulkfetchvv_numvols",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_bulkfetchvv_spare1,
      { "BulkFetchVv spare1", "fileexp.bulkfetchvv_spare1",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_bulkfetchvv_spare2,
      { "BulkFetchVv spare2", "fileexp.bulkfetchvv_spare2",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_bulkkeepalive_numexecfids,
      { "BulkKeepAlive numexecfids", "fileexp.bulkkeepalive_numexecfids",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_bulkkeepalive_spare4,
      { "BulkKeepAlive spare4", "fileexp.bulkfetchkeepalive_spare2",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_bulkkeepalive_spare2,
      { "BulkKeepAlive spare2", "fileexp.bulkfetchkeepalive_spare2",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_bulkkeepalive_spare1,
      { "BulkFetch KeepAlive spare1", "fileexp.bulkfetchkeepalive_spare1",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsacl_defaultcell_uuid,
      { "Default Cell UUID", "fileexp.defaultcell_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        "UUID", HFILL}
    },
    { &hf_fileexp_afsuuid_uuid,
      { "AFS UUID", "fileexp.uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        "UUID", HFILL}
    },
    { &hf_fileexp_gettime_syncdispersion,
      { "GetTime Syncdispersion", "fileexp.gettime_syncdispersion",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_gettime_syncdistance,
      { "SyncDistance", "fileexp.gettime.syncdistance",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_gettime_usecondsp,
      { "GetTime usecondsp", "fileexp.gettime_usecondsp",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_readdir_size,
      { "Readdir Size", "fileexp.readdir.size",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsNameString_t_principalName_size,
      { "Principal Name Size", "fileexp.principalName_size",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsTaggedPath_tp_length,
      { "Tagged Path Length", "fileexp.afsTaggedPath_length",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_fstype,
      { "Filetype", "fileexp.fstype",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_gettime_secondsp,
      { "GetTime secondsp", "fileexp.gettime_secondsp",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_afsNameString_t_principalName_string,
      { "Principal Name", "fileexp.NameString_principal",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_fileexp_fetchdata_pipe_t_size,
      { "FetchData Pipe_t size", "fileexp.fetchdata_pipe_t_size",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
  };

  static gint *ett[] = {
    &ett_fileexp,
    &ett_fileexp_afsReturnDesc,
    &ett_fileexp_afsFid,
    &ett_fileexp_afsNetAddr,
    &ett_fileexp_fetchstatus,
    &ett_fileexp_afsflags,
    &ett_fileexp_volsync,
    &ett_fileexp_minvvp,
    &ett_fileexp_afsfidtaggedname,
    &ett_fileexp_afstaggedname,
    &ett_fileexp_afstoken,
    &ett_fileexp_afsstorestatus,
    &ett_fileexp_afsRecordLock,
    &ett_fileexp_afsAcl,
    &ett_fileexp_afsNameString_t,
    &ett_fileexp_afsConnParams,
    &ett_fileexp_afsErrorStatus,
    &ett_fileexp_afsTaggedPath,
    &ett_fileexp_afsNetData,
    &ett_fileexp_afsBulkStat,
    &ett_fileexp_afsuuid,
    &ett_fileexp_offsetp,
    &ett_fileexp_returntokenidp,
    &ett_fileexp_afsbundled_stat,
  };

  proto_fileexp = proto_register_protocol ("DCE DFS File Exporter", "FILEEXP", "fileexp");
  proto_register_field_array (proto_fileexp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_fileexp (void)
{
  /*
   * Register the protocol as dcerpc
   */
  dcerpc_init_uuid (proto_fileexp, ett_fileexp, &uuid_fileexp, ver_fileexp,
                    fileexp_dissectors, hf_fileexp_opnum);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
