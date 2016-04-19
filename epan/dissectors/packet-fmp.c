/* packet-fmp.c
 * Routines for fmp dissection
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
#include <epan/prefs.h>
#include "packet-fmp.h"
#include "packet-rpc.h"

void proto_register_fmp(void);
void proto_reg_handoff_fmp(void);

static int hf_fmp_procedure = -1;
static int hf_fmp_fsID = -1;
static int hf_fmp_fsBlkSz = -1;
static int hf_fmp_sessionHandle = -1;
static int hf_fmp_fmpFHandle = -1;
static int hf_fmp_msgNum = -1;
static int hf_fmp_fileSize = -1;
static int hf_fmp_cookie = -1;
static int hf_fmp_firstLogBlk = -1;
static int hf_fmp_numBlksReq = -1;

static int proto_fmp = -1;
static int hf_fmp_hostID = -1;
static int hf_fmp_status = -1;
static int hf_fmp_btime = -1;
static int hf_fmp_time_sec = -1;
static int hf_fmp_time_nsec = -1;
static int hf_fmp_notifyPort = -1;
static int hf_fmp_minBlks = -1;
static int hf_fmp_eof = -1;
static int hf_fmp_path = -1;
static int hf_fmp_plugInID = -1;
static int hf_fmp_plugInBuf = -1;
static int hf_fmp_nfsFHandle = -1;
static int hf_fmp_extentList_len = -1;
static int hf_fmp_extent_state = -1;
static int hf_fmp_numBlks = -1;
static int hf_fmp_volID = -1;
static int hf_fmp_startOffset = -1;
static int hf_fmp_volHandle = -1;
static int hf_fmp_devSignature = -1;
static int hf_fmp_dskSigEnt_val = -1;
static int hf_fmp_mount_path = -1;
static int hf_fmp_sig_offset = -1;
static int hf_fmp_os_major = -1;
static int hf_fmp_os_minor = -1;
static int hf_fmp_os_name = -1;
static int hf_fmp_os_patch = -1;
static int hf_fmp_os_build = -1;
static int hf_fmp_server_version_string = -1;
static int hf_fmp_description = -1;
static int hf_fmp_nfsv3Attr_type = -1;
static int hf_fmp_nfsv3Attr_mode = -1;
static int hf_fmp_nfsv3Attr_nlink = -1;
static int hf_fmp_nfsv3Attr_uid = -1;
static int hf_fmp_nfsv3Attr_gid = -1;
static int hf_fmp_nfsv3Attr_used = -1;
static int hf_fmp_nfsv3Attr_rdev = -1;
static int hf_fmp_nfsv3Attr_fsid = -1;
static int hf_fmp_nfsv3Attr_fileid = -1;
static int hf_fmp_cmd = -1;
static int hf_fmp_topVolumeId = -1;
static int hf_fmp_cursor = -1;
static int hf_fmp_offset64 = -1;
static int hf_fmp_start_offset64 = -1;
static int hf_fmp_slice_size = -1;
static int hf_fmp_volume = -1;
static int hf_fmp_stripeSize = -1;
static int hf_fmp_firstLogBlk64 =-1;
static int hf_fmp_native_protocol = -1;
static int hf_fmp_encoding_mode = -1;
static int hf_fmp_capability = -1;
static int hf_fmp_devSerial_query_cmd = -1;
static int hf_fmp_volume_desc = -1;
static int hf_fmp_disk_identifier = -1;
static int hf_fmp_volume_mgmt_type = -1;
static int hf_fmp_notify_protocol = -1;
static int hf_fmp_client_error_number = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_fmp_cap = -1;
static int hf_fmp_cap_revoke_handle_list = -1;
static int hf_fmp_length_of_volume_list = -1;
static int hf_fmp_cap_unc_names = -1;
static int hf_fmp_length_of_list = -1;
static int hf_fmp_sigoffset = -1;
static int hf_fmp_uid = -1;
static int hf_fmp_fid = -1;
static int hf_fmp_fsid = -1;
static int hf_fmp_tid = -1;
static int hf_fmp_cifsport = -1;
static int hf_fmp_blockindex = -1;
static int hf_fmp_number_of_disk = -1;
static int hf_fmp_cap_cifsv2 = -1;
static int hf_fmp_mtime = -1;
static int hf_fmp_atime = -1;
static int hf_fmp_ctime = -1;
static int hf_fmp_heartbeat_interval = -1;
static int hf_fmp_volindex = -1;

static gint ett_fmp = -1;
static gint ett_fmp_timeval = -1;
static gint ett_fmp_extList = -1;
static gint ett_fmp_ext = -1;
static gint ett_fmp_fileHandle = -1;
static gint ett_capabilities = -1;
static gint ett_HierVolumeDescription = -1;
static gint ett_attrs = -1;

static const value_string fmp_encoding_mode_vals[] = {
    {FMP_ASCII, "ASCII"},
    {FMP_UTF8, "UTF8"},
    {FMP_UNICODE1, "UNICODE"},
    {0,NULL}
};

static gboolean fmp_fhandle_reqrep_matching = FALSE;

static int
dissect_fmp_genString(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_fmp_encoding_mode, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (try_val_to_str(tvb_get_ntohl(tvb, offset), fmp_encoding_mode_vals) == NULL)
        return offset;

    offset = dissect_rpc_string(tvb, tree, hf_fmp_path,
                                offset, NULL);

    return offset;
}

static int
get_fileHandleSrc_size(tvbuff_t *tvb, int offset)
{
    int            length;
    nativeProtocol np;

    np = (nativeProtocol)tvb_get_ntohl(tvb, offset);

    switch (np) {
    case FMP_PATH:
        length =  4 + FMP_MAX_PATH_LEN;
        break;
    case FMP_NFS:
        length =  8 + tvb_get_ntohl(tvb, offset + 4);
        break;
    case FMP_CIFS:
        length =  10;
        break;
    case FMP_FMP:
        length =  8 + tvb_get_ntohl(tvb, offset + 4);
        break;
    case FMP_FS_ONLY:
        length =  8;
        break;
    case FMP_SHARE:
        /* FALLTHROUGH */
    case FMP_MOUNT:
        length =  8 + FMP_MAX_PATH_LEN;
        break;
    default:
        length =  4;
        break;
    }

    return length;
}

static int
dissect_fmp_fileHandleSrc(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                          proto_tree *tree)
{
    nativeProtocol      np;

    proto_tree *fileHandleTree;
    int         length;

    length = get_fileHandleSrc_size(tvb, offset);

    fileHandleTree = proto_tree_add_subtree(tree, tvb, offset, length,
                                          ett_fmp_fileHandle, NULL, "Source File Handle");

    np = (nativeProtocol)tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(fileHandleTree, hf_fmp_native_protocol, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    switch (np) {
    case FMP_PATH:
        offset = dissect_rpc_string(tvb, fileHandleTree,
                                    hf_fmp_mount_path, offset, NULL);
        break;

    case FMP_NFS:
        offset = dissect_rpc_data(tvb, fileHandleTree,
                                  hf_fmp_nfsFHandle, offset);
        break;

    case FMP_CIFS:
        proto_tree_add_item(fileHandleTree, hf_fmp_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(fileHandleTree, hf_fmp_tid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(fileHandleTree, hf_fmp_uid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;

    case FMP_FMP:
        offset = dissect_rpc_string(tvb, fileHandleTree,
                                    hf_fmp_fmpFHandle, offset, NULL);
        break;

    case FMP_FS_ONLY:
        proto_tree_add_item(fileHandleTree, hf_fmp_fsid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case FMP_SHARE:
        offset = dissect_fmp_genString(tvb, offset, fileHandleTree);
        break;

    case FMP_MOUNT:
        offset = dissect_fmp_genString(tvb, offset, fileHandleTree);
        break;

    case FMP_CIFSV2:
        proto_tree_add_item(fileHandleTree, hf_fmp_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(fileHandleTree, hf_fmp_tid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(fileHandleTree, hf_fmp_uid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(fileHandleTree, hf_fmp_cifsport, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;
    case FMP_UNC:
        offset = dissect_fmp_genString(tvb, offset, fileHandleTree);
        break;

    default:
        break;
    }

    return offset;
}

static int
dissect_fmp_extentState(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_extent_state,
                                offset);

    return offset;
}

static int
dissect_fmp_extent(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint32 ext_num)
{
    proto_tree *extTree;

    extTree = proto_tree_add_subtree_format(tree, tvb, offset, 20 ,
                                  ett_fmp_ext, NULL, "Extent (%u)", (guint32) ext_num);

    offset = dissect_rpc_uint32(tvb,  extTree, hf_fmp_firstLogBlk,
                                offset);
    offset = dissect_rpc_uint32(tvb, extTree, hf_fmp_numBlks,
                                offset);
    offset = dissect_rpc_uint32(tvb, extTree, hf_fmp_volID, offset);
    offset = dissect_rpc_uint32(tvb, extTree, hf_fmp_startOffset,
                                offset);
    offset = dissect_fmp_extentState(tvb, offset, extTree);

    return offset;
}

static int
dissect_fmp_extentList(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree)
{
    guint32     numExtents;
    guint32     totalLength;
    proto_tree *extListTree;
    guint32     i;

    numExtents = tvb_get_ntohl(tvb, offset);
    totalLength = 4 + (20 * numExtents);

    extListTree =  proto_tree_add_subtree(tree, tvb, offset, totalLength,
                                       ett_fmp_extList, NULL, "Extent List");

    offset = dissect_rpc_uint32(tvb, extListTree,
                                hf_fmp_extentList_len, offset);

    for (i = 0; i < numExtents; i++) {
        offset = dissect_fmp_extent(tvb, offset, pinfo, extListTree, i+1);
    }

    return offset;
}


static int
dissect_fmp_extentListEx(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                         proto_tree *tree)
{
    guint32     numExtents;
    proto_tree *extListTree;
    guint32     i;

    numExtents = tvb_get_ntohl(tvb, offset);

    offset += 4;

    for (i = 0; i < numExtents; i++) {
        extListTree =  proto_tree_add_subtree(tree, tvb, offset, 28,
                                           ett_fmp_extList, NULL, "Extent List");

        offset = dissect_rpc_uint64(tvb,extListTree , hf_fmp_firstLogBlk64,  offset);

        offset = dissect_rpc_uint32(tvb,extListTree , hf_fmp_numBlksReq,
                                    offset);

        offset = dissect_rpc_uint32(tvb,extListTree , hf_fmp_volID, offset);

        offset = dissect_rpc_uint64(tvb,extListTree , hf_fmp_start_offset64, offset);

        offset = dissect_fmp_extentState(tvb, offset, extListTree);

    }

    return offset;
}


static int
dissect_plugInID(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    if (!tree) {
        return offset;
    }

    proto_tree_add_item(tree, hf_fmp_plugInID, tvb, offset, FMP_PLUG_IN_ID_SZ,
                        ENC_NA);
    return offset;
}

static int
dissect_fmp_flushCmd(tvbuff_t *tvb, int offset,  proto_tree *tree)
{
    guint32 cmd;
    char    msg[MAX_MSG_SIZE];
    guint32 bitValue;
    int     i;

    if (tree) {
        cmd = tvb_get_ntohl(tvb, offset);

        /* Initialize the message for an empty string */
        msg[0] = '\0';

        for (i = 0; cmd != 0 && i < 32; i++) {

            bitValue = 1 << i;

            if (cmd & bitValue) {
                switch (bitValue) {
                case FMP_COMMIT_SPECIFIED:
                    g_strlcat(msg, "COMMIT_SPECIFIED", MAX_MSG_SIZE);
                    break;
                case FMP_RELEASE_SPECIFIED:
                    g_strlcat(msg, "RELEASE_SPECIFIED", MAX_MSG_SIZE);
                    break;
                case FMP_RELEASE_ALL:
                    g_strlcat(msg, "RELEASE_ALL", MAX_MSG_SIZE);
                    break;
                case FMP_CLOSE_FILE:
                    g_strlcat(msg, "CLOSE_FILE", MAX_MSG_SIZE);
                    break;
                case FMP_UPDATE_TIME:
                    g_strlcat(msg, "UPDATE_TIME", MAX_MSG_SIZE);
                    break;
                case FMP_ACCESS_TIME:
                    g_strlcat(msg, "ACCESS_TIME", MAX_MSG_SIZE);
                    break;
                default:
                    g_strlcat(msg, "UNKNOWN", MAX_MSG_SIZE);
                    break;
                }

                /* clear the bit that we processed */
                cmd &= ~bitValue;

                /* add a "bitwise inclusive OR" symbol between cmds */
                if (cmd) {
                    g_strlcat(msg, " | ", MAX_MSG_SIZE);
                }
            }
        }

        if (strlen(msg) == 0) {
            g_strlcpy(msg, "No command specified", MAX_MSG_SIZE);
        }

        proto_tree_add_uint_format_value(tree, hf_fmp_cmd, tvb, offset, 4, cmd, "%s", msg);
    }
    offset += 4;
    return offset;
}

static int
dissect_InterpretVolMgtStuff(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    int length, numdisks, i, j;

    numdisks = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_fmp_number_of_disk, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    for (i=0; i<numdisks; i++) {
        offset = dissect_rpc_uint64(tvb, tree, hf_fmp_sig_offset,  offset);
        length = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(tree, hf_fmp_length_of_list, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        for (j=0; j<length; j++) {
            proto_tree_add_item(tree, hf_fmp_sigoffset, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            offset = dissect_rpc_string(tvb, tree, hf_fmp_dskSigEnt_val,
                                        offset, NULL);

        }
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_volID, offset);

    }
    return offset;


}

static int
dissect_fmp_capability(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_fmp_capability, tvb, offset, 4, ENC_BIG_ENDIAN);
    return offset+4;
}

static int
dissect_fmp_timeval(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hf_time, int hf_time_sec,
                    int hf_time_nsec)
{
    if (tree) {
        nstime_t ts;

        proto_item* time_item;
        proto_tree* time_tree;

        ts.secs = tvb_get_ntohl(tvb, offset+0);
        ts.nsecs = tvb_get_ntohl(tvb, offset+4);

        time_item = proto_tree_add_time(tree, hf_time, tvb, offset, 8, &ts);
        time_tree = proto_item_add_subtree(time_item, ett_fmp_timeval);

        proto_tree_add_uint(time_tree, hf_time_sec, tvb, offset, 4,
                            (guint32) ts.secs);
        proto_tree_add_uint(time_tree, hf_time_nsec, tvb, offset+4, 4,
                            ts.nsecs);
    }
    offset += 8;
    return offset;
}

static int
dissect_fmp_heartBeatIntv(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                          proto_tree *tree)
{
    proto_tree_add_item(tree, hf_fmp_heartbeat_interval, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    return offset;
}

static int
dissect_fmp_status(tvbuff_t *tvb, int offset, proto_tree *tree, int *rval)
{
    fmpStat status;

    status = (fmpStat)tvb_get_ntohl(tvb, offset);

    switch (status) {
    case FMP_OK:
        *rval = 0;
        break;
    case FMP_IOERROR:
        *rval = 1;
        break;
    case FMP_NOMEM:
        *rval = 1;
        break;
    case FMP_NOACCESS:
        *rval = 1;
        break;
    case FMP_INVALIDARG:

        *rval = 1;
        break;
    case FMP_FSFULL:
        *rval = 0;
        break;
    case FMP_QUEUE_FULL:
    case FMP_NOTIFY_ERROR:
    case FMP_WRITER_LOST_BLK:
    case FMP_WRONG_MSG_NUM:
    case FMP_SESSION_LOST:
    case FMP_REQUEST_CANCELLED:
        *rval = 1;
        break;
    case FMP_HOT_SESSION:
        *rval = 0;
        break;
    case FMP_COLD_SESSION:
        *rval = 0;
        break;
    case FMP_CLIENT_TERMINATED:
        *rval = 0;
        break;
    case FMP_REQUEST_QUEUED:
        *rval = 0;
        break;
    case FMP_FALL_BACK:
        *rval = 0;
        break;
    case FMP_WRITER_ZEROED_BLK:
        *rval = 0;
        break;
    case FMP_WRONG_HANDLE:
        *rval = 0;
        break;
    case FMP_DUPLICATE_OPEN:
        *rval = 1;
        break;
    case FMP_PLUGIN_NOFUNC:
        *rval = 1;
        break;
    default:
        *rval = 1;
        break;
    }
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_status , offset);
    return offset;
}

static int
dissect_fmp_devSerial(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                      proto_tree *tree)
{
    proto_tree_add_item(tree, hf_fmp_devSerial_query_cmd, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_fmp_sigoffset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_rpc_string(tvb, tree, hf_fmp_devSignature,
                                offset, NULL);
    return offset;
}

static int
dissect_fmp_VolumeDescription(tvbuff_t *tvb, int offset, proto_tree * tree)
{
    int                    i,length;
    proto_tree            *Hietree;
    proto_item            *ti;
    fmpVolumeType          volumeType;
    fmpDiskIdentifierType  diskIdentifierType;

    volumeType = (fmpVolumeType)tvb_get_ntohl(tvb, offset);
    ti = proto_tree_add_item(tree, hf_fmp_volume_desc, tvb, offset, 4, ENC_BIG_ENDIAN);
    Hietree = proto_item_add_subtree(ti, ett_HierVolumeDescription);
    offset += 4;

    switch (volumeType) {

    case FMP_VOLUME_DISK:
        offset = dissect_rpc_uint32(tvb, Hietree, hf_fmp_volID, offset);
        offset += 8; /* blockIndex64 */
        diskIdentifierType = (fmpDiskIdentifierType)tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(Hietree, hf_fmp_disk_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        switch (diskIdentifierType) {
        case FMP_DISK_IDENTIFIER_SIGNATURE:
            offset = dissect_rpc_uint64(tvb, Hietree, hf_fmp_sig_offset,  offset);
            length = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(Hietree, hf_fmp_length_of_list, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            for (i=0; i<length; i++) {
                proto_tree_add_item(Hietree, hf_fmp_sigoffset, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                offset = dissect_rpc_string(tvb, Hietree, hf_fmp_dskSigEnt_val,  offset, NULL);


            }
            break;

        case FMP_DISK_IDENTIFIER_SERIAL:
            dissect_fmp_devSerial(tvb, offset, NULL, Hietree);
            break;
        }

        break;
    case FMP_VOLUME_SLICE:
        offset = dissect_rpc_uint32(tvb, Hietree, hf_fmp_volID, offset);

        offset = dissect_rpc_uint64(tvb, Hietree, hf_fmp_offset64, offset);

        offset = dissect_rpc_uint64(tvb, Hietree, hf_fmp_slice_size, offset);

        offset = dissect_rpc_uint32(tvb, Hietree, hf_fmp_volume, offset);

        break;

    case FMP_VOLUME_STRIPE:
        offset = dissect_rpc_uint32(tvb, Hietree, hf_fmp_volID, offset);

        offset = dissect_rpc_uint64(tvb, Hietree, hf_fmp_stripeSize, offset);
        length = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(Hietree, hf_fmp_length_of_list, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        for (i=0; i<length; i++) {
            offset = dissect_rpc_uint32(tvb, Hietree, hf_fmp_volume, offset); /* FIXME: Size or length not know */

        }
        break;

    case FMP_VOLUME_META:
        offset = dissect_rpc_uint32(tvb, Hietree, hf_fmp_volID, offset);

        length = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(Hietree, hf_fmp_length_of_list, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        for (i=0; i<length; i++) {
            offset = dissect_rpc_uint32(tvb, Hietree, hf_fmp_volume, offset); /* FIXME: Size or length not know */
        }
        break;
    default:
        break;
    }
    return offset;
}


static int
dissect_fmp_Hiervolume(tvbuff_t *tvb, int offset, proto_tree * tree)
{

    int vollength;

    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_topVolumeId, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_cursor, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_cookie, offset);

    /* hierarchical description of volume.  Each volume describes a
       piece of the entire hierarchy and is guarenteed to only refer to
       volumes that have already been described by the data structure up
       to this point in time.  In some extreme cases, the number of
       volumes and their descriptions may be to large to fit in a single
       RPC reply.  In this case, the application may send getVolumeInfo
       requests for the specific topVolumeId -- specifying the number of
       volumes already received by the client, and the cookie.  The
       server is then responsible for sending another message containing
       additional volumes.  These RPCs exchanges may continue multiple
       times, until the client has fetched the entire hierarchical
       volume description.  If the volume hierarchy changes duing a
       multiple RPC sequence, the server will return an
       FMP_VOLUME_CHANGED error, and the client must discard all
       information already received and restart the request with
       FMP_Mount.
    */

    vollength = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_fmp_length_of_volume_list, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    while (vollength) {
        offset =  dissect_fmp_VolumeDescription(tvb, offset, tree);
        vollength--;
    }

    return offset;

}



static int
dissect_fmp_vmInfo(tvbuff_t *tvb, int offset, packet_info *pinfo,
                   proto_tree *tree)
{
    int     vmType;
    guint32 phyVolList_len;

    vmType = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_fmp_volume_mgmt_type, tvb, offset, 4, ENC_BIG_ENDIAN);

    switch (vmType) {
    case FMP_SERVER_BASED:
        /*
         * Need to finish
         */
        phyVolList_len = tvb_get_ntohl(tvb, offset);
        offset += 4;

        /*
         * Loop through and print all of the devInfo
         * structures.
         */
        while (phyVolList_len) {
            offset = dissect_fmp_devSerial(tvb, offset, pinfo, tree);
            proto_tree_add_item(tree, hf_fmp_volindex, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            phyVolList_len--;
        }
        break;

    case FMP_THIRD_PARTY:
        offset = dissect_rpc_string(tvb, tree, hf_fmp_volHandle,
                                    offset, NULL);
        break;

    case FMP_CLIENT_BASED_DART:
        offset = dissect_rpc_string(tvb,  tree, hf_fmp_volHandle,
                                    offset, NULL);
        break;

    case FMP_CLIENT_BASED_SIMPLE:
        /*
         * Decoding simpleVolInfo
         */
        offset = dissect_fmp_devSerial(tvb, offset, pinfo, tree);

        proto_tree_add_item(tree, hf_fmp_blockindex, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case FMP_DISK_SIGNATURE:
        offset = dissect_InterpretVolMgtStuff(tvb, offset, tree);
        break;

    case FMP_HIERARCHICAL_VOLUME:
        dissect_fmp_Hiervolume(tvb, offset, tree);
        break;

    default:
        break;
    }

    return offset;
}

static int
dissect_fmp_notifyProtocol(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_fmp_notify_protocol, tvb, offset, 4, ENC_BIG_ENDIAN);
    return (offset+4);
}


static int
dissect_fmp_capabilities(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    static const int *capabilities[] = {
        &hf_fmp_cap_revoke_handle_list,
        &hf_fmp_cap_unc_names,
        &hf_fmp_cap_cifsv2,
        NULL
    };

    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_fmp_cap, ett_capabilities,
                        capabilities, ENC_BIG_ENDIAN, BMT_NO_APPEND);
    return (offset+4);
}

static int
dissect_fmp_cerrInfo(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    int            rval;

    proto_tree_add_item(tree, hf_fmp_client_error_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);

    return offset;
}

static int
dissect_fmp_attrs(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree *attrsTree;

    attrsTree =  proto_tree_add_subtree(tree, tvb, offset, 84,
                                     ett_attrs, NULL, "Attribute: ");
    offset = dissect_rpc_uint32(tvb, attrsTree, hf_fmp_nfsv3Attr_type, offset);
    offset = dissect_rpc_uint32(tvb, attrsTree, hf_fmp_nfsv3Attr_mode, offset);
    offset = dissect_rpc_uint32(tvb, attrsTree, hf_fmp_nfsv3Attr_nlink, offset);
    offset = dissect_rpc_uint32(tvb, attrsTree, hf_fmp_nfsv3Attr_uid, offset);
    offset = dissect_rpc_uint32(tvb, attrsTree, hf_fmp_nfsv3Attr_gid, offset);
    offset = dissect_rpc_uint64(tvb, attrsTree, hf_fmp_fileSize, offset);
    /* Here hf_fmp_fileSize is used in
     * place of size
     */
    offset = dissect_rpc_uint64(tvb, attrsTree, hf_fmp_nfsv3Attr_used,   offset);
    offset = dissect_rpc_uint64(tvb, attrsTree, hf_fmp_nfsv3Attr_rdev,   offset);
    offset = dissect_rpc_uint64(tvb, attrsTree, hf_fmp_nfsv3Attr_fsid,   offset);
    offset = dissect_rpc_uint64(tvb, attrsTree, hf_fmp_nfsv3Attr_fileid, offset);
    proto_tree_add_item(tree, hf_fmp_atime, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset +=8;
    proto_tree_add_item(tree, hf_fmp_mtime, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset +=8;
    proto_tree_add_item(tree, hf_fmp_ctime, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset +=8;
    return offset;
}



static int
dissect_FMP_SessionCreate_request(tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_string(tvb, tree, hf_fmp_hostID,
                                offset, NULL);
    offset = dissect_fmp_timeval(tvb, offset, pinfo, tree, hf_fmp_btime,
                                 hf_fmp_time_sec, hf_fmp_time_nsec);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_notifyPort,
                                offset);
    return offset;
}

static int
dissect_FMP_SessionCreate_reply(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_data(tvb, tree,
                                  hf_fmp_sessionHandle, offset);
        offset = dissect_rpc_string(tvb,  tree, hf_fmp_hostID,
                                    offset, NULL);
        offset = dissect_fmp_timeval(tvb, offset, pinfo, tree,
                                     hf_fmp_btime, hf_fmp_time_sec,
                                     hf_fmp_time_nsec);
        offset = dissect_fmp_heartBeatIntv(tvb, offset, pinfo, tree);
    }

    return offset;
}

static int
dissect_FMP_HeartBeat_request(tvbuff_t *tvb, packet_info *pinfo _U_,
                              proto_tree *tree, void* data _U_)
{
    return dissect_rpc_data(tvb, tree, hf_fmp_sessionHandle, 0);
}

static int
dissect_FMP_HeartBeat_reply(tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, void* data _U_)
{
    int rval;

    return dissect_fmp_status(tvb, 0, tree, &rval);
}

static int
dissect_FMP_Mount_request(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb,  tree, hf_fmp_sessionHandle,
                              offset);
    offset = dissect_fmp_capability(tvb, offset, tree);
    offset = dissect_fmp_fileHandleSrc(tvb, offset, pinfo, tree);
    return offset;
}

static int
dissect_FMP_Mount_reply(tvbuff_t *tvb, packet_info *pinfo,
                        proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_fsID,
                                    offset);
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_fsBlkSz,
                                    offset);
        offset = dissect_fmp_vmInfo(tvb, offset, pinfo, tree);
    }

    return offset;
}

static int
dissect_FMP_Open_request(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb, tree, hf_fmp_sessionHandle,
                              offset);
    offset = dissect_fmp_fileHandleSrc(tvb, offset, pinfo, tree);
    return offset;
}

static int
dissect_FMP_Open_reply(tvbuff_t *tvb, packet_info *pinfo _U_,
                       proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle,
                                  offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_msgNum,
                                    offset);
        offset = dissect_rpc_uint64(tvb, tree, hf_fmp_fileSize,
                                    offset);

        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_fsID,
                                    offset);
    }
    return offset;
}

static int
dissect_FMP_Close_request(tvbuff_t *tvb, packet_info *pinfo _U_,
                          proto_tree *tree, void* data _U_)
{
    int offset = 0;

    offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
    return offset;
}

static int
dissect_FMP_Close_reply(tvbuff_t *tvb, packet_info *pinfo _U_,
                        proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_msgNum,
                                    offset);
    }

    return offset;
}

static int
dissect_FMP_OpenGetMap_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb, tree, hf_fmp_sessionHandle,
                              offset);

    offset = dissect_fmp_fileHandleSrc(tvb, offset, pinfo, tree);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_firstLogBlk,
                                offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_numBlksReq,
                                offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_minBlks, offset);
    return offset;
}

static int
dissect_FMP_OpenGetMap_reply(tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle,
                                  offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_msgNum,
                                    offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_cookie,
                                    offset);
        offset = dissect_rpc_uint64(tvb, tree, hf_fmp_fileSize,
                                    offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_fsID,
                                    offset);
        offset = dissect_fmp_extentList(tvb, offset, pinfo, tree);
    }

    return offset;
}

static int
dissect_FMP_OpenAllocSpace_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb, tree, hf_fmp_sessionHandle, offset);
    offset = dissect_fmp_fileHandleSrc(tvb, offset, pinfo, tree);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_firstLogBlk, offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_numBlksReq, offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_minBlks, offset);
    return offset;
}

static int
dissect_FMP_OpenAllocSpace_reply(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle,
                                  offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_msgNum,
                                    offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_cookie,
                                    offset);
        offset = dissect_rpc_uint64(tvb,  tree, hf_fmp_fileSize,
                                    offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_fsID,
                                    offset);
        offset = dissect_fmp_extentList(tvb, offset, pinfo, tree);
    }
    return offset;
}

static int
dissect_FMP_GetMap_request(tvbuff_t *tvb, packet_info *pinfo _U_,
                           proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_msgNum, offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_firstLogBlk,
                                offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_numBlksReq,
                                offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_minBlks, offset);
    return offset;
}

static int
dissect_FMP_GetMap_reply(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_msgNum,
                                    offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_cookie,
                                    offset);
        offset = dissect_rpc_uint64(tvb, tree, hf_fmp_fileSize,
                                    offset);
        offset = dissect_fmp_extentList(tvb, offset, pinfo, tree);
    }

    return offset;
}

static int
dissect_FMP_AllocSpace_request(tvbuff_t *tvb, packet_info *pinfo _U_,
                               proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb,  tree, hf_fmp_fmpFHandle, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_firstLogBlk,
                                offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_numBlksReq,
                                offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_minBlks, offset);
    return offset;
}

static int
dissect_FMP_AllocSpace_reply(tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum,
                                    offset);
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_cookie,
                                    offset);
        offset = dissect_rpc_uint64(tvb, tree, hf_fmp_fileSize,
                                    offset);
        offset = dissect_fmp_extentList(tvb, offset, pinfo, tree);
    }

    return offset;
}

static int
dissect_FMP_Flush_request(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
    offset = dissect_fmp_flushCmd(tvb, offset, tree);
    offset = dissect_rpc_uint64(tvb,tree, hf_fmp_eof, offset);
    offset = dissect_fmp_extentList(tvb, offset, pinfo, tree);
    return offset;
}

static int
dissect_FMP_Flush_reply(tvbuff_t *tvb, packet_info *pinfo _U_,
                        proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum,
                                    offset);
    }
    return offset;
}

static int
dissect_FMP_CancelReq_request(tvbuff_t *tvb, packet_info *pinfo _U_,
                              proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_cookie, offset);
    return offset;
}

static int
dissect_FMP_CancelReq_reply(tvbuff_t *tvb, packet_info *pinfo _U_,
                            proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum,
                                    offset);
    }
    return offset;
}

static int
dissect_FMP_PlugIn_request(tvbuff_t *tvb, packet_info *pinfo _U_,
                           proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_plugInID(tvb, offset, tree);
    offset = dissect_rpc_data(tvb, tree, hf_fmp_plugInBuf, offset);
    return offset;
}

static int
dissect_FMP_PlugIn_reply(tvbuff_t *tvb, packet_info *pinfo _U_,
                         proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_data(tvb,  tree, hf_fmp_plugInBuf,
                                  offset);
    }
    return offset;
}

static int
dissect_FMP_SessionTerminate_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    return dissect_rpc_data(tvb,  tree, hf_fmp_sessionHandle, 0);
}

static int
dissect_FMP_SessionTerminate_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int rval;

    return dissect_fmp_status(tvb, 0,tree, &rval);
}

static int
dissect_FMP_SessionCreateEx_request(tvbuff_t *tvb, packet_info *pinfo,  proto_tree *tree, void* data _U_)
{
    int offset = 0;

    offset = dissect_rpc_string(tvb, tree, hf_fmp_hostID,
                                offset, NULL);
    offset = dissect_fmp_timeval(tvb, offset, pinfo ,tree, hf_fmp_btime,
                                 hf_fmp_time_sec, hf_fmp_time_nsec);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_notifyPort,
                                offset);
    offset = dissect_fmp_notifyProtocol(tvb, offset, tree);

    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_os_major,
                                offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_os_minor,
                                offset);

    offset = dissect_rpc_string(tvb, tree, hf_fmp_os_name,
                                offset, NULL);

    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_os_patch,
                                offset);

    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_os_build,
                                offset);

    offset = dissect_fmp_capabilities(tvb, offset, tree);

    return offset;
}


static int
dissect_FMP_SessionCreateEx_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset, tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_data(tvb, tree,
                                  hf_fmp_sessionHandle, offset);
        offset = dissect_rpc_string(tvb,  tree, hf_fmp_hostID,
                                    offset, NULL);
        offset = dissect_fmp_timeval(tvb, offset, pinfo ,tree,
                                     hf_fmp_btime, hf_fmp_time_sec,
                                     hf_fmp_time_nsec);
        offset = dissect_fmp_heartBeatIntv(tvb, offset, pinfo , tree);

        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_os_major,
                                    offset);

        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_os_minor,
                                    offset);

        offset = dissect_rpc_string(tvb, tree, hf_fmp_server_version_string,
                                    offset, NULL);

        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_os_patch,
                                    offset);

        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_os_build,
                                    offset);

        offset = dissect_fmp_capabilities(tvb, offset, tree);
    }

    return offset;
}


static int
dissect_FMP_ReportClientError_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_string(tvb, tree, hf_fmp_description,
                                offset, NULL);

    offset = dissect_fmp_cerrInfo(tvb, offset, tree);
    return offset;
}

static int
dissect_FMP_ReportClientError_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;
    offset = dissect_fmp_status(tvb, offset,tree, &rval);

    return offset;
}

static int
dissect_FMP_GetAttr_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);

    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);

    return offset;
}


static int
dissect_FMP_GetAttr_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;
    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);

        offset = dissect_fmp_attrs(tvb, offset, tree);
    }

    return offset;
}

static int
dissect_FMP_OpenGetAttr_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;

    offset = dissect_rpc_data(tvb,  tree, hf_fmp_sessionHandle,
                              offset);

    offset = dissect_fmp_fileHandleSrc(tvb, offset, pinfo, tree);

    return offset;
}


static int
dissect_FMP_OpenGetAttr_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset, tree, &rval);

    if (rval == 0) {
        offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
        offset = dissect_rpc_uint64(tvb, tree, hf_fmp_fileSize, offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_fsID, offset);
        offset = dissect_fmp_attrs(tvb, offset, tree);
    }


    return offset;
}


static int
dissect_FMP_FlushGetAttr_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;

    offset = dissect_fmp_fileHandleSrc(tvb, offset, pinfo, tree);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_cmd, offset);
    offset = dissect_rpc_uint64(tvb,tree, hf_fmp_eof, offset);

    proto_tree_add_item(tree, hf_fmp_mtime, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    offset = dissect_fmp_extentList(tvb, offset, pinfo, tree);

    return offset;
}


static int
dissect_FMP_FlushGetAttr_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);

        offset = dissect_fmp_attrs(tvb, offset, tree);
    }

    return offset;
}


static int
dissect_FMP_GetVolumeInfo_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_topVolumeId, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_cursor, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_cookie, offset);
    return offset;
}



static int
dissect_FMP_GetVolumeInfo_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        /* FIXME: I don't know size of this volumes */
        offset = dissect_fmp_Hiervolume(tvb,offset, tree);
    }
    return offset;

}

static int
dissect_FMP_OpenGetMapEx_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb, tree, hf_fmp_sessionHandle,
                              offset);
    offset = dissect_fmp_fileHandleSrc(tvb, offset, pinfo, tree);
    offset = dissect_rpc_uint64(tvb, tree, hf_fmp_firstLogBlk64,  offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_numBlksReq,
                                offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_minBlks, offset);
    return offset;
}


static int
dissect_FMP_OpenGetMapEx_reply(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;
    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle,
                                  offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_msgNum,
                                    offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_cookie,
                                    offset);
        offset = dissect_rpc_uint64(tvb, tree, hf_fmp_fileSize,
                                    offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_fsID,
                                    offset);
        offset = dissect_fmp_extentListEx(tvb, offset, pinfo, tree);
    }

    return offset;
}


static int
dissect_FMP_OpenAllocSpaceEx_request(tvbuff_t *tvb,
                                     packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb , tree, hf_fmp_sessionHandle,
                              offset);
    offset = dissect_fmp_fileHandleSrc(tvb, offset, pinfo, tree);
    offset = dissect_rpc_uint64(tvb, tree, hf_fmp_firstLogBlk64,  offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_numBlksReq,
                                offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_minBlks, offset);
    return offset;
}


static int
dissect_FMP_OpenAllocSpaceEx_reply(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle,
                                  offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_msgNum,
                                    offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_cookie,
                                    offset);
        offset = dissect_rpc_uint64(tvb,  tree, hf_fmp_fileSize,
                                    offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_fsID,
                                    offset);
        offset = dissect_fmp_extentListEx(tvb, offset, pinfo, tree);
    }
    return offset;
}

static int
dissect_FMP_GetMapEx_request(tvbuff_t *tvb, packet_info *pinfo _U_,
                             proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_msgNum, offset);
    offset = dissect_rpc_uint64(tvb, tree, hf_fmp_firstLogBlk64,  offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_numBlksReq,
                                offset);
    offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_minBlks, offset);
    return offset;
}


static int
dissect_FMP_GetMapEx_reply(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_msgNum,
                                    offset);
        offset = dissect_rpc_uint32(tvb,  tree, hf_fmp_cookie,
                                    offset);
        offset = dissect_rpc_uint64(tvb, tree, hf_fmp_fileSize,
                                    offset);
        offset = dissect_fmp_extentListEx(tvb, offset, pinfo, tree);
    }

    return offset;
}


static int
dissect_FMP_AllocSpaceEx_request(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb,  tree, hf_fmp_fmpFHandle, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
    offset = dissect_rpc_uint64(tvb, tree, hf_fmp_firstLogBlk64,  offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_numBlksReq,
                                offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_minBlks, offset);
    return offset;
}


static int
dissect_FMP_AllocSpaceEx_reply(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum,
                                    offset);
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_cookie,
                                    offset);
        offset = dissect_rpc_uint64(tvb, tree, hf_fmp_fileSize,
                                    offset);
        offset = dissect_fmp_extentListEx(tvb, offset, pinfo, tree);
    }

    return offset;
}

static int
dissect_FMP_FlushEx_request(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, void* data _U_)
{
    int offset = 0;
    offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
    offset = dissect_fmp_flushCmd(tvb, offset, tree);
    offset = dissect_rpc_uint64(tvb,tree, hf_fmp_eof, offset);
    offset = dissect_fmp_extentListEx(tvb, offset, pinfo, tree);
    return offset;
}

static int
dissect_FMP_FlushEx_reply(tvbuff_t *tvb, packet_info *pinfo _U_,
                          proto_tree *tree, void* data _U_)
{
    int rval;
    int offset = 0;

    offset = dissect_fmp_status(tvb, offset,tree, &rval);
    if (rval == 0) {
        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum,
                                    offset);
    }
    return offset;
}
/*
 * proc number, "proc name", dissect_request, dissect_reply
 */
static const vsff fmp3_proc[] = {
    { 0,
      "NULL",
      dissect_rpc_void,
      dissect_rpc_void, },

    { 1,
      "SessionCreate",
      dissect_FMP_SessionCreate_request,
      dissect_FMP_SessionCreate_reply },

    { 2,
      "HeartBeat",
      dissect_FMP_HeartBeat_request,
      dissect_FMP_HeartBeat_reply },

    { 3,
      "Mount",
      dissect_FMP_Mount_request,
      dissect_FMP_Mount_reply },

    { 4,
      "Open",
      dissect_FMP_Open_request,
      dissect_FMP_Open_reply },

    { 5,
      "Close",
      dissect_FMP_Close_request,
      dissect_FMP_Close_reply },

    { 6,
      "OpenGetMap",
      dissect_FMP_OpenGetMap_request,
      dissect_FMP_OpenGetMap_reply },

    { 7,
      "OpenAllocSpace",
      dissect_FMP_OpenAllocSpace_request,
      dissect_FMP_OpenAllocSpace_reply },

    { 8,
      "GetMap",
      dissect_FMP_GetMap_request,
      dissect_FMP_GetMap_reply },

    { 9,
      "AllocSpace",
      dissect_FMP_AllocSpace_request,
      dissect_FMP_AllocSpace_reply },

    { 10,
      "Flush",
      dissect_FMP_Flush_request,
      dissect_FMP_Flush_reply },

    { 11,
      "CancelReq",
      dissect_FMP_CancelReq_request,
      dissect_FMP_CancelReq_reply },

    { 12,
      "PlugIn",
      dissect_FMP_PlugIn_request,
      dissect_FMP_PlugIn_reply },

    { 13,
      "SessionTerminate",
      dissect_FMP_SessionTerminate_request,
      dissect_FMP_SessionTerminate_reply },

    { 14,
      "SessionCreateEx",
      dissect_FMP_SessionCreateEx_request,
      dissect_FMP_SessionCreateEx_reply },

    { 15,
      "ReportClientError",
      dissect_FMP_ReportClientError_request,
      dissect_FMP_ReportClientError_reply },

    { 16           ,
      "Get Attribute",
      dissect_FMP_GetAttr_request,
      dissect_FMP_GetAttr_reply },

    { 17               ,
      "Open Get Attribute",
      dissect_FMP_OpenGetAttr_request,
      dissect_FMP_OpenGetAttr_reply },

    { 18               ,
      "Flush Get Attribute",
      dissect_FMP_FlushGetAttr_request,
      dissect_FMP_FlushGetAttr_reply },

    { 19               ,
      "OpenGetMapEx",
      dissect_FMP_OpenGetMapEx_request,
      dissect_FMP_OpenGetMapEx_reply },

    { 20               ,
      "OpenAllocSpaceEx",
      dissect_FMP_OpenAllocSpaceEx_request,
      dissect_FMP_OpenAllocSpaceEx_reply },

    { 21               ,
      "GetMapEx",
      dissect_FMP_GetMapEx_request,
      dissect_FMP_GetMapEx_reply },

    { 22               ,
      "AllocSpaceEx",
      dissect_FMP_AllocSpaceEx_request,
      dissect_FMP_AllocSpaceEx_reply },

    { 23               ,
      "FMP_FlushEx",
      dissect_FMP_FlushEx_request,
      dissect_FMP_FlushEx_reply },
#if 0

    { 24               ,
      "FlushGetAttrEx",
      dissect_FMP_FlushGetAttrEx_request,
      dissect_FMP_FlushGetAttrEx_reply },

#endif

    { 25               ,
      "GetVolumeInfo",
      dissect_FMP_GetVolumeInfo_request,
      dissect_FMP_GetVolumeInfo_reply },


    {0 , NULL , NULL , NULL }

};


static const rpc_prog_vers_info fmp_vers_info[] = {
    { FMP_VERSION_3, fmp3_proc, &hf_fmp_procedure }
};


static const value_string fmp_proc_vals[] = {
    {  0, "NULL" },
    {  1, "SessionCreate" },
    {  2, "HeartBeat" },
    {  3, "Mount" },
    {  4, "Open" },
    {  5, "Close" },
    {  6, "OpenGetMap" },
    {  7, "OpenAllocSpace" },
    {  8, "GetMap" },
    {  9, "AllocSpace " },
    { 10, "Flush" },
    { 11, "CancelReq" },
    { 12, "PlugIn" },
    { 13, "SessionTerminate" },
    { 14, "SessionCreateEx" },
    { 15, "ReportClientError" },
    { 16, "GetAttr " },
    { 17, "OpenGetAttr" },
    { 18, "FlushGetAttr"},
    { 19, "OpenGetMapEx"},
    { 20, "OpenAllocSpaceEx"},
    { 21, "GetMapEx"},
    { 22, "AllocSpaceEx"},
    { 23, "FlushEx"},
    { 24, "FlushGetAttrEx"},
    { 25, "GetVolumeInfo"},
    { 0,NULL }
};


static const value_string fmp_status_vals[] = {
    {  0, "OK"},
    {  5, "IOERROR"},
    { 12, "NOMEM"},
    { 13, "NOACCESS"},
    { 22, "INVALIDARG"},
    { 28, "FSFULL"},
    { 79, "QUEUE_FULL"},
    {500, "WRONG_MSG_NUM"},
    {501, "SESSION_LOST"},
    {502, "HOT_SESSION"},
    {503, "COLD_SESSION"},
    {504, "CLIENT_TERMINATED"},
    {505, "WRITER_LOST_BLK"},
    {506, "FMP_REQUEST_QUEUED"},
    {507, "FMP_FALL_BACK"},
    {508, "REQUEST_CANCELLED"},
    {509, "WRITER_ZEROED_BLK"},
    {510, "NOTIFY_ERROR"},
    {511, "FMP_WRONG_HANDLE"},
    {512, "DUPLICATE_OPEN"},
    {600, "PLUGIN_NOFUNC"},
    {0,NULL}
};


static const value_string fmp_extentState_vals[] = {
    {0,"VALID_DATA"},
    {1,"INVALID_DATA"},
    {2,"NONE_DATA"},
    {0,NULL}
};

static const value_string fmp_native_protocol_vals[] = {
    {FMP_PATH, "PATH"},
    {FMP_NFS, "NFS"},
    {FMP_CIFS, "CIFS"},
    {FMP_FMP, "FMP"},
    {FMP_FS_ONLY, "FS_ONLY"},
    {FMP_SHARE, "SHARE"},
    {FMP_MOUNT, "MOUNT"},
    {FMP_CIFSV2, "CIFSV2"},
    {FMP_UNC,"UNC"},
    {0,NULL}
};

static const value_string fmp_volume_mgmt_capability_vals[] = {
    {FMP_SERVER_BASED, "SERVER_BASED"},
    {FMP_THIRD_PARTY, "THIRD_PARTY"},
    {FMP_CLIENT_BASED_DART, "CLIENT_BASED_DART"},
    {FMP_CLIENT_BASED_SIMPLE, "CLIENT_BASED_SIMPLE"},
    {FMP_HIERARCHICAL_VOLUME, "FMP_HIERARCHICAL_VOLUME"},
    {0,NULL}
};

static const value_string fmp_query_cmd_vals[] = {
    {FMP_SCSI_INQUIRY, "SCSI_INQUIRY"},
    {FMP_DART_STAMP, "DART_STAMP"},
    {0,NULL}
};

static const value_string fmp_volume_desc_vals[] = {
    {FMP_VOLUME_DISK, "DISK"},
    {FMP_VOLUME_SLICE, "SLICE"},
    {FMP_VOLUME_STRIPE, "STRIPE"},
    {FMP_VOLUME_META, "META"},
    {FMP_VOLUME_SLICE, "SLICE"},
    {FMP_VOLUME_SLICE, "SLICE"},
    {0,NULL}
};

static const value_string fmp_disk_identifier_vals[] = {
    {FMP_DISK_IDENTIFIER_SIGNATURE, "SIGNATURE"},
    {FMP_DISK_IDENTIFIER_SERIAL, "SERIAL"},
    {0,NULL}
};

static const value_string fmp_notify_protocol_vals[] = {
    {FMP_TCP, "TCP"},
    {FMP_UDP, "UDP"},
    {0,NULL}
};

static const value_string fmp_volume_mgmt_type_vals[] = {
    {FMP_SERVER_BASED, "SERVER_BASED"},
    {FMP_THIRD_PARTY, "THIRD_PARTY"},
    {FMP_CLIENT_BASED_DART, "CLIENT_BASED_DART"},
    {FMP_CLIENT_BASED_SIMPLE, "CLIENT_BASED_SIMPLE"},
    {FMP_DISK_SIGNATURE, "DISK_SIGNATURE"},
    {FMP_HIERARCHICAL_VOLUME, "HIERARCHICAL_VOLUME"},
    {0,NULL}
};

static const value_string fmp_client_error_number_vals[] = {
    {FMP_CE_GENERIC, "FMP_CE_GENERIC"},
    {FMP_CE_DISK_ERROR, "FMP_CE_DISK_ERROR"},
    {0,NULL}
};

void
proto_register_fmp(void)
{
    static hf_register_info hf[] = {
        { &hf_fmp_procedure,
          { "Procedure", "fmp.procedure",
            FT_UINT32, BASE_DEC, VALS(fmp_proc_vals),
            0, NULL, HFILL }},        /* New addition */

        { &hf_fmp_hostID,
          { "Host ID", "fmp.hostID",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_btime,
          { "Boot Time", "fmp.btime",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
            "Machine Boot Time", HFILL }},

        { &hf_fmp_time_sec,
          { "seconds", "fmp.btime.sec",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_time_nsec,
          { "nanoseconds", "fmp.btime.nsec",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_notifyPort,
          { "Notify Port", "fmp.notifyPort",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_sessionHandle,
          { "Session Handle", "fmp.sessHandle",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_fmpFHandle,
          { "FMP File Handle", "fmp.fmpFHandle",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL,

                HFILL }},
        { &hf_fmp_nfsFHandle,
          { "NFS File Handle", "fmp.nfsFHandle",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_fsID,
          { "File System ID", "fmp.fsID",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_status,
          { "Status", "fmp.status",
            FT_UINT32, BASE_DEC, VALS(fmp_status_vals), 0,
            "Reply Status", HFILL }},

        { &hf_fmp_fsBlkSz,
          { "File System Block Size", "fmp.fsBlkSz",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_volHandle,
          { "Volume Handle", "fmp.volHandle",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_dskSigEnt_val,
          { "Celerra Signature", "fmp.dsi.ds.dsList.dskSigLst_val.dse.dskSigEnt_val",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_devSignature,
          { "Signature DATA", "fmp.devSig",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_mount_path,
          { "Native Protocol: PATH", "fmp.mount_path",
            FT_STRING, BASE_NONE, NULL, 0,
            "Absolute path from the root on the server side", HFILL }},

        { &hf_fmp_sig_offset,
          { "Sig Offset", "fmp.dsi.ds.sig_offset",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_numBlksReq,
          { "Extent Length", "fmp.numBlksReq",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_minBlks,
          { "Minimum Blocks to Grant", "fmp.minBlks",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_msgNum,
          { "Message Number", "fmp.msgNum",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_cookie,
          { "Cookie", "fmp.cookie",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Cookie for FMP_REQUEST_QUEUED Resp", HFILL }},

        { &hf_fmp_fileSize,
          { "File Size", "fmp.fileSize",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_extentList_len,
          { "Extent List Length", "fmp.extentList_len",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_extent_state,
          { "Extent State", "fmp.extentState",
            FT_UINT32,BASE_DEC, VALS(fmp_extentState_vals), 0,
            NULL, HFILL }},

        { &hf_fmp_firstLogBlk,
          { "First Logical File Block", "fmp.firstLogBlk",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_numBlks,
          { "Number of Blocks", "fmp.numBlks",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_volID,
          { "Volume ID inside DART", "fmp.volID",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_startOffset,
          { "Start Offset", "fmp.startOffset",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_start_offset64,
          { "Start offset", "fmp.start_offset64",
            FT_UINT64, BASE_DEC, NULL, 0,
            "Start Offset of extentEx", HFILL }},

        { &hf_fmp_eof,
          { "EOF", "fmp.eof",
            FT_UINT64, BASE_DEC, NULL, 0,
            "End Of File", HFILL }},

        { &hf_fmp_plugInID,
          { "Plug In Cmd ID", "fmp.plugInID",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_plugInBuf,
          { "Plug In Args", "fmp.plugIn",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_os_major,
          { "OS Major", "fmp.os_major",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_os_minor,
          { "OS Minor", "fmp.os_minor",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_os_name,
          { "OS Name", "fmp.os_name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_path,
          { "Mount Path", "fmp.Path",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_os_patch,
          { "OS Path", "fmp.os_patch",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_os_build,
          { "OS Build", "fmp.os_build",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_server_version_string,
          { "Server Version String", "fmp.server_version_string",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_description,
          { "Error Description", "fmp.description",
            FT_STRING, BASE_NONE, NULL, 0,
            "Client Error Description", HFILL }},

        { &hf_fmp_nfsv3Attr_type,
          { "Type", "fmp.nfsv3Attr_type",
            FT_UINT32, BASE_DEC, NULL, 0,
            "NFSV3 Attr Type", HFILL }},

        { &hf_fmp_nfsv3Attr_mode,
          { "Mode", "fmp.nfsv3Attr_mod",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_nfsv3Attr_nlink,
          { "nlink", "fmp.nfsv3Attr_nlink",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_nfsv3Attr_uid,
          { "uid", "fmp.nfsv3Attr_uid",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_nfsv3Attr_gid,
          { "gid", "fmp.nfsv3Attr_gid",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        /* for nfsv3Attr_size use hf_fmp_fileSize */
        { &hf_fmp_nfsv3Attr_used,
          { "Used", "fmp.nfsv3Attr_used",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_nfsv3Attr_rdev,
          { "rdev", "fmp.nfsv3Attr_rdev",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_nfsv3Attr_fsid,
          { "fsid", "fmp.nfsv3Attr_fsid",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_nfsv3Attr_fileid,
          { "File ID", "fmp.nfsv3Attr_fileid",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_cmd,
          { "Command", "fmp.cmd",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_topVolumeId,
          { "Top Volume ID", "fmp.topVolumeId",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_cursor,
          { "number of volumes", "fmp.cursor",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_offset64,
          { "offset", "fmp.offset64",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_slice_size,
          { "size of the slice", "fmp.slice_size",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_volume,
          { "Volume ID's", "fmp.volume",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_stripeSize,
          { "size of the stripe", "fmp.stripeSize",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_firstLogBlk64,
          { "First Logical Block", "fmp.firstLogBlk64",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

        { &hf_fmp_native_protocol,
          { "Native Protocol", "fmp.native_protocol",
            FT_UINT32, BASE_DEC, VALS(fmp_native_protocol_vals), 0,
            NULL, HFILL }},

        { &hf_fmp_encoding_mode,
          { "Encoding Mode", "fmp.encoding_mode",
            FT_UINT32, BASE_DEC, VALS(fmp_encoding_mode_vals), 0,
            NULL, HFILL }},

        { &hf_fmp_capability,
          { "Volume Mgmt Capability", "fmp.capability",
            FT_UINT32, BASE_DEC, VALS(fmp_volume_mgmt_capability_vals), 0,
            NULL, HFILL }},

        { &hf_fmp_devSerial_query_cmd,
          { "Query Command", "fmp.devSerial.query_cmd",
            FT_UINT32, BASE_DEC, VALS(fmp_query_cmd_vals), 0,
            NULL, HFILL }},

        { &hf_fmp_volume_desc,
          { "VOLUME", "fmp.volume_desc",
            FT_UINT32, BASE_DEC, VALS(fmp_volume_desc_vals), 0,
            NULL, HFILL }},

        { &hf_fmp_disk_identifier,
          { "DISK IDENTIFIER", "fmp.disk_identifier",
            FT_UINT32, BASE_DEC, VALS(fmp_disk_identifier_vals), 0,
            NULL, HFILL }},

        { &hf_fmp_volume_mgmt_type,
          { "Volume Mgmt Type", "fmp.volume_mgmt_type",
            FT_UINT32, BASE_DEC, VALS(fmp_volume_mgmt_type_vals), 0,
            NULL, HFILL }},

        { &hf_fmp_notify_protocol,
          { "Protocol", "fmp.notify_protocol",
            FT_UINT32, BASE_DEC, VALS(fmp_notify_protocol_vals), 0,
            NULL, HFILL }},

        { &hf_fmp_client_error_number,
          { "CLIENT Error Number", "fmp.client_error_number",
            FT_UINT32, BASE_DEC, VALS(fmp_client_error_number_vals), 0,
            NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_fmp_fid, { "fid", "fmp.fid", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_tid, { "tid", "fmp.tid", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_uid, { "uid", "fmp.uid", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_fsid, { "FsID", "fmp.fsid", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_cifsport, { "cifsPort", "fmp.cifsport", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_number_of_disk, { "Number of Disk", "fmp.number_of_disk", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_length_of_list, { "Length of List", "fmp.length_of_list", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_sigoffset, { "sigOffset", "fmp.sigoffset", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_length_of_volume_list, { "Length of volume List", "fmp.length_of_volume_list", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_blockindex, { "blockIndex", "fmp.blockindex", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_cap, { "Capabilities", "fmp.cap", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_cap_revoke_handle_list, { "CAP_REVOKE_HANDLE_LIST", "fmp.cap.revoke_handle_list", FT_BOOLEAN, 32, TFS(&tfs_yes_no), FMP_CAP_REVOKE_HANDLE_LIST, NULL, HFILL }},
      { &hf_fmp_cap_unc_names, { "CAP_UNC_NAMES", "fmp.cap.unc_names", FT_BOOLEAN, 32, TFS(&tfs_yes_no), FMP_CAP_UNC_NAMES, NULL, HFILL }},
      { &hf_fmp_cap_cifsv2, { "CAP_CIFSV2", "fmp.cap.cifsv2", FT_BOOLEAN, 32, TFS(&tfs_yes_no), FMP_CAP_CIFSV2, NULL, HFILL }},
      { &hf_fmp_mtime, { "mtime", "fmp.mtime", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_atime, { "atime", "fmp.atime", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_ctime, { "ctime", "fmp.ctime", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_heartbeat_interval, { "Heartbeat interval", "fmp.heartbeat_interval", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_fmp_volindex, { "volIndex", "fmp.volindex", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_fmp,
        &ett_fmp_timeval,
        &ett_fmp_extList,
        &ett_fmp_ext,
        &ett_fmp_fileHandle,
        &ett_capabilities,
        &ett_HierVolumeDescription,
        &ett_attrs
    };

    module_t *fmp_module;
    proto_fmp = proto_register_protocol("File Mapping Protocol", "FMP", "fmp");

    proto_register_field_array(proto_fmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    fmp_module=prefs_register_protocol(proto_fmp, NULL);

    prefs_register_bool_preference(fmp_module, "fhandle_find_both_reqrep",
                                   "Fhandle filters finds both request/response",
                                   "With this option display filters for fmp fhandle a RPC call,"
                                   " even if the actual fhandle is only present in one of the packets",
                                   &fmp_fhandle_reqrep_matching);

}

void
proto_reg_handoff_fmp(void)
{
    /* Register the protocol as RPC */
    rpc_init_prog(proto_fmp, FMP_PROGRAM, ett_fmp,
                  G_N_ELEMENTS(fmp_vers_info), fmp_vers_info);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
