/* packet-afs-macros.h
 * Helper macros for AFS packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 * Based on routines from tcpdump patches by
 *   Ken Hornstein <kenh@cmf.nrl.navy.mil>
 * Portions based on information retrieved from the RX definitions
 *   in Arla, the free AFS client at http://www.stacken.kth.se/project/arla/
 * Portions based on information/specs retrieved from the OpenAFS sources at
 *   www.openafs.org, Copyright IBM. 
 *
 * $Id: packet-afs-macros.h,v 1.12 2001/09/14 07:10:05 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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



/*
 * Macros for helper dissection routines
 *
 * The macros are here to save on coding. They assume that
 * the current offset is in 'offset', and that the offset
 * should be incremented after performing the macro's operation.
 */


/* Output a unsigned integer, stored into field 'field'
   Assumes it is in network byte order, converts to host before using */
#define OUT_UINT(field) \
	proto_tree_add_uint(tree, field, tvb, offset, sizeof(guint32), tvb_get_ntohl(tvb, offset)); \
	offset += 4;

/* Output a unsigned integer, stored into field 'field'
   Assumes it is in network byte order, converts to host before using */
#define OUT_INT(field) \
	proto_tree_add_int(tree, field, tvb, offset, sizeof(gint32), tvb_get_ntohl(tvb, offset)); \
	offset += 4;
	
/* Output a unsigned integer, stored into field 'field'
   Assumes it is in network byte order, converts to host before using, 
   Note - does not increment offset, so can be used repeatedly for bitfields */
#define DISP_UINT(field) \
	proto_tree_add_uint(tree,field,tvb,offset,sizeof(guint32),tvb_get_ntohl(tvb, offset)); 

/* Output an IPv4 address, stored into field 'field' */
#define OUT_IP(field) \
	proto_tree_add_ipv4(tree,field,tvb,offset,sizeof(gint32),\
		tvb_get_letohl(tvb, offset));\
	offset += 4;

/* Output a UNIX seconds/microseconds timestamp, after converting to an
   nstime_t */
#define OUT_TIMESTAMP(field) \
	{ nstime_t ts; \
	ts.secs = tvb_get_ntohl(tvb, offset); \
	ts.nsecs = tvb_get_ntohl(tvb, offset)*1000; \
	proto_tree_add_time(tree,field, tvb,offset,2*sizeof(guint32),&ts); \
	offset += 8; \
	}

/* Output a UNIX seconds-only timestamp, after converting to an nstime_t */
#define OUT_DATE(field) \
	{ nstime_t ts; \
	ts.secs = tvb_get_ntohl(tvb, offset); \
	ts.nsecs = 0; \
	proto_tree_add_time(tree,field, tvb,offset,sizeof(guint32),&ts); \
	offset += 4; \
	}

/* Output a callback */
#define OUT_FS_AFSCallBack() \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 3*4, "Callback"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_callback); \
		OUT_UINT(hf_afs_fs_callback_version); \
		OUT_DATE(hf_afs_fs_callback_expires); \
		OUT_UINT(hf_afs_fs_callback_type); \
		tree = save; \
	}

/* Output a callback */
#define OUT_CB_AFSCallBack() \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 3*4, "Callback"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_callback); \
		OUT_UINT(hf_afs_cb_callback_version); \
		OUT_DATE(hf_afs_cb_callback_expires); \
		OUT_UINT(hf_afs_cb_callback_type); \
		tree = save; \
	}


/* Output a File ID */
#define OUT_FS_AFSFid(label) \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 3*4, \
			"FileID (%s)", label); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_fid); \
		OUT_UINT(hf_afs_fs_fid_volume); \
		OUT_UINT(hf_afs_fs_fid_vnode); \
		OUT_UINT(hf_afs_fs_fid_uniqifier); \
		tree = save; \
	}

/* Output a Status mask */
#define OUT_FS_STATUSMASK() \
	{ 	proto_tree *save, *ti; \
		guint32 mask; \
		mask = tvb_get_ntohl(tvb, offset); \
		ti = proto_tree_add_uint(tree, hf_afs_fs_status_mask, tvb, offset, \
			sizeof(guint32), mask); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_status_mask); \
		proto_tree_add_uint(tree, hf_afs_fs_status_mask_setmodtime, \
			tvb,offset,sizeof(guint32), mask); \
		proto_tree_add_uint(tree, hf_afs_fs_status_mask_setowner, \
			tvb,offset,sizeof(guint32), mask); \
		proto_tree_add_uint(tree, hf_afs_fs_status_mask_setgroup, \
			tvb,offset,sizeof(guint32), mask); \
		proto_tree_add_uint(tree, hf_afs_fs_status_mask_setmode, \
			tvb,offset,sizeof(guint32), mask); \
		proto_tree_add_uint(tree, hf_afs_fs_status_mask_setsegsize, \
			tvb,offset,sizeof(guint32), mask); \
		proto_tree_add_uint(tree, hf_afs_fs_status_mask_fsync, \
			tvb,offset,sizeof(guint32), mask); \
		offset += 4; \
		tree = save; \
	}

/* Output a File ID */
#define OUT_CB_AFSFid(label) \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 3*4, \
			"FileID (%s)", label); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_fid); \
		OUT_UINT(hf_afs_cb_fid_volume); \
		OUT_UINT(hf_afs_cb_fid_vnode); \
		OUT_UINT(hf_afs_cb_fid_uniqifier); \
		tree = save; \
	}
	
/* Output a StoreStatus */
#define OUT_FS_AFSStoreStatus(label) \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 6*4, \
			label); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_status); \
		OUT_FS_STATUSMASK(); \
		OUT_DATE(hf_afs_fs_status_clientmodtime); \
		OUT_UINT(hf_afs_fs_status_owner); \
		OUT_UINT(hf_afs_fs_status_group); \
		OUT_UINT(hf_afs_fs_status_mode); \
		OUT_UINT(hf_afs_fs_status_segsize); \
		tree = save; \
	}

/* Output a FetchStatus */
#define OUT_FS_AFSFetchStatus(label) \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 21*4, \
			label); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_status); \
		OUT_UINT(hf_afs_fs_status_interfaceversion); \
		OUT_UINT(hf_afs_fs_status_filetype); \
		OUT_UINT(hf_afs_fs_status_linkcount); \
		OUT_UINT(hf_afs_fs_status_length); \
		OUT_UINT(hf_afs_fs_status_dataversion); \
		OUT_UINT(hf_afs_fs_status_author); \
		OUT_UINT(hf_afs_fs_status_owner); \
		OUT_UINT(hf_afs_fs_status_calleraccess); \
		OUT_UINT(hf_afs_fs_status_anonymousaccess); \
		OUT_UINT(hf_afs_fs_status_mode); \
		OUT_UINT(hf_afs_fs_status_parentvnode); \
		OUT_UINT(hf_afs_fs_status_parentunique); \
		OUT_UINT(hf_afs_fs_status_segsize); \
		OUT_DATE(hf_afs_fs_status_clientmodtime); \
		OUT_DATE(hf_afs_fs_status_servermodtime); \
		OUT_UINT(hf_afs_fs_status_group); \
		OUT_UINT(hf_afs_fs_status_synccounter); \
		OUT_UINT(hf_afs_fs_status_dataversionhigh); \
		OUT_UINT(hf_afs_fs_status_spare2); \
		OUT_UINT(hf_afs_fs_status_spare3); \
		OUT_UINT(hf_afs_fs_status_spare4); \
		tree = save; \
	}

/* Output a VolSync */
#define OUT_FS_AFSVolSync() \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 6*4, \
			"VolSync"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_volsync); \
		OUT_UINT(hf_afs_fs_volsync_spare1); \
		OUT_UINT(hf_afs_fs_volsync_spare2); \
		OUT_UINT(hf_afs_fs_volsync_spare3); \
		OUT_UINT(hf_afs_fs_volsync_spare4); \
		OUT_UINT(hf_afs_fs_volsync_spare5); \
		OUT_UINT(hf_afs_fs_volsync_spare6); \
		tree = save; \
	}

/* Output a AFSCBFids */
#define OUT_FS_AFSCBFids() \
	{ \
		guint32 j,i; \
		j = tvb_get_ntohl(tvb, offset); \
		offset += 4; \
		for (i=0; i<j; i++) { \
			OUT_FS_AFSFid("Target"); \
		} \
	}	

/* Output a ViceIds */
#define OUT_FS_ViceIds() \
	{ \
		unsigned int j,i; \
		j = tvb_get_guint8(tvb,offset); \
		offset += 1; \
		for (i=0; i<j; i++) { \
			OUT_UINT(hf_afs_fs_viceid); \
		} \
	}

/* Output a IPAddrs */
#define OUT_FS_IPAddrs() \
	{ \
		unsigned int j,i; \
		j = tvb_get_guint8(tvb, offset); \
		offset += 1; \
		for (i=0; i<j; i++) { \
			OUT_IP(hf_afs_fs_ipaddr); \
		} \
	}

/* Output a AFSCBs */
#define OUT_FS_AFSCBs()	\
	{ \
		guint32 j,i; \
		j = tvb_get_ntohl(tvb,offset); \
		offset += 4; \
		for (i=0; i<j; i++) { \
			OUT_FS_AFSCallBack(); \
		} \
	}


/* Output a AFSBulkStats */
#define OUT_FS_AFSBulkStats() \
	{ \
		unsigned int j,i; \
		j = tvb_get_guint8(tvb,offset); \
		offset += 1; \
		for (i=0; i<j; i++) { \
			OUT_FS_AFSFetchStatus("Status"); \
		} \
	}

/* Output a AFSFetchVolumeStatus */
#define OUT_FS_AFSFetchVolumeStatus()

/* Output a AFSStoreVolumeStatus */
#define OUT_FS_AFSStoreVolumeStatus()

/* Output a ViceStatistics structure */
#define OUT_FS_ViceStatistics()

/* Output a AFS_CollData structure */
#define OUT_FS_AFS_CollData()

/* Output a VolumeInfo structure */
#define OUT_FS_VolumeInfo()

/* Output an AFS Token - might just be bytes though */
#define OUT_FS_AFSTOKEN() VECOUT(hf_afs_fs_token, 1024)

/* Output a AFS acl */
#define ACLOUT(who, positive, acl, bytes) \
	{ 	proto_tree *save, *ti; \
		int tmpoffset; \
		int acllen; \
		char tmp[10]; \
		tmp[0] = 0; \
		if ( acl & PRSFS_READ ) strcat(tmp, "r"); \
		if ( acl & PRSFS_LOOKUP ) strcat(tmp, "l"); \
		if ( acl & PRSFS_INSERT ) strcat(tmp, "i"); \
		if ( acl & PRSFS_DELETE ) strcat(tmp, "d"); \
		if ( acl & PRSFS_WRITE ) strcat(tmp, "w"); \
		if ( acl & PRSFS_LOCK ) strcat(tmp, "k"); \
		if ( acl & PRSFS_ADMINISTER ) strcat(tmp, "a"); \
		ti = proto_tree_add_text(tree, tvb, offset, bytes, \
			"ACL:  %s %s%s", \
			who, tmp, positive ? "" : " (negative)"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_acl); \
		proto_tree_add_string(tree,hf_afs_fs_acl_entity, tvb,offset,strlen(who), who);\
		tmpoffset = offset + strlen(who) + 1; \
		acllen = bytes - strlen(who) - 1; \
		proto_tree_add_uint(tree,hf_afs_fs_acl_r, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_l, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_i, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_d, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_w, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_k, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_a, tvb,tmpoffset,acllen,acl);\
		tree = save; \
	}

/* output a bozo_key */
#define OUT_BOS_KEY() \
	OUT_BYTES(hf_afs_bos_key, 8);

/* output a bozo_key */
#define OUT_BOS_KEYINFO() \
	OUT_TIMESTAMP(hf_afs_bos_keymodtime); \
	OUT_UINT(hf_afs_bos_keychecksum); \
	OUT_UINT(hf_afs_bos_keyspare2);

/* output a bozo_netKTime */
#define OUT_BOS_TIME() \
	SKIP(4); SKIP(2); SKIP(2); SKIP(2); SKIP(2);

/* output a bozo_status */
#define OUT_BOS_STATUS() \
	SKIP(10 * 4);

/* output a ubik interface addr array */
#define OUT_UBIK_InterfaceAddrs() \
    { \
        unsigned int i,j,seen_null=0; \
        for (i=0; i<255; i++) { \
		j = tvb_get_ntohl(tvb, offset); \
		if ( j != 0 ) { \
			OUT_IP(hf_afs_ubik_interface); \
			seen_null = 0; \
		} else { \
			if ( ! seen_null ) { \
			proto_tree_add_text(tree, tvb, offset, \
				tvb_length_remaining(tvb, offset), \
				"Null Interface Addresses"); \
				seen_null = 1; \
			} \
			offset += 4; \
		}\
        } \
    }

#define OUT_UBIK_DebugOld() \
	{ \
		OUT_DATE(hf_afs_ubik_now); \
		OUT_DATE(hf_afs_ubik_lastyestime); \
		OUT_IP(hf_afs_ubik_lastyeshost); \
		OUT_UINT(hf_afs_ubik_lastyesstate); \
		OUT_DATE(hf_afs_ubik_lastyesclaim); \
		OUT_IP(hf_afs_ubik_lowesthost); \
		OUT_DATE(hf_afs_ubik_lowesttime); \
		OUT_IP(hf_afs_ubik_synchost); \
		OUT_DATE(hf_afs_ubik_synctime); \
		OUT_UBIKVERSION("Sync Version"); \
		OUT_UBIKVERSION("Sync TID"); \
		OUT_UINT(hf_afs_ubik_amsyncsite); \
		OUT_DATE(hf_afs_ubik_syncsiteuntil); \
		OUT_UINT(hf_afs_ubik_nservers); \
		OUT_UINT(hf_afs_ubik_lockedpages); \
		OUT_UINT(hf_afs_ubik_writelockedpages); \
		OUT_UBIKVERSION("Local Version"); \
		OUT_UINT(hf_afs_ubik_activewrite); \
		OUT_UINT(hf_afs_ubik_tidcounter); \
		OUT_UINT(hf_afs_ubik_anyreadlocks); \
		OUT_UINT(hf_afs_ubik_anywritelocks); \
		OUT_UINT(hf_afs_ubik_recoverystate); \
		OUT_UINT(hf_afs_ubik_currenttrans); \
		OUT_UINT(hf_afs_ubik_writetrans); \
		OUT_DATE(hf_afs_ubik_epochtime); \
	}

#define OUT_UBIK_SDebugOld() \
	{ \
		OUT_IP(hf_afs_ubik_addr); \
		OUT_DATE(hf_afs_ubik_lastvotetime); \
		OUT_DATE(hf_afs_ubik_lastbeaconsent); \
		OUT_UINT(hf_afs_ubik_lastvote); \
		OUT_UBIKVERSION("Remote Version"); \
		OUT_UINT(hf_afs_ubik_currentdb); \
		OUT_UINT(hf_afs_ubik_beaconsincedown); \
		OUT_UINT(hf_afs_ubik_up); \
	}

/* Skip a certain number of bytes */
#define SKIP(bytes) \
	offset += bytes;
	
/* Raw data - to end of frame */
#define OUT_BYTES_ALL(field) OUT_BYTES(field, tvb_length_remaining(tvb,offset))

/* Raw data */
#define OUT_BYTES(field, bytes) \
	proto_tree_add_item(tree, field, tvb, offset, bytes, FALSE);\
	offset += bytes;

/* Output a rx style string, up to a maximum length first 
   4 bytes - length, then char data */
#define OUT_STRING(field) \
	{	int i; \
		i = tvb_get_ntohl(tvb, offset); \
		offset += 4; \
		if ( i > 0 ) { \
			char *tmp; \
			tmp = g_malloc(i+1); \
			memcpy(tmp, tvb_get_ptr(tvb,offset,i), i); \
			tmp[i] = '\0'; \
			proto_tree_add_string(tree, field, tvb, offset-4, i+4, \
			(void *)tmp); \
			g_free(tmp); \
		} else { \
			proto_tree_add_string(tree, field, tvb, offset-4, 4, \
			""); \
		} \
		offset += i; \
	}

/* Output a fixed length vectorized string (each char is a 32 bit int) */
#define VECOUT(field, length) \
	{ 	char tmp[length+1]; \
		int i,soff; \
		soff = offset;\
		for (i=0; i<length; i++)\
		{\
			tmp[i] = (char) tvb_get_ntohl(tvb, offset);\
			offset += sizeof(guint32);\
		}\
		tmp[length] = '\0';\
		proto_tree_add_string(tree, field, tvb, soff, length, tmp);\
	}

/* Skip the opcode */
#define SKIP_OPCODE() \
	{ \
		SKIP(sizeof(guint32)); \
	}

/* Output a UBIK version code */
#define OUT_UBIKVERSION(label) \
	{ 	proto_tree *save, *ti; \
		unsigned int epoch,counter; \
		nstime_t ts; \
		epoch = tvb_get_ntohl(tvb, offset); \
		offset += 4; \
		counter = tvb_get_ntohl(tvb, offset); \
		offset += 4; \
		ts.secs = epoch; \
		ts.nsecs = 0; \
		ti = proto_tree_add_text(tree, tvb, offset-8, 8, \
			"UBIK Version (%s): %u.%u", label, epoch, counter ); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_ubikver); \
		if ( epoch != 0 ) \
		proto_tree_add_time(tree,hf_afs_ubik_version_epoch, tvb,offset-8, \
			sizeof(guint32),&ts); \
		else \
			proto_tree_add_text(tree, tvb, offset-8, \
			sizeof(guint32),"Epoch: 0"); \
		proto_tree_add_uint(tree,hf_afs_ubik_version_counter, tvb,offset-4, \
			sizeof(guint32),counter); \
		tree = save; \
	}
