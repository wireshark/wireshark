/* packet-ncp.h
 * Routines for NetWare Core Protocol
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-ncp.h,v 1.2 1998/10/15 21:12:17 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
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
 *  ncp.h
 *
 *  Copyright (C) 1995 by Volker Lendecke
 *
 */

#define NCP_PTYPE                (0x11)
#define NCP_PORT                 (0x0451)

#define NCP_ALLOC_SLOT_REQUEST   (0x1111)
#define NCP_REQUEST              (0x2222)
#define NCP_DEALLOC_SLOT_REQUEST (0x5555)

struct ncp_common_header {
	guint16   type       ;
	guint8    sequence   ;
	guint8    conn_low   ;
	guint8    task       ;
	guint8    conn_high  ;
};
struct ncp_request_header {
/*	guint16   type       ;
	guint8    sequence   ;
	guint8    conn_low   ;
	guint8    task       ;
	guint8    conn_high  ;*/
	guint8    function   ;
	guint8    data[0]    ;
};

#define NCP_REPLY                (0x3333)
#define NCP_POSITIVE_ACK         (0x9999)

struct ncp_reply_header {
/*	guint16   type              ;
	guint8    sequence          ;
	guint8    conn_low          ;
	guint8    task              ;
	guint8    conn_high         ;*/
	guint8    completion_code   ;
	guint8    connection_state  ;
	guint8    data[0]           ;
};


#define NCP_BINDERY_USER (0x0001)
#define NCP_BINDERY_UGROUP (0x0002)
#define NCP_BINDERY_PQUEUE (0x0003)
#define NCP_BINDERY_FSERVER (0x0004)
#define NCP_BINDERY_NAME_LEN (48)
struct ncp_bindery_object {
	guint32   object_id;
	guint16   object_type;
	guint8    object_name[NCP_BINDERY_NAME_LEN];
	guint8    object_flags;
	guint8    object_security;
	guint8    object_has_prop;
};

struct nw_property {
	guint8    value[128];
	guint8    more_flag;
	guint8    property_flag;
};

struct prop_net_address {
	guint32 network                 ;
	guint8  node[IPX_NODE_LEN]      ;
	guint16 port                    ;
};

#define NCP_VOLNAME_LEN (16)
#define NCP_NUMBER_OF_VOLUMES (64)
struct ncp_volume_info {
	guint32   total_blocks;
	guint32   free_blocks;
	guint32   purgeable_blocks;
	guint32   not_yet_purgeable_blocks;
	guint32   total_dir_entries;
	guint32   available_dir_entries;
	guint8    sectors_per_block;
	char    volume_name[NCP_VOLNAME_LEN+1];
};

struct ncp_filesearch_info {
	guint8    volume_number;
	guint16   directory_id;
	guint16   sequence_no;
	guint8    access_rights;
};

#define NCP_MAX_FILENAME 14

/* these define the attribute byte as seen by NCP */
#define aRONLY     (1L<<0)
#define aHIDDEN    (1L<<1)
#define aSYSTEM    (1L<<2)
#define aEXECUTE   (1L<<3)
#define aDIR       (1L<<4)
#define aARCH      (1L<<5)

#define AR_READ      (0x01)
#define AR_WRITE     (0x02)
#define AR_EXCLUSIVE (0x20)

#define NCP_FILE_ID_LEN 6
struct ncp_file_info {
	guint8    file_id[NCP_FILE_ID_LEN];
        char    file_name[NCP_MAX_FILENAME+1];
	guint8    file_attributes;
	guint8    file_mode;
	guint32   file_length;
	guint16   creation_date;
	guint16   access_date;
	guint16   update_date;
	guint16   update_time;
};

/* Defines for Name Spaces */
#define NW_NS_DOS     0
#define NW_NS_MAC     1
#define NW_NS_NFS     2
#define NW_NS_FTAM    3
#define NW_NS_OS2     4

/*  Defines for ReturnInformationMask */
#define RIM_NAME	      (0x0001L)
#define RIM_SPACE_ALLOCATED   (0x0002L)
#define RIM_ATTRIBUTES	      (0x0004L)
#define RIM_DATA_SIZE	      (0x0008L)
#define RIM_TOTAL_SIZE	      (0x0010L)
#define RIM_EXT_ATTR_INFO     (0x0020L)
#define RIM_ARCHIVE	      (0x0040L)
#define RIM_MODIFY	      (0x0080L)
#define RIM_CREATION	      (0x0100L)
#define RIM_OWNING_NAMESPACE  (0x0200L)
#define RIM_DIRECTORY	      (0x0400L)
#define RIM_RIGHTS	      (0x0800L)
#define RIM_ALL 	      (0x0FFFL)
#define RIM_COMPRESSED_INFO   (0x80000000L)

/* open/create modes */
#define OC_MODE_OPEN	  0x01
#define OC_MODE_TRUNCATE  0x02
#define OC_MODE_REPLACE   0x02
#define OC_MODE_CREATE	  0x08

/* open/create results */
#define OC_ACTION_NONE	   0x00
#define OC_ACTION_OPEN	   0x01
#define OC_ACTION_CREATE   0x02
#define OC_ACTION_TRUNCATE 0x04
#define OC_ACTION_REPLACE  0x04

/* access rights attributes */
#ifndef AR_READ_ONLY
#define AR_READ_ONLY	   0x0001
#define AR_WRITE_ONLY	   0x0002
#define AR_DENY_READ	   0x0004
#define AR_DENY_WRITE	   0x0008
#define AR_COMPATIBILITY   0x0010
#define AR_WRITE_THROUGH   0x0040
#define AR_OPEN_COMPRESSED 0x0100
#endif

struct nw_info_struct
{
	guint32 spaceAlloc                   ;
	guint32 attributes                   ;
	guint16 flags                        ;
	guint32 dataStreamSize               ;
	guint32 totalStreamSize              ;
	guint16 numberOfStreams              ;
	guint16 creationTime                 ;
	guint16 creationDate                 ;
	guint32 creatorID                    ;
	guint16 modifyTime                   ;
	guint16 modifyDate                   ;
	guint32 modifierID                   ;
	guint16 lastAccessDate               ;
	guint16 archiveTime                  ;
	guint16 archiveDate                  ;
	guint32 archiverID                   ;
	guint16 inheritedRightsMask          ;
	guint32 dirEntNum                    ;
	guint32 DosDirNum                    ;
	guint32 volNumber                    ;
	guint32 EADataSize                   ;
	guint32 EAKeyCount                   ;
	guint32 EAKeySize                    ;
	guint32 NSCreator                    ;
	guint8  nameLen                      ;
	guint8  entryName[256]               ;
};

/* modify mask - use with MODIFY_DOS_INFO structure */
#define DM_ATTRIBUTES		  (0x0002L)
#define DM_CREATE_DATE		  (0x0004L)
#define DM_CREATE_TIME		  (0x0008L)
#define DM_CREATOR_ID		  (0x0010L)
#define DM_ARCHIVE_DATE 	  (0x0020L)
#define DM_ARCHIVE_TIME 	  (0x0040L)
#define DM_ARCHIVER_ID		  (0x0080L)
#define DM_MODIFY_DATE		  (0x0100L)
#define DM_MODIFY_TIME		  (0x0200L)
#define DM_MODIFIER_ID		  (0x0400L)
#define DM_LAST_ACCESS_DATE	  (0x0800L)
#define DM_INHERITED_RIGHTS_MASK  (0x1000L)
#define DM_MAXIMUM_SPACE	  (0x2000L)

struct nw_modify_dos_info
{
	guint32 attributes                   ;
	guint16 creationDate                 ;
	guint16 creationTime                 ;
	guint32 creatorID                    ;
	guint16 modifyDate                   ;
	guint16 modifyTime                   ;
	guint32 modifierID                   ;
	guint16 archiveDate                  ;
	guint16 archiveTime                  ;
	guint32 archiverID                   ;
	guint16 lastAccessDate               ;
	guint16 inheritanceGrantMask         ;
	guint16 inheritanceRevokeMask        ;
	guint32 maximumSpace                 ;
};

struct nw_file_info {
	struct nw_info_struct i;
	int   opened;
	int   access;
	guint32 server_file_handle           ;
	guint8  open_create_action           ;
	guint8  file_handle[6]               ;
};

struct nw_search_sequence {
	guint8  volNumber                    ;
	guint32 dirBase                      ;
	guint32 sequence                     ;
};

struct nw_queue_job_entry {
	guint16 InUse                        ;
	guint32 prev                         ;
	guint32 next                         ;
	guint32 ClientStation                ;
	guint32 ClientTask                   ;
	guint32 ClientObjectID               ;
	guint32 TargetServerID               ;
	guint8  TargetExecTime[6]            ;
	guint8  JobEntryTime[6]              ;
	guint32 JobNumber                    ;
	guint16 JobType                      ;
	guint16 JobPosition                  ;
	guint16 JobControlFlags              ;
	guint8  FileNameLen                  ;
	char  JobFileName[13]              ;
	guint32 JobFileHandle                ;
	guint32 ServerStation                ;
	guint32 ServerTaskNumber             ;
	guint32 ServerObjectID               ;
	char  JobTextDescription[50]       ;
	char  ClientRecordArea[152]        ;
};

struct queue_job {
	struct nw_queue_job_entry j;
	guint8 file_handle[6];
};

#define QJE_OPER_HOLD	0x80
#define QJE_USER_HOLD	0x40
#define QJE_ENTRYOPEN	0x20
#define QJE_SERV_RESTART    0x10
#define QJE_SERV_AUTO	    0x08

/* ClientRecordArea for print jobs */

#define   KEEP_ON        0x0400
#define   NO_FORM_FEED   0x0800
#define   NOTIFICATION   0x1000
#define   DELETE_FILE    0x2000
#define   EXPAND_TABS    0x4000
#define   PRINT_BANNER   0x8000

struct print_job_record {
    guint8  Version                          ;
    guint8  TabSize                          ;
    guint16 Copies                           ;
    guint16 CtrlFlags                        ;
    guint16 Lines                            ;
    guint16 Rows                             ;
    char  FormName[16]                     ;
    guint8  Reserved[6]                      ;
    char  BannerName[13]                   ;
    char  FnameBanner[13]                  ;
    char  FnameHeader[14]                  ;
    char  Path[80]                         ;
};


