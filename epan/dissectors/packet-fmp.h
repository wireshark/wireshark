/* packet-fmp.h
 * Defines for fmp dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_FMP_H
#define PACKET_FMP_H

#define FMP_PROGRAM	1001911
#define FMP_VERSION_3	 3



/*
 * FMP Procedures
 */
#define	FMP_SessionCreate	1
#define	FMP_HeartBeat		2
#define	FMP_Mount		3
#define	FMP_Open		4
#define	FMP_Close		5
#define	FMP_OpenGetMap		6
#define	FMP_OpenAllocSpace	7
#define	FMP_GetMap		8
#define	FMP_AllocSpace		9
#define	FMP_Flush		10
#define	FMP_CancelReq		11
#define	FMP_PlugIn		12
#define	FMP_SessionTerminate	13
#define	FMP_SessionCreateEx	14
#define FMP_ReportClientError   15
#define FMP_GetAttr		16
#define FMP_OpenGetAttr		17
#define FMP_FlushGetAttr 	18
#define FMP_OpenGetMapEx       	19
#define FMP_OpenAllocSpaceEx   	20
#define FMP_GetMapEx           	21
#define FMP_AllocSpaceEx       	22
#define FMP_FlushEx            	23
#define FMP_FlushGetAttrEx     	24
#define FMP_GetVolumeInfo      	25



/*
 * Volume Mgmt Capability
 */

#define	FMP_SERVER_BASED		0x01
#define	FMP_THIRD_PARTY			0x02
#define	FMP_CLIENT_BASED_DART		0x04
#define	FMP_CLIENT_BASED_SIMPLE		0x08
#define FMP_DISK_SIGNATURE		0x10
#define FMP_IPSTORAGE_BASED		0X20
#define FMP_HIERARCHICAL_VOLUME		0x40

/*
 * Flush Command Type
 */

#define FMP_COMMIT_SPECIFIED 0x01
#define FMP_RELEASE_SPECIFIED 0x02
#define FMP_RELEASE_ALL 0x04
#define FMP_CLOSE_FILE 0x08
#define FMP_UPDATE_TIME 0x10
#define FMP_ACCESS_TIME 0x20

#define FMP_PLUG_IN_ID_SZ 16

/*
 * FMP Notify Protocol
 */
#define FMP_TCP	0
#define FMP_UDP	1

/*
 * Capabilities
 */

#define FMP_CAP_REVOKE_HANDLE_LIST 0x0001
#define FMP_CAP_UNC_NAMES 0x0002
#define FMP_CAP_CIFSV2 0x0004


typedef enum  {
        FMP_CE_GENERIC = 1,
        FMP_CE_DISK_ERROR = 2
}clientErrorNum;


/*
 * FMP Reply Status
 */

typedef enum {
	FMP_OK = 0,
	FMP_IOERROR = 5,
	FMP_NOMEM = 12,
	FMP_NOACCESS = 13,
	FMP_INVALIDARG = 22,
	FMP_FSFULL = 28,
	FMP_QUEUE_FULL = 79,
	FMP_WRONG_MSG_NUM = 500,
	FMP_SESSION_LOST = 501,
	FMP_HOT_SESSION = 502,
	FMP_COLD_SESSION = 503,
	FMP_CLIENT_TERMINATED = 504,
	FMP_WRITER_LOST_BLK = 505,
	FMP_REQUEST_QUEUED = 506,
	FMP_FALL_BACK = 507,
	FMP_REQUEST_CANCELLED = 508,
	FMP_WRITER_ZEROED_BLK = 509,
	FMP_NOTIFY_ERROR = 510,
	FMP_WRONG_HANDLE = 511,
	FMP_DUPLICATE_OPEN = 512,
	FMP_PLUGIN_NOFUNC = 600
} fmpStat;


typedef enum {
	FMP_PATH = 0,
	FMP_NFS = 1,
	FMP_CIFS = 2,
	FMP_FMP = 3,
	FMP_FS_ONLY = 4,
	FMP_SHARE = 5,
	FMP_MOUNT = 6,
	FMP_CIFSV2  = 7,
	FMP_UNC     = 8
} nativeProtocol;


#define FMP_MAX_PATH_LEN	1024


/*
 * Encoding type for genString
 */

typedef enum {
	FMP_ASCII = 0,
	FMP_UTF8 = 1,
	FMP_UNICODE1 = 2
} encoding;

typedef enum  {
    FMP_DISK_IDENTIFIER_SIGNATURE = 0,
    FMP_DISK_IDENTIFIER_SERIAL = 1
} fmpDiskIdentifierType;

typedef enum  {
    FMP_VOLUME_DISK    = 0,
    FMP_VOLUME_SLICE   = 1,
    FMP_VOLUME_STRIPE  = 2,
    FMP_VOLUME_META    = 3
} fmpVolumeType;

/*
 * Extent States
 */
typedef enum {
       FMP_VALID_DATA = 0,
       FMP_INVALID_DATA = 1,
       FMP_NONE_DATA = 2
} extentState;


#define FMP_MAX_PATH_LEN       1024

/*
 * Query Command
 */
typedef enum {
        FMP_SCSI_INQUIRY = 0,
        FMP_DART_STAMP = 1
} queryCmd;


#define MAX_MSG_SIZE		256  /* For wireshark messages */

#endif
