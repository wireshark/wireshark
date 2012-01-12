/* Routines for 'Metadata' disassembly
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

/* schemas */
#define META_SCHEMA_PCAP		1
#define META_SCHEMA_DXT			2

/* protocols */
#define META_PROTO_DXT_ETHERNET		1
#define META_PROTO_DXT_ETHERNET_CRC	36
#define META_PROTO_DXT_ATM			41
#define META_PROTO_DXT_ERF_AAL5		49
#define META_PROTO_DXT_M3UA			61
#define META_PROTO_DXT_NBAP			69
#define META_PROTO_DXT_ATM_AAL2		76
#define META_PROTO_DXT_FP_HINT		82
#define META_PROTO_DXT_CONTAINER	127
#define META_PROTO_DXT_FP_CAPTURE	193
#define META_PROTO_DXT_UTRAN_CAPSULE 194

/* data types */
#define META_TYPE_NONE			0
#define META_TYPE_BOOLEAN		1
#define META_TYPE_UINT8			2
#define META_TYPE_UINT16		3
#define META_TYPE_UINT32		4
#define META_TYPE_UINT64		5
#define META_TYPE_STRING		16

/* item ids */
#define META_ID_NULL			0
#define	META_ID_DIRECTION		1
#define	META_ID_SIGNALING		2
#define	META_ID_INCOMPLETE		3
#define	META_ID_DECIPHERED		4
#define	META_ID_PAYLOADCUT		5
#define	META_ID_TIMESTAMP64		6
#define META_ID_AAL5PROTO		7
#define	META_ID_PHYLINKID		256
#define	META_ID_LOCALDEVID		257
#define	META_ID_REMOTEDEVID		258
#define	META_ID_TAPGROUPID		259
#define	META_ID_IMSI			1024
#define	META_ID_IMEI			1025
#define	META_ID_CELL			1026
#define	META_ID_TLLI			1027
#define	META_ID_NSAPI			1028
#define	META_ID_APN				1029
#define	META_ID_RAT				1030
#define	META_ID_CALLING			1031
#define	META_ID_CALLED			1032

enum meta_direction {
	META_DIR_UP,
	META_DIR_DOWN
};
