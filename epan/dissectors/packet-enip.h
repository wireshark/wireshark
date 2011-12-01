/* packet-enip.h
 * Routines for EtherNet/IP (Industrial Protocol) dissection
 * EtherNet/IP Home: www.odva.org
 *
 * Conversation data support for CIP
 *   Jan Bartels, Siempelkamp Maschinen- und Anlagenbau GmbH & Co. KG
 *   Copyright 2007
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* Offsets of fields within the DLR Common Frame Header */
#define DLR_CFH_SUB_TYPE       0
#define DLR_CFH_PROTO_VERSION  1

/* Offsets (from beginning of the packet) of fields within the DLR Message
 * Payload Fields
 */
#define DLR_MPF_FRAME_TYPE       2
#define DLR_MPF_SOURCE_PORT      3
#define DLR_MPF_SOURCE_IP        4
#define DLR_MPF_SEQUENCE_ID      8

/* Offset for Beacon frames */
#define DLR_BE_RING_STATE              12
#define DLR_BE_SUPERVISOR_PRECEDENCE   13
#define DLR_BE_BEACON_INTERVAL         14
#define DLR_BE_BEACON_TIMEOUT          18
#define DLR_BE_RESERVED                22

/* Offset for Neighbor_Check_Request frames */
#define DLR_NREQ_RESERVED     12

/* Offset for Neighbor_Check_Response frames */
#define DLR_NRES_SOURCE_PORT  12
#define DLR_NRES_RESERVED     13

/* Offset for Link_Status/Neighbor_Status frames */
#define DLR_LNS_SOURCE_PORT   12
#define DLR_LNS_RESERVED      13

/* Offset for Locate_Fault frames */
#define DLR_LF_RESERVED     12

/* Offset for Announce frames */
#define DLR_AN_RING_STATE   12
#define DLR_AN_RESERVED     13

/* Offset for Sign_On frames */
#define DLR_SO_NUM_NODES    12
#define DLR_SO_NODE_1_MAC   14

/* DLR commmands */
#define DLR_FT_BEACON            1
#define DLR_FT_NEIGHBOR_REQ      2
#define DLR_FT_NEIGHBOR_RES      3
#define DLR_FT_LINK_STAT         4
#define DLR_FT_LOCATE_FLT        5
#define DLR_FT_ANNOUNCE          6
#define DLR_FT_SIGN_ON           7


typedef struct {
   guint32 req_num, rep_num;
   nstime_t req_time;
   cip_req_info_t* cip_info;
} enip_request_info_t;

void enip_open_cip_connection( packet_info *pinfo, cip_conn_info_t* connInfo);
void enip_close_cip_connection( packet_info *pinfo, guint16 ConnSerialNumber, guint16 VendorID, guint32 DeviceSerialNumber );

extern attribute_info_t enip_attribute_vals[29];
