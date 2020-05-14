/* packet-enip.h
 * Routines for EtherNet/IP (Industrial Protocol) dissection
 * EtherNet/IP Home: www.odva.org
 *
 * Conversation data support for CIP
 *   Jan Bartels, Siempelkamp Maschinen- und Anlagenbau GmbH & Co. KG
 *   Copyright 2007
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ENIP_H
#define PACKET_ENIP_H

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

/* Offset for Advertise frames */
#define DLR_ADV_GATEWAY_STATE          12
#define DLR_ADV_GATEWAY_PRECEDENCE     13
#define DLR_ADV_ADVERTISE_INTERVAL     14
#define DLR_ADV_ADVERTISE_TIMEOUT      18
#define DLR_ADV_LEARNING_UPDATE_ENABLE 22
#define DLR_ADV_RESERVED               23

/* Offset for Advertise frames */
#define DLR_FLUSH_LEARNING_UPDATE_ENABLE  12
#define DLR_FLUSH_RESERVED                13

/* Offset for Advertise frames */
#define DLR_LEARN_RESERVED             12

/* DLR commands */
#define DLR_FT_BEACON            1
#define DLR_FT_NEIGHBOR_REQ      2
#define DLR_FT_NEIGHBOR_RES      3
#define DLR_FT_LINK_STAT         4
#define DLR_FT_LOCATE_FLT        5
#define DLR_FT_ANNOUNCE          6
#define DLR_FT_SIGN_ON           7
#define DLR_FT_ADVERTISE         8
#define DLR_FT_FLUSH_TABLES      9
#define DLR_FT_LEARNING_UPDATE  10


typedef struct {
   guint32 req_num, rep_num;
   nstime_t req_time;
   cip_req_info_t* cip_info;
} enip_request_info_t;

typedef struct enip_conn_val {
   guint32 O2TConnID;
   guint32 T2OConnID;
   cip_connection_triad_t triad;
   guint8  TransportClass_trigger;
   guint32 open_frame;
   guint32 open_reply_frame;
   guint32 close_frame;
   guint32 connid;
   cip_safety_epath_info_t safety;
   guint32 ClassID;
   guint32 ConnPoint;

   guint32 FwdOpenPathLenBytes;
   void *pFwdOpenPathData;
   guint32 O2Tapi;
   guint32 T2Oapi;
} enip_conn_val_t;

enum enip_connid_type {ECIDT_UNKNOWN, ECIDT_O2T, ECIDT_T2O};

typedef struct cip_io_data_input {
   enip_conn_val_t* conn_info;
   enum enip_connid_type connid_type;
} cip_io_data_input;

/* proto_data types */
#define ENIP_REQUEST_INFO     0
#define ENIP_CONNECTION_INFO  1

void enip_close_cip_connection(packet_info *pinfo, const cip_connection_triad_t* triad);
void enip_mark_connection_triad(packet_info *pinfo, const cip_connection_triad_t* triad);

extern attribute_info_t enip_attribute_vals[103];

#endif /* PACKET_ENIP_H */
