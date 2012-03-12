/* packet-btsdp.h
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

#ifndef __PACKET_BTSDP_H__
#define __PACKET_BTSDP_H__

/* protocol UUIDs */
#define BTSDP_SDP_PROTOCOL_UUID                 0x0001
#define BTSDP_RFCOMM_PROTOCOL_UUID              0x0003
#define BTSDP_BNEP_PROTOCOL_UUID                0x000f
#define BTSDP_HIDP_PROTOCOL_UUID                0x0011
#define BTSDP_AVCTP_PROTOCOL_UUID               0x0017
#define BTSDP_AVDTP_PROTOCOL_UUID               0x0019
#define BTSDP_L2CAP_PROTOCOL_UUID               0x0100
/* service UUIDs */
#define BTSDP_SPP_SERVICE_UUID                  0x1101
#define BTSDP_DUN_SERVICE_UUID                  0x1103
#define BTSDP_OPP_SERVICE_UUID                  0x1105
#define BTSDP_FTP_SERVICE_UUID                  0x1106
#define BTSDP_HSP_SERVICE_UUID                  0x1108
#define BTSDP_PAN_PANU_SERVICE_UUID             0x1115
#define BTSDP_PAN_NAP_SERVICE_UUID              0x1116
#define BTSDP_PAN_GN_SERVICE_UUID               0x1117
#define BTSDP_BIP_SERVICE_UUID                  0x111a
#define BTSDP_BIP_RESPONDER_SERVICE_UUID        0x111b
#define BTSDP_BIP_AUTO_ARCH_SERVICE_UUID        0x111c
#define BTSDP_BIP_REF_OBJ_SERVICE_UUID          0x111d
#define BTSDP_HFP_SERVICE_UUID                  0x111e
#define BTSDP_HFP_GW_SERVICE_UUID               0x111f
#define BTSDP_BPP_SERVICE_UUID                  0x1122
#define BTSDP_BPP_STATUS_SERVICE_UUID           0x1123
#define BTSDP_SAP_SERVICE_UUID                  0x112d
#define BTSDP_PBAP_PCE_SERVICE_UUID             0x112e
#define BTSDP_PBAP_PSE_SERVICE_UUID             0x112f
#define BTSDP_PBAP_SERVICE_UUID                 0x1130
#define BTSDP_MAP_ACCESS_SRV_SERVICE_UUID       0x1132
#define BTSDP_MAP_NOIYFY_SRV_SERVICE_UUID       0x1133
#define BTSDP_MAP_SERVICE_UUID                  0x1134
#define BTSDP_HDP_SERVICE_UUID                  0x1400

#define BTSDP_LOCAL_SERVICE_FLAG_MASK           0x0001
#define BTSDP_SECONDARY_CHANNEL_FLAG_MASK       0x0002

/* This structure is passed to other dissectors through the tap interface
 * and contains information about the relation between service, PSM/server
 * channel, local/remote service. The btrfcomm and btl2cap dissectors
 * need this information to determine the kind of data transfered on
 * dynamically assigned server channels and PSM's, respectively.
 */
typedef struct _btsdp_data_t {
    guint32         service;    /* service UUID, see below */
    guint32         channel;    /* rfcomm server channel or PSM */
    guint16         protocol;   /* either rfcomm or l2cap UUID */
    guint16         flags;      /* indicate if the service is local or remote
                                   (peer device) and/or a secondary PSM */
} btsdp_data_t;

extern value_string_ext vs_service_classes_ext;

#endif
