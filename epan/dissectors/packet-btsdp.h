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

/* service UUIDs */
static const value_string vs_service_classes[] = {
    {0x0001, "SDP"},
    {0x0002, "UDP"},
    {0x0003, "RFCOMM"},
    {0x0004, "TCP"},
    {0x0005, "TCS-BIN"},
    {0x0006, "TCS-AT"},
    {0x0008, "OBEX"},
    {0x0009, "IP"},
    {0x000A, "FTP"},
    {0x000C, "HTTP"},
    {0x000E, "WSP"},
    {0x000F, "BNEP"},
    {0x0010, "UPNP"},
    {0x0011, "HIDP"},
    {0x0012, "Hardcopy Control Channel"},
    {0x0014, "Hardcopy Data Channel"},
    {0x0016, "Hardcopy Notification"},
    {0x0017, "AVCTP"},
    {0x0019, "AVDTP"},
    {0x001B, "CMPT"},
    {0x001D, "UDI C-Plane"},
    {0x001E, "MCAP Control Channel"},
    {0x001F, "MCAP Data Channel"},
    {0x0100, "L2CAP"},
    {0x1000, "Service Discovery Server Service Class ID"},
    {0x1001, "Browse Group Descriptor Service Class ID"},
    {0x1002, "Public Browse Group"},
    {0x1101, "Serial Port"},
    {0x1102, "LAN Access Using PPP"},
    {0x1103, "Dialup Networking"},
    {0x1104, "IrMC Sync"},
    {0x1105, "OBEX Object Push"},
    {0x1106, "OBEX File Transfer"},
    {0x1107, "IrMC Sync Command"},
    {0x1108, "Headset"},
    {0x1109, "Cordless Telephony"},
    {0x110A, "Audio Source"},
    {0x110B, "Audio Sink"},
    {0x110C, "A/V Remote Control Target"},
    {0x110D, "Advanced Audio Distribution"},
    {0x110E, "A/V Remote Control"},
    {0x110F, "Video Conferencing"},
    {0x1110, "Intercom"},
    {0x1111, "Fax"},
    {0x1112, "Headset Audio Gateway"},
    {0x1113, "WAP"},
    {0x1114, "WAP client"},
    {0x1115, "PANU"},
    {0x1116, "NAP"},
    {0x1117, "GN"},
    {0x1118, "Direct Printing"},
    {0x1119, "Reference Printing"},
    {0x111A, "Imaging"},
    {0x111B, "Imaging Responder"},
    {0x111C, "Imaging Automatic Archive"},
    {0x111D, "Imaging Referenced Objects"},
    {0x111E, "Handsfree"},
    {0x111F, "Handsfree Audio Gateway"},
    {0x1120, "Direct Printing Reference Objects Service"},
    {0x1121, "Reflected UI"},
    {0x1122, "Basic Printing"},
    {0x1123, "Printing Status"},
    {0x1124, "Human Interface Device Service"},
    {0x1125, "Hardcopy Cable Replacement"},
    {0x1126, "HCR Print"},
    {0x1127, "HCR Scan"},
    {0x1128, "Common ISDN Access"},
    {0x1129, "Video Conferencing GW"},
    {0x112A, "UDI MT"},
    {0x112B, "UDI TA"},
    {0x112C, "Audio/Video"},
    {0x112D, "SIM Access"},
    {0x112E, "Phonebook Access client"},
    {0x112F, "Phonebook Access server"},
    {0x1130, "Phonebook Access Profile"},
    {0x1131, "Headset - HS"},
    {0x1132, "Message Access Server"},
    {0x1133, "Message Notification Server"},
    {0x1134, "Message Access Profile"},
    {0x1200, "PnP Information"},
    {0x1201, "Generic Networking"},
    {0x1202, "Generic File Transfer"},
    {0x1203, "Generic Audio"},
    {0x1204, "Generic Telephony"},
    {0x1205, "UPNP_Service"},
    {0x1206, "UPNP_IP_Service"},
    {0x1300, "ESDP_UPNP_IP_PAN"},
    {0x1301, "ESDP_UPNP_IP_LAP"},
    {0x1302, "ESDP_UPNP_L2CAP"},
    {0x1303, "Video Source"},
    {0x1304, "Video Sink"},
    {0x1305, "Video Distribution"},
    {0x1400, "Health Device Profile"},
    {0x1401, "Health Device Source"},
    {0x1402, "Health Device Sink"},
    {0, NULL}
};

#endif
