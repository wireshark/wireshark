/* packet-btsdp.h
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

#ifndef __PACKET_BTSDP_H__
#define __PACKET_BTSDP_H__

#include "packet-bluetooth.h"

/*
 * Based on value provided by Bluetooth SIG:
 * https://www.bluetooth.org/Technical/AssignedNumbers/service_discovery.htm
 */
/* protocol UUIDs */
#define BTSDP_SDP_PROTOCOL_UUID                         0x0001
#define BTSDP_UDP_PROTOCOL_UUID                         0x0002
#define BTSDP_RFCOMM_PROTOCOL_UUID                      0x0003
#define BTSDP_TCP_PROTOCOL_UUID                         0x0004
#define BTSDP_TCS_BIN_PROTOCOL_UUID                     0x0005
#define BTSDP_TCS_AT_PROTOCOL_UUID                      0x0006
#define BTSDP_ATT_PROTOCOL_UUID                         0x0007
#define BTSDP_OBEX_PROTOCOL_UUID                        0x0008
#define BTSDP_IP_PROTOCOL_UUID                          0x0009
#define BTSDP_FTP_PROTOCOL_UUID                         0x000A
#define BTSDP_HTTP_PROTOCOL_UUID                        0x000C
#define BTSDP_WSP_PROTOCOL_UUID                         0x000E
#define BTSDP_BNEP_PROTOCOL_UUID                        0x000F
#define BTSDP_UPNP_PROTOCOL_UUID                        0x0010
#define BTSDP_HIDP_PROTOCOL_UUID                        0x0011
#define BTSDP_HARDCOPY_CONTROL_CHANNEL_PROTOCOL_UUID    0x0012
#define BTSDP_HARDCOPY_DATA_CHANNEL_PROTOCOL_UUID       0x0014
#define BTSDP_HARDCOPY_NOTIFICATION_PROTOCOL_UUID       0x0016
#define BTSDP_AVCTP_PROTOCOL_UUID                       0x0017
#define BTSDP_AVDTP_PROTOCOL_UUID                       0x0019
#define BTSDP_CMTP_PROTOCOL_UUID                        0x001B
#define BTSDP_MCAP_CONTROL_CHANNEL_PROTOCOL_UUID        0x001E
#define BTSDP_MCAP_DATA_CHANNEL_PROTOCOL_UUID           0x001F
#define BTSDP_L2CAP_PROTOCOL_UUID                       0x0100

/* service UUIDs */
#define BTSDP_SPP_SERVICE_UUID                          0x1101
#define BTSDP_LAN_SERVICE_UUID                          0x1102
#define BTSDP_DUN_SERVICE_UUID                          0x1103
#define BTSDP_SYNC_SERVICE_UUID                         0x1104
#define BTSDP_OPP_SERVICE_UUID                          0x1105
#define BTSDP_FTP_SERVICE_UUID                          0x1106
#define BTSDP_SYNC_COMMAND_SERVICE_UUID                 0x1107
#define BTSDP_HSP_SERVICE_UUID                          0x1108
#define BTSDP_CTP_SERVICE_UUID                          0x1109

#define BTSDP_A2DP_SOURCE_SERVICE_UUID                  0x110A
#define BTSDP_A2DP_SINK_SERVICE_UUID                    0x110B
#define BTSDP_AVRCP_TG_SERVICE_UUID                     0x110C
#define BTSDP_A2DP_DISTRIBUTION_SERVICE_UUID            0x110D
#define BTSDP_AVRCP_SERVICE_UUID                        0x110E
#define BTSDP_AVRCP_CT_SERVICE_UUID                     0x110F

#define BTSDP_ICP_SERVICE_UUID                          0x1110
#define BTSDP_FAX_SERVICE_UUID                          0x1111
#define BTSDP_HSP_GW_SERVICE_UUID                       0x1112
#define BTSDP_WAP_SERVICE_UUID                          0x1113
#define BTSDP_WAP_CLIENT_SERVICE_UUID                   0x1114

#define BTSDP_PAN_PANU_SERVICE_UUID                     0x1115
#define BTSDP_PAN_NAP_SERVICE_UUID                      0x1116
#define BTSDP_PAN_GN_SERVICE_UUID                       0x1117

#define BTSDP_BPP_DIRECT_PRINTING_SERVICE_UUID          0x1118
#define BTSDP_BPP_REFERENCE_PRINTING_SERVICE_UUID       0x1119

#define BTSDP_BIP_SERVICE_UUID                          0x111A
#define BTSDP_BIP_RESPONDER_SERVICE_UUID                0x111B
#define BTSDP_BIP_AUTO_ARCH_SERVICE_UUID                0x111C
#define BTSDP_BIP_REF_OBJ_SERVICE_UUID                  0x111D

#define BTSDP_HFP_SERVICE_UUID                          0x111E
#define BTSDP_HFP_GW_SERVICE_UUID                       0x111F

#define BTSDP_BPP_DIRECT_PRINTING_REF_OBJ_SERVICE_UUID  0x1120
#define BTSDP_BPP_REFLECTED_UI_SERVICE_UUID             0x1121
#define BTSDP_BPP_SERVICE_UUID                          0x1122
#define BTSDP_BPP_STATUS_SERVICE_UUID                   0x1123

#define BTSDP_HID_SERVICE_UUID                          0x1124

#define BTSDP_HCRP_SERVICE_UUID                         0x1125
#define BTSDP_HCRP_PRINT_SERVICE_UUID                   0x1126
#define BTSDP_HCRP_SCAN_SERVICE_UUID                    0x1127

#define BTSDP_CIP_SERVICE_UUID                          0x1128

#define BTSDP_VIDEO_CONFERENCING_GW_SERVICE_UUID        0x1129 /* not assigned*/

#define BTSDP_UDI_MT_SERVICE_UUID                       0x112A /* not assigned*/
#define BTSDP_UDI_TA_SERVICE_UUID                       0x112B /* not assigned*/

#define BTSDP_AUDIO_VIDEO_SERVICE_UUID                  0x112C /* not assigned*/

#define BTSDP_SAP_SERVICE_UUID                          0x112D

#define BTSDP_PBAP_PCE_SERVICE_UUID                     0x112E
#define BTSDP_PBAP_PSE_SERVICE_UUID                     0x112F
#define BTSDP_PBAP_SERVICE_UUID                         0x1130

#define BTSDP_HSP_HS_SERVICE_UUID                       0x1131

#define BTSDP_MAP_ACCESS_SRV_SERVICE_UUID               0x1132
#define BTSDP_MAP_NOTIFICATION_SRV_SERVICE_UUID         0x1133
#define BTSDP_MAP_SERVICE_UUID                          0x1134

#define BTSDP_GNSS_UUID                                 0x1135
#define BTSDP_GNSS_SERVER_UUID                          0x1136

#define BTSDP_3D_DISPLAY_UUID                           0x1137
#define BTSDP_3D_GLASSES_UUID                           0x1138
#define BTSDP_3D_SYNCHRONIZATION_UUID                   0x1139

#define BTSDP_MULTI_PROFILE_UUID                        0x113A
#define BTSDP_MULTI_PROFILE_SC_UUID                     0x113B

#define BTSDP_CTN_ACCESS_SERVICE_UUID                   0x113C
#define BTSDP_CTN_NOTIFICATION_SERVICE_UUID             0x113D
#define BTSDP_CTN_SERVICE_UUID                          0x113E

#define BTSDP_DID_SERVICE_UUID                          0x1200

#define BTSDP_GENERIC_NETWORKING_SERVICE_UUID           0x1201
#define BTSDP_GENERIC_FILE_TRANSFER_SERVICE_UUID        0x1202
#define BTSDP_GENERIC_AUDIO_SERVICE_UUID                0x1203
#define BTSDP_GENERIC_TELEPHONY_SERVICE_UUID            0x1204

#define BTSDP_ESDP_UPNP_SERVICE_SERVICE_UUID            0x1205
#define BTSDP_ESDP_UPNP_IP_SERVICE_SERVICE_UUID         0x1206
#define BTSDP_ESDP_UPNP_IP_PAN_SERVICE_UUID             0x1300
#define BTSDP_ESDP_UPNP_IP_LAP_SERVICE_UUID             0x1301
#define BTSDP_ESDP_UPNP_L2CAP_SERVICE_UUID              0x1302

#define BTSDP_VDP_SOURCE_SERVICE_UUID                   0x1303
#define BTSDP_VDP_SINK_SERVICE_UUID                     0x1304
#define BTSDP_VDP_DISTRIBUTION_SERVICE_UUID             0x1305

#define BTSDP_HDP_SERVICE_UUID                          0x1400
#define BTSDP_HDP_SOURCE_SERVICE_UUID                   0x1401
#define BTSDP_HDP_SINK_SERVICE_UUID                     0x1402

#define BTSDP_LOCAL_SERVICE_FLAG_MASK                   0x0001
#define BTSDP_SECONDARY_CHANNEL_FLAG_MASK               0x0002

#define SDP_PSM_DEFAULT  1

/* This structure is passed to other dissectors
 * and contains information about the relation between service, PSM/server
 * channel, local/remote service. The btrfcomm and btl2cap dissectors
 * need this information to determine the kind of data transferred on
 * dynamically assigned server channels and PSM's, respectively.
 */
typedef struct _btsdp_data_t {
    guint32    interface_id;
    guint32    adapter_id;
    guint32    chandle;
    guint32    frame_number;
    guint32    service;    /* service UUID, see below */
    guint32    channel;    /* rfcomm server channel or PSM */
    guint16    protocol;   /* either rfcomm or l2cap UUID */
    guint16    flags;      /* indicate if the service is local or remote
                              peer device) and/or a secondary PSM */
} btsdp_data_t;


typedef struct _service_info_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint32  sdp_psm;
    guint32  direction;
    guint32  bd_addr_oui;
    guint32  bd_addr_id;
    guint32  type;
    guint32  channel;

    bluetooth_uuid_t uuid;
    gint     protocol_order; /* main service protocol has 0, goep -1, additional protocol 1, 2... */
    gint     protocol;

    void    *data;        /* Used to transfer service record data to profiles */

    struct _service_info_t *parent_info;
} service_info_t;

extern const value_string hid_country_code_vals[];

extern service_info_t* btsdp_get_service_info(wmem_tree_key_t* key);

#endif

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
