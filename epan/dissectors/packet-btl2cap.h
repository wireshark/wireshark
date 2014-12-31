/* packet-btl2cap.h
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

#ifndef __PACKET_BTL2CAP_H__
#define __PACKET_BTL2CAP_H__

#define BTL2CAP_PSM_SDP               0x0001
#define BTL2CAP_PSM_RFCOMM            0x0003
#define BTL2CAP_PSM_TCS_BIN           0x0005
#define BTL2CAP_PSM_TCS_BIN_CORDLESS  0x0007
#define BTL2CAP_PSM_BNEP              0x000f
#define BTL2CAP_PSM_HID_CTRL          0x0011
#define BTL2CAP_PSM_HID_INTR          0x0013
#define BTL2CAP_PSM_UPNP              0x0015
#define BTL2CAP_PSM_AVCTP_CTRL        0x0017
#define BTL2CAP_PSM_AVDTP             0x0019
#define BTL2CAP_PSM_AVCTP_BRWS        0x001b
#define BTL2CAP_PSM_UDI_C_PLANE       0x001d
#define BTL2CAP_PSM_ATT               0x001f
#define BTL2CAP_PSM_3DS               0x0021
#define BTL2CAP_PSM_LE_IPSP           0x0023

#define BTL2CAP_DYNAMIC_PSM_START   0x1000

#define BTL2CAP_FIXED_CID_NULL      0x0000
#define BTL2CAP_FIXED_CID_SIGNAL    0x0001
#define BTL2CAP_FIXED_CID_CONNLESS  0x0002
#define BTL2CAP_FIXED_CID_AMP_MAN   0x0003
#define BTL2CAP_FIXED_CID_ATT       0x0004
#define BTL2CAP_FIXED_CID_LE_SIGNAL 0x0005
#define BTL2CAP_FIXED_CID_SMP       0x0006
#define BTL2CAP_FIXED_CID_AMP_TEST  0x003F
#define BTL2CAP_FIXED_CID_LAST      0x003F

#define BTL2CAP_UNKNOWN_CID 0xFFFFFFFF

typedef struct _btl2cap_data_t {
    guint32   interface_id;
    guint32   adapter_id;
    guint32  *adapter_disconnect_in_frame;
    guint16   chandle;  /* only low 12 bits used */
    guint32  *hci_disconnect_in_frame;
    guint16   psm;
    guint32  *disconnect_in_frame;
    guint16   cid;
    guint32   local_cid;
    guint32   remote_cid;

    gboolean  is_local_psm; /* otherwise it is PSM in remote device */
    guint32   remote_bd_addr_oui;
    guint32   remote_bd_addr_id;
} btl2cap_data_t;

extern int proto_btl2cap;

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
