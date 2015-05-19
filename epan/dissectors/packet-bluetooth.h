/* packet-bluetooth.h
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

#ifndef __PACKET_BLUETOOTH_H__
#define __PACKET_BLUETOOTH_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <epan/wmem/wmem.h>

#include "packet-usb.h"
#include "packet-ubertooth.h"

#define PROTO_DATA_BLUETOOTH_SERVICE_UUID  0

#define BLUETOOTH_DATA_SRC 0
#define BLUETOOTH_DATA_DST 1

#define HCI_H4_TYPE_CMD   0x01
#define HCI_H4_TYPE_ACL   0x02
#define HCI_H4_TYPE_SCO   0x03
#define HCI_H4_TYPE_EVT   0x04

#define HCI_OGF_LINK_CONTROL           0x01
#define HCI_OGF_LINK_POLICY            0x02
#define HCI_OGF_HOST_CONTROLLER        0x03
#define HCI_OGF_INFORMATIONAL          0x04
#define HCI_OGF_STATUS                 0x05
#define HCI_OGF_TESTING                0x06
#define HCI_OGF_LOW_ENERGY             0x08
#define HCI_OGF_LOGO_TESTING           0x3e
#define HCI_OGF_VENDOR_SPECIFIC        0x3f

#define HCI_VENDOR_DEFAULT  0

#define DID_VENDOR_ID_SOURCE_BLUETOOTH_SIG  1
#define DID_VENDOR_ID_SOURCE_USB_FORUM      2

#define ACCESS_ADDRESS_ADVERTISING 0x8e89bed6

extern int proto_bluetooth;

extern const value_string bluetooth_address_type_vals[];

#define STATUS_SUCCESS 0x00

#define UUID_GATT_PRIMARY_SERVICE_DECLARATION    0x2800
#define UUID_GATT_SECONDARY_SERVICE_DECLARATION  0x2801
#define UUID_GATT_INCLUDE_DECLARATION            0x2802
#define UUID_GATT_CHARACTERISTIC_DECLARATION     0x2803

/* We support Bluetooth over various interfaces, interface_id and adapter_id
   is used to decode further payload. Case: there is a host. Host has X
   interfaces. Each interface has Y adapter. Each adapter has ACL handle or
   L2CAP CID. ACL handle has L2CAP CID and/or L2CAP PSM. L2CAP CID or
   L2CAP PSM has RFCOMM channel or other end-protocol like OBEX, AVRCP, HID,
   AVDTP, BNEP etc. RFCOMM channel has end-protocol like OBEX, HFP, etc.
   Important note: correct payload decoding should store needed data using
   key contain interface_id, adapter_id, ..., last_channel_type (for example
   RFCOMM channel, transaction_id, frame number etc. )

   interface_id - interface id provided by Wireshark, see "frame.interface_id",
                  in case where is only one interface id HCI_INTERFACE_DEFAULT
                  is used (for example open BTSNOOP file with HCI H4 protocol)
   adapter_id   - identified Bluetooth device (interface, for example Linux
                  hci0, hci1, etc.)
*/
#define HCI_INTERFACE_DEFAULT  0
#define HCI_ADAPTER_DEFAULT    0

typedef enum {
    BT_PD_NONE,           /* no protocol data */
    BT_PD_BTHCI,          /* struct bthci_phdr * */
    BT_PD_BTMON,          /* struct btmon_phdr * */
    BT_PD_USB_CONV_INFO,  /* usb_conv_info_t * */
    BT_PD_UBERTOOTH_DATA  /* ubertooth_data_t * */
} bt_protocol_data_type;

/* chandle_sessions:         interface_id + adapter_id + connection_handle + frame_number -> connect_in_frame, disconnect_in_frame */
/* chandle_to_bdaddr:        interface_id + adapter_id + connection_handle + frame_number -> bd_addr[6] */
/* chandle_to_mode:          interface_id + adapter_id + connection_handle + frame_number -> mode */
/* bdaddr_to_name:           bd_addr[6] + frame_number -> name */
/* bdaddr_to_role:           bd_addr[6] + frame_number -> role */
/* localhost_bdaddr:         interface_id + adapter_id + frame_number -> bd_addr[6] */
/* localhost_name:           interface_id + adapter_id + frame_number -> name */
typedef struct _bluetooth_data_t {
    guint32      interface_id;
    guint32      adapter_id;
    guint32     *adapter_disconnect_in_frame;
    wmem_tree_t *chandle_sessions;
    wmem_tree_t *chandle_to_bdaddr;
    wmem_tree_t *chandle_to_mode;
    wmem_tree_t *bdaddr_to_name;
    wmem_tree_t *bdaddr_to_role;
    wmem_tree_t *localhost_bdaddr;
    wmem_tree_t *localhost_name;
    wmem_tree_t *hci_vendors;

    bt_protocol_data_type  previous_protocol_data_type;
    union {
        void              *none;
        struct bthci_phdr *bthci;
        struct btmon_phdr *btmon;
        usb_conv_info_t   *usb_conv_info;
        ubertooth_data_t  *ubertooth_data;
    } previous_protocol_data;

} bluetooth_data_t;

typedef struct _chandle_session_t {
    guint32  connect_in_frame;
    guint32  disconnect_in_frame;
} chandle_session_t;

typedef struct _remote_bdaddr_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint16  chandle;
    guint8   bd_addr[6];
} remote_bdaddr_t;

typedef struct _device_name_t {
    guint32  bd_addr_oui;
    guint32  bd_addr_id;
    gchar    *name;
} device_name_t;

typedef struct _device_role_t {
    guint32  role;
    guint32  change_in_frame;
} device_role_t;

typedef struct _connection_mode_t {
    gint32   mode;
    guint32  change_in_frame;
} connection_mode_t;

#define ROLE_UNKNOWN  0
#define ROLE_MASTER   1
#define ROLE_SLAVE    2

typedef struct _localhost_bdaddr_entry_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint8   bd_addr[6];
} localhost_bdaddr_entry_t;

typedef struct _localhost_name_entry_t {
    guint32  interface_id;
    guint32  adapter_id;
    gchar    *name;
} localhost_name_entry_t;

typedef struct _bluetooth_tap_data_t {
    guint32  interface_id;
    guint32  adapter_id;
} bluetooth_tap_data_t;

typedef struct _hci_vendor_data_t {
    guint16                     manufacturer;
    guint16                     hci_revision;
    guint16                     lmp_subversion;
    guint32                     change_in_frame;
    struct _hci_vendor_data_t  *previous;
} hci_vendor_data_t;

typedef struct _uuid_t {
    guint16  bt_uuid;
    guint8   size;
    guint8   data[16];
} bluetooth_uuid_t;

enum bluetooth_device_type {
    BLUETOOTH_DEVICE_BD_ADDR,
    BLUETOOTH_DEVICE_NAME,
    BLUETOOTH_DEVICE_LOCAL_ADAPTER,
    BLUETOOTH_DEVICE_LOCAL_VERSION,
    BLUETOOTH_DEVICE_REMOTE_VERSION,
    BLUETOOTH_DEVICE_RESET,
    BLUETOOTH_DEVICE_SCAN,
    BLUETOOTH_DEVICE_VOICE_SETTING,
    BLUETOOTH_DEVICE_AUTHENTICATION,
    BLUETOOTH_DEVICE_ENCRYPTION,
    BLUETOOTH_DEVICE_CLASS_OF_DEVICE,
    BLUETOOTH_DEVICE_SIMPLE_PAIRING_MODE,
    BLUETOOTH_DEVICE_PAGE_TIMEOUT,
    BLUETOOTH_DEVICE_INQUIRY_MODE,
    BLUETOOTH_DEVICE_MTUS,
    BLUETOOTH_DEVICE_LE_MTU
};

typedef struct _bluetooth_device_tap_t {
    guint32                     interface_id;
    guint32                     adapter_id;

    gboolean                    is_local;
    gboolean                    has_bd_addr;
    guint8                      bd_addr[6];
    enum bluetooth_device_type  type;
    union {
        char  *name;
        struct {
            guint8   hci_version;
            guint16  hci_revision;
            guint8   lmp_version;
            guint16  lmp_subversion;
            guint16  manufacturer;
        } local_version;
        struct {
            guint8   lmp_version;
            guint16  lmp_subversion;
            guint16  manufacturer;
        } remote_version;
        guint8   scan;
        guint16  page_timeout;
        guint8   authentication;
        guint8   encryption;
        guint32  class_of_device;
        guint16  voice_setting;
        guint8   simple_pairing_mode;
        guint8   inquiry_mode;
        struct {
            guint16  acl_mtu;
            guint8   sco_mtu;
            guint16  acl_packets;
            guint16  sco_packets;
        } mtus;
        struct {
            guint16  acl_mtu;
            guint16  acl_packets;
        } le_mtus;
    } data;
} bluetooth_device_tap_t;

enum bluetooth_hci_summary_type {
    BLUETOOTH_HCI_SUMMARY_OPCODE,
    BLUETOOTH_HCI_SUMMARY_EVENT_OPCODE,
    BLUETOOTH_HCI_SUMMARY_EVENT,
    BLUETOOTH_HCI_SUMMARY_VENDOR_OPCODE,
    BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT_OPCODE,
    BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT,
    BLUETOOTH_HCI_SUMMARY_STATUS,
    BLUETOOTH_HCI_SUMMARY_STATUS_PENDING,
    BLUETOOTH_HCI_SUMMARY_REASON,
    BLUETOOTH_HCI_SUMMARY_HARDWARE_ERROR
};

typedef struct _bluetooth_hci_summary_tap_t {
    guint32                          interface_id;
    guint32                          adapter_id;

    guint16                          ocf;
    guint8                           ogf;
    guint8                           event;
    guint8                           status;
    guint8                           reason;
    guint8                           hardware_error;

    const gchar                     *name;
    enum bluetooth_hci_summary_type  type;
} bluetooth_hci_summary_tap_t;

typedef struct _bluetooth_eir_ad_data_t {
    guint32           interface_id;
    guint32           adapter_id;

    guint8           *bd_addr;
} bluetooth_eir_ad_data_t;


extern int bluetooth_device_tap;
extern int bluetooth_hci_summary_tap;

WS_DLL_PUBLIC const value_string   bluetooth_uuid_vals[];

extern dissector_table_t  bluetooth_uuid_table;

WS_DLL_PUBLIC wmem_tree_t *bluetooth_uuids;

WS_DLL_PUBLIC value_string_ext  bluetooth_uuid_vals_ext;
WS_DLL_PUBLIC value_string_ext  bluetooth_company_id_vals_ext;
extern guint32           max_disconnect_in_frame;

extern gint dissect_bd_addr(gint hf_bd_addr, packet_info *pinfo, proto_tree *tree,
        tvbuff_t *tvb, gint offset, gboolean is_local_bd_addr,
        guint32 interface_id, guint32 adapter_id, guint8 *bdaddr);

extern bluetooth_uuid_t  get_uuid(tvbuff_t *tvb, gint offset, gint size);
WS_DLL_PUBLIC const gchar  *print_uuid(bluetooth_uuid_t *uuid);
WS_DLL_PUBLIC const gchar  *print_numeric_uuid(bluetooth_uuid_t *uuid);

extern void save_local_device_name_from_eir_ad(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, guint8 size, bluetooth_data_t *bluetooth_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
