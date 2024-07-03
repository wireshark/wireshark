/* packet-bluetooth.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BLUETOOTH_H__
#define __PACKET_BLUETOOTH_H__

#include <epan/wmem_scopes.h>

#include "packet-usb.h"
#include "packet-ubertooth.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define PROTO_DATA_BLUETOOTH_SERVICE_UUID  0

#define BLUETOOTH_DATA_SRC 0
#define BLUETOOTH_DATA_DST 1

#define HCI_H4_TYPE_CMD   0x01
#define HCI_H4_TYPE_ACL   0x02
#define HCI_H4_TYPE_SCO   0x03
#define HCI_H4_TYPE_EVT   0x04
#define HCI_H4_TYPE_ISO   0x05

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
/* shandle_to_chandle:       interface_id + adapter_id + stream_handle + frame_number -> connection_handle */
/* bdaddr_to_name:           bd_addr[6] + frame_number -> name */
/* bdaddr_to_role:           bd_addr[6] + frame_number -> role */
/* localhost_bdaddr:         interface_id + adapter_id + frame_number -> bd_addr[6] */
/* localhost_name:           interface_id + adapter_id + frame_number -> name */
typedef struct _bluetooth_data_t {
    uint32_t     interface_id;
    uint32_t     adapter_id;
    uint32_t    *adapter_disconnect_in_frame;
    wmem_tree_t *chandle_sessions;
    wmem_tree_t *chandle_to_bdaddr;
    wmem_tree_t *chandle_to_mode;
    wmem_tree_t *shandle_to_chandle;
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

#define BT_LINK_TYPE_UNKNOWN 0
#define BT_LINK_TYPE_ACL     1
#define BT_LINK_TYPE_SCO     2
#define BT_LINK_TYPE_LL      3
#define BT_LINK_TYPE_ISO     4

typedef struct _chandle_session_t {
    uint32_t connect_in_frame;
    uint32_t disconnect_in_frame;
    uint32_t link_type;
} chandle_session_t;

typedef struct _remote_bdaddr_t {
    uint32_t interface_id;
    uint32_t adapter_id;
    uint16_t chandle;
    uint8_t  bd_addr[6];
} remote_bdaddr_t;

typedef struct _device_name_t {
    uint32_t bd_addr_oui;
    uint32_t bd_addr_id;
    char     *name;
} device_name_t;

typedef struct _device_role_t {
    uint32_t role;
    uint32_t change_in_frame;
} device_role_t;

typedef struct _connection_mode_t {
    int32_t  mode;
    uint32_t change_in_frame;
} connection_mode_t;

typedef struct _stream_connection_handle_pair_t {
    int32_t  chandle;
    uint32_t change_in_frame;
} stream_connection_handle_pair_t;

#define ROLE_UNKNOWN    0
#define ROLE_CENTRAL    1
#define ROLE_PERIPHERAL 2

typedef struct _localhost_bdaddr_entry_t {
    uint32_t interface_id;
    uint32_t adapter_id;
    uint8_t  bd_addr[6];
} localhost_bdaddr_entry_t;

typedef struct _localhost_name_entry_t {
    uint32_t interface_id;
    uint32_t adapter_id;
    char     *name;
} localhost_name_entry_t;

typedef struct _bluetooth_tap_data_t {
    uint32_t interface_id;
    uint32_t adapter_id;
} bluetooth_tap_data_t;

typedef struct _hci_vendor_data_t {
    uint16_t                    manufacturer;
    uint16_t                    hci_revision;
    uint16_t                    lmp_subversion;
    uint32_t                    change_in_frame;
    struct _hci_vendor_data_t  *previous;
} hci_vendor_data_t;

typedef struct _uuid_t {
    uint16_t bt_uuid;
    uint8_t  size;
    uint8_t  data[16];
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
    uint32_t                    interface_id;
    uint32_t                    adapter_id;

    bool                        is_local;
    bool                        has_bd_addr;
    uint8_t                     bd_addr[6];
    enum bluetooth_device_type  type;
    union {
        char  *name;
        struct {
            uint8_t  hci_version;
            uint16_t hci_revision;
            uint8_t  lmp_version;
            uint16_t lmp_subversion;
            uint16_t manufacturer;
        } local_version;
        struct {
            uint8_t  lmp_version;
            uint16_t lmp_subversion;
            uint16_t manufacturer;
        } remote_version;
        uint8_t  scan;
        uint16_t page_timeout;
        uint8_t  authentication;
        uint8_t  encryption;
        uint32_t class_of_device;
        uint16_t voice_setting;
        uint8_t  simple_pairing_mode;
        uint8_t  inquiry_mode;
        struct {
            uint16_t acl_mtu;
            uint8_t  sco_mtu;
            uint16_t acl_packets;
            uint16_t sco_packets;
        } mtus;
        struct {
            uint16_t acl_mtu;
            uint16_t iso_mtu;
            uint16_t acl_packets;
            uint16_t iso_packets;
        } le_mtus;
    } data;
} bluetooth_device_tap_t;

enum bluetooth_hci_summary_type {
    BLUETOOTH_HCI_SUMMARY_OPCODE,
    BLUETOOTH_HCI_SUMMARY_EVENT_OPCODE,
    BLUETOOTH_HCI_SUMMARY_EVENT,
    BLUETOOTH_HCI_SUMMARY_SUBEVENT,
    BLUETOOTH_HCI_SUMMARY_VENDOR_OPCODE,
    BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT_OPCODE,
    BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT,
    BLUETOOTH_HCI_SUMMARY_STATUS,
    BLUETOOTH_HCI_SUMMARY_STATUS_PENDING,
    BLUETOOTH_HCI_SUMMARY_REASON,
    BLUETOOTH_HCI_SUMMARY_HARDWARE_ERROR
};

typedef struct _bluetooth_hci_summary_tap_t {
    uint32_t                         interface_id;
    uint32_t                         adapter_id;

    uint16_t                         ocf;
    uint8_t                          ogf;
    uint8_t                          event;
    uint8_t                          subevent;
    uint8_t                          status;
    uint8_t                          reason;
    uint8_t                          hardware_error;

    const char                      *name;
    enum bluetooth_hci_summary_type  type;
} bluetooth_hci_summary_tap_t;

typedef struct _bluetooth_eir_ad_data_t {
    uint32_t          interface_id;
    uint32_t          adapter_id;

    uint8_t          *bd_addr;
} bluetooth_eir_ad_data_t;


extern int bluetooth_device_tap;
extern int bluetooth_hci_summary_tap;

WS_DLL_PUBLIC const value_string   bluetooth_uuid_vals[];

extern dissector_table_t  bluetooth_uuid_table;

WS_DLL_PUBLIC wmem_tree_t *bluetooth_uuids;

WS_DLL_PUBLIC value_string_ext  bluetooth_uuid_vals_ext;
WS_DLL_PUBLIC value_string_ext  bluetooth_company_id_vals_ext;
extern uint32_t          bluetooth_max_disconnect_in_frame;

extern int dissect_bd_addr(int hf_bd_addr, packet_info *pinfo, proto_tree *tree,
        tvbuff_t *tvb, int offset, bool is_local_bd_addr,
        uint32_t interface_id, uint32_t adapter_id, uint8_t *bdaddr);

extern void bluetooth_unit_1p25_ms(char *buf, uint32_t value);
extern void bluetooth_unit_0p125_ms(char *buf, uint32_t value);

extern bluetooth_uuid_t  get_bluetooth_uuid(tvbuff_t *tvb, int offset, int size);
WS_DLL_PUBLIC const char   *print_bluetooth_uuid(wmem_allocator_t *pool, bluetooth_uuid_t *uuid);
WS_DLL_PUBLIC const char   *print_numeric_bluetooth_uuid(wmem_allocator_t *pool, bluetooth_uuid_t *uuid);

extern void save_local_device_name_from_eir_ad(tvbuff_t *tvb, int offset,
        packet_info *pinfo, uint8_t size, bluetooth_data_t *bluetooth_data);

WS_DLL_PUBLIC bluetooth_data_t *
dissect_bluetooth_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
