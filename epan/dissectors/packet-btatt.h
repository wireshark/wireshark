/* packet-btaatt.h
 * Headers for ATT
 *
 * Copyright 2015, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BTATT_H__
#define __PACKET_BTATT_H__

#include <epan/expert.h>
#include "packet-bluetooth.h"

#define ATT_OPCODE_ERROR_RESPONSE               0x01
#define ATT_OPCODE_EXCHANGE_MTU_REQUEST         0x02
#define ATT_OPCODE_EXCHANGE_MTU_RESPONSE        0x03
#define ATT_OPCODE_FIND_INFORMATION_REQUEST     0x04
#define ATT_OPCODE_FIND_INFORMATION_RESPONSE    0x05
#define ATT_OPCODE_FIND_BY_TYPE_VALUE_REQUEST   0x06
#define ATT_OPCODE_FIND_BY_TYPE_VALUE_RESPONSE  0x07

#define ATT_OPCODE_READ_BY_TYPE_REQUEST         0x08
#define ATT_OPCODE_READ_BY_TYPE_RESPONSE        0x09
#define ATT_OPCODE_READ_REQUEST                 0x0A
#define ATT_OPCODE_READ_RESPONSE                0x0B
#define ATT_OPCODE_READ_BLOB_REQUEST            0x0C
#define ATT_OPCODE_READ_BLOB_RESPONSE           0x0D
#define ATT_OPCODE_READ_MULTIPLE_REQUEST        0x0E
#define ATT_OPCODE_READ_MULTIPLE_RESPONSE       0x0F
#define ATT_OPCODE_READ_BY_GROUP_TYPE_REQUEST   0x10
#define ATT_OPCODE_READ_BY_GROUP_TYPE_RESPONSE  0x11

#define ATT_OPCODE_WRITE_REQUEST                0x12
#define ATT_OPCODE_WRITE_RESPONSE               0x13
#define ATT_OPCODE_WRITE_PREPARE_REQUEST        0x16
#define ATT_OPCODE_WRITE_PREPARE_RESPONSE       0x17
#define ATT_OPCODE_WRITE_EXECUTE_REQUEST        0x18
#define ATT_OPCODE_WRITE_EXECUTE_RESPONSE       0x19
#define ATT_OPCODE_WRITE_COMMAND                0x52
#define ATT_OPCODE_WRITE_SIGNED_COMMAND         0xD2

#define ATT_OPCODE_HANDLE_VALUE_NOTIFICATION    0x1B
#define ATT_OPCODE_HANDLE_VALUE_INDICATION      0x1D
#define ATT_OPCODE_HANDLE_VALUE_CONFIRMATION    0x1E

typedef struct _btatt_data_t {
    bluetooth_data_t  *bluetooth_data;
    uint8_t   opcode;
    /* ATT handle for currently processed packet (optional) */
    uint32_t  handle;
} btatt_data_t;


typedef struct _tap_handles_t {
    uint32_t  handle;
    bluetooth_uuid_t uuid;
} tap_handles_t;


extern const value_string btatt_ips_coordinate_system[];
extern const value_string btatt_ips_uncertainty_stationary_vals[];
extern const value_string btatt_ips_uncertainty_update_time_vals[];
extern const value_string btatt_ips_uncertainty_precision_vals[];
extern const value_string btatt_ips_uncertainty_coordinate_system[];
extern const value_string tds_organization_id_vals[];
extern const value_string characteristic_presentation_namespace_description_btsig_vals[];

bluetooth_uuid_t
get_gatt_bluetooth_uuid_from_handle(packet_info *pinfo, uint32_t handle, uint8_t opcode,
    bluetooth_data_t *bluetooth_data);

WS_DLL_PUBLIC bool bluetooth_gatt_has_no_parameter(uint8_t opcode);
WS_DLL_PUBLIC expert_field ei_btatt_invalid_usage;

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
