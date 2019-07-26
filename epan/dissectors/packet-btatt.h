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

typedef struct _btatt_data_t {
    bluetooth_data_t  *bluetooth_data;

    guint8    opcode;
} btatt_data_t;


typedef struct _tap_handles_t {
    guint32   handle;
    bluetooth_uuid_t uuid;
} tap_handles_t;


extern const value_string btatt_ips_coordinate_system[];
extern const value_string btatt_ips_uncertainty_stationary_vals[];
extern const value_string btatt_ips_uncertainty_update_time_vals[];
extern const value_string btatt_ips_uncertainty_precision_vals[];
extern const value_string btatt_ips_uncertainty_coordinate_system[];
extern const value_string tds_organization_id_vals[];
extern const value_string characteristic_presentation_namespace_description_btsig_vals[];

WS_DLL_PUBLIC gboolean bluetooth_gatt_has_no_parameter(guint8 opcode);
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
