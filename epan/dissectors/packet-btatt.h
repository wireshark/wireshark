/* packet-btaatt.h
 * Headers for ATT
 *
 * Copyright 2015, Michal Labedzki for Tieto Corporation
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

WS_DLL_PUBLIC gboolean bluetooth_gatt_has_no_parameter(guint8 opcode);
WS_DLL_PUBLIC expert_field ei_btatt_invalid_usage;

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
