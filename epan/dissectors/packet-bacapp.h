/* packet-bacapp.h
 * by fkraemer, SAUTER
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

#ifndef __PACKET_BACNET_H__
#define __PACKET_BACNET_H__

#define BACINFO_SERVICE         0
#define BACINFO_INVOKEID        1
#define BACINFO_INSTANCEID      2
#define BACINFO_OBJECTID        4


/* Used for BACnet statistics */
typedef struct _bacapp_info_value_t {
    const gchar     *service_type;
    const gchar     *invoke_id;
    const gchar     *instance_ident;
    const gchar     *object_ident;
} bacapp_info_value_t;

#endif /* __PACKET_BACNET_H__ */

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
