/*
* export_pdu_ui_utils.h
* Routines for exported_pdu dissection
* Copyright 2013, Anders Broman <anders-broman@ericsson.com>
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef EXPORT_PDU_UI_UTILS_H
#define EXPORT_PDU_UI_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
* Filters the current opened capture file into a temporary file. On success,
* TRUE is returned and the filtered file is opened into the UI.
*/
gboolean do_export_pdu(const char *filter, gchar *tap_name, exp_pdu_t *data);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* EXPORT_PDU_UI_UTILS_H */
