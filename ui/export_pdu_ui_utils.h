/** @file
 *
 * Routines for exported_pdu dissection
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORT_PDU_UI_UTILS_H
#define EXPORT_PDU_UI_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
* Filters the current opened capture file into a temporary file. On success,
* the filtered file is opened into the UI.
*/
void do_export_pdu(const char *filter, const char *temp_dir, const char *tap_name);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* EXPORT_PDU_UI_UTILS_H */
