/*
 * export_pdu_ui_utils.h
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
* TRUE is returned and the filtered file is opened into the UI.
*/
gboolean do_export_pdu(const char *filter, const gchar *tap_name, exp_pdu_t *data);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* EXPORT_PDU_UI_UTILS_H */
