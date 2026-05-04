/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_EXPORT_OBJECT_H__
#define __TAP_EXPORT_OBJECT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief List all available object types for export.
 *
 * This function iterates through all registered export object tables and prints their names.
 */
void eo_list_object_types(void);

/**
 * @brief Adds an export object option.
 *
 * This function is called by main each time a --export-objects option is found.
 *
 * @param ws_optarg The argument for the export objects option.
 * @return true if the option was successfully added, false otherwise.
 */
bool eo_tap_opt_add(const char *ws_optarg);

/**
 * @brief Starts exporting objects based on the current options.
 */
void start_exportobjects(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_EXPORT_OBJECT_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
