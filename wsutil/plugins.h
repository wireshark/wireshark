/* plugins.h
 * definitions for plugins structures
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __PLUGINS_H__
#define __PLUGINS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include <gmodule.h>

#include "ws_symbol_export.h"

typedef gboolean (*plugin_check_type_callback)(GModule *handle);

typedef enum {
    REPORT_LOAD_FAILURE,
    DONT_REPORT_LOAD_FAILURE
} plugin_load_failure_mode;
WS_DLL_PUBLIC void scan_plugins(plugin_load_failure_mode mode);
WS_DLL_PUBLIC void add_plugin_type(const char *type, plugin_check_type_callback callback);
typedef void (*plugin_description_callback)(const char *name, const char *version,
                                            const char *types, const char *filename,
                                            void *user_data);
WS_DLL_PUBLIC void plugins_get_descriptions(plugin_description_callback callback, void *user_data);
WS_DLL_PUBLIC void plugins_dump_all(void);
WS_DLL_PUBLIC int plugins_get_count(void);
WS_DLL_PUBLIC void plugins_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PLUGINS_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
