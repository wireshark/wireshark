/** @file
 * definitions for plugins structures
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PLUGINS_H__
#define __PLUGINS_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef void (*plugin_register_func)(void);
typedef uint32_t (*plugin_describe_func)(void);

typedef void plugins_t;

typedef enum {
    WS_PLUGIN_EPAN,
    WS_PLUGIN_WIRETAP,
    WS_PLUGIN_CODEC
} plugin_type_e;

#define WS_PLUGIN_DESC_DISSECTOR    (1UL << 0)
#define WS_PLUGIN_DESC_FILE_TYPE    (1UL << 1)
#define WS_PLUGIN_DESC_CODEC        (1UL << 2)
#define WS_PLUGIN_DESC_EPAN         (1UL << 3)
#define WS_PLUGIN_DESC_TAP_LISTENER (1UL << 4)
#define WS_PLUGIN_DESC_DFILTER      (1UL << 5)

WS_DLL_PUBLIC plugins_t *plugins_init(plugin_type_e type);

typedef void (*plugin_description_callback)(const char *name, const char *version,
                                            uint32_t flags, const char *filename,
                                            void *user_data);

WS_DLL_PUBLIC void plugins_get_descriptions(plugin_description_callback callback, void *user_data);

WS_DLL_PUBLIC void plugins_dump_all(void);

WS_DLL_PUBLIC int plugins_get_count(void);

WS_DLL_PUBLIC void plugins_cleanup(plugins_t *plugins);

WS_DLL_PUBLIC bool plugins_supported(void);

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
