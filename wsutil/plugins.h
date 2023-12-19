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

typedef enum {
    WS_PLUGIN_NONE,
    WS_PLUGIN_EPAN,
    WS_PLUGIN_WIRETAP,
    WS_PLUGIN_CODEC
} plugin_type_e;

typedef enum {
    WS_PLUGIN_SCOPE_NONE,
    WS_PLUGIN_SCOPE_USER,
    WS_PLUGIN_SCOPE_GLOBAL,
    WS_PLUGIN_SCOPE_CLI,
} plugin_scope_e;

#define WS_PLUGIN_SPDX_GPLv2    "GPL-2.0-or-later"
#define WS_PLUGIN_GITLAB_URL    "https://gitlab.com/wireshark/wireshark"

#define WS_PLUGIN_DESC_DISSECTOR    (1UL << 0)
#define WS_PLUGIN_DESC_FILE_TYPE    (1UL << 1)
#define WS_PLUGIN_DESC_CODEC        (1UL << 2)
#define WS_PLUGIN_DESC_EPAN         (1UL << 3)
#define WS_PLUGIN_DESC_TAP_LISTENER (1UL << 4)
#define WS_PLUGIN_DESC_DFUNCTION    (1UL << 5)

// GLib and Qt allow ".dylib" and ".so" on macOS. Should we do the same?
#ifdef _WIN32
#define WS_PLUGIN_MODULE_SUFFIX ".dll"
#else
#define WS_PLUGIN_MODULE_SUFFIX ".so"
#endif

typedef void plugins_t;

typedef void (*module_register_func)(void);

struct ws_module {
    uint32_t flags;
    const char *version;
    const char *spdx_id;
    const char *home_url;
    const char *blurb;
    module_register_func register_cb;
};

typedef plugin_type_e (*ws_load_module_func)(int *, int *, struct ws_module **);

WS_DLL_PUBLIC plugins_t *plugins_init(plugin_type_e type);

typedef void (*plugin_description_callback)(const char *name, const char *version,
                                            uint32_t flags, const char *spdx_id,
                                            const char *blurb, const char *home_url,
                                            const char *filename, plugin_scope_e scope,
                                            void *user_data);

WS_DLL_PUBLIC void plugins_get_descriptions(plugin_description_callback callback, void *user_data);

WS_DLL_PUBLIC void plugins_print_description(const char *name, const char *version,
                         uint32_t flags, const char *spdx_id,
                         const char *blurb, const char *home_url,
                         const char *filename, plugin_scope_e scope,
                         void *user_data _U_);

WS_DLL_PUBLIC void plugins_dump_all(void);

WS_DLL_PUBLIC int plugins_get_count(void);

WS_DLL_PUBLIC void plugins_cleanup(plugins_t *plugins);

WS_DLL_PUBLIC bool plugins_supported(void);

WS_DLL_PUBLIC plugin_type_e plugins_check_file(const char *path);

WS_DLL_PUBLIC char *plugins_pers_type_folder(plugin_type_e type);

WS_DLL_PUBLIC
int plugins_abi_version(plugin_type_e type);

#define WIRESHARK_PLUGIN_REGISTER(type, ptr_, api_level_) \
    WS_DLL_PUBLIC plugin_type_e \
    wireshark_load_module(int *abi_version_ptr, int *min_api_level_ptr, \
                            struct ws_module **module_ptr) \
    { \
        if (abi_version_ptr) \
            *abi_version_ptr = WIRESHARK_ABI_VERSION_ ## type; \
        if (min_api_level_ptr) \
            *min_api_level_ptr = api_level_; \
        if (module_ptr) \
            *module_ptr = ptr_; \
        return WS_PLUGIN_ ## type; \
    }

#define WIRESHARK_PLUGIN_REGISTER_EPAN(ptr, level) \
    WIRESHARK_PLUGIN_REGISTER(EPAN, ptr, level)

#define WIRESHARK_PLUGIN_REGISTER_WIRETAP(ptr, level) \
    WIRESHARK_PLUGIN_REGISTER(WIRETAP, ptr, level)

#define WIRESHARK_PLUGIN_REGISTER_CODEC(ptr, level) \
    WIRESHARK_PLUGIN_REGISTER(CODEC, ptr, level)

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
