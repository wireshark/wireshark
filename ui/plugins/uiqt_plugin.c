/* uiqt_plugin.c
 * Plugin interface for Qt-based UI
 * 2025 Michael Mann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "include/uiqt_plugin.h"

#include <wsutil/wslog.h>
#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#ifdef HAVE_PLUGINS
static plugins_t *libqtui_plugins;
#endif

static GSList *qtui_plugins;

#ifdef HAVE_PLUGINS
void
uiqt_register_plugin(const qtui_plugin* plug)
{
    qtui_plugins = g_slist_prepend(qtui_plugins, (qtui_plugin*)plug);
}
#else /* HAVE_PLUGINS */
void
uiqt_register_plugin(const qtui_plugin*plug _U_)
{
	ws_warning("uiqt_register_plugin: built without support for binary plugins");
}
#endif /* HAVE_PLUGINS */

static void
call_plugin_register_uiqt_module(void * data, void * user_data _U_)
{
    qtui_plugin* plug = (qtui_plugin*)data;

    if (plug->register_qtui_module) {
        plug->register_qtui_module();
    }
}


/*
 * For all UI plugins, call their register routines.
 */
void
uiqt_plugin_init(const char* app_env_var_prefix _U_)
{
#ifdef HAVE_PLUGINS
    libqtui_plugins = plugins_init(WS_PLUGIN_UI, app_env_var_prefix);
#endif
    g_slist_foreach(qtui_plugins, call_plugin_register_uiqt_module, NULL);
}

void
uiqt_plugin_cleanup(void)
{
    g_slist_free(qtui_plugins);
    qtui_plugins = NULL;
#ifdef HAVE_PLUGINS
    plugins_cleanup(libqtui_plugins);
    libqtui_plugins = NULL;
#endif
}

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
