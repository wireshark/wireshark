/* extcap.h
 * Definitions for extcap external capture
 * Copyright 2013, Mike Ryan <mikeryan@lacklustre.net>
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

#ifndef __EXTCAP_H__
#define __EXTCAP_H__

#include <config.h>

#include <glib.h>

#ifdef _WIN32
#include <windows.h>
#include <wsutil/unicode-utils.h>
#endif

#include <ui/capture_ui_utils.h>

/* As boolean flags will be allowed any form of yes, true or any number != 0 (or starting with 0)
 * The regex will be matched case-insensitive, so only the lower-case is defined here. */
#define EXTCAP_BOOLEAN_REGEX "^.*([yt1-9])"

/* Prefix for the pipe interfaces */
#define EXTCAP_PIPE_PREFIX "wireshark_extcap"

#define EXTCAP_ARGUMENT_CONFIG                  "--extcap-config"
#define EXTCAP_ARGUMENT_LIST_INTERFACES "--extcap-interfaces"
#define EXTCAP_ARGUMENT_INTERFACE               "--extcap-interface"
#define EXTCAP_ARGUMENT_LIST_DLTS               "--extcap-dlts"

#define EXTCAP_ARGUMENT_RUN_CAPTURE             "--capture"
#define EXTCAP_ARGUMENT_CAPTURE_FILTER          "--extcap-capture-filter"
#define EXTCAP_ARGUMENT_RUN_PIPE                "--fifo"

typedef struct _extcap_info {
    gchar * basename;
    gchar * full_path;
    gchar * version;
} extcap_info;

struct _extcap_arg;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Registers preferences for all interfaces */
void
extcap_register_preferences(void);

/* try to get if capabilities from extcap */
if_capabilities_t *
extcap_get_if_dlts(const gchar * ifname, char ** err_str);

/* append a list of all extcap capture interfaces to the specified list */
GList *
append_extcap_interface_list(GList *list, char **err_str);

/* get a list of all available extcap tools */
GHashTable *
extcap_tools_list(void);

/* returns the configuration for the given interface name, or an
 * empty list, if no configuration has been found */
GList *
extcap_get_if_configuration(const char * ifname);

gboolean
extcap_has_configuration(const char * ifname, gboolean is_required);

#ifdef WIN32
HANDLE
extcap_get_win32_handle();
#endif

gboolean
extcap_init_interfaces(capture_options * capture_opts);

gboolean
extcap_create_pipe(char ** fifo);

/* Clean up all if related stuff */
void
extcap_if_cleanup(capture_options * capture_opts _U_, gchar ** errormsg);

struct preference *
extcap_pref_for_argument(const gchar *ifname, struct _extcap_arg * arg);

void
extcap_pref_store(struct _extcap_arg * arg, const char * newval);

/* Clean up global extcap stuff on program exit */
void extcap_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
