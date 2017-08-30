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
#include <wsutil/unicode-utils.h>
#endif

#include <ui/capture_ui_utils.h>

/* As boolean flags will be allowed any form of yes, true or any number != 0 (or starting with 0)
 * The regex will be matched case-insensitive, so only the lower-case is defined here. */
#define EXTCAP_BOOLEAN_REGEX "^.*([yt1-9])"

/* Prefix for the pipe interfaces */
#define EXTCAP_PIPE_PREFIX "wireshark_extcap"
#define EXTCAP_CONTROL_IN_PREFIX  "wireshark_control_ext_to_ws"
#define EXTCAP_CONTROL_OUT_PREFIX "wireshark_control_ws_to_ext"

#define EXTCAP_ARGUMENT_CONFIG                  "--extcap-config"
#define EXTCAP_ARGUMENT_LIST_INTERFACES         "--extcap-interfaces"
#define EXTCAP_ARGUMENT_INTERFACE               "--extcap-interface"
#define EXTCAP_ARGUMENT_LIST_DLTS               "--extcap-dlts"

#define EXTCAP_ARGUMENT_RUN_CAPTURE             "--capture"
#define EXTCAP_ARGUMENT_CAPTURE_FILTER          "--extcap-capture-filter"
#define EXTCAP_ARGUMENT_RUN_PIPE                "--fifo"
#define EXTCAP_ARGUMENT_CONTROL_IN              "--extcap-control-in"
#define EXTCAP_ARGUMENT_CONTROL_OUT             "--extcap-control-out"

typedef struct _extcap_info {
    gchar * basename;
    gchar * full_path;
    gchar * version;
    gchar * help;

    GList * interfaces;
} extcap_info;

typedef enum {
    EXTCAP_FILTER_UNKNOWN,
    EXTCAP_FILTER_VALID,
    EXTCAP_FILTER_INVALID
} extcap_filter_status;

struct _extcap_arg;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Count the number of extcap binaries */
guint
extcap_count(void);

/* Registers preferences for all interfaces */
void
extcap_register_preferences(void);

/* try to get if capabilities from extcap */
if_capabilities_t *
extcap_get_if_dlts(const gchar * ifname, char ** err_str);

/* append a list of all extcap capture interfaces to the specified list */
GList *
append_extcap_interface_list(GList *list, char **err_str);

extcap_info *
extcap_get_tool_info(const gchar * toolname);

extcap_info *
extcap_get_tool_by_ifname(const gchar *ifname);

/* return the help page or NULL for the given ifname */
gchar *
extcap_get_help_for_ifname(const char *ifname);

/* get a list of all available extcap executables and their interfaces */
GHashTable *
extcap_loaded_interfaces(void);

/* remove all loaded interfaces */
void
extcap_clear_interfaces(void);

/* returns the configuration for the given interface name, or an
 * empty list, if no configuration has been found */
GList *
extcap_get_if_configuration(const char * ifname);

/**
 * Check if the capture filter for the given interface name is valid.
 * @param ifname Interface to check
 * @param filter Capture filter to check
 * @param err_str Error string returned if filter is invalid
 * @return Filter check status.
 */
extcap_filter_status
extcap_verify_capture_filter(const char *ifname, const char *filter, gchar **err_str);

/**
 * Frees the memory from extcap_get_if_configuration.
 * @param list The list returned by extcap_get_if_configuration.
 * @param free_args TRUE if all arguments in the list must be freed too or FALSE
 * if the ownership of the arguments is taken by the caller.
 */
void
extcap_free_if_configuration(GList *list, gboolean free_args);

gboolean
extcap_has_configuration(const char * ifname, gboolean is_required);

gboolean
extcap_has_toolbar(const char *ifname);

gboolean
extcap_init_interfaces(capture_options * capture_opts);

gboolean
extcap_create_pipe(const gchar *ifname, gchar **fifo, const gchar *pipe_prefix, gboolean byte_mode);

/* Clean up all if related stuff */
void
extcap_if_cleanup(capture_options * capture_opts, gchar ** errormsg);

struct preference *
extcap_pref_for_argument(const gchar *ifname, struct _extcap_arg * arg);

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
